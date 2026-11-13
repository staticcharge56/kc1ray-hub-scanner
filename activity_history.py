"""Validated restart history and throttled, atomic JSON checkpoints."""
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time

SCHEMA_VERSION = 1
MAX_HISTORY_BYTES = 2 * 1024 * 1024
KINDS = ('rate_limit', 'http', 'network', 'timeout', 'invalid_response', 'stale_response')


def timestamp(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value > 0
    except OverflowError:
        return False


def fresh(record, now, maximum):
    return (all(timestamp(record.get(k)) and 0 <= now - record[k] <= maximum
                for k in ('checked', 'stats_time')) and not record.get('error'))


def activity(record, now, maximum, window):
    if not fresh(record, now, maximum):
        return 'unknown'
    last = record.get('last_activity')
    recent = timestamp(last) and 0 <= now - last <= window
    return 'active' if record.get('keyed') is True or recent else 'idle'


def clean_record(record, now, retention):
    """Never trust persisted activity labels; retain only independently valid fields."""
    if not isinstance(record, dict):
        return None
    for key in ('checked', 'stats_time'):
        if not timestamp(record.get(key)) or not 0 <= now - record[key] <= retention:
            return None
    if record['stats_time'] > record['checked']:
        return None
    for key in ('keyups', 'txtime', 'links'):
        if type(record.get(key)) is not int or record[key] < 0:
            return None
    if type(record.get('keyed')) is not bool or type(record.get('registered')) is not bool:
        return None
    clean = {key: record[key] for key in ('checked', 'stats_time', 'keyups', 'txtime',
                                          'links', 'keyed', 'registered')}
    last = record.get('last_activity')
    if last is not None:
        if not timestamp(last) or last > record['checked'] or not 0 <= now - last <= retention:
            # An invalid event must not erase otherwise useful counter baselines.
            last = None
        if last is not None:
            clean['last_activity'] = last
    if record.get('error'):
        kind = record.get('error_kind')
        clean['error_kind'] = kind if kind in KINDS else 'invalid_response'
        clean['error'] = clean['error_kind']
    else:
        clean['error'] = None
    attempted = record.get('attempted')
    if timestamp(attempted) and record['checked'] <= attempted <= now:
        clean['attempted'] = attempted
    return clean


def load_history(path, local_node, source, favorites, now, retention):
    """Missing/damaged/wrong-source state is an empty baseline, never a crash."""
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(MAX_HISTORY_BYTES + 1)
        if len(raw) > MAX_HISTORY_BYTES:
            raise ValueError('history too large')
        saved = json.loads(raw)
        if (type(saved.get('version')) is not int or saved['version'] != SCHEMA_VERSION or
                saved.get('local_node') != local_node or saved.get('source') != source or
                not timestamp(saved.get('saved_at')) or saved['saved_at'] > now or
                not isinstance(saved.get('records'), dict)):
            raise ValueError('invalid history envelope')
        wanted = {f['node'] for f in favorites}
        result = {}
        for node, record in saved['records'].items():
            if node not in wanted or not re.fullmatch(r'[0-9]{4,7}', node):
                continue
            clean = clean_record(record, now, retention)
            if clean and clean['checked'] <= saved['saved_at']:
                result[node] = clean
        retry = saved.get('retry')
        # Retention limits observations, not a still-pending provider retry delay.
        return result, retry if isinstance(retry, dict) and (retry.get('failures') or retry.get('nodes')) else {}
    except FileNotFoundError:
        return {}, {}
    except (OSError, ValueError, TypeError, AttributeError, RecursionError) as exc:
        print(f'Activity history unavailable; starting with fresh baselines: {type(exc).__name__}', flush=True)
        return {}, {}


def atomic_json(path, data, *, durable=True):
    """Publish a complete snapshot in the same filesystem; retain old on failure."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
            stream.write('\n')
            stream.flush()
            if durable:
                os.fsync(stream.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
        if durable:
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class WriteThrottle:
    """Gate attempts as well as successes, so a full disk cannot create a hot loop."""
    def __init__(self, interval):
        self.interval = interval
        self.last_attempt = None

    def due(self, force=False):
        now = time.monotonic()
        if force or self.last_attempt is None or now - self.last_attempt >= self.interval:
            self.last_attempt = now
            return True
        return False


class HistoryWriter:
    def __init__(self, path, local_node, source, interval, retention):
        self.path, self.local_node, self.source = Path(path), local_node, source
        self.retention = retention
        self.gate = WriteThrottle(interval)
        self.previous = None

    def save(self, records, favorites, retry, *, force=False):
        if not self.gate.due(force):
            return False
        now = time.time()
        clean = {}
        for favorite in favorites:
            node = favorite['node']
            record = clean_record(records.get(node), now, self.retention)
            if record is not None:
                clean[node] = record
        content = {'version': SCHEMA_VERSION, 'local_node': self.local_node,
                   'source': self.source, 'records': clean, 'retry': retry}
        if content == self.previous:
            return False
        atomic_json(self.path, content | {'saved_at': now})
        self.previous = content
        return True
