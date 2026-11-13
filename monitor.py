#!/usr/bin/env python3
import time
import http.client
import signal
import urllib.error
import urllib.request
from pathlib import Path

from activity_history import (HistoryWriter, WriteThrottle, activity, atomic_json,
                              fresh, load_history)
from stats_api import (InvalidStatistics, StaleStatistics, RetryPolicy,
                       fetch_statistics, parse_statistics, provider_wide_limit)

from configuration import CONFIG, require_node
import favorites_store

CACHE = Path(CONFIG['paths']['cache_dir']) / 'activity.json'
HISTORY = Path(CONFIG['paths']['monitor_state_dir']) / 'monitor-history.json'
LOCAL_NODE = CONFIG['allstar']['local_node']
POLL_INTERVAL = CONFIG['monitor']['poll_interval_seconds']
MAX_STATS_AGE = CONFIG['monitor']['max_stats_age_seconds']
ACTIVITY_WINDOW = CONFIG['monitor']['activity_window_seconds']

records = {}
retry = RetryPolicy(CONFIG['monitor']['backoff_initial_seconds'], CONFIG['monitor']['backoff_max_seconds'])
node_retries = {}


def new_node_retry():
    return RetryPolicy(CONFIG['monitor']['backoff_initial_seconds'], CONFIG['monitor']['backoff_max_seconds'])


def retry_snapshot():
    return retry.snapshot() | {'scope_version': 2, 'nodes': {
        node: policy.snapshot() for node, policy in node_retries.items()}}


def restore_retries(saved, favorites):
    retry.success()
    node_retries.clear()
    if not isinstance(saved, dict):
        return
    wanted = {favorite['node'] for favorite in favorites}
    if saved.get('scope_version') == 2:
        if saved.get('error_kind') in ('rate_limit', 'http', None):
            retry.restore(saved)
        nodes = saved.get('nodes', {})
        if isinstance(nodes, dict):
            for node in wanted:
                policy = new_node_retry()
                policy.restore(nodes.get(node))
                if policy.failures:
                    node_retries[node] = policy
    elif 'scope_version' not in saved:
        # Upgrade old global-only checkpoints without reinstating a global block
        # for a malformed/timed-out node. Only legacy 429s are unambiguously shared.
        if saved.get('error_kind') == 'rate_limit':
            retry.restore(saved)
        else:
            for node in wanted:
                if records.get(node, {}).get('error_kind') == saved.get('error_kind'):
                    policy = new_node_retry()
                    policy.restore(saved)
                    if policy.failures:
                        node_retries[node] = policy


def get_favorites():
    return favorites_store.read()


def save_cache(favorites):
    now = int(time.time())
    result = []

    for fav in favorites:
        node = fav["node"]
        record = records.get(node, {}).copy()
        record.update(fav)

        status = activity(record, now, MAX_STATS_AGE, ACTIVITY_WINDOW)

        record["activity"] = status
        result.append(record)

    data = {
        "updated": now,
        "local_node": LOCAL_NODE,
        "favorites": result,
        "api": retry_snapshot(),
        "polling": polling_info(len(favorites)),
    }

    atomic_json(CACHE, data, durable=False)


def polling_info(count):
    minimum = count * POLL_INTERVAL
    return {'favorite_count': count, 'minimum_cycle_seconds': minimum,
            'max_stats_age_seconds': MAX_STATS_AGE, 'activity_window_seconds': ACTIVITY_WINDOW,
            'freshness_warning': minimum >= min(MAX_STATS_AGE, ACTIVITY_WINDOW)}


def warn_cycle(favorites):
    info = polling_info(len(favorites))
    if info['freshness_warning']:
        print(f"Polling {len(favorites)} favorites takes at least {info['minimum_cycle_seconds']}s "
              f"before network time/backoff; freshness={MAX_STATS_AGE}s, activity={ACTIVITY_WINDOW}s. "
              'Some activity may be missed or become unknown. Polling rate is unchanged.', flush=True)


def update_node(node):
    if not retry.ready() or (node in node_retries and not node_retries[node].ready()):
        return False
    record = records.setdefault(node, {})
    url = CONFIG['monitor']['stats_url_template'].format(node=node)
    settings = CONFIG['monitor']
    kind, header, shared_limit = None, None, False
    try:
        payload = fetch_statistics(url, settings['request_timeout_seconds'], settings['response_max_bytes'])
        now = int(time.time())
        sample = parse_statistics(payload, now, MAX_STATS_AGE)
        old_time = record.get('stats_time', 0)
        if sample['stats_time'] < old_time:
            raise StaleStatistics('Out-of-order statistics')
        reset = (record.get('keyups') is not None and
                 (sample['keyups'] < record['keyups'] or sample['txtime'] < record['txtime']))
        baseline_fresh = fresh(record | {'error': None}, now, MAX_STATS_AGE)
        changed = (baseline_fresh and not reset and sample['stats_time'] > old_time and
                   (sample['keyups'] > record['keyups'] or sample['txtime'] > record['txtime']))
        if reset:
            record.pop('last_activity', None)
        if sample['keyed'] or changed:
            record['last_activity'] = now
        # Invalid future events cannot become active later when the clock catches up.
        if record.get('last_activity', 0) > now:
            record.pop('last_activity', None)
        record.update(sample | {'checked': now, 'attempted': now, 'error': None})
        record.pop('error_kind', None)
        node_retries.pop(node, None)
        retry.success()
        return True
    except urllib.error.HTTPError as exc:
        kind = 'rate_limit' if exc.code == 429 else 'http'
        header = exc.headers.get('Retry-After') if exc.headers else None
        shared_limit = provider_wide_limit(exc.code, header, time.time())
        exc.close()
    except (TimeoutError,):
        kind = 'timeout'
    except urllib.error.URLError as exc:
        kind = 'timeout' if isinstance(exc.reason, TimeoutError) else 'network'
    except StaleStatistics:
        kind = 'stale_response'
    except (InvalidStatistics, ValueError, TypeError, RecursionError):
        kind = 'invalid_response'
    except (OSError, http.client.HTTPException):
        kind = 'network'
    # Keep successful checked/stats_time/counters/keyed intact, with an explicit
    # error that makes the sample unknown rather than active or idle.
    record.update({'attempted': int(time.time()), 'error': kind, 'error_kind': kind})
    record.setdefault('keyed', False)
    if shared_limit:
        policy, scope = retry, 'shared'
    else:
        policy = node_retries.setdefault(node, new_node_retry())
        scope = 'node'
    policy.fail(kind, header)
    print(f'Statistics request failed for {node}: {kind}; {scope} retry gate {policy.snapshot()}', flush=True)
    return False


def main():
    require_node()
    favorites = get_favorites()
    restored, saved_retry = load_history(
        HISTORY, LOCAL_NODE, CONFIG['monitor']['stats_url_template'], favorites,
        time.time(), CONFIG['monitor']['history_retention_seconds'])
    records.clear()
    records.update(restored)
    restore_retries(saved_retry, favorites)
    writer = HistoryWriter(HISTORY, LOCAL_NODE, CONFIG['monitor']['stats_url_template'],
                           CONFIG['monitor']['history_write_interval_seconds'],
                           CONFIG['monitor']['history_retention_seconds'])
    cache_gate = WriteThrottle(CONFIG['monitor']['cache_write_interval_seconds'])

    def publish(force=False):
        if cache_gate.due(force):
            try:
                save_cache(favorites)
            except (OSError, ValueError) as exc:
                print(f'Activity cache write failed: {type(exc).__name__}', flush=True)
        try:
            writer.save(records, favorites, retry_snapshot(), force=force)
        except (OSError, ValueError) as exc:
            print(f'Activity checkpoint failed: {type(exc).__name__}', flush=True)

    print(f'Monitoring {len(favorites)} favorites (live favorites reload); restored {len(records)} records', flush=True)
    warn_cycle(favorites)
    previous_signature = tuple((f['node'], f['name']) for f in favorites)
    next_node, next_position = None, 0
    try:
        publish(force=True)
        while True:
            try:
                latest = get_favorites()
            except (OSError, UnicodeError, ValueError) as exc:
                print(f'Favorites reload failed; keeping previous list: {exc}', flush=True)
                latest = favorites
            signature = tuple((f['node'], f['name']) for f in latest)
            changed = signature != previous_signature
            if changed:
                old_nodes = {f['node'] for f in favorites}
                new_nodes = {f['node'] for f in latest}
                for node in old_nodes - new_nodes:
                    records.pop(node, None)
                    node_retries.pop(node, None)
                favorites, previous_signature = latest, signature
                # Publish changed membership/names promptly; history stays throttled.
                try:
                    save_cache(favorites)
                except (OSError, ValueError) as exc:
                    print(f'Activity cache write failed: {type(exc).__name__}', flush=True)
                print(f'Favorites reloaded: {len(favorites)} total, '
                      f'{len(new_nodes-old_nodes)} added, {len(old_nodes-new_nodes)} removed', flush=True)
                warn_cycle(favorites)
            else:
                favorites = latest
            if favorites and retry.ready():
                nodes = [f['node'] for f in favorites]
                index = nodes.index(next_node) if next_node in nodes else min(next_position, len(nodes)-1)
                node = nodes[index]
                next_position = (index + 1) % len(nodes)
                next_node = nodes[next_position]
                # A backed-off node keeps its round-robin slot idle; do not
                # backfill it with extra healthy-node requests or catch-up bursts.
                update_node(node)
                state = records.get(node, {})
                print(f"{node}: links={state.get('links', '-')} keyed={state.get('keyed', False)} "
                      f"error={state.get('error')}", flush=True)
            publish()
            # Backoff skips requests rather than sleeping for the full delay, so
            # favorite edits, cache freshness and checkpoints remain responsive.
            time.sleep(POLL_INTERVAL)
    finally:
        publish(force=True)


def _terminate(signum, frame):
    raise SystemExit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, _terminate)
    try:
        main()
    except KeyboardInterrupt:
        pass
