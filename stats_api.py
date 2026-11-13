"""Bounded statistics reads and monotonic retry policies for shared/node scopes."""
from datetime import timezone
from email.utils import parsedate_to_datetime
import json
import math
import re
import time
import urllib.error
import urllib.request


class InvalidStatistics(ValueError):
    pass


class StaleStatistics(InvalidStatistics):
    pass


def nonnegative_int(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r'[0-9]{1,20}', value):
        return int(value)
    raise InvalidStatistics('Invalid statistics integer')


def parse_statistics(payload, now, max_age):
    try:
        data = payload['stats']['data']
        node = payload['node']
        if not isinstance(data, dict) or not isinstance(node, dict) or not isinstance(node['Status'], str):
            raise InvalidStatistics('Invalid statistics structure')
        counters = {key: nonnegative_int(data[field]) for key, field in (
            ('keyups', 'totalkeyups'), ('txtime', 'totaltxtime'), ('stats_time', 'time'))}
        if not counters['stats_time'] or not 0 <= now - counters['stats_time'] <= max_age:
            raise StaleStatistics('Statistics timestamp is stale or in the future')
        keyed = data.get('keyed', False)
        if type(keyed) is bool:
            pass
        elif type(keyed) is int and keyed in (0, 1):
            keyed = bool(keyed)
        elif isinstance(keyed, str) and keyed.lower() in ('0', '1', 'false', 'true'):
            keyed = keyed.lower() in ('1', 'true')
        else:
            raise InvalidStatistics('Invalid keyed value')
        links = data.get('links')
        if links is None:
            links = []
        if not isinstance(links, list):
            raise InvalidStatistics('Invalid links value')
        return counters | {'keyed': keyed, 'links': len(links),
                           'registered': node['Status'] == 'Active'}
    except (KeyError, TypeError) as exc:
        raise InvalidStatistics('Missing statistics fields') from exc


def fetch_statistics(url, timeout, maximum):
    request = urllib.request.Request(url, headers={'User-Agent': 'KC1RAY-Hub-Scanner/1.0',
                                                 'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = getattr(response, 'status', 200)
        if status != 200:
            raise urllib.error.HTTPError(url, status, 'Statistics HTTP error',
                                         getattr(response, 'headers', {}), None)
        raw = response.read(maximum + 1)
    size = len(raw.encode('utf-8')) if isinstance(raw, str) else len(raw)
    if size > maximum:
        raise InvalidStatistics('Statistics response too large')
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise InvalidStatistics('Invalid statistics JSON') from exc


def _parse_retry_after(value, now):
    if not isinstance(value, str):
        return None
    value = value.strip()
    try:
        if re.fullmatch(r'[0-9]+', value):
            seconds = float(value)
        else:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                return None
            seconds = date.astimezone(timezone.utc).timestamp() - now
        return max(0, seconds) if math.isfinite(seconds) else None
    except (ValueError, TypeError, OverflowError):
        return None


def retry_after_seconds(value, now):
    return _parse_retry_after(value, now) or 0


def provider_wide_limit(status, retry_after, now):
    """429 is shared; 503 with a valid retry directive is explicit overload."""
    return status == 429 or (status == 503 and _parse_retry_after(retry_after, now) is not None)


class RetryPolicy:
    """One monotonic gate, usable globally or for one node; no inline retries."""
    def __init__(self, initial, maximum):
        self.initial, self.maximum = initial, maximum
        self.failures = 0
        self.deadline = 0.0
        self.kind = None

    def ready(self):
        return time.monotonic() >= self.deadline

    def fail(self, kind, retry_after=None):
        self.failures = min(32, self.failures + 1)
        delay = min(self.maximum, self.initial * 2 ** (self.failures - 1))
        delay = max(delay, retry_after_seconds(retry_after, time.time()))
        # Retry-After is a provider minimum; it may exceed our exponential ceiling.
        self.deadline = time.monotonic() + delay
        self.kind = kind

    def success(self):
        self.failures, self.deadline, self.kind = 0, 0.0, None

    def snapshot(self):
        remaining = max(0, self.deadline - time.monotonic())
        return {'failures': self.failures, 'retry_at': math.ceil(time.time() + remaining) if remaining else 0,
                'error_kind': self.kind}

    def restore(self, saved):
        self.success()
        if not isinstance(saved, dict):
            return
        failures, when, kind = (saved.get(k) for k in ('failures', 'retry_at', 'error_kind'))
        try:
            valid_time = type(when) in (int, float) and math.isfinite(when) and when >= 0
        except OverflowError:
            valid_time = False
        if (type(failures) is not int or not 0 <= failures <= 32 or not valid_time or
                kind not in (None, 'rate_limit', 'http', 'network', 'timeout', 'invalid_response', 'stale_response')):
            return
        if (failures == 0 and (when != 0 or kind is not None)) or (failures > 0 and kind is None):
            return
        self.failures, self.kind = failures, kind
        self.deadline = time.monotonic() + max(0, when - time.time())
