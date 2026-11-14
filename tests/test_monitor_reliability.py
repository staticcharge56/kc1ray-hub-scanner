"""Offline Phase 2B tests with controlled wall/monotonic clocks and no real sleep."""
import contextlib
from copy import deepcopy
from email.message import Message
import hashlib
import http.client
import io
import json
from pathlib import Path
import unittest
import subprocess
import shutil
import re
import tempfile
from unittest.mock import patch
import urllib.error

import activity_history as history
import configuration
import monitor
import stats_api
from test_baseline import OfflineCase, ROOT


class FakeClock:
    def __init__(self, wall=1000, monotonic=100):
        self.wall, self.tick = wall, monotonic

    def advance(self, seconds):
        self.wall += seconds
        self.tick += seconds


class ReliabilityCase(OfflineCase):
    def setUp(self):
        super().setUp()
        self.clock = FakeClock()
        self.enterContext(patch('time.time', side_effect=lambda: self.clock.wall))
        self.enterContext(patch('time.monotonic', side_effect=lambda: self.clock.tick))
        self.enterContext(patch.object(monitor, 'records', {}))
        self.enterContext(patch.object(monitor, 'retry', stats_api.RetryPolicy(30, 120)))
        self.enterContext(patch.object(monitor, 'node_retries', {}))
        self.enterContext(patch.dict(monitor.CONFIG['monitor'], {'backoff_initial_seconds':30,'backoff_max_seconds':120}))
        self.enterContext(patch.object(monitor, 'HISTORY', self.tmp/'monitor-history.json'))
        self.enterContext(patch.object(monitor, 'CACHE', self.tmp/'activity.json'))
        self.enterContext(patch.object(monitor, 'LOCAL_NODE', '1000'))
        self.favorites = [dict(node='1001', name='First'), dict(node='1002', name='Second')]
        self.source = monitor.CONFIG['monitor']['stats_url_template']

    def record(self, **changes):
        return dict(checked=1000, stats_time=995, keyups=5, txtime=10,
                    keyed=False, registered=True, links=2, last_activity=990, error=None) | changes

    def envelope(self, records=None, **changes):
        return dict(version=1, saved_at=1000, local_node='1000', source=self.source,
                    records=records if records is not None else {'1001':self.record()},
                    retry={'failures':0,'retry_at':0,'error_kind':None}) | changes

    def write_history(self, data):
        monitor.HISTORY.write_text(json.dumps(data))

    def restore(self, retention=86400):
        return history.load_history(monitor.HISTORY, '1000', self.source,
                                    self.favorites, self.clock.wall, retention)

    def payload(self, keyups=5, txtime=10, stamp=None, keyed=False):
        return {'stats':{'data':dict(totalkeyups=keyups, totaltxtime=txtime,
                                    time=self.clock.wall if stamp is None else stamp,
                                    keyed=keyed, links=[])}, 'node':{'Status':'Active'}}

    def respond(self, payload):
        raw = json.dumps(payload).encode()
        return patch.object(monitor.urllib.request, 'urlopen',
                            return_value=contextlib.nullcontext(io.BytesIO(raw)))

    def http_error(self, status=429, retry_after=None):
        headers = Message()
        if retry_after is not None:
            headers['Retry-After'] = retry_after
        return urllib.error.HTTPError('https://example.invalid', status, 'test', headers, None)

    def status(self, record):
        return history.activity(record, self.clock.wall, 300, 300)


class HistoryTests(ReliabilityCase):
    def test_clean_restart_restores_counters_and_recent_activity(self):
        self.write_history(self.envelope())
        self.clock.advance(5)
        restored, _ = self.restore()
        self.assertEqual(restored['1001']['keyups'], 5)
        self.assertEqual(restored['1001']['last_activity'], 990)
        self.assertEqual(self.status(restored['1001']), 'active')

    def test_derived_saved_activity_is_never_trusted(self):
        record = self.record(last_activity=1, activity='active', keyed=False)
        self.write_history(self.envelope({'1001':record}))
        restored, _ = self.restore()
        self.assertNotIn('activity', restored['1001'])
        self.assertEqual(self.status(restored['1001']), 'idle')

    def test_fresh_saved_keyed_requires_both_fresh_timestamps(self):
        for checked, stamp, expected in ((700,700,'active'), (699,699,'unknown'),
                                         (1000,699,'unknown'), (1000,700,'active')):
            with self.subTest(checked=checked, stamp=stamp):
                self.write_history(self.envelope({'1001': self.record(
                    checked=checked, stats_time=stamp, keyed=True, last_activity=1)}))
                restored, _ = self.restore()
                self.assertEqual(self.status(restored['1001']), expected)

    def test_old_history_can_retain_baselines_without_active_status(self):
        self.write_history(self.envelope())
        self.clock.advance(301)
        restored, _ = self.restore()
        self.assertEqual(restored['1001']['keyups'], 5)
        self.assertEqual(self.status(restored['1001']), 'unknown')
        monitor.records.update(restored)
        with self.respond(self.payload(keyups=50, stamp=1301)):
            monitor.update_node('1001')
        # Growth since a stale baseline cannot be attributed to recent activity.
        self.assertEqual(self.status(monitor.records['1001']), 'idle')

    def test_retention_expired_history_is_discarded(self):
        self.write_history(self.envelope())
        self.clock.advance(86401)
        self.assertEqual(self.restore(), ({}, {}))

    def test_missing_damaged_and_wrong_envelopes_are_safe(self):
        self.assertEqual(self.restore(), ({}, {}))
        for raw in ('{bad', 'null', '[]', '{}', '"text"'):
            with self.subTest(raw=raw):
                monitor.HISTORY.write_text(raw)
                self.assertEqual(self.restore(), ({}, {}))
        for changes in ({'version':2}, {'version':True}, {'local_node':'9999'},
                        {'source':'https://other.invalid/{node}'}, {'saved_at':1001},
                        {'saved_at':float('nan')}, {'records':[]}):
            self.write_history(self.envelope(**changes))
            self.assertEqual(self.restore(), ({}, {}))

    def test_oversized_history_is_ignored(self):
        monitor.HISTORY.write_bytes(b' ' * (history.MAX_HISTORY_BYTES + 1))
        self.assertEqual(self.restore(), ({}, {}))

    def test_invalid_record_does_not_discard_other_valid_nodes(self):
        for change in ({'checked':1001}, {'stats_time':1001}, {'stats_time':None},
                       {'keyups':-1}, {'keyups':True}, {'txtime':'10'}, {'links':[]},
                       {'keyed':'false'}, {'registered':None}, {'checked':float('inf')}, {'checked':10**1000}):
            with self.subTest(change=change):
                self.write_history(self.envelope({'1001':self.record(**change), '1002':self.record()}))
                restored, _ = self.restore()
                self.assertEqual(set(restored), {'1002'})

    def test_future_last_activity_is_discarded_permanently(self):
        self.write_history(self.envelope({'1001':self.record(last_activity=1100)}))
        restored, _ = self.restore()
        self.assertNotIn('last_activity', restored['1001'])
        self.clock.advance(100)
        self.assertEqual(self.status(restored['1001']), 'idle')

    def test_only_current_favorites_are_restored_with_new_names(self):
        self.write_history(self.envelope({'1001':self.record(), '1002':self.record()}))
        self.favorites = [dict(node='1002', name='Renamed')]
        restored, _ = self.restore()
        self.assertEqual(set(restored), {'1002'})
        self.assertNotIn('name', restored['1002'])

    def test_error_state_cannot_restore_active_even_with_fresh_stats(self):
        self.write_history(self.envelope({'1001':self.record(keyed=True, error='network',error_kind='network')}))
        restored, _ = self.restore()
        self.assertEqual(self.status(restored['1001']), 'unknown')
        self.assertEqual(restored['1001']['keyups'], 5)

    def test_main_loads_history_and_flushes_normal_shutdown(self):
        self.write_history(self.envelope())
        self.clock.advance(5)
        def observe(node):
            self.assertEqual(monitor.records['1001']['keyups'], 5)
            monitor.records['1001'].update(checked=1005, stats_time=1005, keyups=6, last_activity=1005)
        with patch.object(monitor, 'require_node'), \
             patch.object(monitor, 'get_favorites', return_value=self.favorites), \
             patch.object(monitor, 'update_node', side_effect=observe), \
             patch.object(monitor.time, 'sleep', side_effect=SystemExit(0)):
            with self.assertRaises(SystemExit):
                monitor.main()
        saved = json.loads(monitor.HISTORY.read_text())
        self.assertEqual(saved['records']['1001']['keyups'], 6)
        self.assertEqual(saved['records']['1001']['last_activity'], 1005)
        self.assertNotIn('activity', saved['records']['1001'])
        cache = json.loads(monitor.CACHE.read_text())
        self.assertEqual(cache['favorites'][0]['activity'], 'active')


class CounterAndFreshnessTests(ReliabilityCase):
    def test_counter_reset_clears_old_activity_without_marking_active(self):
        monitor.records['1001'] = self.record()
        self.clock.advance(5)
        with self.respond(self.payload(keyups=1,txtime=1)):
            monitor.update_node('1001')
        self.assertNotIn('last_activity', monitor.records['1001'])
        self.assertEqual(self.status(monitor.records['1001']), 'idle')
        self.clock.advance(5)
        with self.respond(self.payload(keyups=2,txtime=2)):
            monitor.update_node('1001')
        self.assertEqual(self.status(monitor.records['1001']), 'active')

    def test_partial_counter_reset_is_not_an_increase(self):
        monitor.records['1001'] = self.record()
        with self.respond(self.payload(keyups=6,txtime=1)):
            monitor.update_node('1001')
        self.assertEqual(self.status(monitor.records['1001']), 'idle')

    def test_keyed_restart_sample_can_indicate_real_activity(self):
        monitor.records['1001'] = self.record()
        with self.respond(self.payload(keyups=1,txtime=1,keyed=True)):
            monitor.update_node('1001')
        self.assertEqual(self.status(monitor.records['1001']), 'active')

    def test_repeated_timestamp_does_not_detect_counter_growth(self):
        monitor.records['1001'] = self.record(last_activity=1)
        with self.respond(self.payload(keyups=6,stamp=995)):
            monitor.update_node('1001')
        self.assertEqual(self.status(monitor.records['1001']), 'idle')

    def test_out_of_order_response_preserves_last_successful_sample(self):
        monitor.records['1001'] = self.record()
        with self.respond(self.payload(keyups=6,stamp=994)):
            monitor.update_node('1001')
        self.assertEqual(monitor.records['1001']['stats_time'], 995)
        self.assertEqual(monitor.records['1001']['keyups'], 5)
        self.assertEqual(monitor.records['1001']['error_kind'], 'stale_response')

    def test_freshness_and_event_boundaries(self):
        for age, expected in ((299,'active'),(300,'active'),(301,'unknown'),(-1,'unknown')):
            record = self.record(checked=1000-age,stats_time=1000-age,last_activity=1000-age)
            with self.subTest(age=age):
                self.assertEqual(self.status(record), expected)
        self.assertEqual(self.status(self.record(last_activity=699)), 'idle')
        self.assertEqual(self.status(self.record(last_activity=700)), 'active')
        self.assertEqual(self.status(self.record(last_activity=1001)), 'idle')

    def test_configured_freshness_and_window_are_used(self):
        record = self.record(checked=990,stats_time=990,last_activity=980)
        self.assertEqual(history.activity(record, 1000, 9, 300), 'unknown')
        self.assertEqual(history.activity(record, 1000, 10, 19), 'idle')
        self.assertEqual(history.activity(record, 1000, 10, 20), 'active')

    def test_stale_and_future_api_samples_are_errors(self):
        for stamp in (699,1001,0):
            monitor.retry.success()
            monitor.node_retries.clear()
            with self.subTest(stamp=stamp), self.respond(self.payload(stamp=stamp,keyed=True)):
                monitor.update_node('1001')
            self.assertEqual(monitor.records['1001']['error_kind'], 'stale_response')
            self.assertEqual(self.status(monitor.records['1001']), 'unknown')


class ApiReliabilityTests(ReliabilityCase):
    def test_rate_limit_gate_applies_to_all_nodes_and_honors_seconds(self):
        with patch.object(monitor.urllib.request, 'urlopen', side_effect=self.http_error(retry_after='120')) as call:
            monitor.update_node('1001')
            for _ in range(5):
                self.clock.advance(4)
                monitor.update_node('1002')
            self.assertEqual(call.call_count, 1)
        self.assertEqual(monitor.retry.snapshot()['retry_at'], 1120)
        self.assertEqual(monitor.records['1001']['error_kind'], 'rate_limit')
        self.clock.advance(100)
        with self.respond(self.payload()):
            self.assertTrue(monitor.update_node('1002'))
        self.assertEqual(monitor.retry.failures, 0)

    def test_http_date_retry_after_and_provider_minimum_above_cap(self):
        # 1970-01-01 00:20:00 UTC = epoch 1200 (200s ahead).
        with patch.object(monitor.urllib.request, 'urlopen', side_effect=self.http_error(
                retry_after='Thu, 01 Jan 1970 00:20:00 GMT')):
            monitor.update_node('1001')
        self.assertEqual(monitor.retry.snapshot()['retry_at'], 1200)
        self.assertGreater(200, monitor.retry.maximum)

    def test_invalid_retry_headers_use_exponential_default(self):
        for value in (None, '-1', 'garbage', '1.5', 'NaN', '9'*400,
                      'Thu, 01 Jan 1970 00:00:01 GMT'):
            monitor.retry.success()
            monitor.node_retries.clear()
            with self.subTest(value=value), patch.object(monitor.urllib.request, 'urlopen',
                    side_effect=self.http_error(retry_after=value)):
                monitor.update_node('1001')
            self.assertEqual(monitor.retry.snapshot()['retry_at'], 1030)

    def test_repeated_network_failures_use_bounded_exponential_backoff(self):
        for delay in (30,60,120,120,120):
            with patch.object(monitor.urllib.request, 'urlopen', side_effect=urllib.error.URLError('offline')) as call:
                monitor.update_node('1001')
                self.assertEqual(call.call_count, 1)
                self.assertEqual(monitor.node_retries['1001'].snapshot()['retry_at'], self.clock.wall+delay)
                self.clock.advance(delay-1)
                monitor.update_node('1001')
                self.assertEqual(call.call_count, 1)
                self.clock.advance(1)

    def test_timeouts_are_distinct_from_inactivity(self):
        for exception in (TimeoutError(), urllib.error.URLError(TimeoutError())):
            monitor.retry.success()
            monitor.node_retries.clear()
            monitor.records['1001'] = self.record()
            with self.subTest(exception=exception), patch.object(monitor.urllib.request, 'urlopen', side_effect=exception):
                monitor.update_node('1001')
            self.assertEqual(monitor.records['1001']['error_kind'], 'timeout')
            self.assertEqual(self.status(monitor.records['1001']), 'unknown')

    def test_incomplete_http_body_is_a_recoverable_network_error(self):
        monitor.records['1001'] = self.record()
        with patch.object(monitor.urllib.request, 'urlopen', side_effect=http.client.IncompleteRead(b'partial')):
            monitor.update_node('1001')
        self.assertEqual(monitor.records['1001']['error_kind'], 'network')
        self.assertEqual(monitor.records['1001']['keyups'], 5)
        self.clock.advance(30)
        with self.respond(self.payload(keyups=6)):
            self.assertTrue(monitor.update_node('1001'))

    def test_preserves_last_valid_statistics_on_failure_and_recovers(self):
        monitor.records['1001'] = self.record(keyed=True)
        with patch.object(monitor.urllib.request, 'urlopen', side_effect=OSError('offline')):
            monitor.update_node('1001')
        for key,value in self.record(keyed=True).items():
            if key != 'error':
                self.assertEqual(monitor.records['1001'][key], value)
        self.assertEqual(self.status(monitor.records['1001']), 'unknown')
        self.clock.advance(30)
        with self.respond(self.payload(keyups=6)):
            monitor.update_node('1001')
        self.assertIsNone(monitor.records['1001']['error'])
        self.assertEqual(self.status(monitor.records['1001']), 'active')
        self.assertEqual(monitor.retry.snapshot(), dict(failures=0,retry_at=0,error_kind=None))

    def test_recovery_after_long_outage_does_not_invent_recent_activity(self):
        monitor.records['1001'] = self.record(keyed=True)
        with patch.object(monitor.urllib.request, 'urlopen', side_effect=TimeoutError()):
            monitor.update_node('1001')
        self.clock.advance(301)
        with self.respond(self.payload(keyups=500)):
            monitor.update_node('1001')
        self.assertEqual(self.status(monitor.records['1001']), 'idle')

    def test_invalid_json_null_missing_fields_preserve_old_data(self):
        values = (b'{broken', b'null', b'[]', b'{}', b'{"stats":null}',
                  b'{"stats":{"data":null},"node":{}}')
        for raw in values:
            monitor.retry.success()
            monitor.node_retries.clear()
            monitor.records['1001'] = self.record()
            with self.subTest(raw=raw), patch.object(monitor.urllib.request, 'urlopen',
                    return_value=contextlib.nullcontext(io.BytesIO(raw))):
                monitor.update_node('1001')
            self.assertEqual(monitor.records['1001']['error_kind'], 'invalid_response')
            self.assertEqual(monitor.records['1001']['keyups'], 5)

    def test_invalid_stat_types_are_rejected(self):
        for field,value in (('totalkeyups',True),('totalkeyups',-1),('totaltxtime',None),
                            ('keyed','arbitrary'),('links','not a list'),('time',True)):
            payload = self.payload()
            payload['stats']['data'][field] = value
            monitor.retry.success()
            monitor.node_retries.clear()
            with self.subTest(field=field,value=value), self.respond(payload):
                monitor.update_node('1001')
            self.assertEqual(monitor.records['1001']['error_kind'], 'invalid_response')

    def test_string_zero_keyed_is_not_truthy_activity(self):
        with self.respond(self.payload(keyed='0')):
            monitor.update_node('1001')
        self.assertFalse(monitor.records['1001']['keyed'])
        self.assertEqual(self.status(monitor.records['1001']), 'idle')

    def test_size_limit_and_timeout_are_forwarded(self):
        with patch.dict(monitor.CONFIG['monitor'], {'response_max_bytes':1024,'request_timeout_seconds':7}):
            body = io.BytesIO(b' ' * 2048)
            with patch.object(monitor.urllib.request, 'urlopen', return_value=contextlib.nullcontext(body)) as request:
                monitor.update_node('1001')
            self.assertEqual(request.call_args.kwargs['timeout'], 7)
            self.assertEqual(body.tell(), 1025)
            self.assertEqual(monitor.records['1001']['error_kind'], 'invalid_response')

    def test_retry_gate_uses_monotonic_clock(self):
        monitor.retry.fail('rate_limit', '60')
        self.clock.wall += 86400
        self.assertFalse(monitor.retry.ready())
        self.clock.tick += 60
        self.assertTrue(monitor.retry.ready())

    def test_retry_gate_survives_checkpoint_and_restart(self):
        monitor.retry.fail('rate_limit', '120')
        self.write_history(self.envelope(retry=monitor.retry.snapshot()))
        self.clock.advance(30)
        _, saved_retry = self.restore()
        restarted = stats_api.RetryPolicy(30,120)
        restarted.restore(saved_retry)
        self.assertFalse(restarted.ready())
        self.clock.advance(90)
        self.assertTrue(restarted.ready())

    def test_provider_retry_minimum_survives_beyond_activity_retention(self):
        monitor.retry.fail('rate_limit', '172800')
        self.write_history(self.envelope(retry=monitor.retry.snapshot()))
        self.clock.advance(86401)
        restored, saved_retry = self.restore()
        self.assertEqual(restored, {})
        restarted = stats_api.RetryPolicy(30,120)
        restarted.restore(saved_retry)
        self.assertFalse(restarted.ready())
        self.clock.advance(86399)
        self.assertTrue(restarted.ready())

    def test_malformed_retry_state_does_not_crash(self):
        for saved in (None, [], {}, {'failures':-1,'retry_at':1100,'error_kind':'rate_limit'},
                      {'failures':1,'retry_at':float('nan'),'error_kind':'http'},
                      {'failures':1,'retry_at':1100,'error_kind':'bad'},
                      {'failures':1,'retry_at':10**1000,'error_kind':'http'},
                      {'failures':0,'retry_at':1100,'error_kind':None}):
            with self.subTest(saved=saved):
                monitor.retry.restore(saved)
                self.assertTrue(monitor.retry.ready())

    def test_http_503_supports_retry_after(self):
        with patch.object(monitor.urllib.request, 'urlopen', side_effect=self.http_error(503,'45')):
            monitor.update_node('1001')
        self.assertEqual(monitor.records['1001']['error_kind'], 'http')
        self.assertEqual(monitor.retry.snapshot()['retry_at'], 1045)


class CheckpointTests(ReliabilityCase):
    def writer(self):
        return history.HistoryWriter(monitor.HISTORY,'1000',self.source,60,86400)

    def test_checkpoint_throttling_and_forced_shutdown(self):
        writer = self.writer()
        data = {'1001':self.record()}
        retry = monitor.retry.snapshot()
        self.assertTrue(writer.save(data,self.favorites,retry))
        first = monitor.HISTORY.read_bytes()
        data['1001']['keyups'] = 6
        self.clock.advance(59)
        self.assertFalse(writer.save(data,self.favorites,retry))
        self.assertEqual(monitor.HISTORY.read_bytes(),first)
        self.clock.advance(1)
        self.assertTrue(writer.save(data,self.favorites,retry))
        data['1001']['keyups'] = 7
        self.assertTrue(writer.save(data,self.favorites,retry,force=True))
        self.assertEqual(json.loads(monitor.HISTORY.read_text())['records']['1001']['keyups'],7)

    def test_unchanged_state_does_not_rewrite(self):
        writer = self.writer()
        records = {'1001':self.record()}
        self.assertTrue(writer.save(records,self.favorites,monitor.retry.snapshot()))
        first = monitor.HISTORY.read_bytes()
        self.clock.advance(60)
        self.assertFalse(writer.save(records,self.favorites,monitor.retry.snapshot()))
        self.assertEqual(monitor.HISTORY.read_bytes(),first)

    def test_atomic_failure_retains_previous_file_and_cleans_temporary(self):
        writer = self.writer()
        data = {'1001':self.record()}
        writer.save(data,self.favorites,monitor.retry.snapshot())
        original = monitor.HISTORY.read_bytes()
        data['1001']['keyups'] = 6
        self.clock.advance(60)
        with patch.object(history.os,'replace',side_effect=OSError('full disk')):
            with self.assertRaises(OSError):
                writer.save(data,self.favorites,monitor.retry.snapshot())
        self.assertEqual(monitor.HISTORY.read_bytes(),original)
        self.assertEqual(list(self.tmp.glob('.monitor-history.json-*')),[])
        # Even failures are throttled until the next interval.
        self.assertFalse(writer.save(data,self.favorites,monitor.retry.snapshot()))
        self.clock.advance(60)
        self.assertTrue(writer.save(data,self.favorites,monitor.retry.snapshot()))

    def test_atomic_history_is_durable_cache_avoids_fsync(self):
        with patch.object(history.os,'fsync') as sync:
            history.atomic_json(monitor.HISTORY,self.envelope())
            self.assertEqual(sync.call_count,2)
        with patch.object(history.os,'fsync') as sync:
            monitor.save_cache(self.favorites)
            sync.assert_not_called()
        self.assertEqual(monitor.HISTORY.stat().st_mode & 0o777,0o640)

    def test_fsync_failure_keeps_old_history(self):
        history.atomic_json(monitor.HISTORY,self.envelope())
        old = monitor.HISTORY.read_bytes()
        with patch.object(history.os,'fsync',side_effect=OSError('I/O failure')):
            with self.assertRaises(OSError):
                history.atomic_json(monitor.HISTORY, self.envelope(records={}))
        self.assertEqual(monitor.HISTORY.read_bytes(),old)
        self.assertEqual(list(self.tmp.glob('.monitor-history.json-*')),[])

    def test_disk_write_failures_do_not_stop_monitoring(self):
        with patch.object(monitor,'require_node'), \
             patch.object(monitor,'get_favorites',return_value=self.favorites), \
             patch.object(monitor,'update_node') as update, \
             patch.object(monitor,'save_cache',side_effect=OSError('disk unavailable')), \
             patch.object(monitor.HistoryWriter,'save',side_effect=OSError('disk unavailable')), \
             patch.object(monitor.time,'sleep',side_effect=SystemExit(0)):
            with self.assertRaises(SystemExit):
                monitor.main()
        update.assert_called_once_with('1001')

    def test_favorites_edits_preserve_remaining_history(self):
        writer = self.writer()
        records = {'1001':self.record(), '1002':self.record(keyups=7)}
        writer.save(records,self.favorites,monitor.retry.snapshot())
        favorites = [dict(node='1002',name='Renamed'),dict(node='1001',name='First'),dict(node='1003',name='New')]
        writer.save(records,favorites,monitor.retry.snapshot(),force=True)
        restored,_ = history.load_history(monitor.HISTORY,'1000',self.source,favorites,1000,86400)
        self.assertEqual(restored['1002']['keyups'],7)
        self.assertEqual(restored['1001']['last_activity'],990)
        writer.save(records,favorites[:1],monitor.retry.snapshot(),force=True)
        self.assertEqual(set(json.loads(monitor.HISTORY.read_text())['records']),{'1002'})

    def test_cache_write_throttle_does_not_increase_poll_rate(self):
        calls, sleeps = [], []
        def sleep(seconds):
            sleeps.append(seconds)
            self.clock.advance(seconds)
            if len(sleeps)==5:
                raise SystemExit(0)
        def update(node):
            calls.append((self.clock.wall,node))
            monitor.records[node] = self.record(checked=int(self.clock.wall),stats_time=int(self.clock.wall))
        with patch.object(monitor,'require_node'), \
             patch.object(monitor,'get_favorites',return_value=self.favorites), \
             patch.object(monitor,'update_node',side_effect=update), \
             patch.object(monitor,'save_cache',wraps=monitor.save_cache) as cache, \
             patch.object(monitor.time,'sleep',side_effect=sleep):
            with self.assertRaises(SystemExit):
                monitor.main()
        self.assertEqual(sleeps,[4]*5)
        self.assertEqual([stamp for stamp,_ in calls],[1000,1004,1008,1012,1016])
        self.assertEqual(cache.call_count,3) # startup, at 16s, and final flush

    def test_favorites_remain_live_while_rate_limited(self):
        revised = [dict(node='1002',name='Renamed'),dict(node='1003',name='New')]
        self.write_history(self.envelope(retry=dict(failures=1,retry_at=1120,error_kind='rate_limit')))
        with patch.object(monitor,'require_node'), \
             patch.object(monitor,'get_favorites',side_effect=[self.favorites,revised]), \
             patch.object(monitor,'update_node') as update, \
             patch.object(monitor.time,'sleep',side_effect=SystemExit(0)):
            with self.assertRaises(SystemExit):
                monitor.main()
        update.assert_not_called()
        self.assertNotIn('1001',monitor.records)
        cache = json.loads(monitor.CACHE.read_text())
        self.assertEqual([f['name'] for f in cache['favorites']],['Renamed','New'])
        self.assertEqual(cache['api']['retry_at'],1120)

    def test_polling_metadata_warns_at_freshness_limit(self):
        self.assertFalse(monitor.polling_info(74)['freshness_warning'])
        self.assertTrue(monitor.polling_info(75)['freshness_warning'])
        self.assertEqual(monitor.polling_info(250)['minimum_cycle_seconds'],1000)


class PhaseBoundaryTests(OfflineCase):
    def test_protected_runtime_files_are_byte_for_byte_unchanged(self):
        expected = json.loads((ROOT/'tests/fixtures/phase-2b-protected.json').read_text())
        for filename,digest in expected.items():
            if filename=='broker.py':
                reviewed=json.loads((ROOT/'tests/fixtures/radio-policy-protected.json').read_text())['admin_runtime_sha256'][filename]
                self.assertEqual(hashlib.sha256((ROOT/filename).read_bytes()).hexdigest(),reviewed)
                continue
            if filename in ('dashboard.py', 'scanner.py'):
                continue # Phase 3 explicitly authorizes dashboard security changes.
            with self.subTest(filename=filename):
                self.assertEqual(hashlib.sha256((ROOT/filename).read_bytes()).hexdigest(),digest)

    def test_phase_2a_config_works_without_new_keys(self):
        path = self.tmp/'old.toml'
        path.write_text('[allstar]\nlocal_node="1001"\n[controls]\ncooldown_seconds=15\n')
        original = path.read_bytes()
        result = configuration.load_config(path)
        self.assertEqual(result['monitor']['history_write_interval_seconds'],60)
        self.assertEqual(result['controls']['cooldown_seconds'],15)
        self.assertEqual(path.read_bytes(),original)

    def test_invalid_new_settings_are_rejected(self):
        path = self.tmp/'bad.toml'
        for text in ('history_retention_seconds=0','history_write_interval_seconds=-1',
                     'cache_write_interval_seconds=0','response_max_bytes=1',
                     'response_max_bytes=16777217','backoff_initial_seconds=901',
                     'backoff_initial_seconds=true','backoff_max_seconds=0'):
            path.write_text('[monitor]\n'+text)
            with self.subTest(text=text),self.assertRaises(ValueError):
                configuration.load_config(path)


if __name__ == '__main__':
    unittest.main()


class DescriptionCachingTests(ReliabilityCase):
    def described_payload(self,value='Directory Hub'):
        result=self.payload()
        result['node'].update(node_frequency=value,name=1001)
        return result

    def test_verified_directory_field_is_separate_from_favorite_and_schedule(self):
        for payload in (None,{}, {'node':None},{'node':{'name':'Not a description','server':{'SiteName':'Machine name'}}}, {'node':{'node_frequency':None}}, {'node':{'node_frequency':42}}):
            self.assertIsNone(stats_api.description_from_payload(payload))
        payload={'node':{'node_frequency':'  Directory Hub\nTown  ','name':1001},'description':'NetWatch schedule'}
        self.assertEqual(stats_api.description_from_payload(payload),'Directory Hub Town')
        self.assertEqual(stats_api.clean_description('a'*1000),'a'*256)
        self.assertEqual(stats_api.clean_description('A\x00B'),'AB')

    def test_existing_poll_caches_description_without_changing_custom_title(self):
        with self.respond(self.described_payload()) as request:
            self.assertTrue(monitor.update_node('1001'))
            self.assertEqual(request.call_count,1)
        self.assertEqual(monitor.records['1001']['node_description'],'Directory Hub')
        monitor.save_cache(self.favorites)
        result=json.loads(monitor.CACHE.read_text())['favorites'][0]
        self.assertEqual(result['name'],'First')
        self.assertEqual(result['node_description'],'Directory Hub')

    def test_network_failure_keeps_description_and_statistics_unknown(self):
        monitor.records['1001']=self.record(node_description='Cached Hub')
        with patch.object(monitor.urllib.request,'urlopen',side_effect=TimeoutError):
            self.assertFalse(monitor.update_node('1001'))
        self.assertEqual(monitor.records['1001']['node_description'],'Cached Hub')
        self.assertEqual(monitor.records['1001']['keyups'],5)
        self.assertEqual(self.status(monitor.records['1001']),'unknown')

    def test_description_does_not_make_stale_statistics_active(self):
        payload=self.described_payload();payload['stats']['data']['time']=1
        with self.respond(payload):self.assertFalse(monitor.update_node('1001'))
        self.assertEqual(monitor.records['1001']['node_description'],'Directory Hub')
        self.assertEqual(self.status(monitor.records['1001']),'unknown')

    def test_valid_empty_description_clears_and_malformed_metadata_keeps_cache(self):
        monitor.records['1001']=self.record(node_description='Cached Hub')
        with self.respond(self.described_payload({'invalid':'text'})):
            self.assertTrue(monitor.update_node('1001'))
        self.assertEqual(monitor.records['1001']['node_description'],'Cached Hub')
        with self.respond(self.described_payload('  ')):
            self.assertTrue(monitor.update_node('1001'))
        self.assertNotIn('node_description',monitor.records['1001'])

    def test_description_survives_restart_beyond_activity_retention(self):
        writer=history.HistoryWriter(monitor.HISTORY,'1000',self.source,60,86400)
        writer.save({'1001':self.record(node_description='Cached Hub')},self.favorites,{})
        self.clock.advance(86401)
        restored,_=self.restore()
        self.assertEqual(restored['1001'],{'node_description':'Cached Hub'})
        self.assertEqual(self.status(restored['1001']),'unknown')
        self.assertNotIn('keyups',restored['1001'])

    def test_metadata_checkpoints_keep_existing_write_throttle(self):
        writer=history.HistoryWriter(monitor.HISTORY,'1000',self.source,60,86400)
        records={'1001':self.record(node_description='First Hub')}
        self.assertTrue(writer.save(records,self.favorites,{}))
        records['1001']['node_description']='Renamed Hub'
        self.clock.advance(59)
        self.assertFalse(writer.save(records,self.favorites,{}))
        self.assertEqual(json.loads(monitor.HISTORY.read_text())['node_descriptions'],{'1001':'First Hub'})
        self.clock.advance(1)
        self.assertTrue(writer.save(records,self.favorites,{}))
        restored,_=self.restore()
        self.assertEqual(restored['1001']['node_description'],'Renamed Hub')


class DescriptionDisplayTests(unittest.TestCase):
    def test_shared_formatter_and_all_view_call_sites(self):
        import dashboard
        source=dashboard.HTML
        helper=re.search(r'let nodeDescriptions = Object.create\(null\);.*?(?=function render\(\))',source,re.S).group()
        script="const assert=require('node:assert/strict'); const document={dispatchEvent(){}}; class Event{}; function fetch(){throw Error('unexpected request');}\n"+helper+r"""
rememberNodeDescriptions({updated:1,favorites:[{node:'29332',name:'My custom favorite',node_description:'Alaska AllStar Hub'}],net_schedule:{nets:[{node:'29332',name:'NetWatch net',description:'Schedule text'}]}});
assert.equal(nodeInfoLine('29332','active'),'Node 29332 - Alaska AllStar Hub - Active');
assert.equal(nodeInfoLine('29332','In your favorites'),'Node 29332 - Alaska AllStar Hub - In your favorites');
assert.equal(nodeInfoLine('29332'),'Node 29332 - Alaska AllStar Hub');
assert.equal(nodeInfoLine('9999','unknown'),'Node 9999 - Unknown');
rememberNodeDescriptions({updated:0,favorites:[]});
assert.equal(nodeInfoLine('29332','idle'),'Node 29332 - Alaska AllStar Hub - Idle');
rememberNodeDescriptions({updated:2,favorites:[{node:'29332',node_description:''}]});
assert.equal(nodeInfoLine('29332','active'),'Node 29332 - Active');
rememberNodeDescriptions({updated:3,favorites:[{node:'29332',node_description:'<img src=x onerror=alert(1)>'}]});
assert.equal(nodeInfoLine('29332','active'),'Node 29332 - <img src=x onerror=alert(1)> - Active');
console.log('OK');
"""
        node=shutil.which('node');self.assertIsNotNone(node,'Node.js is required for display checks')
        result=subprocess.run([node,'-e',script],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'OK\n')
        self.assertIn('meta.textContent = nodeInfoLine(f.node, f.displayStatus)',source)
        self.assertIn('info.textContent = nodeInfoLine(entry.node',source)
        self.assertIn("' · ' + nodeInfoLine(f.node)",source)
        self.assertIn('name.textContent = f.name;',source)
        self.assertIn('title.textContent = f.name;',source)
        self.assertNotIn('innerHTML = nodeInfoLine',source)


    def test_cached_api_metadata_cannot_replace_authoritative_favorite_title(self):
        import dashboard
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'activity.json'
            path.write_text(json.dumps(dict(updated=1,favorites=[dict(node='1001',name='Cached old name',node_description='Directory Hub')])) )
            schedule=dict(nets=[dict(node='1001',name='NetWatch net',description='Schedule description')])
            with patch.object(dashboard,'CACHE',path),patch.object(dashboard.favorites_store,'read',return_value=[dict(node='1001',name='My custom title')]),patch.object(dashboard,'load_schedule',return_value=schedule),patch('urllib.request.urlopen',side_effect=AssertionError('No upstream reads')) as request:
                result=dashboard.activity_payload()
            self.assertEqual(result['favorites'][0]['name'],'My custom title')
            self.assertEqual(result['favorites'][0]['node_description'],'Directory Hub')
            self.assertEqual(result['net_schedule'],schedule)
            request.assert_not_called()
