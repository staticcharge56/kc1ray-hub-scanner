"""Mixed-node retry regression tests; no live API calls, subprocesses, or sleeps."""
import contextlib
import io
import json
from unittest.mock import patch
import urllib.error

import monitor
import stats_api
from test_monitor_reliability import ReliabilityCase


class RetryScopeTests(ReliabilityCase):
    def test_node_errors_leave_other_favorites_eligible_and_preserve_baselines(self):
        cases = ('malformed', 'missing', 'stale', 'timeout', 'network', '404', '503')
        for case in cases:
            with self.subTest(case=case):
                monitor.retry.success()
                monitor.node_retries.clear()
                monitor.records.clear()
                monitor.records['1001'] = self.record(keyed=True)
                if case in ('timeout', 'network', '404', '503'):
                    error = {'timeout':TimeoutError(), 'network':urllib.error.URLError('offline'),
                             '404':self.http_error(404), '503':self.http_error(503)}[case]
                    response = patch.object(monitor.urllib.request, 'urlopen', side_effect=error)
                else:
                    raw = {'malformed':b'{broken', 'missing':b'null',
                           'stale':json.dumps(self.payload(stamp=1)).encode()}[case]
                    response = patch.object(monitor.urllib.request, 'urlopen',
                        return_value=contextlib.nullcontext(io.BytesIO(raw)))
                with response:
                    self.assertFalse(monitor.update_node('1001'))
                self.assertTrue(monitor.retry.ready())
                self.assertEqual(monitor.retry.failures, 0)
                self.assertFalse(monitor.node_retries['1001'].ready())
                self.assertEqual(monitor.records['1001']['keyups'],5)
                self.assertEqual(monitor.records['1001']['checked'],1000)
                self.assertEqual(self.status(monitor.records['1001']),'unknown')
                with self.respond(self.payload()):
                    self.assertTrue(monitor.update_node('1002'))
                self.assertFalse(monitor.node_retries['1001'].ready())
                self.assertEqual(self.status(monitor.records['1002']),'idle')

    def test_healthy_responses_do_not_reset_another_nodes_exponential_backoff(self):
        with self.respond(None):
            monitor.update_node('1001')
        self.clock.advance(4)
        with self.respond(self.payload()):
            monitor.update_node('1002')
        self.assertEqual(monitor.node_retries['1001'].failures,1)
        self.clock.advance(26)
        with self.respond(None):
            monitor.update_node('1001')
        self.assertEqual(monitor.node_retries['1001'].failures,2)
        self.assertEqual(monitor.node_retries['1001'].snapshot()['retry_at'],1090)
        self.assertEqual(monitor.retry.failures,0)

    def test_node_retry_after_does_not_pause_healthy_nodes(self):
        for header in ('200','Thu, 01 Jan 1970 00:20:00 GMT'):
            monitor.node_retries.clear()
            with self.subTest(header=header), patch.object(monitor.urllib.request, 'urlopen',
                    side_effect=self.http_error(404,header)):
                monitor.update_node('1001')
            self.assertEqual(monitor.node_retries['1001'].snapshot()['retry_at'],1200)
            with self.respond(self.payload()):
                self.assertFalse(monitor.update_node('1001'))
                self.assertTrue(monitor.update_node('1002'))
            self.assertEqual(monitor.node_retries['1001'].snapshot()['retry_at'],1200)

    def test_node_recovery_clears_only_its_gate_and_preserves_activity_baseline(self):
        monitor.records['1001'] = self.record()
        for node in ('1001','1002'):
            with patch.object(monitor.urllib.request,'urlopen',side_effect=TimeoutError()):
                monitor.update_node(node)
        self.clock.advance(30)
        with self.respond(self.payload(keyups=6)):
            self.assertTrue(monitor.update_node('1001'))
        self.assertNotIn('1001',monitor.node_retries)
        self.assertIn('1002',monitor.node_retries)
        self.assertEqual(self.status(monitor.records['1001']),'active')
        self.assertEqual(self.status(monitor.records['1002']),'unknown')

    def test_global_rate_limit_overrides_all_node_gates(self):
        with self.respond(None):
            monitor.update_node('1001')
        with patch.object(monitor.urllib.request,'urlopen',side_effect=self.http_error(429,'120')) as calls:
            monitor.update_node('1002')
            self.clock.advance(30)
            for node in ('1001','1002','1003'):
                self.assertFalse(monitor.update_node(node))
            self.assertEqual(calls.call_count,1)
        self.assertEqual(monitor.retry.snapshot()['retry_at'],1120)
        self.clock.advance(90)
        with self.respond(self.payload()):
            self.assertTrue(monitor.update_node('1002'))
        self.assertEqual(monitor.retry.failures,0)
        self.assertIn('1001',monitor.node_retries) # Recovery elsewhere does not erase its failure.

    def test_explicit_503_provider_delay_is_shared_but_other_http_errors_are_local(self):
        for code, header, shared in ((429,None,True),(429,'bad',True),
                                     (503,'0',True),(503,'60',True),
                                     (503,None,False),(503,'bad',False),(404,'60',False)):
            monitor.retry.success()
            monitor.node_retries.clear()
            with self.subTest(code=code,header=header), patch.object(monitor.urllib.request,'urlopen',
                    side_effect=self.http_error(code,header)):
                monitor.update_node('1001')
            self.assertEqual(not monitor.retry.ready(),shared)
            self.assertEqual('1001' in monitor.node_retries,not shared)

    def test_mixed_loop_keeps_healthy_cadence_and_does_not_backfill_failed_slots(self):
        calls, sleeps = [], []
        self.write_history(self.envelope())
        def fetch(request, **kwargs):
            node = request.full_url.rsplit('/',1)[-1]
            calls.append((self.clock.wall,node))
            payload = None if node == '1001' else self.payload()
            return contextlib.nullcontext(io.BytesIO(json.dumps(payload).encode()))
        def sleep(seconds):
            sleeps.append(seconds)
            self.clock.advance(seconds)
            if len(sleeps) == 20:
                raise SystemExit(0)
        with patch.object(monitor,'require_node'), \
             patch.object(monitor,'get_favorites',return_value=self.favorites), \
             patch.object(monitor.urllib.request,'urlopen',side_effect=fetch), \
             patch.object(monitor.time,'sleep',side_effect=sleep):
            with self.assertRaises(SystemExit):
                monitor.main()
        self.assertEqual(sleeps,[4]*20)
        self.assertEqual([stamp for stamp,node in calls if node=='1002'],list(range(1004,1080,8)))
        self.assertEqual([stamp for stamp,node in calls if node=='1001'],[1000,1032])
        self.assertLess(len(calls),20)
        self.assertTrue(all(b[0]-a[0]>=4 for a,b in zip(calls,calls[1:])))
        self.assertEqual(monitor.records['1001']['keyups'],5)
        self.assertEqual(monitor.records['1001']['checked'],1000)
        self.assertEqual(self.status(monitor.records['1001']),'unknown')
        cache = json.loads(monitor.CACHE.read_text())
        self.assertEqual(cache['api']['failures'],0)
        self.assertEqual(cache['api']['nodes']['1001']['failures'],2)
        self.assertEqual(cache['favorites'][1]['activity'],'idle')

    def test_loop_does_not_burst_after_shared_cooldown(self):
        calls, sleeps = [], []
        def fetch(request, **kwargs):
            node = request.full_url.rsplit('/',1)[-1]
            calls.append((self.clock.wall,node))
            if len(calls)==1:
                raise self.http_error(429,'30')
            return contextlib.nullcontext(io.BytesIO(json.dumps(self.payload()).encode()))
        def sleep(seconds):
            sleeps.append(seconds)
            self.clock.advance(seconds)
            if len(sleeps)==12:
                raise SystemExit(0)
        with patch.object(monitor,'require_node'), \
             patch.object(monitor,'get_favorites',return_value=self.favorites), \
             patch.object(monitor.urllib.request,'urlopen',side_effect=fetch), \
             patch.object(monitor.time,'sleep',side_effect=sleep):
            with self.assertRaises(SystemExit):
                monitor.main()
        self.assertEqual([stamp for stamp,_ in calls],[1000,1032,1036,1040,1044])
        self.assertEqual(sleeps,[4]*12)

    def test_node_gates_restore_even_without_observations_or_global_failures(self):
        with self.respond(None):
            monitor.update_node('1001')
        self.assertNotIn('checked',monitor.records['1001'])
        writer = monitor.HistoryWriter(monitor.HISTORY,'1000',self.source,60,86400)
        writer.save(monitor.records,self.favorites,monitor.retry_snapshot())
        self.clock.advance(4)
        restored,saved_retry = self.restore()
        self.assertEqual(restored,{})
        monitor.restore_retries(saved_retry,self.favorites)
        self.assertTrue(monitor.retry.ready())
        self.assertFalse(monitor.node_retries['1001'].ready())
        self.assertEqual(monitor.node_retries['1001'].snapshot()['retry_at'],1030)
        with self.respond(self.payload()):
            self.assertFalse(monitor.update_node('1001'))
            self.assertTrue(monitor.update_node('1002'))

    def test_checkpoint_preserves_both_scopes_and_valid_counter_baselines(self):
        monitor.records['1001'] = self.record()
        with patch.object(monitor.urllib.request,'urlopen',side_effect=TimeoutError()):
            monitor.update_node('1001')
        with patch.object(monitor.urllib.request,'urlopen',side_effect=self.http_error(429,'120')):
            monitor.update_node('1002')
        writer = monitor.HistoryWriter(monitor.HISTORY,'1000',self.source,60,86400)
        writer.save(monitor.records,self.favorites,monitor.retry_snapshot())
        self.clock.advance(5)
        restored,saved_retry = self.restore()
        monitor.records.clear()
        monitor.records.update(restored)
        monitor.restore_retries(saved_retry,self.favorites)
        self.assertEqual(monitor.records['1001']['keyups'],5)
        self.assertFalse(monitor.retry.ready())
        self.assertFalse(monitor.node_retries['1001'].ready())
        self.assertEqual(monitor.retry.snapshot()['retry_at'],1120)
        self.assertEqual(monitor.node_retries['1001'].snapshot()['retry_at'],1030)

    def test_legacy_node_failure_checkpoint_does_not_recreate_global_block(self):
        for kind in ('invalid_response','stale_response','timeout','network','http'):
            monitor.records['1001'] = self.record(error=kind,error_kind=kind)
            legacy = dict(failures=2,retry_at=1100,error_kind=kind)
            monitor.restore_retries(legacy,self.favorites)
            with self.subTest(kind=kind):
                self.assertTrue(monitor.retry.ready())
                self.assertFalse(monitor.node_retries['1001'].ready())
                self.assertEqual(monitor.node_retries['1001'].failures,2)
                self.assertNotIn('1002',monitor.node_retries)

    def test_legacy_429_checkpoint_still_blocks_all_nodes(self):
        monitor.restore_retries(dict(failures=1,retry_at=1100,error_kind='rate_limit'),self.favorites)
        self.assertFalse(monitor.retry.ready())
        self.assertEqual(monitor.node_retries,{})

    def test_restore_filters_removed_favorites_and_ignores_damaged_node_gates(self):
        saved = dict(scope_version=2,failures=0,retry_at=0,error_kind=None,nodes={
            '1001':dict(failures=1,retry_at=1100,error_kind='timeout'),
            '1002':dict(failures=1,retry_at=float('nan'),error_kind='http'),
            '9999':dict(failures=1,retry_at=1100,error_kind='network')})
        monitor.restore_retries(saved,self.favorites)
        self.assertEqual(set(monitor.node_retries),{'1001'})
        self.assertTrue(monitor.retry.ready())
        monitor.restore_retries(saved,self.favorites[1:])
        self.assertEqual(monitor.node_retries,{})

    def test_valid_long_node_delay_survives_activity_retention(self):
        with patch.object(monitor.urllib.request,'urlopen',side_effect=self.http_error(404,'172800')):
            monitor.update_node('1001')
        self.write_history(self.envelope(retry=monitor.retry_snapshot()))
        self.clock.advance(86401)
        _,saved_retry = self.restore()
        monitor.restore_retries(saved_retry,self.favorites)
        self.assertTrue(monitor.retry.ready())
        self.assertFalse(monitor.node_retries['1001'].ready())
        self.assertEqual(monitor.node_retries['1001'].snapshot()['retry_at'],173800)

    def test_live_removal_clears_only_removed_nodes_retry_state(self):
        for node in ('1001','1002'):
            with patch.object(monitor.urllib.request,'urlopen',side_effect=TimeoutError()):
                monitor.update_node(node)
        records = {node:self.record(error='timeout',error_kind='timeout') for node in ('1001','1002')}
        self.write_history(self.envelope(records,retry=monitor.retry_snapshot()))
        revised = [dict(node='1002',name='Renamed')]
        with patch.object(monitor,'require_node'), \
             patch.object(monitor,'get_favorites',side_effect=[self.favorites,revised]), \
             patch.object(monitor.time,'sleep',side_effect=SystemExit(0)):
            with self.assertRaises(SystemExit):
                monitor.main()
        self.assertEqual(set(monitor.node_retries),{'1002'})
        self.assertEqual(set(monitor.records),{'1002'})
        self.assertEqual(monitor.records['1002']['keyups'],5)
        self.assertEqual(monitor.node_retries['1002'].snapshot()['retry_at'],1030)
