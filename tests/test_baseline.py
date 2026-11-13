"""Characterization tests: current behavior, not future security acceptance."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from stats_api import RetryPolicy
from radio_control import link_record
from unittest.mock import patch, ANY

ROOT = Path(__file__).resolve().parents[1]

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

scanner = load('baseline_scanner', 'scanner.py')
monitor = load('baseline_monitor', 'monitor.py')
favorites = load('baseline_favorites', 'favorites_store.py')
netwatch = load('baseline_netwatch', 'update_netwatch.py')
nets = load('baseline_nets', 'update-nets.py')


class OfflineCase(unittest.TestCase):
    def setUp(self):
        # Any missed mock fails rather than invoking Asterisk or an upstream API.
        for target in ('subprocess.run', 'urllib.request.urlopen'):
            self.enterContext(patch(target, side_effect=AssertionError('External I/O forbidden')))
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))


class ScannerBaseline(OfflineCase):
    def setUp(self):
        super().setUp()
        for name, value in {'STATE_DIR': self.tmp, 'STATE': self.tmp/'state.json',
                            'CACHE': self.tmp/'activity.json', 'LOCK': self.tmp/'scanner.lock'}.items():
            self.enterContext(patch.object(scanner, name, value))
        self.enterContext(patch.object(scanner.time, 'time', return_value=1000))
        self.enterContext(patch.object(scanner, 'NODE', '1000'))
        self.links=[]
        self.enterContext(patch.object(scanner, 'direct_links', side_effect=lambda **kw:[link_record(node, 'TU') for node in self.links]))
        def command(action,node,**kwargs):
            if action=='connect': self.links.append(node)
            elif node in self.links: self.links.remove(node)
        self.radio = self.enterContext(patch.object(scanner, 'run_asterisk', side_effect=command))
        self.entries = [self.favorite('1001'), self.favorite('1002')]
        self.enterContext(patch.object(scanner.favorites_store, 'read',
            side_effect=lambda: [dict(node=f['node'], name=f['name']) for f in json.loads(scanner.CACHE.read_text())['favorites']]))
        scanner.CACHE.write_text(json.dumps({'favorites': self.entries}))

    def favorite(self, node):
        return dict(node=node, name='Example', activity='active', registered=True,
                    checked=1000, stats_time=1000, error=None)

    def test_freshness_boundaries_and_bad_samples(self):
        f = self.favorite('1001')
        self.assertTrue(scanner.eligible(f, 1300))
        self.assertFalse(scanner.eligible(f, 1301))
        for change in ({'checked':1001}, {'stats_time':1001}, {'registered':False},
                       {'error':'offline'}, {'activity':'idle'}, {'checked':'bad'}):
            with self.subTest(change=change):
                self.assertFalse(scanner.eligible(f | change, 1000))

    def test_first_uses_order(self):
        scanner.scan('first', True)
        self.radio.assert_called_once_with('connect', '1001', timeout=ANY)
        self.assertEqual(json.loads(scanner.STATE.read_text())['node'], '1001')

    def test_next_wraps(self):
        scanner.save_state({'node':'1002'})
        scanner.scan('next', True)
        self.radio.assert_called_once_with('connect', '1001', timeout=ANY)

    def test_next_with_removed_selection_starts_at_first(self):
        scanner.save_state({'node':'1999'})
        scanner.scan('next', True)
        self.radio.assert_called_once_with('connect', '1001', timeout=ANY)

    def test_next_skips_only_current_eligible_favorite(self):
        scanner.save_state({'node':'1001'})
        scanner.CACHE.write_text(json.dumps({'favorites':self.entries[:1]}))
        scanner.scan('next', True)
        self.radio.assert_not_called()
        self.assertEqual(json.loads(scanner.STATE.read_text()), {'node':'1001'})

    def test_no_eligible_preserves_selection(self):
        scanner.save_state({'node':'1002'})
        for f in self.entries:
            f['stats_time'] = 1
        scanner.CACHE.write_text(json.dumps({'favorites':self.entries}))
        scanner.scan('first', True)
        self.radio.assert_not_called()
        self.assertEqual(json.loads(scanner.STATE.read_text()), {'node':'1002'})

    def test_dry_run_has_no_command_or_state_write(self):
        scanner.scan('first', False)
        self.radio.assert_not_called()
        self.assertFalse(scanner.STATE.exists())

    def test_stop_disconnects_saved_selection(self):
        scanner.save_state({'node':'1002'})
        self.links.append('1002')
        scanner.scan('stop', True)
        self.radio.assert_called_once_with('disconnect', '1002', timeout=ANY)
        self.assertEqual(json.loads(scanner.STATE.read_text()), {})

    def test_command_failure_preserves_previous_state(self):
        scanner.save_state({'node':'1002'})
        self.radio.side_effect = RuntimeError('offline')
        with self.assertRaises(RuntimeError):
            scanner.scan('first', True)
        self.assertEqual(json.loads(scanner.STATE.read_text()), {'node':'1002', 'pending_node':'1001', 'confirmed':False})


class FavoritesBaseline(OfflineCase):
    def setUp(self):
        super().setUp()
        for name, filename in [('JSON_PATH','favorites.json'), ('LOCK','favorites.lock')]:
            self.enterContext(patch.object(favorites, name, self.tmp/filename))
        favorites.save([{'node':'1001','name':'First'}, {'node':'1002','name':'Second'}])

    def test_mutations_preserve_order_and_names(self):
        favorites.mutate({'action':'add','node':'1003','name':'Third'})
        favorites.mutate({'action':'up','node':'1003'})
        favorites.mutate({'action':'edit','node':'1003','name':'Renamed'})
        self.assertEqual(favorites.read(), [dict(node='1001', name='First'),
            dict(node='1003', name='Renamed'), dict(node='1002', name='Second')])
        favorites.mutate({'action':'down','node':'1003'})
        favorites.mutate({'action':'remove','node':'1002'})
        self.assertEqual([e['node'] for e in favorites.read()], ['1001','1003'])

    def test_invalid_changes_leave_store_intact(self):
        original = favorites.JSON_PATH.read_bytes()
        for payload in ({'action':'add','node':'1001','name':'Duplicate'},
                        {'action':'add','node':'bad','name':'Bad'},
                        {'action':'edit','node':'1001','name':'bad\nname'}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                favorites.mutate(payload)
            self.assertEqual(favorites.JSON_PATH.read_bytes(), original)

    def test_legacy_import_order_and_duplicate_policy(self):
        entries = favorites.parse_original((ROOT/'tests/fixtures/legacy-favorites.ini').read_text())
        self.assertEqual(entries, [dict(node='1002',name='Second'),dict(node='1001',name='First')])

    def test_monitor_reads_replaced_favorites_without_restart(self):
        with patch.object(monitor, 'favorites_store', favorites):
            self.assertEqual([f['node'] for f in monitor.get_favorites()], ['1001','1002'])
            favorites.mutate({'action':'up','node':'1002'})
            self.assertEqual([f['node'] for f in monitor.get_favorites()], ['1002','1001'])


class MonitorBaseline(OfflineCase):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(monitor, 'records', {}))
        self.enterContext(patch.object(monitor, 'retry', RetryPolicy(30, 900)))
        self.enterContext(patch.object(monitor, 'node_retries', {}))
        self.enterContext(patch.object(monitor, 'CACHE', self.tmp/'activity.json'))
        self.enterContext(patch.object(monitor.time, 'time', return_value=1000))

    def sample(self, keyups, stamp, keyed=False):
        payload = {'stats':{'data':dict(totalkeyups=keyups, totaltxtime=10,
                    time=stamp, keyed=keyed, links=[])}, 'node':{'Status':'Active'}}
        response = contextlib.nullcontext(io.StringIO(json.dumps(payload)))
        with patch.object(monitor.urllib.request, 'urlopen', return_value=response):
            monitor.update_node('1001')

    def test_initial_baseline_then_counter_increase(self):
        self.sample(5, 990)
        self.assertNotIn('last_activity', monitor.records['1001'])
        self.sample(6, 995)
        self.assertEqual(monitor.records['1001']['last_activity'], 1000)

    def test_stale_keyed_sample_is_not_activity(self):
        self.sample(5, 100, True)
        self.assertFalse(monitor.records['1001']['keyed'])
        self.assertNotIn('last_activity', monitor.records['1001'])

    def test_counter_reset_is_not_activity(self):
        self.sample(5, 990)
        self.sample(1, 995)
        self.assertNotIn('last_activity', monitor.records['1001'])

    def test_cache_marks_stale_record_unknown(self):
        monitor.records['1001'] = dict(checked=1000, stats_time=100, keyed=True)
        monitor.save_cache([dict(node='1001', name='Example')])
        self.assertEqual(json.loads(monitor.CACHE.read_text())['favorites'][0]['activity'], 'unknown')


class ScheduleBaseline(OfflineCase):
    def test_netwatch_approved_allstar_filter_and_dedup(self):
        payload = json.loads((ROOT/'tests/fixtures/netwatch.json').read_text())
        with patch.object(netwatch.time, 'time', return_value=1893456000):
            result = netwatch.parse(payload)
        self.assertEqual(len(result['nets']), 1)
        self.assertEqual(result['nets'][0]['node'], '1001')
        self.assertEqual(result['source'], 'NetWatch')

    def test_netwatch_rejects_stale_generated_time(self):
        payload = json.loads((ROOT/'tests/fixtures/netwatch.json').read_text())
        with patch.object(netwatch.time, 'time', return_value=1893466000):
            with self.assertRaises(ValueError):
                netwatch.parse(payload)

    def test_netwatch_requires_timezone(self):
        with self.assertRaises(ValueError):
            netwatch.iso_time('2030-01-01T00:00:00')

    def test_weekly_parser_rejects_truncated_schedule(self):
        with self.assertRaises(ValueError):
            nets.parse_page('<h2>Monday</h2><a>Node 1001 Example 12:00 UTC</a>')

    def test_weekly_parser_accepts_complete_synthetic_schedule(self):
        html = ''.join('<h2>'+day+'</h2>'+''.join(
            f'<a href="/net/example">Node {1000+i} Example {hour}:00 UTC</a>'
            for hour in ('10','11','12')) for i,day in enumerate(nets.DAYS))
        result = nets.parse_page(html)
        self.assertEqual(len(result), 21)
        self.assertEqual(result[0]['weekday'], 0)


if __name__ == '__main__':
    unittest.main()
