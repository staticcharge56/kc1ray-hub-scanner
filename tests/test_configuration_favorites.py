"""Phase 2A tests; external commands and network access remain blocked."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock, ANY

# Also supports running unittest directly, independent of tools/check.py.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import configuration
from radio_control import link_record
import dashboard
import favorites_store as store
import migrate_favorites as migration
import monitor
import scanner
from test_baseline import OfflineCase


class ConfigTests(OfflineCase):
    def config(self, text):
        path = self.tmp/'config.toml'
        path.write_text(text)
        return configuration.load_config(path)

    def test_defaults_are_independent_and_local(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(configuration, 'DEFAULT_PATH', self.tmp/'missing'):
            a = configuration.load_config()
            a['web']['port'] = 1234
            b = configuration.load_config()
        self.assertEqual(b['web']['port'], 8085)
        self.assertEqual(b['web']['bind'], '127.0.0.1')
        self.assertFalse(b['web']['controls_enabled'])
        self.assertEqual(b['controls']['cooldown_seconds'], 15)

    def test_environment_and_explicit_precedence(self):
        a, b = self.tmp/'a.toml', self.tmp/'b.toml'
        a.write_text('[allstar]\nlocal_node="1001"\n')
        b.write_text('[allstar]\nlocal_node="1002"\n')
        with patch.dict(os.environ, {'KC1RAY_CONFIG':str(a)}):
            self.assertEqual(configuration.load_config()['allstar']['local_node'], '1001')
            self.assertEqual(configuration.load_config(b)['allstar']['local_node'], '1002')
        self.assertEqual(a.read_text(), '[allstar]\nlocal_node="1001"\n')

    def test_missing_explicit_config_fails(self):
        with self.assertRaises(FileNotFoundError):
            configuration.load_config(self.tmp/'missing')

    def test_invalid_values_and_unknown_options_rejected(self):
        cases = ['[web]\nport=0', '[web]\nport=65536', '[web]\nport=true',
                 '[web]\nport="8085"', '[web]\nbind=""', '[web]\nbind="bad host"',
                 '[paths]\nstate_dir="relative"', '[allstar]\nlocal_node="１２３４"',
                 '[allstar]\nlocal_node=1001', '[allstar]\nasterisk_binary="asterisk"',
                 '[monitor]\npoll_interval_seconds=0', '[controls]\ncooldown_seconds=-1',
                 '[schedules.netwatch]\nenabled="yes"', '[schedules.netwatch]\nmax_age_seconds=0',
                 '[schedules.netwatch]\nurl="http://example.org"',
                 '[schedules.netwatch]\nurl="https://user:secret@example.org"',
                 '[monitor]\nstats_url_template="https://example.org/{bad}"',
                 '[monitor]\nstats_url_template="https://example.org/{node}/{node}"',
                 '[web]\nanonymous_view=123', 'paths="bad"', '[typo]\nx=1']
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.config(text)

    def test_custom_paths_node_network_and_intervals(self):
        result = self.config('[allstar]\nlocal_node="1001"\n'
            '[paths]\nstate_dir="/tmp/custom-state"\n[web]\nport=9090\n'
            '[monitor]\npoll_interval_seconds=7\n[controls]\ncooldown_seconds=30')
        self.assertEqual(result['allstar']['local_node'], '1001')
        self.assertEqual(result['paths']['state_dir'], '/tmp/custom-state')
        self.assertEqual(result['web']['port'], 9090)
        self.assertEqual(result['monitor']['poll_interval_seconds'], 7)
        self.assertEqual(result['controls']['cooldown_seconds'], 30)

    def test_unconfigured_node_blocks_entrypoint(self):
        with patch.dict(configuration.CONFIG['allstar'], {'local_node':''}):
            with self.assertRaises(ValueError):
                configuration.require_node()

    def test_values_propagate_to_runtime_modules(self):
        cfg = self.config('[allstar]\nlocal_node="1001"\n'
            '[paths]\nstate_dir="/tmp/example-state"\ncache_dir="/tmp/example-cache"\n'
            'runtime_dir="/tmp/example-run"\n[monitor]\npoll_interval_seconds=9\n'
            'max_stats_age_seconds=120\n[web]\nport=9090\n[controls]\ncooldown_seconds=22')
        with patch.object(configuration, 'CONFIG', cfg):
            for filename in ('monitor.py', 'scanner.py', 'dashboard.py', 'favorites_store.py',
                             'update_netwatch.py', 'update-nets.py'):
                spec = importlib.util.spec_from_file_location('configured_module', ROOT/filename)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                with self.subTest(filename=filename):
                    if hasattr(module, 'LOCAL_NODE'):
                        self.assertEqual(module.LOCAL_NODE, '1001')
                    if hasattr(module, 'NODE') and isinstance(module.NODE, str):
                        self.assertEqual(module.NODE, '1001')
                    if hasattr(module, 'CACHE'):
                        self.assertEqual(module.CACHE, Path('/tmp/example-cache/activity.json'))
                    if hasattr(module, 'COOLDOWN_SECONDS'):
                        self.assertEqual(module.COOLDOWN_SECONDS, 22)
                        self.assertEqual(module.PORT, 9090)
                    if hasattr(module, 'POLL_INTERVAL'):
                        self.assertEqual(module.POLL_INTERVAL, 9)
                    if hasattr(module, 'JSON_PATH'):
                        self.assertEqual(module.JSON_PATH, Path('/tmp/example-state/favorites.json'))


class StoreTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(store, 'JSON_PATH', self.tmp/'favorites.json'))
        self.enterContext(patch.object(store, 'LOCK', self.tmp/'favorites.lock'))
        store.save([dict(node='1001', name='Café "Radio" \\ Test')])

    def test_single_store_preserves_exact_descriptions(self):
        entries = [dict(node='1002', name='  Café "Radio" \\ Test  ')]
        store.save(entries)
        self.assertEqual(store.read(), entries)
        self.assertFalse((self.tmp/'favorites.ini').exists())
        self.assertEqual(store.JSON_PATH.stat().st_mode & 0o777, 0o640)

    def test_failed_replace_keeps_previous_data_and_cleans_temporary(self):
        original = store.JSON_PATH.read_bytes()
        with patch.object(store.os, 'replace', side_effect=OSError('simulated failure')):
            with self.assertRaises(OSError):
                store.mutate(dict(action='edit', node='1001', name='Changed'))
        self.assertEqual(store.JSON_PATH.read_bytes(), original)
        self.assertEqual(list(self.tmp.glob('.fav-*')), [])

    def test_concurrent_mutations_do_not_lose_updates(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda node: store.mutate(dict(action='add', node=str(node), name='Test')), range(1002,1022)))
        self.assertEqual(len(store.read()), 21)
        self.assertEqual(len({f['node'] for f in store.read()}), 21)

    def test_corrupt_store_is_not_reset(self):
        store.JSON_PATH.write_text('{broken')
        with self.assertRaises(ValueError):
            store.mutate(dict(action='add', node='1002', name='Test'))
        self.assertEqual(store.JSON_PATH.read_text(), '{broken')

    def test_read_validates_entries(self):
        for data in ([{'node':'bad','name':'Test'}], [{'node':'1001'}], {},
                     [dict(node='1001',name='A'),dict(node='1001',name='B')]):
            store.JSON_PATH.write_text(json.dumps(data))
            with self.subTest(data=data), self.assertRaises(ValueError):
                store.read()

    def test_all_consumers_follow_live_store_without_cache_refresh(self):
        sample = dict(node='1001', name='OLD', checked=1000, stats_time=1000,
                      activity='active', registered=True, error=None)
        cache = self.tmp/'activity.json'
        cache.write_text(json.dumps({'updated':1000,'favorites':[sample]}))
        self.enterContext(patch.object(dashboard, 'CACHE', cache))
        self.enterContext(patch.object(scanner, 'CACHE', cache))
        self.enterContext(patch.object(scanner, 'STATE', self.tmp/'state.json'))
        self.enterContext(patch.object(scanner, 'STATE_DIR', self.tmp))
        self.enterContext(patch.object(scanner, 'LOCK', self.tmp/'scanner.lock'))
        self.enterContext(patch.object(scanner, 'NODE', '1000'))
        self.enterContext(patch.object(scanner, 'direct_links', side_effect=[[], [], [link_record('1001','TU')]]))
        self.enterContext(patch.object(scanner.time, 'time', return_value=1000))
        radio = self.enterContext(patch.object(scanner, 'run_asterisk'))
        store.save([dict(node='1002',name='New'),dict(node='1001',name='Renamed')])
        self.assertEqual(monitor.get_favorites(), store.read())
        self.assertEqual(dashboard.favorite_numbers(), {'1001','1002'})
        self.assertEqual([f['name'] for f in dashboard.activity_payload()['favorites']], ['New','Renamed'])
        with patch.object(scanner,'LOCK',self.tmp/'scanner.lock'):
            scanner.scan('first', True) # New favorite has no statistics and cannot be selected yet.
        radio.assert_called_once_with('connect', '1001', timeout=ANY)
        store.save([dict(node='1002',name='New')])
        radio.reset_mock()
        scanner.scan('first', True)
        radio.assert_not_called() # Removed node is excluded even though still active in cache.

    def test_monitor_transient_invalid_store_retains_records(self):
        # Validate read failure and unchanged records; full loop retention remains baseline logic.
        with patch.object(monitor, 'records', {'1001': {'keyups':5}}):
            store.JSON_PATH.write_text('invalid')
            with self.assertRaises(ValueError):
                monitor.get_favorites()
            self.assertEqual(monitor.records, {'1001': {'keyups':5}})

    def test_running_monitor_reload_preserves_records_on_transient_failure(self):
        initial = [dict(node='1001',name='Original')]
        revised = [dict(node='1002',name='New'),dict(node='1001',name='Renamed')]
        snapshots = []
        class Finished(Exception):
            pass
        with patch.object(monitor, 'require_node'), \
             patch.object(monitor, 'HISTORY', self.tmp/'history.json'), \
             patch.object(monitor, 'load_history', return_value=({'1001': {'keyups':5}}, {})), \
             patch.dict(monitor.CONFIG['monitor'], {'cache_write_interval_seconds':0}), \
             patch.object(monitor, 'records', {'1001': {'keyups':5}}), \
             patch.object(monitor, 'get_favorites', side_effect=[initial,revised,ValueError('partial'),revised[:1]]), \
             patch.object(monitor, 'save_cache', side_effect=lambda favs: snapshots.append((deepcopy(favs),deepcopy(monitor.records)))), \
             patch.object(monitor, 'update_node', side_effect=lambda node: monitor.records.setdefault(node, {'keyups':0})), \
             patch.object(monitor.time, 'sleep', side_effect=[None,None,Finished()]):
            with self.assertRaises(Finished):
                monitor.main()
            self.assertEqual(snapshots[1][0], revised)
            self.assertEqual(snapshots[1][1]['1001']['keyups'], 5)
            self.assertEqual(snapshots[3][0], revised) # temporary failure retains list
            self.assertNotIn('1001', monitor.records) # removal drops only removed record


class MigrationTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.source = self.tmp/'source.json'
        self.entries = [dict(node='1002',name='  Café \\ "Radio"  '), dict(node='1001',name='First')]
        self.source.write_text(json.dumps(self.entries, ensure_ascii=False))
        self.dest = self.tmp/'state'/'favorites.json'

    def test_dry_run_creates_nothing(self):
        result = migration.migrate(self.source, self.dest)
        self.assertEqual(result['status'], 'dry-run')
        self.assertFalse(self.dest.parent.exists())

    def test_backup_exact_source_and_idempotent_import(self):
        raw = self.source.read_bytes()
        result = migration.migrate(self.source, self.dest, apply=True)
        self.assertEqual(Path(result['backup']).read_bytes(), raw)
        self.assertEqual(self.source.read_bytes(), raw)
        self.assertEqual(json.loads(self.dest.read_text()), self.entries)
        before = self.dest.read_bytes()
        again = migration.migrate(self.source, self.dest, apply=True)
        self.assertEqual(again['status'], 'unchanged')
        self.assertEqual(len(list(self.dest.parent.glob('*.bak'))), 1)
        self.assertEqual(self.dest.read_bytes(), before)

    def test_different_existing_favorites_never_overwritten(self):
        self.dest.parent.mkdir()
        self.dest.write_text('[]')
        with self.assertRaises(ValueError):
            migration.migrate(self.source, self.dest, apply=True)
        self.assertEqual(self.dest.read_text(), '[]')
        self.assertEqual(list(self.dest.parent.glob('*.bak')), [])

    def test_invalid_source_or_duplicate_aborts_without_writes(self):
        for text in ('broken', '[{"node":"bad","name":"Bad"}]',
                     json.dumps([self.entries[0], self.entries[0]])):
            self.source.write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                migration.migrate(self.source, self.dest, apply=True)
            self.assertFalse(self.dest.parent.exists())

    def test_symlink_destination_refused(self):
        self.dest.parent.mkdir()
        self.dest.symlink_to(self.source)
        with self.assertRaises(ValueError):
            migration.migrate(self.source, self.dest, apply=True)

    def test_legacy_unicode_escapes_and_node_section(self):
        text = '[general]\nlabel[] = "Café \\\"Radio\\\" \\\\ Test 1002"\ncmd[] = "rpt cmd %node% ilink 3 1002"\n'
        text += '[1000]\nlabel[] = "First 1001"\ncmd[] = "rpt cmd %node% ilink 3 1001"\n'
        self.source.write_text(text)
        migration.migrate(self.source, self.dest, apply=True, source_format='ini', local_node='1000')
        self.assertEqual(json.loads(self.dest.read_text()),
                         [dict(node='1002',name='Café "Radio" \\ Test'),dict(node='1001',name='First')])

    def test_legacy_duplicates_and_unsupported_commands_rejected(self):
        text = (ROOT/'tests/fixtures/legacy-favorites.ini').read_text()
        with self.assertRaises(ValueError):
            migration.parse_legacy(text, '1000')
        for text in ('[general]\nlabel[] = "A"',
                     '[general]\nlabel[] = "A"\ncmd[] = "system reboot"'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                migration.parse_legacy(text, '1000')

    def test_failed_publish_retains_source_backup_and_no_destination(self):
        raw = self.source.read_bytes()
        with patch.object(migration.os, 'link', side_effect=OSError('simulated failure')):
            with self.assertRaises(OSError):
                migration.migrate(self.source, self.dest, apply=True)
        self.assertFalse(self.dest.exists())
        self.assertEqual(self.source.read_bytes(), raw)
        self.assertEqual(len(list(self.dest.parent.glob('*.bak'))), 1)
        self.assertEqual(list(self.dest.parent.glob('.migration-*')), [])

    def test_concurrent_destination_creation_is_not_overwritten(self):
        real_link = migration.os.link
        def race(source, destination):
            Path(destination).write_text('[]')
            return real_link(source, destination)
        with patch.object(migration.os, 'link', side_effect=race):
            with self.assertRaises(FileExistsError):
                migration.migrate(self.source, self.dest, apply=True)
        self.assertEqual(self.dest.read_text(), '[]')

    def test_config_is_unchanged_during_migration(self):
        config = self.tmp/'config.toml'
        config.write_text('[allstar]\nlocal_node="1001"\n')
        original = config.read_bytes()
        with patch.dict(os.environ, {'KC1RAY_CONFIG':str(config)}):
            configuration.load_config()
            migration.migrate(self.source, self.dest, apply=True)
            configuration.load_config()
        self.assertEqual(config.read_bytes(), original)

    def test_empty_json_initializes_new_store(self):
        self.source.write_text('[]')
        migration.migrate(self.source, self.dest, apply=True)
        self.assertEqual(json.loads(self.dest.read_text()), [])


class DashboardConfigurationTests(OfflineCase):
    def test_rendered_node_and_timing_use_config_without_leaking_paths(self):
        with patch.object(dashboard, 'LOCAL_NODE', '1001'):
            html = dashboard.render_html()
        self.assertIn('AllStarLink Node 1001', html)
        self.assertNotIn('__PUBLIC_CONFIG__', html)
        self.assertNotIn('__LOCAL_NODE__', html)
        self.assertNotIn(configuration.CONFIG['paths']['state_dir'], html)
        self.assertIn('publicConfig.statsMaxAge', html)

    def test_disabled_sources_ignore_existing_cache(self):
        for key in ('netwatch', 'allstarnets'):
            self.enterContext(patch.dict(dashboard.CONFIG['schedules'][key], {'enabled':False}))
        with patch.object(Path, 'read_text', side_effect=AssertionError('Disabled cache read')):
            self.assertEqual(dashboard.load_schedule()['nets'], [])

    def test_netwatch_fallback_and_custom_max_age(self):
        netwatch, fallback = self.tmp/'netwatch.json', self.tmp/'nets.json'
        netwatch.write_text(json.dumps(dict(updated=900, source='NetWatch', nets=[{'node':'1001'}])))
        fallback.write_text(json.dumps(dict(updated=990, nets=[{'node':'1002'}])))
        self.enterContext(patch.object(dashboard, 'NETWATCH_CACHE', netwatch))
        self.enterContext(patch.object(dashboard, 'NETS_CACHE', fallback))
        self.enterContext(patch.object(dashboard.time, 'time', return_value=1000))
        for key in ('netwatch','allstarnets'):
            self.enterContext(patch.dict(dashboard.CONFIG['schedules'][key], {'enabled':True}))
        self.assertEqual(dashboard.scheduled_net_numbers(), {'1001'})
        with patch.object(dashboard, 'NETWATCH_MAX_AGE_SECONDS', 50), patch.object(dashboard, 'NET_DURATION_MINUTES', 90):
            self.assertEqual(dashboard.scheduled_net_numbers(), {'1002'})
            self.assertEqual(dashboard.load_schedule()['default_duration_minutes'], 90)

    def test_disabled_updaters_do_not_fetch_or_write(self):
        for filename in ('update_netwatch.py','update-nets.py'):
            spec = importlib.util.spec_from_file_location('disabled_updater', ROOT/filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with patch.dict(module.SOURCE, {'enabled':False}):
                module.main() # Network blocker in OfflineCase fails if a request occurs.

    def test_scanner_asterisk_command_contract_uses_configured_node(self):
        result = Mock(returncode=0, stdout='Submitted', stderr='')
        with patch.object(scanner, 'NODE', '1000'), \
             patch.object(scanner, 'ASTERISK', '/tmp/example-asterisk'), \
             patch('subprocess.run', return_value=result) as run:
            scanner.run_asterisk('connect', '1001')
            self.assertEqual(run.call_args.args[0],
                ['/tmp/example-asterisk', '-rx', 'rpt cmd 1000 ilink 3 1001'])
            scanner.run_asterisk('disconnect', '1001')
            self.assertEqual(run.call_args.args[0],
                ['/tmp/example-asterisk', '-rx', 'rpt cmd 1000 ilink 1 1001'])

    def test_manual_controls_keep_command_sequence_and_selection_state(self):
        result = Mock(returncode=0, stdout='Submitted', stderr='')
        self.enterContext(patch.object(dashboard, 'LOCAL_NODE', '1000'))
        self.enterContext(patch.object(dashboard, 'SCANNER_LOCK', self.tmp/'scanner.lock'))
        self.enterContext(patch.object(dashboard, 'STATE_DIR', self.tmp))
        self.enterContext(patch.object(dashboard, 'SCANNER_STATE', self.tmp/'state.json'))
        self.enterContext(patch.object(dashboard, 'favorite_numbers', return_value={'1001'}))
        links = self.enterContext(patch.object(dashboard, 'direct_links', side_effect=[[],[],[link_record('1001','TU')],[link_record('1001','TU')],[]]))
        run = self.enterContext(patch('subprocess.run', return_value=result))
        dashboard.run_link_action('connect-node', '1001')
        self.assertEqual(run.call_args.args[0][-1], 'rpt cmd 1000 ilink 3 1001')
        self.assertEqual(run.call_count, 1) # Link observations use the mocked status callback.
        self.assertEqual(json.loads(dashboard.SCANNER_STATE.read_text())['node'], '1001')
        dashboard.run_link_action('disconnect-node', '1001')
        self.assertEqual(run.call_args.args[0][-1], 'rpt cmd 1000 ilink 1 1001')
        self.assertEqual(json.loads(dashboard.SCANNER_STATE.read_text()), {})

    def test_post_mutations_disabled_by_default(self):
        handler = object.__new__(dashboard.Handler)
        handler.reply = lambda status, message: replies.append((status,message))
        replies = []
        with patch.dict(dashboard.CONFIG['web'], {'controls_enabled':False}):
            handler.do_POST()
        self.assertEqual(replies[0][0], 403)


if __name__ == '__main__':
    unittest.main()
