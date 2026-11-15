"""Phase 2 settings and diagnostics; temporary files and mocked services only."""
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import activity_history as history
import admin_advanced as advanced
import admin_settings as settings
import admin_service as service
import configuration
import dashboard
import scanner
import security
import test_admin as phase1
from test_baseline import OfflineCase,ROOT
from test_packaging import PackagingCase,pkg


class AdvancedTests(phase1.AdminEnvironment):
    def activate(self):
        for unit in service.RESTARTABLE:self.system.states[unit].update(active=True,active_state='active')
    def change_node(self):
        payload=self.payload(local_node='2000');payload['confirm_node_change']=True
        return self.admin.settings(payload)
    def test_node_change_requires_confirmation_and_verified_discovery(self):
        with self.assertRaises(security.Denied):self.admin.settings(self.payload(local_node='2000'))
        payload=self.payload(local_node='3000');payload['confirm_node_change']=True
        with self.assertRaises(security.Denied):self.admin.settings(payload)
        self.assertEqual(self.config.read_bytes(),self.before)
        self.activate();credentials=self.credentials.read_bytes();result=self.change_node()
        self.assertEqual(result['settings']['local_node'],'2000');self.assertEqual(self.credentials.read_bytes(),credentials)
        self.assertEqual({unit for action,unit,_ in self.system.commands if action=='restart'},service.RESTARTABLE)
    def test_unavailable_or_exec_only_discovery_never_authorizes_node(self):
        for discover in (lambda:([],True),Mock(side_effect=OSError('private config'))):
            self.admin.node_discovery=discover
            with self.assertRaises(security.Denied):self.change_node()
        self.assertEqual(self.config.read_bytes(),self.before)
        self.admin.settings(self.payload(refresh_seconds=30)) # Phase 1 still works.
    def test_scanner_selection_must_be_cleared_before_switch(self):
        config=configuration.load_config(self.config);config['paths']['state_dir']=str(self.tmp)
        self.config.write_bytes(service.encode_toml(config))
        path=self.tmp/'scanner-state.json';path.write_text('{"node":"3000","confirmed":true}')
        with self.assertRaises(security.Denied):self.change_node()
        self.assertEqual(json.loads(path.read_text())['node'],'3000')
        path.write_text('{}');self.change_node();self.assertEqual(path.read_text(),'{}')
    def test_restart_failure_restores_node_configuration_and_services(self):
        self.activate()
        def fail(action,unit):
            if action=='restart':self.system.fail=None;return True
            return False
        self.system.fail=fail
        with self.assertRaises(security.Denied):self.change_node()
        self.assertEqual(self.config.read_bytes(),self.before);self.assertFalse(self.admin.journal.exists())
        self.assertTrue(all(self.system.state(unit)['active'] for unit in service.RESTARTABLE))
    def test_cooldown_bounds_and_only_broker_restart(self):
        self.activate()
        for value in (0,1,14,301,True,'15'):
            with self.subTest(value=value),self.assertRaises(security.Denied):self.admin.settings(self.payload(cooldown_seconds=value))
        self.admin.settings(self.payload(cooldown_seconds=30))
        self.assertEqual(configuration.load_config(self.config)['controls']['cooldown_seconds'],30)
        self.assertEqual([unit for action,unit,_ in self.system.commands if action=='restart'],[service.PREFIX+'broker.service'])
        config=configuration.load_config(self.config)
        with patch.dict(os.environ,KC1RAY_CONFIG=str(self.config)):settings.refresh(config,path=self.runtime/'settings.json',owner=os.geteuid())
        handler=object.__new__(dashboard.Handler)
        with patch.dict(dashboard.CONFIG,config),patch.object(dashboard,'COOLDOWN_SECONDS',15),patch.object(dashboard,'LOCAL_NODE','1000'):
            handler.sync_admin_settings();self.assertEqual(dashboard.COOLDOWN_SECONDS,30)
    def test_monitor_limits_preserve_backoff_and_unrelated_configuration(self):
        self.activate();before=configuration.load_config(self.config)
        for changes in ({'poll_interval_seconds':3},{'poll_interval_seconds':301},{'max_stats_age_seconds':59},{'max_stats_age_seconds':3601},{'activity_window_seconds':0},{'backoff_initial_seconds':1}):
            with self.subTest(changes=changes),self.assertRaises(security.Denied):self.admin.settings(self.payload(**changes))
        self.admin.settings(self.payload(poll_interval_seconds=8,max_stats_age_seconds=600,activity_window_seconds=600))
        after=configuration.load_config(self.config)
        for key in ('backoff_initial_seconds','backoff_max_seconds','history_retention_seconds','history_write_interval_seconds'):self.assertEqual(before['monitor'][key],after['monitor'][key])
        self.assertEqual([unit for action,unit,_ in self.system.commands if action=='restart'],[service.PREFIX+'monitor.service'])
    def test_timer_frequency_preserves_existing_semantics_and_enabled_state(self):
        self.admin.settings(self.payload(netwatch_interval_minutes=60,allstarnets_frequency='weekly'))
        self.assertEqual(self.admin.schedules()[0],dict(netwatch_interval_minutes=60,allstarnets_frequency='weekly'))
        net=self.admin.dropin('netwatch').read_text();self.assertIn('OnBootSec=2min',net);self.assertIn('OnUnitActiveSec=\n',net)
        self.assertNotIn('Persistent=',self.admin.dropin('allstarnets').read_text())
        self.assertFalse(any(state['active'] for state in self.system.states.values()))
        before=len(self.system.commands);self.admin.settings(self.payload(netwatch_interval_minutes=60))
        self.assertEqual(len(self.system.commands),before)
    def test_enabled_timer_restarts_once_without_new_timer_or_import_command(self):
        self.admin.settings(self.payload(netwatch_enabled=True));self.system.commands.clear()
        self.admin.settings(self.payload(netwatch_interval_minutes=45))
        self.assertEqual(self.system.commands,[('daemon-reload',None,False),('restart',service.TIMERS['netwatch'],False)])
    def test_custom_timer_overrides_are_not_overwritten(self):
        path=self.admin.dropin('netwatch').parent/'operator.conf';path.write_text('[Timer]\nOnUnitActiveSec=90min\n')
        self.assertIsNone(self.admin.snapshot()['settings']['netwatch_interval_minutes'])
        with self.assertRaises(security.Denied):self.admin.settings(self.payload(netwatch_interval_minutes=60))
        self.assertIn('90min',path.read_text());self.assertFalse(self.admin.dropin('netwatch').exists())
        self.admin.settings(self.payload(anonymous_view=True))
    def test_schedule_failure_restores_file_config_and_timer(self):
        self.admin.settings(self.payload(netwatch_interval_minutes=60,netwatch_enabled=True))
        before=self.config.read_bytes();dropin=self.admin.dropin('netwatch').read_bytes()
        def fail(action,unit):
            if action=='restart':self.system.fail=None;return True
            return False
        self.system.fail=fail
        with self.assertRaises(security.Denied):self.admin.settings(self.payload(netwatch_interval_minutes=90))
        self.assertEqual(self.config.read_bytes(),before);self.assertEqual(self.admin.dropin('netwatch').read_bytes(),dropin)
        self.assertTrue(self.system.state(service.TIMERS['netwatch'])['active'])
    def test_timer_limits_reject_arbitrary_schedule_text(self):
        for values in ({'netwatch_interval_minutes':29},{'netwatch_interval_minutes':1441},{'netwatch_interval_minutes':True},{'allstarnets_frequency':'*:*:00'},{'allstarnets_frequency':[]},{'unit':'ssh.service'}):
            with self.subTest(values=values),self.assertRaises(security.Denied):self.admin.settings(self.payload(**values))
        self.assertFalse(self.system.commands)
    def test_timer_frequency_changes_invalidate_old_revision(self):
        payload=self.payload(netwatch_interval_minutes=90)
        self.admin.settings(self.payload(netwatch_interval_minutes=60))
        with self.assertRaises(security.Denied) as error:self.admin.settings(payload)
        self.assertEqual(error.exception.status,409)

    def test_daemon_reload_failure_restores_previous_schedule(self):
        original=self.system.reload;failed=False
        def reload():
            nonlocal failed
            if not failed:failed=True;raise security.Denied(503,'reload failed')
            original()
        with patch.object(self.system,'reload',side_effect=reload),self.assertRaises(security.Denied):self.admin.settings(self.payload(netwatch_interval_minutes=90))
        self.assertTrue(failed);self.assertFalse(self.admin.dropin('netwatch').exists());self.assertFalse(self.admin.journal.exists())

    def test_node_handoff_preserves_valid_records_and_pending_backoff(self):
        source=configuration.load_config(self.config)['monitor']['stats_url_template']
        record=dict(checked=1000,stats_time=995,keyups=5,txtime=10,keyed=False,registered=True,links=0,last_activity=990,error=None)
        saved=dict(version=1,saved_at=1000,local_node='1000',source=source,records={'1001':record},retry=dict(failures=1,retry_at=1200,error_kind='rate_limit'))
        path=self.tmp/'monitor-history.json';path.write_text(json.dumps(saved))
        self.change_node()
        restored_node=history.restoration_node(path,self.config,'2000',source,owner=os.geteuid())
        self.assertEqual(restored_node,'1000')
        records,retry=history.load_history(path,restored_node,source,[dict(node='1001',name='Existing')],1000,86400)
        self.assertEqual(records['1001']['keyups'],5);self.assertEqual(retry['retry_at'],1200)
        self.assertEqual(history.restoration_node(path,self.config,'2000','different-source',owner=os.geteuid()),'2000')
        (self.tmp/'node-handoff.json').chmod(0o666)
        self.assertEqual(history.restoration_node(path,self.config,'2000',source,owner=os.geteuid()),'2000')

    def test_inactive_monitor_handoff_retains_authorized_predecessors(self):
        self.change_node()
        config=configuration.load_config(self.config);config['allstar']['local_node']='3000'
        self.admin.handoff('2000',config)
        handoff=json.loads((self.tmp/'node-handoff.json').read_text())
        self.assertEqual(handoff['current'],'3000');self.assertEqual(handoff['predecessors'],['2000','1000'])

    def test_nonselection_metadata_does_not_require_an_impossible_stop(self):
        path=self.tmp/'scanner-state.json';path.write_text('{"confirmed":false}')
        self.change_node();self.assertEqual(path.read_text(),'{"confirmed":false}')

    def test_writable_timer_directory_disables_frequency_edits(self):
        self.admin.dropin('netwatch').parent.chmod(0o777)
        self.assertFalse(self.admin.schedules()[1]['netwatch'])
        with self.assertRaises(security.Denied):self.admin.settings(self.payload(netwatch_interval_minutes=60))
        self.assertEqual(self.config.read_bytes(),self.before)

    def test_concurrent_advanced_save_is_rejected_without_partial_changes(self):
        with (self.runtime/'policy.lock').open() as lock:
            fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
            with self.assertRaises(security.Denied):self.admin.settings(self.payload(poll_interval_seconds=10))
        self.assertEqual(self.config.read_bytes(),self.before)
    def test_phase1_and_advanced_values_can_be_saved_together(self):
        self.admin.settings(self.payload(refresh_seconds=30,anonymous_view=True,poll_interval_seconds=10))
        value=configuration.load_config(self.config)
        self.assertEqual(value['web']['refresh_seconds'],30);self.assertTrue(value['web']['anonymous_view']);self.assertEqual(value['monitor']['poll_interval_seconds'],10)


class DiagnosticsTests(OfflineCase):
    def test_cache_errors_and_backoff_are_projected_without_private_data(self):
        config=deepcopy(configuration.DEFAULTS)
        data=dict(updated=1000,favorites=[dict(node='1000',checked=995,stats_time=990,error='password=secret cookie=secret')],api=dict(failures=1,retry_at=1100,error_kind='rate_limit',url='private',nodes={'1000':dict(failures=2,retry_at=1200,error_kind='network',message='secret')}))
        (self.tmp/'activity.json').write_text(json.dumps(data))
        result=advanced.diagnostics(config,self.tmp,1000)
        self.assertEqual(result['state'],'degraded');self.assertTrue(result['api']['global_limit']['active'])
        self.assertEqual(result['nodes'][0]['state'],'unknown');self.assertNotIn('secret',json.dumps(result));self.assertNotIn('private',json.dumps(result))
    def test_fresh_stale_invalid_and_missing_cache(self):
        config=deepcopy(configuration.DEFAULTS)
        self.assertEqual(advanced.diagnostics(config,self.tmp,1000)['state'],'unavailable')
        file=self.tmp/'activity.json';file.write_text('{bad')
        self.assertEqual(advanced.diagnostics(config,self.tmp,1000)['state'],'unavailable')
        file.write_text(json.dumps(dict(updated=1000,favorites=[dict(node='1000',checked=700,stats_time=700)])))
        self.assertEqual(advanced.diagnostics(config,self.tmp,1000)['nodes'][0]['freshness'],'fresh')
        self.assertEqual(advanced.diagnostics(config,self.tmp,1001)['nodes'][0]['freshness'],'stale')
    def test_journal_projection_never_returns_raw_messages(self):
        rows=[dict(MESSAGE='Activity cache write failed: password=secret',_SYSTEMD_UNIT='kc1ray-hub-scanner-monitor.service',__REALTIME_TIMESTAMP='1000000'),dict(MESSAGE='Cookie: secret',_SYSTEMD_UNIT='kc1ray-hub-scanner-web.service'),dict(MESSAGE='Activity cache write failed: secret',_SYSTEMD_UNIT='ssh.service')]
        result=advanced.safe_logs('\n'.join(json.dumps(row) for row in rows))
        self.assertEqual(len(result),1);self.assertNotIn('secret',json.dumps(result))
        self.assertEqual(len(advanced.safe_logs('\n'.join(json.dumps(rows[0]) for _ in range(200)))),25)
    def test_cli_cannot_bypass_admin_transition_lock(self):
        lock=self.tmp/'policy.lock';lock.touch()
        with lock.open() as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(settings,'trusted',side_effect=lambda *args:os.open(lock,os.O_RDONLY)),patch.object(scanner,'_main') as action:
                with self.assertRaises(security.Denied):scanner.main()
            action.assert_not_called()

    def test_service_allowlist_excludes_web_admin_and_asterisk_restarts(self):
        for name in ('web','admin','asterisk','ssh'):
            with self.assertRaises(security.Denied):service.Systemd().command('restart',service.PREFIX+name+'.service')


class AdvancedPackagingTests(PackagingCase):
    def test_upgrade_rollback_and_uninstall_preserve_owned_schedule_data(self):
        self.install();directory=pkg.TIMER_AREAS['timer-netwatch'];owned=directory/advanced.DROPIN
        pkg.atomic(self.host,owned,advanced.timer_text('netwatch',90),0o640)
        baseline=self.host.path(owned).read_bytes();self.change_release();upgrade=self.manager.apply('upgrade')
        self.assertEqual(self.host.path(owned).read_bytes(),baseline)
        self.manager.rollback(upgrade['backup']);self.assertEqual(self.host.path(owned).read_bytes(),baseline)
        self.manager.uninstall();self.assertFalse(self.host.path(owned).exists())
        self.assertTrue(self.host.path(pkg.CONF/'retained-timers'/directory.name/advanced.DROPIN).exists())
        self.manager.apply('install');self.assertEqual(self.host.path(owned).read_bytes(),baseline)
    def test_phase1_snapshot_is_accepted_without_new_timer_areas(self):
        self.install();identifier=self.manager.snapshot(self.manager.states())
        path=self.host.path(pkg.REGISTRY/'backups'/identifier/'snapshot.json');saved=json.loads(path.read_text())
        for key in pkg.TIMER_AREAS:saved['areas'].pop(key)
        path.write_text(json.dumps(saved));_,value=self.manager.validate_snapshot(identifier)
        self.assertTrue(all(value['areas'][key]=={} for key in pkg.TIMER_AREAS))
