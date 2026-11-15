"""Phase 1 administration, entirely temporary files/mocked systemd; never a real service."""
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import admin_service as service
import admin_settings as settings
import configuration
import dashboard
import security
from test_baseline import OfflineCase,ROOT
import test_security as security_tests
PASSWORD=security_tests.PASSWORD
from test_packaging import PackagingCase,pkg


class FakeSystem(service.Systemd):
    def __init__(self):
        self.states={unit:dict(active=False,enabled=False,active_state='inactive',enabled_state='disabled') for unit in service.UNITS}
        self.commands=[];self.fail=None
    def reload(self):self.commands.append(('daemon-reload',None,False))
    def recent_logs(self):return []
    def state(self,unit):return deepcopy(self.states[unit])
    def command(self,action,unit,*,runtime=False,check=True):
        if unit not in service.UNITS or action not in ('enable','disable','start','stop','restart'):raise AssertionError('Unexpected system operation')
        self.commands.append((action,unit,runtime))
        if self.fail and self.fail(action,unit):raise security.Denied(503,'Timer operation failed: '+unit)
        state=self.states[unit]
        if action in ('enable','disable'):
            state['enabled']=action=='enable';state['enabled_state']=('enabled-runtime' if runtime else 'enabled') if state['enabled'] else 'disabled'
        else:state['active']=action in ('start','restart');state['active_state']='active' if state['active'] else 'inactive'
        return SimpleNamespace(returncode=0,stdout='')


class AdminEnvironment(OfflineCase):
    def setUp(self):
        super().setUp()
        self.config=self.tmp/'config.toml';self.credentials=self.tmp/'credentials.json'
        self.state=self.tmp/'state';self.runtime=self.tmp/'runtime';self.package=self.tmp/'package'
        for path in (self.state,self.runtime,self.package):path.mkdir(mode=0o700)
        for name in ('policy.lock','password.lock'):
            (self.runtime/name).touch();(self.runtime/name).chmod(0o640)
        data=deepcopy(configuration.DEFAULTS)
        data['allstar']['local_node']='1000';data['paths']['cache_dir']=str(self.tmp);data['paths']['state_dir']=str(self.tmp)
        data['auth']['credentials_file']=str(self.credentials)
        data['web'].update(controls_enabled=True,allowed_origins=['https://scanner.test'],trusted_proxies=['127.0.0.1/32'])
        self.config.write_bytes(service.encode_toml(data));self.config.chmod(0o640)
        security.create_credentials(self.credentials,'admin',PASSWORD);self.credentials.chmod(0o640)
        self.units=self.tmp/'units';self.units.mkdir()
        for source,unit in service.TIMERS.items():
            (self.units/(unit+'.d')).mkdir(mode=0o755)
            (self.units/unit).write_bytes((ROOT/'packaging/systemd'/(unit+'.in')).read_bytes())
        self.system=FakeSystem();self.admin=service.Administration(self.config,self.state,self.runtime,self.package,self.system,unit_dir=self.units,node_discovery=lambda:(['1000','2000'],False))
        self.before=self.config.read_bytes()
    def payload(self,**changes):return dict(revision=self.admin.revision(self.config.read_bytes()),settings=changes)


class AdminStateTests(AdminEnvironment):
    def test_status_contains_only_approved_projection(self):
        result=self.admin.dispatch(dict(op='status',payload=None));text=json.dumps(result)
        self.assertEqual(set(result['settings']),set(settings.FIELDS+service.advanced.SCHEDULE_FIELDS))
        for secret in ('credentials_file','trusted_proxies','digest','salt',PASSWORD):self.assertNotIn(secret,text)
        self.assertEqual(result['status']['local_node'],'1000')
        self.assertEqual(set(result['status']['services']),set(service.UNITS))
    def test_save_preserves_unedited_fields_and_permissions(self):
        before=configuration.load_config(self.config)
        result=self.admin.settings(self.payload(refresh_seconds=5,anonymous_view=True))
        after=configuration.load_config(self.config)
        self.assertEqual(after['web']['refresh_seconds'],5);self.assertTrue(after['web']['anonymous_view'])
        for section in before:
            if section!='web':self.assertEqual(before[section],after[section])
        self.assertEqual(after['web']['trusted_proxies'],before['web']['trusted_proxies'])
        self.assertEqual(self.config.stat().st_mode&0o777,0o640)
        self.assertEqual(self.config.stat().st_uid,os.geteuid())
        self.assertFalse(self.admin.journal.exists());self.assertFalse(self.system.commands)
        self.assertNotEqual(result['revision'],hashlib.sha256(self.before).hexdigest())
    def test_control_disable_requires_confirmation_without_disconnect(self):
        with self.assertRaises(security.Denied):self.admin.settings(self.payload(controls_enabled=False))
        payload=self.payload(controls_enabled=False);payload['confirm_disable']=True
        self.admin.settings(payload)
        self.assertFalse(configuration.load_config(self.config)['web']['controls_enabled'])
        self.assertFalse(self.system.commands)
    def test_invalid_settings_and_stale_revisions_do_not_write(self):
        for changes in ({'refresh_seconds':7},{'refresh_seconds':True},{'controls_enabled':'yes'},{'local_node':'577930'},{'unit':'asterisk.service'},{'credentials_file':'/tmp/arbitrary'},{'cooldown_seconds':0}):
            with self.subTest(changes=changes),self.assertRaises(security.Denied):self.admin.settings(self.payload(**changes))
            self.assertEqual(self.config.read_bytes(),self.before)
        payload=self.payload(anonymous_view=True);payload['revision']='0'*64
        with self.assertRaises(security.Denied) as error:self.admin.settings(payload)
        self.assertEqual(error.exception.status,409)
    def test_enable_disable_timers_keeps_caches_and_no_extra_requests(self):
        cache=self.tmp/'netwatch-nets.json';cache.write_text('{"updated":1000}')
        self.admin.settings(self.payload(netwatch_enabled=True,allstarnets_enabled=True))
        for unit in service.TIMERS.values():self.assertTrue(self.system.state(unit)['active']);self.assertTrue(self.system.state(unit)['enabled'])
        self.admin.settings(self.payload(netwatch_enabled=False,allstarnets_enabled=False))
        for unit in service.TIMERS.values():self.assertFalse(self.system.state(unit)['active']);self.assertFalse(self.system.state(unit)['enabled'])
        self.assertEqual(cache.read_text(),'{"updated":1000}')
        self.assertTrue(all(unit in service.TIMERS.values() for _,unit,_ in self.system.commands))
    def test_timer_failure_restores_config_and_service_states(self):
        def fail(action,unit):
            if action=='start':self.system.fail=None;return True
            return False
        self.system.fail=fail
        with self.assertRaises(security.Denied) as error:self.admin.settings(self.payload(netwatch_enabled=True))
        self.assertIn('restored',error.exception.message)
        self.assertEqual(self.config.read_bytes(),self.before)
        self.assertFalse(self.system.state(service.TIMERS['netwatch'])['enabled'])
        self.assertFalse(self.admin.journal.exists())
    def test_write_failure_is_atomic(self):
        original=service.atomic;failed=False
        def write(path,data,info=None,mode=0o600):
            nonlocal failed
            if Path(path)==self.config and not failed:failed=True;raise OSError('disk unavailable')
            return original(path,data,info,mode)
        with patch.object(service,'atomic',side_effect=write),self.assertRaises(security.Denied):self.admin.settings(self.payload(anonymous_view=True))
        self.assertEqual(self.config.read_bytes(),self.before)
        self.assertFalse(self.admin.journal.exists())
    def test_concurrent_install_or_radio_request_is_busy(self):
        for path in (self.package/'operation.lock',self.runtime/'policy.lock'):
            with path.open('a+') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(security.Denied) as error:self.admin.settings(self.payload(refresh_seconds=15))
                self.assertEqual(error.exception.status,429)
        self.assertEqual(self.config.read_bytes(),self.before)
    def test_pending_recovery_restores_previous_settings(self):
        raw,info=self.admin.read(self.config)
        self.admin.save_journal(self.config,raw,info,self.admin.timer_states())
        changed=configuration.load_config(self.config);changed['web']['refresh_seconds']=60
        self.config.write_bytes(service.encode_toml(changed));self.admin.recover()
        self.assertEqual(self.config.read_bytes(),self.before)
        self.assertFalse(self.admin.journal.exists())
    def test_password_change_requires_current_and_preserves_owner_hash_profile(self):
        original=self.credentials.read_bytes()
        payload=dict(current_password='wrong-password',new_password='12345678',confirmation='12345678')
        with self.assertRaises(security.Denied):self.admin.password(payload)
        self.assertEqual(self.credentials.read_bytes(),original)
        payload['current_password']=PASSWORD;payload['new_password']=payload['confirmation']='1234567'
        with self.assertRaises(security.Denied):self.admin.password(payload)
        payload['new_password']=payload['confirmation']='12345678'
        result=self.admin.password(payload)
        self.assertTrue(result['reauthenticate'])
        self.assertTrue(security.Credentials(self.credentials).verify('admin','12345678'))
        self.assertEqual(self.credentials.stat().st_mode&0o777,0o640)
        self.assertEqual(json.loads(self.credentials.read_bytes())['n'],2**17)
        self.assertFalse(self.admin.journal.exists())
    def test_legacy_refresh_can_be_retained_but_not_new_arbitrary_value(self):
        config=configuration.load_config(self.config);config['web']['refresh_seconds']=12
        self.config.write_bytes(service.encode_toml(config))
        self.admin.settings(self.payload(refresh_seconds=12))
        self.assertEqual(configuration.load_config(self.config)['web']['refresh_seconds'],12)
        with self.assertRaises(security.Denied):self.admin.settings(self.payload(refresh_seconds=13))

    def test_password_write_failure_restores_previous_credentials(self):
        before=self.credentials.read_bytes();original=service.atomic;failed=False
        def write(path,data,info=None,mode=0o600):
            nonlocal failed
            if Path(path)==self.credentials and not failed:failed=True;raise OSError('unavailable')
            return original(path,data,info,mode)
        with patch.object(service,'atomic',side_effect=write),self.assertRaises(security.Denied):
            self.admin.password(dict(current_password=PASSWORD,new_password='abcdefgh',confirmation='abcdefgh'))
        self.assertEqual(self.credentials.read_bytes(),before)
        self.assertFalse(self.admin.journal.exists())

    def test_missing_credentials_with_existing_marker_fails_closed(self):
        config=configuration.load_config(self.config)
        auth=security.Security(config['auth'],security.Credentials(self.credentials))
        self.admin.publish(config);self.credentials.unlink()
        with patch.dict(os.environ,{'KC1RAY_CONFIG':str(self.config)}),self.assertRaises(security.Denied):
            settings.refresh(config,auth,path=self.runtime/'settings.json',owner=os.geteuid())
        self.assertFalse(config['web']['controls_enabled']);self.assertFalse(config['web']['anonymous_view'])

    def test_failed_timer_rollback_retains_journal_until_recovery(self):
        self.system.fail=lambda action,unit:action in ('start','disable')
        with self.assertRaises(security.Denied) as error:self.admin.settings(self.payload(netwatch_enabled=True))
        self.assertIn('recovery required',error.exception.message)
        self.assertEqual(self.config.read_bytes(),self.before);self.assertTrue(self.admin.journal.exists())
        self.system.fail=None;self.admin.recover();self.assertFalse(self.admin.journal.exists())

    def test_password_attempt_limit(self):
        payload=dict(current_password='wrong-password',new_password='12345678',confirmation='12345678')
        for _ in range(5):
            with self.assertRaises(security.Denied) as error:self.admin.password(payload)
            self.assertEqual(error.exception.status,401)
        with self.assertRaises(security.Denied) as error:self.admin.password(payload)
        self.assertEqual(error.exception.status,429)
    def test_live_marker_preserves_privacy_and_revokes_all_sessions_on_password_change(self):
        config=configuration.load_config(self.config)
        auth=security.Security(config['auth'],security.Credentials(self.credentials))
        a,_=auth.sessions.create(False,'admin');b,_=auth.sessions.create(False,'admin')
        self.admin.settings(self.payload(refresh_seconds=30,anonymous_view=True))
        with patch.dict(os.environ,{'KC1RAY_CONFIG':str(self.config)}):settings.refresh(config,auth,path=self.runtime/'settings.json',owner=os.geteuid())
        self.assertEqual(config['web']['refresh_seconds'],30);self.assertTrue(config['web']['anonymous_view'])
        self.admin.password(dict(current_password=PASSWORD,new_password='abcdefgh',confirmation='abcdefgh'))
        with patch.dict(os.environ,{'KC1RAY_CONFIG':str(self.config)}):settings.refresh(config,auth,path=self.runtime/'settings.json',owner=os.geteuid())
        self.assertIsNone(auth.sessions.lookup(a,False));self.assertIsNone(auth.sessions.lookup(b,False))
    def test_backend_disable_enforced_from_live_policy(self):
        config=configuration.load_config(self.config)
        payload=self.payload(controls_enabled=False);payload['confirm_disable']=True;self.admin.settings(payload)
        with patch.dict(os.environ,{'KC1RAY_CONFIG':str(self.config)}):settings.refresh(config,path=self.runtime/'settings.json',owner=os.geteuid())
        driver=SimpleNamespace(CONFIG=config)
        from control_service import ControlService
        with patch('admin_settings.refresh',side_effect=lambda cfg:None):
            with self.assertRaises(security.Denied) as error:ControlService(driver).control({'action':'stop'})
        self.assertEqual(error.exception.status,403)
    def test_systemd_and_dispatch_are_fixed_allowlists(self):
        for request in ({'op':'shell','payload':{'command':'id'}},{'op':'status','payload':{'unit':'asterisk.service'}},{'op':'settings','payload':{'path':'/etc/asterisk/rpt.conf'}}):
            with self.assertRaises(security.Denied):self.admin.dispatch(request)
        for action,unit in (('restart','asterisk.service'),('stop',service.SERVICES[0]),('start','ssh.service')):
            with self.assertRaises(security.Denied):service.Systemd().command(action,unit)


class AdminHttpTests(OfflineCase):
    request=security_tests.HttpSecurityTests.request
    login=security_tests.HttpSecurityTests.login
    def setUp(self):
        super().setUp();self.now=100
        self.enterContext(patch('time.monotonic',side_effect=lambda:self.now))
        self.enterContext(patch.dict(configuration.CONFIG['web'],deepcopy(configuration.DEFAULTS['web'])))
        self.enterContext(patch.dict(configuration.CONFIG['auth'],deepcopy(configuration.DEFAULTS['auth'])))
        self.credentials=Mock(username='admin');self.credentials.verify.return_value=True
        self.auth=security.Security(configuration.CONFIG['auth'],self.credentials);self.server=SimpleNamespace(security=self.auth)
        self.admin=self.enterContext(patch.object(dashboard,'admin_rpc',return_value={'message':'Saved','reauthenticate':True}))
    def test_every_admin_endpoint_denies_anonymous_even_with_public_view(self):
        configuration.CONFIG['web']['anonymous_view']=True
        for method,path in (('GET','/api/admin'),('POST','/api/admin/settings'),('POST','/api/admin/password')):
            result=self.request(method,path,{} if method=='POST' else None)
            self.assertEqual(result[0],401)
        self.admin.assert_not_called()
    def test_settings_need_admin_csrf_and_work_when_radio_is_disabled(self):
        cookie,csrf=self.login()
        self.assertEqual(self.request('GET','/api/admin',headers={'Cookie':cookie})[0],200)
        self.assertEqual(self.request('POST','/api/admin/settings',{}, {'Cookie':cookie})[0],403)
        self.assertEqual(self.request('POST','/api/admin/settings',{}, {'Cookie':cookie,'X-CSRF-Token':csrf})[0],200)
        token,_=self.auth.sessions.create(False,'another-user')
        self.assertEqual(self.request('GET','/api/admin',headers={'Cookie':security.COOKIE+'='+token})[0],403)
    def test_advanced_settings_reuse_admin_csrf_and_origin_checks(self):
        cookie,csrf=self.login()
        body=dict(revision='0'*64,settings={'cooldown_seconds':30,'local_node':'2000'},confirm_node_change=True)
        headers={'Cookie':cookie,'X-CSRF-Token':csrf}
        self.assertEqual(self.request('POST','/api/admin/settings',body,headers)[0],200)
        self.admin.assert_called_with('settings',body)
        count=self.admin.call_count
        self.assertEqual(self.request('POST','/api/admin/settings',body,headers|{'Origin':'https://untrusted.test'})[0],403)
        self.assertEqual(self.request('POST','/api/admin/settings',body,{'Cookie':cookie})[0],403)
        self.assertEqual(self.admin.call_count,count)

    def test_password_change_invalidates_all_sessions(self):
        cookie,csrf=self.login();other,_=self.login()
        status,headers,_=self.request('POST','/api/admin/password',dict(current_password=PASSWORD,new_password='abcdefgh',confirmation='abcdefgh'),{'Cookie':cookie,'X-CSRF-Token':csrf})
        self.assertEqual(status,200);self.assertIn('Max-Age=0',headers['set-cookie'])
        self.assertEqual(self.request('GET','/api/admin',headers={'Cookie':other})[0],401)
    def test_apache_prefix_applies_to_administration_and_cookie_deletion(self):
        configuration.CONFIG['web'].update(url_prefix='/hubscanner',allowed_origins=['https://scanner.test'],trusted_proxies=['127.0.0.1/32'])
        proxy={'X-Forwarded-Proto':'https','X-Forwarded-For':'192.168.50.11'}
        _,headers,data=self.request('GET','/hubscanner/api/session',headers=proxy,host='scanner.test')
        values=proxy|{'Cookie':headers['set-cookie'].split(';')[0],'X-CSRF-Token':data['csrf'],'Origin':'https://scanner.test'}
        _,headers,data=self.request('POST','/hubscanner/api/auth/login',{'username':'admin','password':PASSWORD},values,host='scanner.test')
        values.update(Cookie=headers['set-cookie'].split(';')[0],**{'X-CSRF-Token':data['csrf']})
        self.assertEqual(self.request('GET','/hubscanner/api/admin',headers=values,host='scanner.test')[0],200)
        status,headers,_=self.request('POST','/hubscanner/api/admin/password',dict(current_password=PASSWORD,new_password='abcdefgh',confirmation='abcdefgh'),values,host='scanner.test')
        self.assertEqual(status,200);self.assertIn('Path=/hubscanner/',headers['set-cookie']);self.assertIn('; Secure',headers['set-cookie'])


class AdminPackagingTests(PackagingCase):
    def test_install_provisions_admin_without_new_accounts_or_config_keys(self):
        self.install()
        unit=self.host.path(pkg.UNIT_DIR/'kc1ray-hub-scanner-admin.service').read_text()
        self.assertIn('User=root',unit);self.assertIn('CapabilityBoundingSet=\n',unit)
        self.assertIn('RestrictAddressFamilies=AF_UNIX',unit)
        self.assertIn('InaccessiblePaths=-/run/asterisk',unit)
        self.assertEqual(set(self.host.users),set(pkg.USERS))
        self.assertTrue(self.host.service_state('kc1ray-hub-scanner-admin.service')['active'])
    def test_upgrade_from_old_manifest_activates_new_helper_and_preserves_accounts(self):
        self.install();before=self.bytes_at(pkg.CONF/'credentials.json');config=self.bytes_at(pkg.CONF/'config.toml')
        manifest=self.manager.manifest();manifest['units'].pop('kc1ray-hub-scanner-admin.service')
        pkg.json_write(self.host,pkg.REGISTRY/'manifest.json',manifest)
        self.host.path(pkg.UNIT_DIR/'kc1ray-hub-scanner-admin.service').unlink()
        self.host.services['kc1ray-hub-scanner-admin.service'].update(active=False,enabled=False)
        self.change_release();self.manager.apply('upgrade')
        self.assertTrue(self.host.service_state('kc1ray-hub-scanner-admin.service')['enabled'])
        self.assertTrue(self.host.service_state('kc1ray-hub-scanner-admin.service')['active'])
        self.assertEqual(self.bytes_at(pkg.CONF/'credentials.json'),before);self.assertEqual(self.bytes_at(pkg.CONF/'config.toml'),config)
    def test_legacy_backup_without_admin_area_still_validates(self):
        self.install();identifier=self.manager.snapshot(self.manager.states())
        path=self.host.path(pkg.REGISTRY/'backups'/identifier/'snapshot.json');data=json.loads(path.read_text())
        data['areas'].pop('unit-kc1ray-hub-scanner-admin.service');[data['areas'].pop(area) for area in pkg.TIMER_AREAS];data['services'].pop('kc1ray-hub-scanner-admin.service');path.write_text(json.dumps(data))
        _,restored=self.manager.validate_snapshot(identifier)
        self.assertEqual(restored['areas']['unit-kc1ray-hub-scanner-admin.service'],{})
    def test_pending_admin_change_blocks_packaging(self):
        pending=self.host.path('/var/lib/kc1ray-hub-scanner-admin/transaction.json');pending.parent.mkdir(parents=True);pending.write_text('{}')
        with self.assertRaises(pkg.InstallError):self.manager.plan('install',node='1000',port=8085)

    def test_pending_admin_transaction_blocks_rollback_before_service_changes(self):
        self.install();identifier=self.manager.snapshot(self.manager.states())
        pending=self.host.path('/var/lib/kc1ray-hub-scanner-admin/transaction.json');pending.parent.mkdir(parents=True,exist_ok=True);pending.write_text('{}')
        before=len(self.host.commands)
        with self.assertRaises(pkg.InstallError):self.manager.rollback(identifier)
        self.assertFalse(any(command[:2]==['systemctl','stop'] for command in self.host.commands[before:]))


class AdminPeerTests(unittest.TestCase):
    def test_root_helper_rejects_radio_or_other_peer_uid(self):
        request=Mock();server=SimpleNamespace(web_uid=10001,router=Mock())
        with patch.object(service,'peer_uid',return_value=10002):service.AdminHandler(request,None,server)
        server.router.dispatch.assert_not_called()
        reply=json.loads(request.sendall.call_args.args[0]);self.assertEqual(reply['status'],403)

    def test_web_client_rejects_nonroot_helper_before_sending_payload(self):
        connection=Mock();context=Mock();context.__enter__=Mock(return_value=connection);context.__exit__=Mock(return_value=False)
        with patch.dict(configuration.CONFIG['broker'],web_uid=10001),patch.object(settings.os,'geteuid',return_value=10001),patch.object(settings.socket,'socket',return_value=context),patch('broker.peer_uid',return_value=10002):
            with self.assertRaises(security.Denied):settings.rpc('password',{'current_password':'not-sent'})
        connection.sendall.assert_not_called()
