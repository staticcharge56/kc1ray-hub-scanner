"""Local control policy, privilege boundary, and concurrency tests (mocked Asterisk)."""
from copy import deepcopy
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

import broker
import configuration
import control_service
import dashboard
import security
from radio_control import RadioTimeout, Busy
from test_baseline import OfflineCase, ROOT


class ControlPolicyTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.settings=deepcopy(configuration.DEFAULTS)
        self.settings['web']['controls_enabled']=True
        self.now=1000
        self.enterContext(patch('time.time',side_effect=lambda:self.now))
        self.driver=SimpleNamespace(CONFIG=self.settings,LOCAL_NODE='1000',
            SCANNER_STATE=self.tmp/'state.json',LOCK=self.tmp/'control.lock',
            LAST_COMMAND=self.tmp/'last.json',SCANNER=self.tmp/'scanner.py',COOLDOWN_SECONDS=15,
            favorite_numbers=Mock(return_value={'1001'}),scheduled_net_numbers=Mock(return_value={'2001'}),
            direct_links=Mock(return_value=['9001']),run_link_action=Mock(return_value='Connection requested'),
            scan_action=Mock(return_value='Reported link confirmed'))
        self.service=control_service.ControlService(self.driver)
        self.run=self.enterContext(patch('subprocess.run',
            return_value=SimpleNamespace(returncode=0,stdout='Connection requested',stderr='')))

    def test_every_radio_action_uses_existing_driver_or_cli_contract(self):
        for action in sorted(control_service.ACTIONS):
            self.driver.LAST_COMMAND.unlink(missing_ok=True)
            payload={'action':action}
            if action.endswith('-node'):
                payload['node']='1001'
            elif action.endswith('-net'):
                payload['node']='2001'
            result=self.service.control(payload)
            self.assertIn('message',result)
            if action in ('first','next','stop'):
                self.driver.scan_action.assert_called_with(action)
            else:
                self.driver.run_link_action.assert_called_with(action,payload['node'])
        self.assertEqual(json.loads(self.driver.LAST_COMMAND.read_text())['time'],1000)

    def test_invalid_actions_nodes_fields_and_self_connections_never_execute(self):
        cases=([None,[],{}, {'action':[]},{'action':'shell','node':'1001'},
            {'action':'connect-node','node':'1001; reboot'}, {'action':'connect-node','node':'１２３４'},
            {'action':'connect-node','node':1001},{'action':'connect-node','node':'1000'},
            {'action':'first','node':'1001'}, {'action':'first','command':'rpt arbitrary'}])
        for payload in cases:
            with self.subTest(payload=payload),self.assertRaises(security.Denied):
                self.service.control(payload)
        self.run.assert_not_called()
        self.driver.run_link_action.assert_not_called()

    def test_unlisted_destinations_cannot_connect_or_disconnect_even_if_linked(self):
        for action in ('connect-node','disconnect-node','connect-net','disconnect-net'):
            with self.subTest(action=action),self.assertRaises(security.Denied) as error:
                self.service.control({'action':action,'node':'9001'})
            self.assertEqual(error.exception.status,403)
        self.driver.run_link_action.assert_not_called()

    def test_nets_disconnect_can_stop_previously_selected_node_after_schedule_removal(self):
        self.driver.SCANNER_STATE.write_text('{"node":"3001"}')
        self.assertIn('message',self.service.control({'action':'disconnect-net','node':'3001'}))
        self.driver.run_link_action.assert_called_once_with('disconnect-net','3001')

    def test_corrupt_stop_state_fails_closed(self):
        for raw in ('broken','[]','{"node":"1001; reboot"}'):
            self.driver.SCANNER_STATE.write_text(raw)
            with self.assertRaises(security.Denied):
                self.service.control({'action':'stop'})
        self.run.assert_not_called()

    def test_cooldown_preserved_and_supplies_retry_after(self):
        self.service.control({'action':'connect-node','node':'1001'})
        self.now=1014
        with self.assertRaises(security.Denied) as error:
            self.service.control({'action':'connect-node','node':'1001'})
        self.assertEqual(error.exception.status,429)
        self.assertEqual(error.exception.retry_after,1)
        self.now=1015
        self.service.control({'action':'connect-node','node':'1001'})
        self.assertEqual(self.driver.run_link_action.call_count,2)

    def test_failed_attempts_do_not_bypass_cooldown_or_leak_raw_errors(self):
        self.driver.run_link_action.side_effect=RuntimeError('secret=do-not-expose')
        with self.assertRaises(security.Denied) as error:
            self.service.control({'action':'connect-node','node':'1001'})
        self.assertNotIn('secret',error.exception.message)
        with self.assertRaises(security.Denied) as error:
            self.service.control({'action':'connect-node','node':'1001'})
        self.assertEqual(error.exception.status,429)
        self.assertEqual(self.driver.run_link_action.call_count,1)

    def test_corrupted_cooldown_state_blocks_commands(self):
        for raw in ('broken','[]','{"time":null}','{"time":NaN}','{"time":true}'):
            self.driver.LAST_COMMAND.write_text(raw)
            with self.subTest(raw=raw),self.assertRaises(security.Denied) as error:
                self.service.control({'action':'first'})
            self.assertEqual(error.exception.status,503)
        self.run.assert_not_called()

    def test_scanner_transition_timeout_and_failures_are_sanitized(self):
        self.driver.scan_action.side_effect=RadioTimeout('hidden-secret')
        with self.assertRaises(security.Denied) as error:
            self.service.control({'action':'first'})
        self.assertEqual(error.exception.status,504)
        self.assertNotIn('hidden',error.exception.message)

    def test_concurrent_commands_only_execute_one(self):
        started,release=threading.Event(),threading.Event()
        errors=[]
        def action(action,node):
            started.set()
            if not release.wait(3):
                raise RuntimeError('test timeout')
            return 'Connection requested'
        self.driver.run_link_action.side_effect=action
        def first():
            try:
                self.service.control({'action':'connect-node','node':'1001'})
            except BaseException as error:
                errors.append(error)
        worker=threading.Thread(target=first)
        worker.start()
        try:
            self.assertTrue(started.wait(3))
            with self.assertRaises(security.Denied) as error:
                self.service.control({'action':'stop'})
            self.assertEqual(error.exception.status,429)
        finally:
            release.set()
            worker.join(3)
        self.assertEqual(errors,[])
        self.assertEqual(self.driver.run_link_action.call_count,1)
        self.run.assert_not_called()

    def test_existing_dtmf_lock_makes_manual_command_fail_promptly(self):
        with patch.object(dashboard,'SCANNER_LOCK',self.tmp/'scanner.lock'), \
             patch.object(dashboard,'favorite_numbers',return_value={'1001'}), \
             patch.object(dashboard,'direct_links') as links:
            with dashboard.SCANNER_LOCK.open('a+') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(Busy):
                    dashboard.run_link_action('connect-node','1001')
            links.assert_not_called()

    def test_links_are_shared_cached_and_failures_cannot_hot_loop(self):
        tick=[100]
        with patch('time.monotonic',side_effect=lambda:tick[0]):
            self.service.links()
            self.service.links()
            self.driver.direct_links.assert_called_once()
            tick[0]=105
            self.driver.direct_links.side_effect=RuntimeError('link failure')
            with self.assertRaises(RuntimeError):
                self.service.links()
            with self.assertRaises(security.Denied):
                self.service.links()
            self.assertEqual(self.driver.direct_links.call_count,2)


class BrokerBoundaryTests(OfflineCase):
    def roundtrip(self,uid,request):
        client,connection=socket.socketpair()
        client.settimeout(3)
        router=Mock()
        router.dispatch.return_value={'links':['1001']}
        errors=[]
        def worker():
            try:
                broker.Handler(connection,None,SimpleNamespace(web_uid=uid,router=router))
            except BaseException as error:
                errors.append(error)
            finally:
                connection.close()
        thread=threading.Thread(target=worker)
        client.sendall(json.dumps(request).encode()+b'\n')
        thread.start()
        try:
            result=broker.receive(client,broker.MAX_RESPONSE)
        finally:
            client.close()
            thread.join(3)
        self.assertEqual(errors,[])
        return result,router

    def test_unix_peer_uid_allows_configured_identity_only(self):
        result,router=self.roundtrip(os.geteuid(),{'op':'links','payload':None})
        self.assertEqual(result['status'],200)
        router.dispatch.assert_called_once()
        result,router=self.roundtrip(os.geteuid()+1,{'op':'control','payload':{'action':'first'}})
        self.assertEqual(result['status'],403)
        router.dispatch.assert_not_called()

    def test_rpc_router_rejects_arbitrary_operations_and_fields(self):
        driver=Mock()
        driver.CONFIG=deepcopy(configuration.DEFAULTS)
        router=broker.Router(driver)
        for request in ({'op':'shell','payload':'anything'}, {'op':'control','payload':{},'uid':123},
                        {'op':'favorites','payload':{},'admin':True},[]):
            with self.subTest(request=request),self.assertRaises(security.Denied):
                router.dispatch(request)

    def test_web_cannot_start_as_root_asterisk_or_same_identity_as_broker(self):
        for uid,web,service in ((0,0,1001),(1001,1001,1001),(1001,1002,1003)):
            with patch.object(broker.os,'geteuid',return_value=uid), \
                 patch.dict(configuration.CONFIG['broker'],{'web_uid':web,'service_uid':service}):
                with self.assertRaises(ValueError):
                    broker.validate_web_identity()
        with patch.object(broker.os,'geteuid',return_value=1001), \
             patch.dict(configuration.CONFIG['broker'],{'web_uid':1001,'service_uid':1002}), \
             patch.object(broker.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=1001)), \
             patch.object(broker.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=2001)):
            with self.assertRaises(ValueError):
                broker.validate_web_identity()

    def test_service_fails_closed_when_identities_unconfigured(self):
        with patch.dict(configuration.CONFIG['broker'],{'web_uid':-1,'service_uid':-1}):
            with self.assertRaises(ValueError):
                broker.validate_service_identity()
            with self.assertRaises(security.Denied):
                broker.rpc('control',{'action':'first'})

    def test_ipc_frame_size_and_trailing_data_rejected(self):
        for raw in (b'{}',b'{}\n{}\n',b'x'*17+b'\n'):
            connection=Mock()
            connection.recv.side_effect=[raw,b'']
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                broker.receive(connection,16)

    def test_worker_limits_close_overflow_connections(self):
        for cls in (broker.Server,dashboard.WebServer):
            server=object.__new__(cls)
            server.slots=threading.BoundedSemaphore(1)
            server.slots.acquire()
            request=Mock()
            server.process_request(request,None)
            request.close.assert_called_once()

    def test_phase_3_preserves_monitor_favorites_scanner_and_schedule_code(self):
        for filename,digest in json.loads((ROOT/'tests/fixtures/phase-3-protected.json').read_text()).items():
            if filename in ('monitor.py','scanner.py'):
                continue # Phase 4 explicitly separates monitor-owned persistence.
            with self.subTest(filename=filename):
                self.assertEqual(hashlib.sha256((ROOT/filename).read_bytes()).hexdigest(),digest)

    def test_service_accepts_trusted_python_symlink_but_rejects_writable_target(self):
        web_uid=os.geteuid()+10000
        service_uid=web_uid+1
        state,cache,runtime=(self.tmp/name for name in ('state','cache','runtime'))
        for directory in (state,cache,runtime):
            directory.mkdir()
        executable=self.tmp/'python-real'
        executable.write_text('synthetic executable; never run')
        executable.chmod(0o755)
        link=self.tmp/'python-link'
        link.symlink_to(executable)
        asterisk=self.tmp/'asterisk'
        asterisk.write_text('synthetic; never run')
        original_stat=Path.stat
        def modeled_stat(path,*args,**kwargs):
            info=original_stat(path,*args,**kwargs)
            if path==Path('/tmp'):
                # Model packaged root-owned ancestors; no real permissions are changed.
                return SimpleNamespace(st_mode=0o40755,st_uid=0,st_gid=0)
            return info
        with patch.dict(configuration.CONFIG['broker'],{'web_uid':web_uid,'service_uid':service_uid,
                'socket_gid':999999,'socket_path':str(runtime/'control.sock')}), \
             patch.dict(configuration.CONFIG['paths'],{'state_dir':str(state),'cache_dir':str(cache),'runtime_dir':str(runtime)}), \
             patch.dict(configuration.CONFIG['allstar'],{'asterisk_binary':str(asterisk)}), \
             patch.object(broker.os,'geteuid',return_value=service_uid), \
             patch.object(broker.pwd,'getpwuid',return_value=SimpleNamespace(pw_name='synthetic-web',pw_gid=999999)), \
             patch.object(broker.os,'getgrouplist',return_value=[999999]), \
             patch.object(broker.sys,'executable',str(link)), \
             patch.object(Path,'stat',modeled_stat):
            broker.validate_service_identity()
            executable.chmod(0o666)
            with self.assertRaises(ValueError):
                broker.validate_service_identity()
