"""Offline application-owned link policy; never touches a real Asterisk/node."""
import ast
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

import configuration
import control_service
import dashboard
import radio_control as radio
import scanner as live_scanner
from test_baseline import OfflineCase, ROOT, scanner


class TransitionCase(OfflineCase):
    def setUp(self):
        super().setUp()
        self.tick=100
        self.enterContext(patch.object(radio.time,'monotonic',side_effect=lambda:self.tick))
        self.enterContext(patch.object(radio.time,'sleep',side_effect=self.advance))
        self.active=[]
        self.events=[]
        self.query_hook=None
        self.command_hook=None
        self.path=self.tmp/'selection.json'

    def advance(self,seconds):
        self.tick+=seconds

    def query(self,timeout):
        self.events.append(('query',tuple(self.active)))
        if self.query_hook:
            self.query_hook()
        return [radio.link_record(node,'TU') for node in self.active]

    def command(self,action,node,timeout):
        self.events.append((action,node))
        if self.command_hook:
            return self.command_hook(action,node)
        if action=='connect':
            self.active.append(node)
        elif node in self.active:
            self.active.remove(node)

    def controller(self):
        return radio.LinkController(self.query,self.command)

    def perform(self,action='connect',node='1001'):
        return radio.perform(action,node,self.controller(),self.path,'1000')

    def commands(self):
        return [event for event in self.events if event[0]!='query']

class TransitionTests(TransitionCase):
    def test_empty_connect_confirms_actual_destination(self):
        self.perform()
        self.assertEqual(self.commands(),[('connect','1001')])
        self.assertEqual(self.active,['1001'])
        self.assertTrue(json.loads(self.path.read_text())['confirmed'])
        self.assertEqual(self.events[-1],('query',('1001',)))

    def test_already_only_target_has_no_asterisk_commands(self):
        self.active=['1001']
        self.path.write_text('{"node":"1002"}') # Saved selection is not truth.
        message=self.perform()
        self.assertIn('already the only connection',message)
        self.assertEqual(self.commands(),[])
        self.assertEqual(json.loads(self.path.read_text())['node'],'1001')

    def test_disconnects_every_existing_link_and_observes_empty_before_connect(self):
        self.active=['1003','1002']
        self.perform()
        self.assertEqual(self.commands(),[('disconnect','1002'),('disconnect','1003'),('connect','1001')])
        index=self.events.index(('connect','1001'))
        self.assertEqual(self.events[index-1],('query',()))
        self.assertEqual(self.active,['1001'])

    def test_target_among_multiple_links_is_disconnected_before_reconnect(self):
        self.active=['1001','1002']
        self.perform()
        self.assertEqual(self.commands(),[('disconnect','1001'),('disconnect','1002'),('connect','1001')])

    def test_disconnect_failure_never_connects_or_changes_selection(self):
        self.active=['1002']
        self.path.write_text('{"node":"1002"}')
        self.command_hook=lambda *args:(_ for _ in ()).throw(radio.RadioError('failure'))
        with self.assertRaises(radio.RadioError):
            self.perform()
        self.assertNotIn(('connect','1001'),self.commands())
        self.assertEqual(json.loads(self.path.read_text()),{'node':'1002'})

    def test_delayed_disconnection_waits_for_a_reported_empty_set(self):
        self.active=['1002']
        def command(action,node):
            if action=='connect': self.active.append(node)
        self.command_hook=command
        def query():
            if self.tick>=101 and '1002' in self.active: self.active.remove('1002')
        self.query_hook=query
        self.perform()
        self.assertGreaterEqual(self.tick,101)
        self.assertEqual(self.active,['1001'])

    def test_uncleared_links_timeout_without_a_connect_request(self):
        self.active=['1002']; self.command_hook=lambda *args:None
        with self.assertRaises(radio.RadioTimeout):
            self.perform()
        self.assertEqual(self.commands(),[('disconnect','1002')])
        self.assertLessEqual(self.tick,100+radio.TRANSITION_SECONDS)

    def test_status_failure_after_disconnect_aborts_new_connection(self):
        self.active=['1002']
        def query():
            if not self.active: raise radio.RadioError('status unavailable')
        self.query_hook=query
        with self.assertRaises(radio.RadioError): self.perform()
        self.assertEqual(self.commands(),[('disconnect','1002')])

    def test_external_new_link_during_clear_aborts_without_touching_new_link(self):
        self.active=['1002']
        self.command_hook=lambda action,node:self.active.__setitem__(slice(None),['9001'])
        with self.assertRaises(radio.RadioError): self.perform()
        self.assertEqual(self.commands(),[('disconnect','1002')])

    def test_new_link_at_preconnect_boundary_aborts(self):
        count=[0]
        def query():
            count[0]+=1
            if count[0]==2: self.active.append('9001')
        self.query_hook=query
        with self.assertRaises(radio.RadioError): self.perform()
        self.assertEqual(self.commands(),[])

    def test_connect_timeout_retains_unconfirmed_target_for_stop(self):
        self.path.write_text('{"node":"1002"}')
        self.command_hook=lambda *args:None
        with self.assertRaises(radio.RadioTimeout): self.perform()
        state=json.loads(self.path.read_text())
        self.assertEqual(state,{'node':'1002','pending_node':'1001','confirmed':False})
        self.active=['1001','9001'] # Late arrival after timed-out connect.
        self.command_hook=None
        self.perform('stop',None)
        self.assertEqual(self.active,['9001'])
        self.assertEqual(self.commands()[-1],('disconnect','1001'))

    def test_new_connect_error_is_not_recorded_as_confirmed(self):
        self.command_hook=lambda *args:(_ for _ in ()).throw(radio.RadioError('failed'))
        with self.assertRaises(radio.RadioError): self.perform()
        self.assertEqual(json.loads(self.path.read_text()),{'pending_node':'1001','confirmed':False})

    def test_connect_acknowledgment_alone_is_not_success(self):
        self.command_hook=lambda *args:None
        with self.assertRaises(radio.RadioTimeout): self.perform()
        self.assertIs(json.loads(self.path.read_text())['confirmed'],False)

    def test_unexpected_link_after_connect_is_not_success(self):
        self.command_hook=lambda *args:self.active.extend(['1001','9001'])
        with self.assertRaises(radio.RadioError): self.perform()
        self.assertEqual(json.loads(self.path.read_text()),{'pending_node':'1001','confirmed':False})

    def test_stop_disconnects_selected_active_node_and_leaves_others_alone(self):
        self.path.write_text('{"node":"1001"}')
        self.active=['1001','9001']
        self.perform('stop',None)
        self.assertEqual(self.commands(),[('disconnect','1001')])
        self.assertEqual(self.active,['9001'])
        self.assertEqual(json.loads(self.path.read_text()),{})

    def test_stop_stale_selection_has_no_disconnect_command(self):
        self.path.write_text('{"node":"1001"}')
        self.active=['9001']
        self.perform('stop',None)
        self.assertEqual(self.commands(),[])
        self.assertEqual(self.active,['9001'])
        self.assertEqual(json.loads(self.path.read_text()),{})

    def test_stop_without_selection_does_not_disconnect_anything(self):
        self.active=['9001']
        self.perform('stop',None)
        self.assertEqual(self.commands(),[])
        self.assertEqual(self.active,['9001'])

    def test_failed_stop_keeps_selection_for_retry(self):
        self.path.write_text('{"node":"1001"}')
        self.active=['1001'];self.command_hook=lambda *args:None
        with self.assertRaises(radio.RadioTimeout): self.perform('stop',None)
        self.assertEqual(json.loads(self.path.read_text()),{'node':'1001'})

    def test_corrupted_state_or_invalid_target_fails_before_radio_changes(self):
        for raw in ('[]','broken','{"pending_node":"1001;bad"}'):
            self.path.write_text(raw)
            with self.subTest(raw=raw),self.assertRaises(radio.RadioError): self.perform()
            self.assertEqual(self.commands(),[])
        self.path.unlink()
        for target in ('1000','１２３４','1001;bad',1001):
            with self.subTest(target=target),self.assertRaises(radio.RadioError): self.perform(node=target)
            self.assertEqual(self.commands(),[])


class SharedFlowTests(TransitionCase):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(scanner,'NODE','1000'))
        self.enterContext(patch.object(scanner,'STATE',self.path))
        self.enterContext(patch.object(scanner,'LOCK',self.tmp/'scanner.lock'))
        self.enterContext(patch.object(scanner,'CACHE',self.tmp/'activity.json'))
        self.enterContext(patch.object(scanner,'direct_links',side_effect=self.query))
        self.enterContext(patch.object(scanner,'run_asterisk',side_effect=self.command))
        favorites=[{'node':'1001','name':'First'},{'node':'1002','name':'Second'}]
        self.enterContext(patch.object(scanner.favorites_store,'read',return_value=favorites))
        now=int(__import__('time').time())
        scanner.CACHE.write_text(json.dumps({'favorites':[f|{'activity':'active','registered':True,
            'checked':now,'stats_time':now,'error':None} for f in favorites]}))

    def test_first_replaces_actual_links_despite_matching_saved_selection(self):
        self.path.write_text('{"node":"1001"}')
        self.active=['1002']
        scanner.scan('first',True)
        self.assertEqual(self.commands(),[('disconnect','1002'),('connect','1001')])

    def test_next_wraps_and_replaces_the_current_connection(self):
        self.path.write_text('{"node":"1002"}')
        self.active=['1002']
        scanner.scan('next',True)
        self.assertEqual(self.commands(),[('disconnect','1002'),('connect','1001')])

    def test_scanner_dry_run_never_queries_or_submits_commands(self):
        scanner.scan('first',False)
        scanner.scan('stop',False)
        self.assertEqual(self.events,[])
        self.assertFalse(self.path.exists())

    def test_manual_and_nets_connect_use_the_shared_policy(self):
        self.enterContext(patch.object(dashboard,'LOCAL_NODE','1000'))
        self.enterContext(patch.object(dashboard,'SCANNER_LOCK',self.tmp/'scanner.lock'))
        self.enterContext(patch.object(dashboard,'SCANNER_STATE',self.path))
        self.enterContext(patch.object(dashboard,'direct_links',side_effect=self.query))
        self.enterContext(patch.object(dashboard.Asterisk,'command',side_effect=self.command))
        self.enterContext(patch.object(dashboard,'favorite_numbers',return_value={'1001'}))
        self.enterContext(patch.object(dashboard,'scheduled_net_numbers',return_value={'2001'}))
        self.active=['9001']
        dashboard.run_link_action('connect-node','1001')
        dashboard.run_link_action('connect-net','2001')
        self.assertEqual(self.commands(),[('disconnect','9001'),('connect','1001'),('disconnect','1001'),('connect','2001')])


class StatusAndCommandTests(OfflineCase):
    def test_status_parser_accepts_complete_status_and_rejects_ambiguous_empty(self):
        self.assertEqual(radio.parse_links('RPT_ALINKS=0\n'),[])
        self.assertEqual(radio.parse_links('RPT_ALINKS=0\r\n'),[])
        self.assertEqual([r['node'] for r in radio.parse_links('Other=x\nRPT_ALINKS=2,1001TU,2002RU\n')],['1001','2002'])
        for raw in ('','RPT_ALINKS=1','RPT_ALINKS=0,1001TU',
                    'RPT_ALINKS=2,1001TU,1001TU','RPT_ALINKS=1,unknownTU',
                    'RPT_ALINKS=0\nRPT_ALINKS=0','RPT_ALINKS=1,1001;bad',
                    'RPT_ALINKS=0,','RPT_ALINKS=257','RPT_ALINKS=1,1001'):
            with self.subTest(raw=raw),self.assertRaises(radio.RadioError): radio.parse_links(raw)

    def test_asl3_exact_empty_field_with_lf_crlf_or_no_newline(self):
        for raw in ('RPT_ALINKS=', 'RPT_ALINKS=\n', 'RPT_ALINKS=\r\n',
                    'Other=x\n\tRPT_ALINKS=\r\nRPT_NUMALINKS=0\r\n'):
            with self.subTest(raw=raw):
                self.assertEqual(radio.parse_links(raw), [])

    def test_owner_reported_asl3_hardware_responses(self):
        # Owner-supplied spare-node observations, not live queries by this test.
        # The owner separately confirmed ESTABLISHED using rpt lstats.
        for raw, expected in (('RPT_ALINKS=', []),
                              ('RPT_ALINKS=1,638901TU', ['638901'])):
            for ending in ('', '\n', '\r\n'):
                with self.subTest(raw=raw, ending=repr(ending)):
                    self.assertEqual([r['node'] for r in radio.parse_links(raw+ending)], expected)

    def test_empty_field_does_not_hide_duplicate_or_malformed_status(self):
        for raw in ('RPT_ALINKS=\nRPT_ALINKS=', 'RPT_ALINKS=\nRPT_ALINKS=0',
                    'RPT_ALINKS=\nRPT_ALINKS=1,1001TU',
                    'RPT_ALINKS=\nRPT_ALINKS =1,1001TU',
                    'RPT_ALINKS=\nRPT_ALINKS:0', 'RPT_ALINKS=\nrpt_alinks=0',
                    'RPT_ALINKS=\nRPT_ALINKS', 'RPT_ALINKS =', 'RPT_ALINKS:',
                    'RPT_ALINKS= \t', 'RPT_ALINKS=,', 'RPT_ALINKS=\x00',
                    'Other=x\nRPT_NUMALINKS=0', 'RPT_ALINKS=\rRPT_ALINKS=0'):
            with self.subTest(raw=raw), self.assertRaises(radio.RadioError):
                radio.parse_links(raw)

    def test_populated_adjacent_link_mode_keyed_suffixes_keep_node_ids(self):
        # Synthetic numeric IDs, using the upstream emitter's mode/keyed shape;
        # these are not captures or claims about the spare's exact module build.
        for suffix in ('TU', 'TK', 'RU', 'RK', 'CU', 'CK'):
            with self.subTest(suffix=suffix):
                self.assertEqual([r['node'] for r in radio.parse_links('RPT_ALINKS=1,1001'+suffix+'\r\n')], ['1001'])
        self.assertEqual([r['node'] for r in radio.parse_links('RPT_ALINKS=3,1001TU,1002RK,1003CU\n')],
                         ['1001','1002','1003'])

    def test_nonempty_count_and_numeric_identifiers_remain_strict(self):
        for value in ('1,1001', '1,T1001', '1,1001T', '1,1001TUU', '1,１００１TU',
                      '1,1001;badTU', '1,ab1001TU', '1,12TU', '1,12345678TU',
                      '2,1001TU', '1,1001TU,1002TU', '2,1001TU,1001RU',
                      '-1,1001TU', '1.0,1001TU', '0,1001TU', '1,,1001TU'):
            with self.subTest(value=value), self.assertRaises(radio.RadioError):
                radio.parse_links('RPT_ALINKS='+value+'\n')

    def test_commands_are_fixed_argv_with_ascii_validation_and_bounded_timeouts(self):
        client=radio.Asterisk('/tmp/synthetic-asterisk','1000')
        with patch.object(radio.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='OK')) as run:
            client.command('disconnect','1001',timeout=2)
            self.assertEqual(run.call_args.args[0],['/tmp/synthetic-asterisk','-rx','rpt cmd 1000 ilink 1 1001'])
            self.assertEqual(run.call_args.kwargs['timeout'],2)
            self.assertNotIn('shell',run.call_args.kwargs)
            run.reset_mock()
            for action,node in (('connect','1000'),('shell','1001'),('connect','1001;bad'),('connect','１２３４')):
                with self.assertRaises(radio.RadioError): client.command(action,node)
            run.assert_not_called()

    def test_asterisk_failures_and_timeout_hide_raw_output(self):
        client=radio.Asterisk('/tmp/synthetic-asterisk','1000')
        for response in (SimpleNamespace(returncode=1,stdout='secret'),subprocess.TimeoutExpired(['secret'],3)):
            with patch.object(radio.subprocess,'run') as run:
                if isinstance(response,Exception): run.side_effect=response
                else: run.return_value=response
                with self.assertRaises(radio.RadioError) as error: client.links()
                self.assertNotIn('secret',str(error.exception))


class GuardTests(OfflineCase):
    def test_cooldown_failure_reservation_and_boundary_are_shared(self):
        lock,cooldown=self.tmp/'web-control.lock',self.tmp/'web-last-command.json'
        now=[1000]
        with patch.object(radio.time,'time',side_effect=lambda:now[0]):
            with self.assertRaises(RuntimeError):
                with radio.command_guard(lock,cooldown,15): raise RuntimeError('failed command')
            now[0]=1014
            with self.assertRaises(radio.Busy) as error:
                with radio.command_guard(lock,cooldown,15): self.fail('cooldown bypassed')
            self.assertEqual(error.exception.retry_after,1)
            now[0]=1015
            with radio.command_guard(lock,cooldown,15): pass

    def test_parallel_guards_reject_without_queuing(self):
        lock,cooldown=self.tmp/'web-control.lock',self.tmp/'last.json'
        started,release=threading.Event(),threading.Event()
        errors=[]
        def first():
            try:
                with radio.command_guard(lock,cooldown,15):
                    started.set()
                    if not release.wait(3): raise RuntimeError('test timeout')
            except BaseException as error: errors.append(error)
        worker=threading.Thread(target=first);worker.start()
        try:
            self.assertTrue(started.wait(3))
            with self.assertRaises(radio.Busy):
                with radio.command_guard(lock,cooldown,15): self.fail('parallel execution')
        finally:
            release.set();worker.join(4)
        self.assertEqual(errors,[])

    def test_cli_and_broker_use_the_same_guard_and_cli_contract(self):
        with patch.object(live_scanner,'require_node'), \
             patch.object(live_scanner,'scan',return_value='confirmed') as scan, \
             patch.object(live_scanner,'STATE_DIR',self.tmp), \
             patch.dict(configuration.CONFIG['paths'],{'runtime_dir':str(self.tmp)}), \
             patch('sys.argv',['scanner.py','first','--apply']):
            live_scanner.main()
            scan.assert_called_once_with('first',True)
        self.assertTrue((self.tmp/'web-last-command.json').exists())
        driver=SimpleNamespace(CONFIG=configuration.CONFIG,LOCAL_NODE='1000',
            LOCK=self.tmp/'web-control.lock',LAST_COMMAND=self.tmp/'web-last-command.json',
            COOLDOWN_SECONDS=15,scan_action=Mock())
        with patch.dict(configuration.CONFIG['web'],{'controls_enabled':True}):
            with self.assertRaises(__import__('security').Denied) as error:
                control_service.ControlService(driver).control({'action':'first'})
        self.assertEqual(error.exception.status,429)
        driver.scan_action.assert_not_called()

    def test_failed_transition_invalidates_link_cache(self):
        driver=SimpleNamespace(CONFIG=configuration.CONFIG,LOCAL_NODE='1000',
            LOCK=self.tmp/'web-control.lock',LAST_COMMAND=self.tmp/'last.json',
            COOLDOWN_SECONDS=15,scan_action=Mock(side_effect=radio.RadioError('failure')))
        service=control_service.ControlService(driver)
        service.cached_links=['1001'];service.links_checked=100
        with patch.dict(configuration.CONFIG['web'],{'controls_enabled':True}):
            with self.assertRaises(__import__('security').Denied): service.control({'action':'first'})
        self.assertIsNone(service.cached_links)
        self.assertIsNone(service.links_checked)


class UnchangedInterfaceTests(OfflineCase):
    def test_http_auth_and_read_handlers_are_unchanged(self):
        def protected(raw):
            raw=raw.replace('not self.context.transport_allowed','not self.context.secure and not self.context.loopback')
            raw=raw.replace("'transport_safe':self.context.transport_allowed,'unencrypted_lan':self.context.lan_http", "'transport_safe':self.context.secure or self.context.loopback")
            nodes=[]
            for node in ast.parse(raw).body:
                if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in (
                    'render_html','Handler','WebServer','activity_payload','load_schedule','scheduled_net_numbers','favorite_numbers'):
                    nodes.append(node)
            return hashlib.sha256(''.join(ast.dump(n,include_attributes=False) for n in nodes).encode()).hexdigest()
        expected=json.loads((ROOT/'tests/fixtures/radio-policy-protected.json').read_text())
        self.assertEqual(protected((ROOT/'dashboard.py').read_text()),expected['dashboard_http_sha256'])

class BrokerTransitionIntegrationTests(OfflineCase):
    """Actual broker driver + scanner + parser/argv, with only Asterisk replaced."""
    def setUp(self):
        super().setUp()
        self.now=1000
        self.enterContext(patch('time.time',side_effect=lambda:self.now))
        self.enterContext(patch.dict(configuration.CONFIG['web'],{'controls_enabled':True}))
        self.entries=[{'node':'1001','name':'First'},{'node':'1002','name':'Second'}]
        self.enterContext(patch.object(dashboard.favorites_store,'read',return_value=self.entries))
        self.enterContext(patch.object(dashboard,'scheduled_net_numbers',return_value={'2001'}))
        common={'SCANNER_STATE':self.tmp/'selection.json','SCANNER_LOCK':self.tmp/'scanner.lock',
                'LOCK':self.tmp/'web-control.lock','LAST_COMMAND':self.tmp/'web-last-command.json',
                'LOCAL_NODE':'1000','ASTERISK':'/tmp/synthetic-asterisk','COOLDOWN_SECONDS':15}
        for name,value in common.items(): self.enterContext(patch.object(dashboard,name,value))
        for name,value in {'STATE':common['SCANNER_STATE'],'LOCK':common['SCANNER_LOCK'],
                           'NODE':'1000','ASTERISK':common['ASTERISK'],'CACHE':self.tmp/'activity.json'}.items():
            self.enterContext(patch.object(live_scanner,name,value))
        live_scanner.CACHE.write_text(json.dumps({'favorites':[f|{'activity':'active','registered':True,
            'checked':1000,'stats_time':1000,'error':None} for f in self.entries]}))
        self.active=['9001'];self.commands=[];self.disconnect_hook=None
        def run(args,**kwargs):
            self.assertEqual(args[:2],['/tmp/synthetic-asterisk','-rx'])
            self.assertGreater(kwargs['timeout'],0)
            self.assertLessEqual(kwargs['timeout'],radio.CALL_SECONDS)
            command=args[2]
            if command=='rpt show variables 1000':
                value=str(len(self.active))+''.join(','+node+'TU' for node in self.active) if self.active else ''
                return SimpleNamespace(returncode=0,stdout='RPT_ALINKS='+value+'\n')
            parts=command.split()
            self.assertEqual(parts[:4],['rpt','cmd','1000','ilink'])
            mode,node=parts[4:]
            self.commands.append((mode,node))
            if mode=='1':
                if self.disconnect_hook: self.disconnect_hook()
                self.active.remove(node)
            elif mode=='3': self.active.append(node)
            else: self.fail('Unexpected control command')
            return SimpleNamespace(returncode=0,stdout='Command accepted')
        self.enterContext(patch('subprocess.run',side_effect=run))
        self.service=control_service.ControlService(dashboard)

    def action(self,action,node=None):
        payload={'action':action}
        if node:payload['node']=node
        response=self.service.control(payload)
        self.now+=15
        return response

    def test_broker_manual_first_next_stop_and_nets_confirm_reported_state(self):
        self.action('connect-node','1001')
        self.assertEqual(self.commands,[('1','9001'),('3','1001')])
        self.commands.clear()
        self.action('first') # Actual query sees only target: no command.
        self.assertEqual(self.commands,[])
        self.action('next')
        self.assertEqual(self.active,['1002'])
        self.assertEqual(self.commands,[('1','1001'),('3','1002')])
        self.active.append('9001')
        self.action('stop')
        self.assertEqual(self.active,['9001'])
        self.action('connect-net','2001')
        self.assertEqual(self.active,['2001'])
        self.action('disconnect-net','2001')
        self.assertEqual(self.active,[])
        self.assertEqual(json.loads(dashboard.SCANNER_STATE.read_text()),{})

    def test_real_driver_disconnect_failure_aborts_and_consumes_cooldown(self):
        self.disconnect_hook=lambda:(_ for _ in ()).throw(radio.RadioError('synthetic failure'))
        with self.assertRaises(__import__('security').Denied) as error:
            self.service.control({'action':'connect-node','node':'1001'})
        self.assertEqual(error.exception.status,503)
        self.assertEqual(self.commands,[('1','9001')])
        with self.assertRaises(__import__('security').Denied) as error:
            self.service.control({'action':'next'})
        self.assertEqual(error.exception.status,429)

    def test_simultaneous_broker_and_cli_requests_cannot_overlap(self):
        started,release=threading.Event(),threading.Event();errors=[]
        def block():
            started.set()
            if not release.wait(3):raise RuntimeError('test timeout')
        self.disconnect_hook=block
        def first():
            try:self.service.control({'action':'connect-node','node':'1001'})
            except BaseException as error:errors.append(error)
        worker=threading.Thread(target=first);worker.start()
        try:
            self.assertTrue(started.wait(3))
            with patch.object(live_scanner,'require_node'), \
                 patch.object(live_scanner,'STATE_DIR',self.tmp), \
                 patch.dict(configuration.CONFIG['paths'],{'runtime_dir':str(self.tmp)}), \
                 patch('sys.argv',['scanner.py','next','--apply']):
                with self.assertRaises(radio.Busy):live_scanner.main()
            with self.assertRaises(__import__('security').Denied) as error:
                self.service.control({'action':'stop'})
            self.assertEqual(error.exception.status,429)
        finally:
            release.set();worker.join(4)
        self.assertEqual(errors,[])
        self.assertEqual(self.commands,[('1','9001'),('3','1001')])

class EmptyStatusHttpTests(OfflineCase):
    """Actual HTTP handler -> broker router -> Asterisk parser, fully offline."""
    def setUp(self):
        super().setUp()
        import broker
        import security
        from test_security import HttpSecurityTests, PASSWORD
        self.enterContext(patch.object(dashboard,'LOCAL_NODE','1000'))
        self.enterContext(patch.object(dashboard,'ASTERISK','/tmp/synthetic-asterisk'))
        self.enterContext(patch.dict(configuration.CONFIG['web'],deepcopy(configuration.DEFAULTS['web'])))
        self.enterContext(patch.dict(configuration.CONFIG['auth'],deepcopy(configuration.DEFAULTS['auth'])))
        credentials=Mock(username='admin')
        credentials.verify.side_effect=lambda user,password:user=='admin' and password==PASSWORD
        self.server=SimpleNamespace(security=security.Security(configuration.CONFIG['auth'],credentials))
        self.request=lambda *args,**kwargs:HttpSecurityTests.request(self,*args,**kwargs)
        self.login=lambda:HttpSecurityTests.login(self)
        self.router=broker.Router(dashboard)
        self.enterContext(patch.object(dashboard,'rpc',side_effect=lambda op,payload=None:
            self.router.dispatch({'op':op,'payload':payload})))
        self.run=self.enterContext(patch('subprocess.run',return_value=SimpleNamespace(
            returncode=0,stdout='RPT_ALINKS=\n',stderr='')))

    def test_authenticated_links_api_returns_empty_list_for_asl3_empty_field(self):
        cookie,csrf=self.login()
        status,_,body=self.request('GET','/api/links',headers={'Cookie':cookie})
        self.assertEqual(status,200)
        self.assertEqual(body,{'links':[], 'link_states':[]})
        self.assertEqual(self.run.call_args.args[0][-1],'rpt show variables '+dashboard.LOCAL_NODE)

    def test_links_api_rejects_empty_plus_malformed_duplicate(self):
        cookie,csrf=self.login()
        self.run.return_value.stdout='RPT_ALINKS=\nRPT_ALINKS =1,1001TU\n'
        status,_,body=self.request('GET','/api/links',headers={'Cookie':cookie})
        self.assertEqual(status,503)
        self.assertNotIn('links',body)

    def test_authenticated_links_api_preserves_connecting_metadata(self):
        cookie,csrf=self.login()
        self.run.return_value.stdout='RPT_ALINKS=1,1001CU\n'
        status,_,body=self.request('GET','/api/links',headers={'Cookie':cookie})
        self.assertEqual(status,200)
        self.assertEqual(body['links'],['1001'])
        self.assertEqual(body['link_states'],[{'node':'1001','mode':'C','keyed':False,
            'state':'connecting','suffix':'CU'}])
