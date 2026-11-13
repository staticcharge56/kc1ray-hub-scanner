"""Verified ASL3 metadata and bounded connection-state safety, fully offline."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest
from unittest.mock import Mock, patch

import dashboard
import radio_control as radio
from test_baseline import OfflineCase


class LinkMetadataTests(OfflineCase):
    def test_parse_preserves_mode_keyed_suffix_and_verified_state(self):
        self.assertEqual(radio.parse_links('RPT_ALINKS=3,1001CU,1002TK,1003RU\n'),[
            {'node':'1001','mode':'C','keyed':False,'state':'connecting','suffix':'CU'},
            {'node':'1002','mode':'T','keyed':True,'state':'established','suffix':'TK'},
            {'node':'1003','mode':'R','keyed':False,'state':'established','suffix':'RU'}])
        self.assertEqual(radio.parse_links('RPT_ALINKS='),[])

    def test_keyed_is_not_connection_state(self):
        for suffix,state,keyed in (('CU','connecting',False),('CK','connecting',True),
                                  ('TU','established',False),('TK','established',True),
                                  ('RU','established',False),('RK','established',True)):
            record=radio.parse_links('RPT_ALINKS=1,1001'+suffix)[0]
            self.assertEqual((record['state'],record['keyed']),(state,keyed))

    def test_no_guessed_native_disconnecting_or_failure_suffix(self):
        for suffix in ('DU','DK','FU','ZZ','TZ','LU','tu'):
            record=radio.parse_links('RPT_ALINKS=1,1001'+suffix)[0]
            self.assertEqual(record['state'],'unknown')
            self.assertEqual(record['suffix'],suffix)

    def test_legacy_bare_ids_cannot_be_promoted_to_established(self):
        self.assertEqual(radio.normalize_links(['1001'])[0]['state'],'unknown')
        controller=radio.LinkController(lambda **kw:['1001'],Mock())
        with self.assertRaises(radio.RadioError):controller.connect('1001',Mock())
        controller.command.assert_not_called()

    def test_forged_metadata_cannot_override_c_mode(self):
        record=radio.link_record('1001','CU')
        record['state']='established'
        with self.assertRaises(radio.RadioError):radio.normalize_links([record])
        with self.assertRaises(radio.RadioError):radio.normalize_links([{'node':'1001'}])
        record=radio.link_record('1001','TK');record['keyed']=1
        with self.assertRaises(radio.RadioError):radio.normalize_links([record])

    def test_malformed_missing_and_duplicate_data_do_not_mean_disconnected(self):
        for raw in ('RPT_ALINKS=1,1001C','RPT_ALINKS=1,1001C1','RPT_ALINKS=2,1001TU',
                    'RPT_ALINKS=1,１００１TU','RPT_ALINKS=1,1001C\x00',
                    'RPT_ALINKS=\nRPT_ALINKS=1,1001CU','missing'):
            with self.subTest(raw=raw),self.assertRaises(radio.RadioError):radio.parse_links(raw)


class ConnectionStateTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.tick=100
        self.enterContext(patch.object(radio.time,'monotonic',side_effect=lambda:self.tick))
        self.enterContext(patch.object(radio.time,'sleep',side_effect=self.sleep))
        self.path=self.tmp/'selection.json'
        self.frames=[];self.commands=[];self.observed=[];self.states=[];self.hook=None

    def sleep(self,seconds):self.tick+=seconds

    def query(self,timeout):
        self.assertGreater(timeout,0)
        self.assertLessEqual(timeout,radio.CALL_SECONDS)
        frame=self.frames.pop(0) if len(self.frames)>1 else self.frames[0]
        if isinstance(frame,BaseException):raise frame
        self.observed.append(frame)
        return radio.parse_links('RPT_ALINKS='+frame+'\n')

    def command(self,action,node,timeout):
        self.commands.append((action,node))
        self.assertLessEqual(timeout,radio.CALL_SECONDS)
        if self.hook:self.hook(action,node)

    def controller(self):
        def observe(state):
            saved=json.loads(self.path.read_text()) if self.path.exists() else {}
            self.states.append((state,saved.get('confirmed')))
        return radio.LinkController(self.query,self.command,observer=observe)

    def perform(self,controller,action='connect',node='1001'):
        return radio.perform(action,node,controller,self.path,'1000')

    def test_connect_waits_c_to_t_before_confirmed_true(self):
        self.frames=['','','1,1001CU','1,1001CK','1,1001TU']
        controller=self.controller()
        self.perform(controller)
        self.assertGreaterEqual(self.tick,101)
        self.assertEqual(self.commands,[('connect','1001')])
        self.assertTrue(json.loads(self.path.read_text())['confirmed'])
        self.assertTrue(all(flag is not True for state,flag in self.states if state=='connecting'))
        self.assertEqual(controller.state,'established')

    def test_receive_mode_and_unkeyed_transceive_are_established(self):
        for suffix in ('RU','RK','TU','TK'):
            self.frames=['1,1001'+suffix]
            controller=self.controller()
            self.perform(controller)
            self.assertEqual(controller.state,'established')
        self.assertEqual(self.commands,[])

    def test_only_c_waits_without_disconnect_or_duplicate_connect(self):
        self.frames=['1,1001CU','1,1001CU','1,1001TK']
        self.path.write_text('{"node":"1001","confirmed":true}')
        self.perform(self.controller())
        self.assertEqual(self.commands,[])
        self.assertTrue(json.loads(self.path.read_text())['confirmed'])
        self.assertTrue(all(flag is False for state,flag in self.states if state=='connecting'))

    def test_stuck_only_c_times_out_and_revokes_old_confirmation(self):
        self.frames=['1,1001CU']
        self.path.write_text('{"node":"1001","confirmed":true}')
        controller=self.controller()
        with self.assertRaises(radio.RadioTimeout):self.perform(controller)
        state=json.loads(self.path.read_text())
        self.assertIs(state['confirmed'],False)
        self.assertEqual(state['pending_node'],'1001')
        self.assertEqual(self.commands,[])
        self.assertEqual(controller.state,'unknown')
        self.assertEqual(self.tick,118)

    def test_new_connect_stuck_c_times_out_no_false_success_or_retry(self):
        self.frames=['','','1,1001CU']
        with self.assertRaises(radio.RadioTimeout):self.perform(self.controller())
        self.assertEqual(self.commands,[('connect','1001')])
        self.assertIs(json.loads(self.path.read_text())['confirmed'],False)
        self.assertEqual(self.tick,118)

    def test_connecting_disappearance_is_failed_connection_not_success(self):
        self.frames=['','','1,1001CU','']
        controller=self.controller()
        with self.assertRaisesRegex(radio.RadioError,'disappeared'):self.perform(controller)
        self.assertEqual(controller.state,'disconnected')
        self.assertIs(json.loads(self.path.read_text())['confirmed'],False)
        self.assertLess(self.tick,118)

    def test_only_connecting_disappearance_does_not_issue_connect(self):
        self.frames=['1,1001CU','']
        with self.assertRaises(radio.RadioError):self.perform(self.controller())
        self.assertEqual(self.commands,[])

    def test_failed_command_does_not_confirm_or_repeat(self):
        self.frames=['','']
        self.hook=lambda *args:(_ for _ in ()).throw(radio.RadioError('command failed'))
        with self.assertRaises(radio.RadioError):self.perform(self.controller())
        self.assertEqual(self.commands,[('connect','1001')])
        self.assertIs(json.loads(self.path.read_text())['confirmed'],False)

    def test_unknown_before_connect_fails_without_commands(self):
        self.frames=['1,1001DU']
        self.path.write_text('{"node":"1001","confirmed":true}')
        controller=self.controller()
        with self.assertRaises(radio.RadioError):self.perform(controller)
        self.assertIs(json.loads(self.path.read_text())['confirmed'],False)
        self.assertEqual(controller.state,'unknown')
        self.assertEqual(self.commands,[])

    def test_unknown_or_malformed_after_submit_cannot_confirm(self):
        for frame in ('1,1001ZZ','1,1001TZ','1,1001C','1,1001'):
            self.frames=['','',frame]
            with self.subTest(frame=frame),self.assertRaises(radio.RadioError):self.perform(self.controller())
            self.assertIs(json.loads(self.path.read_text())['confirmed'],False)

    def test_old_t_or_c_is_not_disconnected_until_absent(self):
        self.frames=['1,1002TU','1,1002CU','','','1,1001CU','1,1001TU']
        controller=self.controller()
        self.perform(controller)
        self.assertEqual(self.commands,[('disconnect','1002'),('connect','1001')])
        self.assertEqual([s for s,flag in self.states],['disconnecting','disconnected','connecting','connecting','established'])
        self.assertGreaterEqual(self.tick,101)

    def test_stuck_disconnecting_link_aborts_before_new_connect(self):
        self.frames=['1,1002TU','1,1002CU']
        with self.assertRaises(radio.RadioTimeout):self.perform(self.controller())
        self.assertEqual(self.commands,[('disconnect','1002')])
        self.assertFalse(self.path.exists())
        self.assertEqual(self.tick,118)

    def test_unknown_or_malformed_clearance_aborts_before_new_connect(self):
        for frame in ('1,1002DU','1,1002X',radio.RadioError('query failed')):
            self.frames=['1,1002TU',frame]
            self.commands.clear()
            with self.subTest(frame=frame),self.assertRaises(radio.RadioError):self.perform(self.controller())
            self.assertEqual(self.commands,[('disconnect','1002')])

    def test_disconnect_c_waits_for_absence_and_keeps_others(self):
        self.frames=['2,1001TU,1002RU','2,1001CU,1002RU','1,1002RU']
        controller=self.controller()
        self.perform(controller,'disconnect','1001')
        self.assertEqual(self.commands,[('disconnect','1001')])
        self.assertEqual(controller.state,'disconnected')

    def test_stop_pending_connecting_target_is_cancelled_only_after_clearance(self):
        self.path.write_text('{"pending_node":"1001","confirmed":false}')
        self.frames=['1,1001CU','1,1001CU','1,1001CU','']
        controller=self.controller()
        self.perform(controller,'stop',None)
        self.assertEqual(self.commands,[('disconnect','1001')])
        self.assertEqual(controller.state,'disconnected')
        self.assertEqual(json.loads(self.path.read_text()),{})

    def test_disconnected_requires_a_valid_empty_snapshot(self):
        for frame in ('1,1001D','missing'):
            self.frames=[frame]
            controller=self.controller()
            with self.assertRaises(radio.RadioError):self.perform(controller,'disconnect','1001')
            self.assertEqual(controller.state,'unknown')
        self.frames=['']
        controller=self.controller()
        self.perform(controller,'disconnect','1001')
        self.assertEqual(controller.state,'disconnected')
        self.assertEqual(self.commands,[])

    def test_disconnect_and_connect_share_one_deadline(self):
        self.frames=['1,1002TU','1,1002CU','','','1,1001CU']
        def hook(action,node):
            if action=='disconnect':self.tick+=12
        self.hook=hook
        with self.assertRaises(radio.RadioTimeout):self.perform(self.controller())
        self.assertEqual(self.tick,118)
        self.assertEqual(self.commands,[('disconnect','1002'),('connect','1001')])

    def test_late_established_response_cannot_extend_deadline(self):
        controller=self.controller()
        def query(timeout):
            self.tick=119
            return radio.parse_links('RPT_ALINKS=1,1001TU')
        controller.query=query
        with self.assertRaises(radio.RadioTimeout):self.perform(controller)
        self.assertEqual(self.commands,[])
        self.assertFalse(self.path.exists())

    def test_review_reproduction_actual_client_c_cannot_confirm(self):
        calls=[]
        def run(args, **kwargs):
            from types import SimpleNamespace
            calls.append(args[-1])
            count=sum(command=='rpt show variables 1000' for command in calls)
            text='' if count<=2 else '1,1001CU'
            return SimpleNamespace(returncode=0,stdout='RPT_ALINKS='+text+'\n')
        client=radio.Asterisk('/tmp/synthetic-asterisk','1000')
        with patch('subprocess.run',side_effect=run):
            controller=radio.LinkController(client.links,client.command)
            with self.assertRaises(radio.RadioTimeout):self.perform(controller)
        self.assertIs(json.loads(self.path.read_text())['confirmed'],False)
        self.assertEqual(calls.count('rpt cmd 1000 ilink 3 1001'),1)
        self.assertEqual(self.tick,118)

    def test_actual_client_polls_c_then_established_before_success(self):
        queries=[0]
        def run(args,**kwargs):
            from types import SimpleNamespace
            if args[-1]=='rpt show variables 1000':queries[0]+=1
            count=queries[0]
            text='' if count<=2 else '1,1001CU' if count<5 else '1,1001TU'
            return SimpleNamespace(returncode=0,stdout='RPT_ALINKS='+text+'\n')
        client=radio.Asterisk('/tmp/synthetic-asterisk','1000')
        with patch('subprocess.run',side_effect=run):
            self.perform(radio.LinkController(client.links,client.command))
        self.assertEqual(queries[0],5)
        self.assertTrue(json.loads(self.path.read_text())['confirmed'])
        self.assertGreaterEqual(self.tick,101)


class StructuredStatusTests(OfflineCase):
    def test_broker_returns_legacy_id_array_and_structured_states(self):
        from control_service import ControlService
        from types import SimpleNamespace
        driver=SimpleNamespace(direct_links=Mock(return_value=radio.parse_links(
            'RPT_ALINKS=2,1001CU,1002TU')))
        payload=ControlService(driver).links()
        self.assertEqual(payload['links'],['1001','1002'])
        self.assertEqual([r['state'] for r in payload['link_states']],['connecting','established'])
        self.assertIs(payload['link_states'][0]['keyed'],False)

    def test_structured_api_does_not_invent_disconnecting_suffix(self):
        from control_service import ControlService
        from types import SimpleNamespace
        payload=ControlService(SimpleNamespace(direct_links=lambda:radio.parse_links('RPT_ALINKS=1,1001DU'))).links()
        self.assertEqual(payload['links'],['1001'])
        self.assertEqual(payload['link_states'][0]['state'],'unknown')


class DashboardStateLabelsTests(unittest.TestCase):
    def test_structured_state_labels_never_describe_c_as_established(self):
        node=shutil.which('node')
        self.assertIsNotNone(node)
        functions='\n'.join(re.findall(r'function (?:observedLinkState|disconnectLabel)\([^\n]*\) \{.*?\n\}',dashboard.HTML,re.S))
        self.assertIn('function disconnectLabel',functions)
        script="let directLinkStates=new Map([['1001',{state:'connecting'}],['1002',{state:'established'}]]);\n"+functions+"\nconsole.log(JSON.stringify([disconnectLabel('1001'),disconnectLabel('1002'),disconnectLabel('1003'),observedLinkState('1003')]));"
        result=subprocess.run([node,'-'],input=script,text=True,capture_output=True,check=True,timeout=10)
        self.assertEqual(json.loads(result.stdout),['Cancel connection','Disconnect','Disconnect (unverified)','unknown'])
