"""ASL3 socket policy/effective-access regressions; no host accounts or Asterisk I/O."""
import os
from pathlib import Path
import socket
import stat
import threading
from types import SimpleNamespace
from unittest.mock import patch

from test_baseline import OfflineCase
from test_packaging import PackagingCase, pkg


def result(code=0, stdout=''):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr='private diagnostic not to expose')


class SocketPolicyTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.host=pkg.Host(self.tmp)
        self.socket=SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=100,st_gid=100)
        self.directory=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=100,st_gid=0)
        self.info=self.enterContext(patch.object(self.host,'info',side_effect=lambda path:
            self.socket if Path(path).name=='asterisk.ctl' else self.directory))
        self.group=self.enterContext(patch.object(pkg.grp,'getgrgid',return_value=SimpleNamespace(gr_name='asterisk')))
        self.run=self.enterContext(patch.object(self.host,'run',side_effect=AssertionError('Inspection must not execute anything')))

    def test_reported_asl3_0755_socket_explains_manual_files_configuration(self):
        self.socket.st_mode=stat.S_IFSOCK|0o755
        with self.assertRaises(pkg.InstallError) as error:
            self.host.socket_info()
        message=str(error.exception)
        for text in ('Recognized ASL3','0755','kc1ray-radio','[files]','astctlpermissions = 0660',
                     'astctlowner = asterisk','astctlgroup = asterisk','approved','no Asterisk configuration or permissions were changed'):
            self.assertIn(text,message)
        self.run.assert_not_called()

    def test_restricted_socket_accepts_reported_0755_asterisk_root_directory(self):
        self.assertEqual(self.host.socket_info(),'asterisk')
        self.assertEqual(self.directory.st_gid,0)
        self.run.assert_not_called()

    def test_group_write_missing_fails_closed(self):
        for mode in (0o600,0o640,0o644,0o750,0o755):
            self.socket.st_mode=stat.S_IFSOCK|mode
            with self.subTest(mode=oct(mode)),self.assertRaises(pkg.InstallError):
                self.host.socket_info()

    def test_world_access_special_bits_and_no_owner_write_fail_closed(self):
        for mode in (0o666,0o667,0o664,0o777,0o4660,0o2660,0o1660,0o460):
            self.socket.st_mode=stat.S_IFSOCK|mode
            with self.subTest(mode=oct(mode)),self.assertRaises(pkg.InstallError):
                self.host.socket_info()

    def test_nonroot_restricted_custom_group_is_supported(self):
        self.group.return_value.gr_name='radio-cli'
        self.assertEqual(self.host.socket_info(),'radio-cli')

    def test_root_privileged_and_shared_application_groups_are_refused(self):
        for name in ('root','sudo','adm','disk','shadow','docker','lxd',*pkg.GROUPS):
            self.group.return_value.gr_name=name
            with self.subTest(group=name),self.assertRaises(pkg.InstallError):
                self.host.socket_info()
        self.group.return_value.gr_name='otherwise-safe'
        self.socket.st_gid=0
        with self.assertRaises(pkg.InstallError):
            self.host.socket_info()

    def test_regular_files_symlinks_missing_or_unknown_group_fail_closed(self):
        for kind in (stat.S_IFREG,stat.S_IFLNK,stat.S_IFDIR):
            self.socket.st_mode=kind|0o660
            with self.subTest(kind=kind),self.assertRaises(pkg.InstallError):
                self.host.socket_info()
        self.socket.st_mode=stat.S_IFSOCK|0o660
        self.group.side_effect=KeyError('missing')
        with self.assertRaisesRegex(pkg.InstallError,'account database'):
            self.host.socket_info()
        self.info.side_effect=FileNotFoundError()
        with self.assertRaisesRegex(pkg.InstallError,'missing or unreadable'):
            self.host.socket_info()

    def test_world_writable_symlinked_or_missing_directory_is_refused(self):
        for mode in (stat.S_IFDIR|0o777,stat.S_IFLNK|0o755,stat.S_IFREG|0o755):
            self.directory.st_mode=mode
            with self.subTest(mode=mode),self.assertRaises(pkg.InstallError):
                self.host.socket_info()


class EffectiveRadioAccessTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.host=pkg.Host()
        self.run=self.enterContext(patch.object(self.host,'run',side_effect=[result(),result(stdout='RPT_ALINKS=0\n')]))

    def test_actual_radio_identity_probe_then_only_read_only_node_query(self):
        self.host.check_radio_access('1000','/usr/sbin/asterisk')
        probe,query=self.run.call_args_list
        args=probe.args[0]
        self.assertEqual(args[:8],['runuser','-u','kc1ray-radio','--','/usr/bin/python3','-B','-I','-c'])
        self.assertIn('connection.settimeout(5)',args[8])
        self.assertIn('connection.connect("/run/asterisk/asterisk.ctl")',args[8])
        self.assertIn('os.geteuid()!=uid',args[8])
        self.assertNotIn('send',args[8])
        self.assertEqual(query.args[0],['runuser','-u','kc1ray-radio','--','/usr/sbin/asterisk','-rx','rpt show variables 1000'])
        self.assertFalse(probe.kwargs['check'])
        self.assertFalse(query.kwargs['check'])

    def test_socket_probe_failure_prevents_cli_and_redacts_output(self):
        self.run.side_effect=[result(1,'secret socket failure')]
        with self.assertRaisesRegex(pkg.RadioAccessError,'cannot connect') as error:
            self.host.check_radio_access('1000','/usr/sbin/asterisk')
        self.assertNotIn('secret',str(error.exception))
        self.assertEqual(self.run.call_count,1)

    def test_query_nonzero_or_missing_marker_prevents_acceptance(self):
        for response in (result(1,'RPT_ALINKS=0\n'),result(stdout='missing'),result(stdout='error: RPT_ALINKS=0')):
            self.run.side_effect=[result(),response]
            with self.subTest(response=response),self.assertRaises(pkg.RadioAccessError):
                self.host.check_radio_access('1000','/usr/sbin/asterisk')

    def test_probe_and_query_timeout_are_sanitized(self):
        for responses in ([pkg.InstallError('secret timeout')],[result(),pkg.InstallError('secret timeout')]):
            self.run.side_effect=responses
            with self.assertRaises(pkg.RadioAccessError) as error:
                self.host.check_radio_access('1000','/usr/sbin/asterisk')
            self.assertNotIn('secret',str(error.exception))

    def test_invalid_node_or_relative_binary_never_execute(self):
        for node,binary in (('1000;command','/usr/sbin/asterisk'),('１２３４','/usr/sbin/asterisk'),
                            (1000,'/usr/sbin/asterisk'),('1000','asterisk')):
            with self.subTest(node=node,binary=binary),self.assertRaises(pkg.RadioAccessError):
                self.host.check_radio_access(node,binary)
        self.run.assert_not_called()

    def test_probe_code_really_connects_to_temporary_socket_without_payload(self):
        # Execute the exact emitted probe against a temporary local listener under
        # this process UID. Multi-UID runuser itself is mocked, never host-run.
        path=self.tmp/'mock-asterisk.ctl'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            listener.bind(str(path)); listener.listen(); listener.settimeout(3)
            received=[]
            def accept():
                connection,_=listener.accept()
                with connection:
                    connection.settimeout(3)
                    received.append(connection.recv(1))
            worker=threading.Thread(target=accept)
            worker.start()
            def invoke(args,check=False):
                if args[4]=='/usr/bin/python3':
                    with patch.object(pkg.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=os.geteuid())):
                        exec(compile(args[-1],'<radio-socket-probe>','exec'),{})
                    return result()
                return result(stdout='RPT_ALINKS=0\n')
            self.run.side_effect=invoke
            try:
                with patch.object(pkg,'ASTERISK_SOCKET',path):
                    self.host.check_radio_access('1000','/usr/sbin/asterisk')
            finally:
                worker.join(4)
            self.assertFalse(worker.is_alive())
            self.assertEqual(received,[b''])


class RadioFailureLifecycleTests(PackagingCase):
    def test_effective_access_failure_restores_files_and_does_not_start_services(self):
        with patch.object(self.host,'check_radio_access',side_effect=pkg.RadioAccessError('kc1ray-radio cannot connect; sanitized')):
            with self.assertRaisesRegex(pkg.InstallError,'kc1ray-radio cannot connect'):
                self.install()
        self.assertFalse(self.host.path(pkg.APP/'current').exists())
        self.assertFalse(self.host.path(pkg.CONF).exists())
        self.assertFalse(any(cmd[:2]==['systemctl','start'] for cmd in self.host.commands))
        self.assertEqual(self.host.path('/etc/asterisk/rpt.conf').read_bytes(),self.asterisk_before[str(self.host.path('/etc/asterisk/rpt.conf'))])
        self.assertTrue(all(user['locked'] for user in self.host.users.values()))

    def test_0755_preflight_failure_makes_no_accounts_or_service_changes(self):
        with patch.object(self.host,'socket_info',side_effect=pkg.InstallError('Recognized ASL3 socket mode 0755')):
            with self.assertRaisesRegex(pkg.InstallError,'0755'):
                self.install()
        self.assertEqual(self.host.users,{})
        self.assertFalse(any(cmd[0] in ('groupadd','useradd') or cmd[:2]==['systemctl','stop'] for cmd in self.host.commands))
