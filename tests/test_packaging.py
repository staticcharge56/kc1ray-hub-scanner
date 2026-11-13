"""Packaging tests model a Debian target entirely under TemporaryDirectory.

Every account/systemd/Asterisk command is intercepted; no host accounts or services
are created, changed, queried or started by these tests.
"""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_baseline import OfflineCase, ROOT
spec=importlib.util.spec_from_file_location('scanner_installer',ROOT/'tools/installer.py')
pkg=importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)


class FakeHost(pkg.Host):
    def __init__(self,root):
        super().__init__(root)
        self.commands=[]
        self.groups={'asterisk':100}
        self.users={}
        self.owners={}
        self.services={name:{'active':False,'enabled':False} for name in pkg.UNITS}
        self.fail=None
        self.failed=False
        self.missing=set()
        self.busy=False
        self.arch='arm64'
        self.python='3.11.2'
        self.asterisk_active=True
        self.package='installed 2:22.6.0+asl3-3.2.0-1.deb12'
        self.socket_group='asterisk'
        self.validated=[]
        self.unit_checks=[]
        self.path('/etc/asterisk').mkdir(parents=True)
        self.path('/etc/os-release').write_text('ID=debian\nVERSION_ID="12"\n')
        self.path('/etc/asterisk/rpt.conf').write_text('[1000]\n[1001](node-template)\n[functions]\n')
        self.path('/etc/asterisk/extensions.conf').write_text('; existing custom DTMF mapping\n')
        self.path('/etc/asterisk/custom-hook.sh').write_text('# operator-owned single-link hook\n')
        self.path('/usr/sbin').mkdir(parents=True)
        self.path('/usr/sbin/asterisk').write_text('synthetic binary; never execute')
        self.path('/usr/sbin/asterisk').chmod(0o755)

    def run(self,args,check=True,env=None):
        args=list(map(str,args))
        self.commands.append(args)
        if self.fail and not self.failed and self.fail(args):
            self.failed=True
            raise pkg.InstallError('Simulated command failure')
        stdout=''
        code=0
        if args[:2]==['dpkg','--print-architecture']:
            stdout=self.arch
        elif args[0]=='/usr/bin/python3':
            stdout=self.python
        elif args[0]=='dpkg-query':
            stdout=self.package
        elif args[:2]==['/usr/sbin/asterisk','-V']:
            stdout='Asterisk 22.6.0+asl3'
        elif args[:3]==['systemctl','is-active','--quiet'] and args[-1]=='asterisk.service':
            code=0 if self.asterisk_active else 3
        elif args[0]=='groupadd':
            self.groups[args[-1]]=900+len(self.groups)
        elif args[0]=='useradd':
            name=args[-1]
            primary=args[args.index('--gid')+1]
            extra=set(args[args.index('--groups')+1].split(',')) if '--groups' in args else set()
            self.users[name]=dict(uid=800+len(self.users),gid=self.groups[primary],home='/nonexistent',
                                  shell='/usr/sbin/nologin',groups=[primary,*sorted(extra)],locked=True)
        elif args[0]=='systemctl':
            operation=args[1]
            if operation not in ('daemon-reload',):
                name=args[-1]
                state=self.services[name]
                if operation in ('enable','disable'):
                    state['enabled']=operation=='enable'
                elif operation in ('start','stop'):
                    state['active']=operation=='start'
        else:
            raise AssertionError('Unmodeled command: '+repr(args))
        if check and code:
            raise pkg.InstallError('Simulated required command failed')
        return SimpleNamespace(returncode=code,stdout=stdout,stderr='')

    def command_exists(self,name):
        return name not in self.missing

    def group(self,name):
        return self.groups.get(name)

    def user(self,name):
        return self.users.get(name)

    def trusted_executable(self,path):
        if not self.path(path).exists():
            raise pkg.InstallError('Missing executable')

    def socket_info(self):
        if self.socket_group is None:
            raise pkg.InstallError('Asterisk group access unavailable')
        return self.socket_group

    def replace(self,source,target):
        source,target=Path(source),Path(target)
        replacements={str(target/path.relative_to(source)):owner for key,owner in self.owners.items()
                      for path in [Path(key)] if path==source or source in path.parents}
        os.replace(source,target)
        self.owners.update(replacements)

    def chown(self,path,uid,gid):
        self.owners[str(Path(path))]=(uid,gid)

    def info(self,path):
        info=Path(path).lstat()
        uid,gid=self.owners.get(str(path),(info.st_uid,info.st_gid))
        return SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=info.st_mode)

    def lan_addresses(self):
        return [{'interface':'eth0','address':'192.168.50.10'}]

    def port_available(self,port,bind='127.0.0.1'):
        if self.busy:
            raise pkg.InstallError('Port in use')

    def service_state(self,name):
        return deepcopy(self.services[name])

    def validate_candidate(self,release):
        self.validated.append(release)
        if not (release/'tools/runtime_check.py').exists():
            raise AssertionError('Runtime checker missing')
        pkg.Credentials(self.path(pkg.CONF/'credentials.json'))
        pkg.validate_favorites(json.loads(self.path(pkg.STATE/'favorites.json').read_bytes()))

    def check_radio_access(self,node,binary):
        self.commands.append(['read-only-asterisk-check',node,binary])
        if self.fail and not self.failed and self.fail(self.commands[-1]):
            self.failed=True
            raise pkg.InstallError('Simulated Asterisk permission failure')

    def verify_units(self,directory):
        self.unit_checks.append(directory)
        for name in pkg.UNITS:
            text=(directory/name).read_text()
            if '@ASTERISK_GROUP@' in text:
                raise AssertionError('Unrendered unit')


class PackagingCase(OfflineCase):
    def setUp(self):
        super().setUp()
        self.host=FakeHost(self.tmp/'target')
        self.source=self.tmp/'source'
        release,inventory,_=pkg.source_inventory(ROOT)
        for name in inventory:
            destination=self.source/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,destination)
        self.manager=pkg.Manager(self.host,self.source)
        self.asterisk_before={str(path):path.read_bytes() for path in self.host.path('/etc/asterisk').glob('*') if path.is_file()}
        self.credentials=json.dumps(dict(version=1,username='operator',algorithm='scrypt',
            n=131072,r=8,p=1,salt='01'*16,digest='02'*32)).encode()
        self.favorites=[dict(node='1002',name='First café'),dict(node='1003',name='Second')]

    def install(self,**kwargs):
        return self.manager.apply('install',node='1000',port=8085,credentials=self.credentials,
                                  favorites=self.favorites,**kwargs)

    def change_release(self):
        path=self.source/'packaging/release.json'
        data=json.loads(path.read_text())
        data['version']='0.4.1-test'
        path.write_text(json.dumps(data))

    def bytes_at(self,path):
        return self.host.path(path).read_bytes()


class DiscoveryTests(PackagingCase):
    def test_arm64_amd64_and_armhf_detection(self):
        for arch in ('arm64','amd64','armhf'):
            self.host.arch=arch
            env=pkg.inspect(self.host)
            self.assertEqual(env['architecture'],arch)
            self.assertEqual(env['nodes'],['1000','1001'])
        self.assertEqual(self.host.users,{})

    def test_mint_debian_version_and_unsupported_architecture_rejected(self):
        for content in ('ID=linuxmint\nVERSION_ID=22','ID=debian\nVERSION_ID=13'):
            self.host.path('/etc/os-release').write_text(content)
            with self.assertRaises(pkg.InstallError):
                pkg.inspect(self.host)
        self.host.path('/etc/os-release').write_text('ID=debian\nVERSION_ID=12')
        self.host.arch='riscv64'
        with self.assertRaises(pkg.InstallError):
            pkg.inspect(self.host)

    def test_missing_dependencies_python_asl_and_control_permissions(self):
        self.host.missing={'runuser'}
        with self.assertRaisesRegex(pkg.InstallError,'Missing dependency'):
            self.manager.plan('install','1000',8085)
        self.host.missing=set()
        self.host.python='3.10.9'
        with self.assertRaises(pkg.InstallError):
            pkg.inspect(self.host)
        self.host.python='3.11.2'
        self.host.package='not-installed'
        with self.assertRaises(pkg.InstallError):
            pkg.inspect(self.host)
        self.host.package='installed asl3'
        self.host.socket_group=None
        with self.assertRaises(pkg.InstallError):
            pkg.inspect(self.host)
        self.assertEqual(self.host.users,{})

    def test_requires_running_asterisk_without_starting_it(self):
        self.host.asterisk_active=False
        with self.assertRaises(pkg.InstallError):
            pkg.inspect(self.host)
        self.assertFalse(any(command[:2]==['systemctl','start'] for command in self.host.commands))

    def test_includes_templates_loops_and_exec_are_discovered_without_execution(self):
        directory=self.host.path('/etc/asterisk')
        (directory/'rpt.conf').write_text('#include "nodes.conf"\n#exec never-run-this\n[1000]\n[9999](!)\n')
        (directory/'nodes.conf').write_text('[2000](base)\n#include rpt.conf\n')
        nodes,dynamic=pkg.discover_nodes(self.host)
        self.assertEqual(nodes,['1000','2000'])
        self.assertTrue(dynamic)
        self.assertEqual(self.host.commands,[])

    def test_include_escape_and_missing_required_file_fail_closed(self):
        path=self.host.path('/etc/asterisk/rpt.conf')
        for text in ('#include ../passwd\n','#include /etc/passwd\n','#include missing.conf\n'):
            path.write_text(text)
            with self.subTest(text=text),self.assertRaises((pkg.InstallError,FileNotFoundError)):
                pkg.discover_nodes(self.host)

    def test_plan_does_not_create_files_accounts_or_services(self):
        before=set(self.host.root.rglob('*'))
        plan=self.manager.plan('install','1000',8085)
        self.assertEqual(plan['node'],'1000')
        self.assertEqual(set(self.host.root.rglob('*')),before)
        self.assertEqual(self.host.users,{})
        self.assertFalse(any(cmd[0] in ('useradd','groupadd') for cmd in self.host.commands))
        self.assertFalse(any(cmd[:2] in (['systemctl','start'],['systemctl','enable']) for cmd in self.host.commands))


class InstallTests(PackagingCase):
    def test_secure_layout_and_least_privilege_accounts(self):
        result=self.install()
        self.assertEqual(result['status'],'installed')
        config=self.manager.configuration()
        web=self.host.users['kc1ray-web']
        radio=self.host.users['kc1ray-radio']
        monitor=self.host.users['kc1ray-monitor']
        self.assertNotIn('asterisk',web['groups'])
        self.assertNotIn('asterisk',monitor['groups'])
        self.assertIn('asterisk',radio['groups'])
        for user in self.host.users.values():
            self.assertEqual(user['shell'],'/usr/sbin/nologin')
            self.assertTrue(user['locked'])
        self.assertFalse(config['web']['anonymous_view'])
        self.assertFalse(config['web']['controls_enabled'])
        self.assertEqual(config['web']['bind'],'127.0.0.1')
        self.assertEqual(config['web']['trusted_proxies'],[])
        self.assertEqual(config['auth']['session_idle_seconds'],1800)
        self.assertEqual(config['auth']['session_max_seconds'],28800)
        self.assertEqual(config['paths']['monitor_state_dir'],str(pkg.MONITOR_STATE))
        self.assertEqual(self.host.path(pkg.CONF/'credentials.json').stat().st_mode & 0o777,0o640)
        self.assertEqual(self.host.path(pkg.STATE).stat().st_mode & 0o7777,0o2750)
        self.assertEqual(self.bytes_at(pkg.CONF/'credentials.json'),self.credentials)
        self.assertEqual(self.host.info(self.host.path(pkg.CONF/'credentials.json')).st_uid,0)
        self.assertEqual(self.host.info(self.host.path(pkg.CONF/'credentials.json')).st_gid,self.host.groups['kc1ray-web'])
        self.assertEqual(self.host.info(self.host.path(pkg.STATE/'favorites.json')).st_uid,radio['uid'])
        self.assertEqual(self.host.info(self.host.path(pkg.CACHE)).st_uid,monitor['uid'])
        self.assertEqual(json.loads(self.bytes_at(pkg.STATE/'favorites.json')),self.favorites)
        self.assertTrue(all(self.host.services[name]['active'] for name in pkg.MAIN_UNITS))
        self.assertFalse(self.host.services[pkg.PREFIX+'netwatch.timer']['enabled'])
        self.assertFalse(self.host.services[pkg.PREFIX+'allstarnets.timer']['enabled'])

    def test_selected_node_port_and_optional_sources(self):
        self.manager.apply('install',node='1001',port=9090,credentials=self.credentials,
                           netwatch=True,allstarnets=True)
        config=self.manager.configuration()
        self.assertEqual(config['allstar']['local_node'],'1001')
        self.assertEqual(config['web']['port'],9090)
        for key in ('netwatch','allstarnets'):
            self.assertTrue(config['schedules'][key]['enabled'])
            self.assertTrue(self.host.services[pkg.PREFIX+key+'.timer']['enabled'])

    def test_unknown_node_reserved_port_busy_port_and_missing_credentials(self):
        for node,port in (('9999',8085),('1000;reboot',8085),('1000',80),('1000',70000)):
            with self.subTest(node=node,port=port),self.assertRaises(pkg.InstallError):
                self.manager.plan('install',node,port)
        self.host.busy=True
        with self.assertRaises(pkg.InstallError):
            self.manager.plan('install','1000',8085)
        self.host.busy=False
        with self.assertRaises(pkg.InstallError):
            self.manager.apply('install',node='1000',port=8085)
        self.assertEqual(self.host.users,{})

    def test_account_collision_and_unmanaged_files_are_never_adopted(self):
        self.host.groups['kc1ray-read']=1234
        with self.assertRaises(pkg.InstallError):
            self.manager.plan('install','1000',8085)
        del self.host.groups['kc1ray-read']
        self.host.path(pkg.CONF).mkdir(parents=True)
        (self.host.path(pkg.CONF)/'config.toml').write_text('operator configuration')
        with self.assertRaises(pkg.InstallError):
            self.manager.plan('install','1000',8085)
        self.assertEqual(self.host.path(pkg.CONF/'config.toml').read_text(),'operator configuration')

    def test_partial_install_failure_rolls_back_and_can_be_retried(self):
        self.host.fail=lambda args:args[:2]==['systemctl','start'] and args[-1]==pkg.PREFIX+'web.service'
        with self.assertRaises(pkg.InstallError):
            self.install()
        self.assertFalse(self.host.path(pkg.APP).exists())
        self.assertFalse(self.host.path(pkg.CONF).exists())
        self.assertFalse(any(state['active'] for state in self.host.services.values()))
        self.assertTrue(self.host.path(pkg.REGISTRY/'accounts.json').exists())
        self.assertEqual(len(self.host.users),3) # retain allocated UIDs safely, never silently recycle them
        self.host.fail=None
        self.assertEqual(self.install()['status'],'installed')

    def test_radio_permission_failure_never_submits_commands_and_rolls_back(self):
        self.host.fail=lambda args:args[0]=='read-only-asterisk-check'
        with self.assertRaises(pkg.InstallError):
            self.install()
        self.assertFalse(self.host.path(pkg.CONF).exists())
        self.assertFalse(any('ilink' in arg for args in self.host.commands for arg in args))

    def test_release_contains_only_allowlisted_source_not_runtime_or_backups(self):
        result=self.install()
        release=self.host.path(pkg.APP/'releases'/result['release'])
        names=[str(path.relative_to(release)) for path in release.rglob('*') if path.is_file()]
        self.assertIn('tools/installer.py',names)
        self.assertNotIn('scanner-state.json',names)
        self.assertFalse(any('.before-' in name or '.git/' in name for name in names))

    def test_imported_config_and_history_preserve_operator_choices(self):
        template=deepcopy(pkg.DEFAULTS)
        template['web'].update(port=9090,anonymous_view=True,allowed_origins=['https://scanner.example'],trusted_proxies=['127.0.0.1/32'])
        template['auth']['session_idle_seconds']=2400
        template['schedules']['netwatch']['enabled']=True
        history=b'{"version":1,"local_node":"1000","records":{"1002":{"keyups":42}}}'
        self.manager.apply('install',node='1000',port=9090,credentials=self.credentials,
                           favorites=self.favorites,config_template=template,history=history)
        config=self.manager.configuration()
        self.assertEqual(config['web']['allowed_origins'],template['web']['allowed_origins'])
        self.assertTrue(config['web']['anonymous_view']) # explicit imported operator choice, not a new default
        self.assertEqual(config['auth']['session_idle_seconds'],2400)
        self.assertTrue(config['schedules']['netwatch']['enabled'])
        self.assertEqual(self.bytes_at(pkg.MONITOR_STATE/'monitor-history.json'),history)
        self.assertEqual(config['broker']['service_uid'],self.host.users['kc1ray-radio']['uid'])
        self.assertEqual(self.host.info(self.host.path(pkg.MONITOR_STATE/'monitor-history.json')).st_uid,self.host.users['kc1ray-monitor']['uid'])

    def test_low_disk_space_refuses_before_account_or_service_changes(self):
        with patch.object(self.host,'free_bytes',return_value=0):
            with self.assertRaises(pkg.InstallError):
                self.install()
        self.assertEqual(self.host.users,{})
        self.assertFalse(any(args[:2]==['systemctl','stop'] for args in self.host.commands))

    def test_systemd_startup_order_permissions_and_write_boundaries(self):
        self.install()
        text={name:self.host.path(pkg.UNIT_DIR/name).read_text() for name in pkg.UNITS}
        broker=text[pkg.PREFIX+'broker.service']
        web=text[pkg.PREFIX+'web.service']
        mon=text[pkg.PREFIX+'monitor.service']
        self.assertIn('Requires=asterisk.service',broker)
        self.assertIn('ExecStartPost=',broker)
        self.assertIn('RuntimeDirectoryMode=2750',broker)
        self.assertIn('RuntimeDirectoryPreserve=no',broker)
        self.assertIn('Requires=kc1ray-hub-scanner-broker.service',web)
        self.assertIn('ReadOnlyPaths=',web)
        self.assertNotIn('ReadWritePaths=',web)
        self.assertIn('User=kc1ray-monitor',mon)
        self.assertNotIn('asterisk',mon)
        for unit in text.values():
            if '[Service]' in unit:
                self.assertIn('NoNewPrivileges=yes',unit)
                self.assertIn('ProtectSystem=strict',unit)
                self.assertIn('UMask=0027',unit)
        starts=[args[-1] for args in self.host.commands if args[:2]==['systemctl','start']]
        self.assertEqual(starts[:3],list(pkg.MAIN_UNITS))


class UpgradeTests(PackagingCase):
    def setUp(self):
        super().setUp()
        self.initial=self.install()
        self.history=pkg.MONITOR_STATE/'monitor-history.json'
        self.host.path(self.history).write_text('{"version":1,"operator_history":"preserve exactly"}\n')
        self.host.chown(self.host.path(self.history),self.host.users['kc1ray-monitor']['uid'],self.host.groups['kc1ray-read'])
        path=self.host.path(pkg.CONF/'config.toml')
        path.write_text(path.read_text().replace('session_idle_seconds = 1800','session_idle_seconds = 2400')+'\n# operator comment\n')
        self.original={name:self.bytes_at(name) for name in (pkg.CONF/'config.toml',pkg.CONF/'credentials.json',
                       pkg.STATE/'favorites.json',self.history)}
        self.accounts=deepcopy(self.host.users)
        self.change_release()

    def test_upgrade_preserves_config_comments_credentials_favorites_history_and_accounts(self):
        result=self.manager.apply('upgrade')
        self.assertEqual(result['status'],'upgraded')
        self.assertNotEqual(result['release'],self.initial['release'])
        for name,content in self.original.items():
            self.assertEqual(self.bytes_at(name),content)
        self.assertEqual(self.host.users,self.accounts)
        self.assertTrue(self.host.path(pkg.REGISTRY/'backups'/result['backup']/'snapshot.json').exists())

    def test_upgrade_failure_restores_program_data_units_and_service_state(self):
        old_current=os.readlink(self.host.path(pkg.APP/'current'))
        states=deepcopy(self.host.services)
        self.host.fail=lambda args:args[:2]==['systemctl','start'] and args[-1]==pkg.PREFIX+'web.service'
        with self.assertRaises(pkg.InstallError):
            self.manager.apply('upgrade')
        self.assertEqual(os.readlink(self.host.path(pkg.APP/'current')),old_current)
        self.assertEqual(self.host.services,states)
        for path,content in self.original.items():
            self.assertEqual(self.bytes_at(path),content)
        self.assertFalse(self.host.path(pkg.REGISTRY/'transaction.json').exists())

    def test_backup_failure_before_switch_restores_service_state(self):
        states=deepcopy(self.host.services)
        with patch.object(self.manager,'snapshot',side_effect=OSError('disk full')):
            with self.assertRaises(pkg.InstallError):
                self.manager.apply('upgrade')
        self.assertEqual(self.host.services,states)
        for path,content in self.original.items():
            self.assertEqual(self.bytes_at(path),content)

    def test_explicit_rollback_restores_previous_release_and_snapshot(self):
        result=self.manager.apply('upgrade')
        self.host.path(pkg.STATE/'favorites.json').write_text('[]')
        rollback=self.manager.rollback(result['backup'])
        self.assertEqual(rollback['status'],'rolled back')
        self.assertEqual(os.readlink(self.host.path(pkg.APP/'current')),'releases/'+self.initial['release'])
        for path,content in self.original.items():
            self.assertEqual(self.bytes_at(path),content)

    def test_compatible_schema_metadata_migrates_without_rewriting_config(self):
        metadata=self.manager.manifest()
        metadata['schemas']['config']=0
        pkg.json_write(self.host,pkg.REGISTRY/'manifest.json',metadata)
        result=self.manager.apply('upgrade')
        self.assertTrue(result['migrations'])
        self.assertEqual(self.bytes_at(pkg.CONF/'config.toml'),self.original[pkg.CONF/'config.toml'])
        self.assertEqual(self.manager.manifest()['schemas']['config'],1)

    def test_metadata_migration_runs_even_without_new_program_content(self):
        (self.source/'packaging/release.json').write_bytes((ROOT/'packaging/release.json').read_bytes())
        metadata=self.manager.manifest()
        metadata['schemas']['config']=0
        pkg.json_write(self.host,pkg.REGISTRY/'manifest.json',metadata)
        result=self.manager.apply('upgrade')
        self.assertEqual(result['release'],self.initial['release'])
        self.assertTrue(result['migrations'])
        self.assertEqual(self.manager.manifest()['schemas']['config'],1)

    def test_unsupported_future_schema_or_invalid_config_stops_before_service_changes(self):
        metadata=self.manager.manifest()
        metadata['schemas']['history']=2
        pkg.json_write(self.host,pkg.REGISTRY/'manifest.json',metadata)
        commands=len(self.host.commands)
        with self.assertRaises(pkg.InstallError):
            self.manager.apply('upgrade')
        self.assertFalse(any(args[:2]==['systemctl','stop'] for args in self.host.commands[commands:]))
        metadata['schemas']['history']=1
        pkg.json_write(self.host,pkg.REGISTRY/'manifest.json',metadata)
        self.host.path(pkg.CONF/'config.toml').write_text('[web]\nport="bad"')
        with self.assertRaises(ValueError):
            self.manager.apply('upgrade')

    def test_insecure_configuration_and_unknown_history_version_stop_in_preflight(self):
        path=self.host.path(pkg.CONF/'config.toml')
        path.chmod(0o666)
        with self.assertRaises(pkg.InstallError):
            self.manager.plan('upgrade')
        path.chmod(0o640)
        self.host.path(self.history).write_text('{"version":2}')
        with self.assertRaises(pkg.InstallError):
            self.manager.plan('upgrade')

    def test_backup_integrity_and_path_validation(self):
        result=self.manager.apply('upgrade')
        base=pkg.REGISTRY/'backups'/result['backup']
        self.host.path(base/'state/favorites.json').write_text('corrupted')
        with self.assertRaises(pkg.InstallError):
            self.manager.rollback(result['backup'])
        with self.assertRaises(pkg.InstallError):
            self.manager.rollback('../../etc/asterisk')

    def test_disabled_service_state_is_preserved(self):
        web=pkg.PREFIX+'web.service'
        self.host.services[web]={'active':False,'enabled':False}
        self.manager.apply('upgrade')
        self.assertEqual(self.host.services[web],{'active':False,'enabled':False})

    def test_operator_unit_or_program_modifications_are_not_silently_overwritten(self):
        path=self.host.path(pkg.UNIT_DIR/(pkg.PREFIX+'web.service'))
        path.write_text(path.read_text()+'# manual unit customization\n')
        with self.assertRaises(pkg.InstallError):
            self.manager.plan('upgrade')

    def test_interrupted_transaction_refuses_new_operations_but_supports_rollback(self):
        result=self.manager.apply('upgrade')
        pkg.json_write(self.host,pkg.REGISTRY/'transaction.json',{'backup':result['backup'],'phase':'simulated power loss'})
        with self.assertRaises(pkg.InstallError):
            self.manager.apply('upgrade')
        self.manager.rollback(result['backup'])
        self.assertFalse(self.host.path(pkg.REGISTRY/'transaction.json').exists())


class UninstallTests(PackagingCase):
    def setUp(self):
        super().setUp()
        self.install()

    def test_uninstall_keeps_operator_data_credentials_accounts_and_backups(self):
        config=self.bytes_at(pkg.CONF/'config.toml')
        result=self.manager.uninstall()
        self.assertEqual(result['status'],'uninstalled')
        self.assertTrue(result['data_retained'])
        self.assertFalse(self.host.path(pkg.APP).exists())
        self.assertFalse(self.host.path(pkg.LAUNCHER).exists())
        self.assertEqual(self.bytes_at(pkg.CONF/'config.toml'),config)
        self.assertEqual(self.bytes_at(pkg.CONF/'credentials.json'),self.credentials)
        self.assertEqual(len(self.host.users),3)
        self.assertFalse(any(state['active'] for state in self.host.services.values()))
        self.assertTrue(self.host.path(pkg.REGISTRY/'backups'/result['backup']).exists())

    def test_reinstall_reuses_retained_configuration_accounts_and_favorites(self):
        accounts=deepcopy(self.host.users)
        self.manager.uninstall()
        self.install()
        self.assertEqual(self.host.users,accounts)
        self.assertEqual(json.loads(self.bytes_at(pkg.STATE/'favorites.json')),self.favorites)
        self.assertEqual(self.bytes_at(pkg.CONF/'credentials.json'),self.credentials)

    def test_purge_requires_exact_explicit_confirmation(self):
        for confirmation in (None,'yes','PURGE'):
            with self.subTest(confirmation=confirmation),self.assertRaises(pkg.InstallError):
                self.manager.uninstall(purge=True,confirmation=confirmation)
        self.assertTrue(self.host.path(pkg.APP).exists())
        result=self.manager.uninstall(purge=True,confirmation=pkg.PURGE_PHRASE)
        self.assertEqual(result['status'],'purged')
        for path in (pkg.CONF,pkg.STATE,pkg.MONITOR_STATE,pkg.CACHE,pkg.REGISTRY/'backups'):
            self.assertFalse(self.host.path(path).exists())
        self.assertTrue(self.host.path(pkg.REGISTRY/'accounts.json').exists())

    def test_failed_uninstall_rolls_back(self):
        self.host.fail=lambda args:args[:2]==['systemctl','disable']
        with self.assertRaises(pkg.InstallError):
            self.manager.uninstall()
        self.assertTrue(self.host.path(pkg.APP/'current').is_symlink())
        self.assertTrue(self.manager.manifest()['installed'])
        self.assertTrue(all(self.host.services[name]['active'] for name in pkg.MAIN_UNITS))

    def test_snapshot_failure_restarts_previously_running_services(self):
        states=deepcopy(self.host.services)
        with patch.object(self.manager,'snapshot',side_effect=OSError('disk full')):
            with self.assertRaises(pkg.InstallError):
                self.manager.uninstall()
        self.assertEqual(self.host.services,states)
        self.assertTrue(self.manager.manifest()['installed'])

    def test_interrupted_purge_is_resumable_only_with_confirmation(self):
        remove=self.manager.remove
        failed=[False]
        def interrupt(path):
            if path==pkg.STATE and not failed[0]:
                failed[0]=True
                raise OSError('simulated partial purge')
            return remove(path)
        with patch.object(self.manager,'remove',side_effect=interrupt):
            with self.assertRaises(pkg.InstallError):
                self.manager.uninstall(purge=True,confirmation=pkg.PURGE_PHRASE)
        self.assertEqual(pkg.read_json(self.host,pkg.REGISTRY/'transaction.json')['action'],'purge')
        with self.assertRaises(pkg.InstallError):
            self.manager.uninstall(purge=True)
        self.assertEqual(self.manager.uninstall(purge=True,confirmation=pkg.PURGE_PHRASE)['status'],'purged')
        self.assertFalse(self.host.path(pkg.STATE).exists())
        self.assertFalse(self.host.path(pkg.REGISTRY/'transaction.json').exists())

    def test_asterisk_files_firewall_and_tailscale_are_never_modified(self):
        asterisk=self.host.path('/etc/asterisk/rpt.conf')
        before=asterisk.read_bytes()
        self.manager.uninstall()
        self.assertEqual(asterisk.read_bytes(),before)
        self.assertEqual({str(path):path.read_bytes() for path in self.host.path('/etc/asterisk').glob('*') if path.is_file()},self.asterisk_before)
        self.assertFalse(any(args[0] in ('tailscale','iptables','nft','ufw','usermod','userdel') for args in self.host.commands))
        self.assertFalse(any('asterisk.service' in args and args[1] in ('stop','restart','enable','disable') for args in self.host.commands if args[0]=='systemctl'))


class PackagingBoundaryTests(OfflineCase):
    def test_staged_real_backend_cannot_execute_system_commands(self):
        with self.assertRaises(pkg.InstallError):
            pkg.Host(self.tmp).run(['useradd','do-not-create'])

    def test_runtime_compatibility_changes_keep_other_modules_identical(self):
        expected=json.loads((ROOT/'tests/fixtures/phase-4-protected.json').read_text())
        for name,digest in expected.items():
            if name in ('dashboard.py','scanner.py','control_service.py'):
                continue # Explicitly authorized application-owned link transitions.
            with self.subTest(name=name):
                raw=(ROOT/name).read_bytes()
                if name=='web_auth.py':
                    raw=raw.replace(b"status.textContent=session.unencrypted_lan?'Warning: HTTP on this trusted LAN does not encrypt your credentials or session.':(session.transport_safe?'':'Use HTTPS or explicitly configured trusted LAN access to sign in.');", b"status.textContent=session.transport_safe?'':'Use HTTPS or local loopback access to sign in.';")
                if name=='security.py':
                    raw=raw.replace(b'    lan_http: bool = False\n\n    @property\n    def transport_allowed(self):\n        return self.secure or self.loopback or self.lan_http\n',b'')
                    start=raw.index(b'    lan_http=(web.get(')
                    end=raw.index(b'\n',raw.index(b'    return RequestContext',start))
                    raw=raw[:start]+b"    return RequestContext(origin,proto=='https',str(client),loopback)"+raw[end:]
                    raw=raw.replace(b'if not context.transport_allowed:',b'if not context.secure and not context.loopback:')
                self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)

    def test_only_monitor_history_path_changed_from_phase_3(self):
        current=(ROOT/'monitor.py').read_bytes()
        normalized=current.replace(b"HISTORY = Path(CONFIG['paths']['monitor_state_dir'])",b"HISTORY = Path(CONFIG['paths']['state_dir'])")
        previous=json.loads((ROOT/'tests/fixtures/phase-3-protected.json').read_text())['monitor.py']
        self.assertEqual(hashlib.sha256(normalized).hexdigest(),previous)


class RuntimeReadinessTests(OfflineCase):
    def load(self):
        spec=importlib.util.spec_from_file_location('runtime_checker',ROOT/'tools/runtime_check.py')
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_socket_readiness_requires_exact_identity_group_and_mode(self):
        import stat
        module=self.load()
        fake=SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=801,st_gid=902)
        with patch.dict(module.CONFIG['broker'],{'service_uid':801,'socket_gid':902}), \
             patch.object(Path,'stat',return_value=fake):
            module.wait_socket()
        bad=SimpleNamespace(st_mode=stat.S_IFSOCK|0o666,st_uid=801,st_gid=902)
        with patch.object(Path,'stat',return_value=bad), \
             patch.object(module.time,'monotonic',side_effect=[0,0,11]), \
             patch.object(module.time,'sleep'):
            with self.assertRaises(ValueError):
                module.wait_socket()

    def test_web_readiness_uses_read_only_login_probe_and_accepts_proxy_denial(self):
        from unittest.mock import Mock
        module=self.load()
        response=Mock(status=403)
        response.getheader.return_value='HubScanner'
        connection=Mock()
        connection.getresponse.return_value=response
        with patch.object(module.http.client,'HTTPConnection',return_value=connection):
            module.wait_web()
        self.assertEqual(connection.request.call_args.args[:2],('GET','/login'))
        connection.close.assert_called_once()


class CliValidationTests(OfflineCase):
    def test_rejects_action_specific_options_before_any_host_command(self):
        import io
        for arguments in (['upgrade','--node','1000'],['upgrade','--admin-name','new'],
                          ['install','--purge'],['uninstall','--backup','example']):
            with self.subTest(arguments=arguments),patch.object(pkg.sys,'argv',['installer',*arguments]), \
                 patch.object(pkg.sys,'stderr',io.StringIO()),patch.object(pkg.Host,'run') as run:
                with self.assertRaises(SystemExit) as error:
                    pkg.main()
                self.assertEqual(error.exception.code,2)
                run.assert_not_called()

    def test_bad_imported_toml_has_controlled_error_without_host_changes(self):
        import io
        path=self.tmp/'bad.toml'
        path.write_text('invalid [')
        with patch.object(pkg.sys,'argv',['installer','install','--config-import',str(path)]), \
             patch.object(pkg.sys,'stderr',io.StringIO()) as stderr,patch.object(pkg.Host,'run') as run:
            with self.assertRaises(SystemExit) as error:
                pkg.main()
            self.assertEqual(error.exception.code,1)
            self.assertIn('Packaging stopped:',stderr.getvalue())
            run.assert_not_called()


class LanInstallationTests(PackagingCase):
    def test_plan_offers_lan_without_selecting_it(self):
        plan=self.manager.plan('install',node='1000',port=8085)
        self.assertEqual(plan['bind'],'127.0.0.1')
        self.assertEqual(plan['lan_candidates'],self.host.lan_addresses())
        self.assertFalse(self.host.users)

    def test_selected_lan_has_exact_origin_and_retains_security(self):
        self.install(bind='192.168.50.10')
        config=self.manager.configuration()
        self.assertEqual(config['web']['bind'],'192.168.50.10')
        self.assertEqual(config['web']['allowed_origins'],['http://192.168.50.10:8085'])
        self.assertTrue(config['web']['allow_lan_http'])
        self.assertFalse(config['web']['anonymous_view'])
        self.assertFalse(config['web']['controls_enabled'])
        self.assertEqual(config['web']['trusted_proxies'],[])
        self.assertEqual(self.asterisk_before,{str(path):path.read_bytes() for path in self.host.path('/etc/asterisk').glob('*') if path.is_file()})
        before=self.bytes_at(pkg.CONF/'config.toml')
        self.change_release()
        self.manager.apply('upgrade')
        self.assertEqual(self.bytes_at(pkg.CONF/'config.toml'),before)

    def test_unoffered_wildcard_public_vpn_and_bad_binds_fail_before_changes(self):
        for address in ('0.0.0.0','44.1.2.3','100.64.1.2','8.8.8.8','192.168.50.99','localhost','::'):
            with self.subTest(address=address),self.assertRaises(pkg.InstallError):
                self.install(bind=address)
        self.assertFalse(self.host.users)

    def test_discovery_filters_virtual_down_nonprivate_and_ipv6(self):
        self.host.path('/sys/class/net/eth0/device').mkdir(parents=True)
        self.host.path('/sys/class/net/eth1/device').mkdir(parents=True)
        def interface(name,addresses,flags=['UP']):
            return dict(ifname=name,flags=flags,addr_info=[dict(family='inet',scope='global',local=value) for value in addresses])
        data=[interface('eth0',['192.168.50.10','10.1.2.3','44.1.2.3','100.64.1.2','169.254.1.2','8.8.8.8']),interface('docker0',['172.17.0.1']),interface('eth1',['192.168.1.2'],[])]
        data[0]['addr_info'].append(dict(family='inet6',scope='global',local='fd00::1'))
        self.assertEqual(pkg.lan_candidates(data,self.host),[dict(interface='eth0',address='10.1.2.3'),dict(interface='eth0',address='192.168.50.10')])

    def test_missing_or_invalid_discovery_falls_back(self):
        with patch.object(pkg.shutil,'which',return_value=None):
            self.assertEqual(pkg.Host.lan_addresses(self.host),[])
        with patch.object(pkg.shutil,'which',return_value='/usr/sbin/ip'),patch.object(self.host,'run',return_value=SimpleNamespace(returncode=0,stdout='bad JSON')):
            self.assertEqual(pkg.Host.lan_addresses(self.host),[])
        with patch.object(pkg.shutil,'which',return_value='/usr/sbin/ip'),patch.object(self.host,'run',side_effect=pkg.InstallError('Unavailable or timed out')):
            self.assertEqual(pkg.Host.lan_addresses(self.host),[])


    def test_preflight_checks_selected_address_instead_of_loopback(self):
        with patch.object(self.host,'port_available') as probe:
            self.manager.plan('install',node='1000',port=8085,bind='192.168.50.10')
        probe.assert_called_once_with(8085,'192.168.50.10')

    def test_imported_network_policy_is_planned_and_preserved(self):
        template=deepcopy(pkg.DEFAULTS)
        template['web'].update(bind='192.168.50.10',allow_lan_http=True,allowed_origins=['http://192.168.50.10:8085'])
        plan=self.manager.plan('install',node='1000',port=8085,config_template=template)
        self.assertEqual(plan['bind'],'192.168.50.10')
        self.install(config_template=template)
        self.assertEqual(self.manager.configuration()['web'],template['web'])

    def test_retained_reinstall_does_not_replace_network_policy(self):
        self.install(bind='192.168.50.10')
        before=self.bytes_at(pkg.CONF/'config.toml')
        self.manager.uninstall()
        with self.assertRaises(pkg.InstallError):
            self.install(bind='127.0.0.1')
        self.install()
        self.assertEqual(self.bytes_at(pkg.CONF/'config.toml'),before)
