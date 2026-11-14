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

    def apache_sites(self):
        return []

    def firewall_running(self):
        return False

    def lan_addresses(self):
        return [{'interface':'eth0','address':'192.168.50.10','subnet':'192.168.50.0/24'}]

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
                if name in ('security.py','web_auth.py'):
                    reviewed=json.loads((ROOT/'tests/fixtures/radio-policy-protected.json').read_text())['prefix_runtime_sha256']
                    self.assertEqual(hashlib.sha256(raw).hexdigest(),reviewed[name])
                    continue # Explicitly reviewed prefix/cookie/transport increment; old hashes retained.
                if name=='manage_admin.py':
                    raw=raw.replace(b'8+ characters',b'15+ characters')
                if name=='web_auth.py':
                    raw=raw.replace(b'required minlength="8"',b'required')
                    raw=raw.replace(b"status.textContent=session.unencrypted_lan?'Warning: HTTP on this trusted LAN does not encrypt your credentials or session.':(session.transport_safe?'':'Use HTTPS or explicitly configured trusted LAN access to sign in.');", b"status.textContent=session.transport_safe?'':'Use HTTPS or local loopback access to sign in.';")
                if name=='security.py':
                    raw=raw.replace(b'    lan_http: bool = False\n\n    @property\n    def transport_allowed(self):\n        return self.secure or self.loopback or self.lan_http\n',b'')
                    start=raw.index(b'    lan_http=(web.get(')
                    end=raw.index(b'\n',raw.index(b'    return RequestContext',start))
                    raw=raw[:start]+b"    return RequestContext(origin,proto=='https',str(client),loopback)"+raw[end:]
                    raw=raw.replace(b"or len(password)<8 or not 1 <=",b"or not 1 <=")
                    raw=raw.replace(b'len(password)<8',b'len(password)<15').replace(b'at least 8 characters',b'at least 15 characters')
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
            return dict(ifname=name,flags=flags,addr_info=[dict(family='inet',scope='global',local=value,prefixlen=24) for value in addresses])
        data=[interface('eth0',['192.168.50.10','10.1.2.3','44.1.2.3','100.64.1.2','169.254.1.2','8.8.8.8']),interface('docker0',['172.17.0.1']),interface('eth1',['192.168.1.2'],[])]
        data[0]['addr_info'].append(dict(family='inet6',scope='global',local='fd00::1'))
        self.assertEqual(pkg.lan_candidates(data,self.host),[dict(interface='eth0',address='10.1.2.3',subnet='10.1.2.0/24'),dict(interface='eth0',address='192.168.50.10',subnet='192.168.50.0/24')])

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


class FirewallLifecycleTests(PackagingCase):
    def setUp(self):
        super().setUp()
        self.rules={False:set(),True:set()}
        self.host.firewall_running=lambda:True
        original=self.host.run
        def run(args,check=True,env=None):
            if args[0]!='firewall-cmd':
                return original(args,check=check,env=env)
            self.host.commands.append(args)
            if '--get-zone-of-interface=eth0' in args:
                return SimpleNamespace(returncode=0,stdout='allstarlink',stderr='')
            permanent='--permanent' in args
            zone=next(value for value in args if value.startswith('--zone='))
            action=next(value for value in args if '-rich-rule=' in value)
            operation,rule=action.split('=',1)
            key=(zone,rule)
            if operation=='--query-rich-rule':
                return SimpleNamespace(returncode=0 if key in self.rules[permanent] else 1,stdout='',stderr='')
            if getattr(self,'firewall_failure',False):
                self.firewall_failure=False
                raise pkg.InstallError('Simulated firewalld failure')
            if operation=='--add-rich-rule':self.rules[permanent].add(key)
            elif operation=='--remove-rich-rule':self.rules[permanent].discard(key)
            else:raise AssertionError(args)
            return SimpleNamespace(returncode=0,stdout='',stderr='')
        self.host.run=run

    def test_lan_plan_install_idempotence_and_uninstall(self):
        plan=self.manager.plan('install',node='1000',port=8085,bind='192.168.50.10')
        self.assertEqual(plan['firewall']['desired'][0]['subnet'],'192.168.50.0/24')
        self.assertEqual(plan['firewall']['desired'][0]['zone'],'allstarlink')
        self.assertFalse(self.rules[True])
        self.install(bind='192.168.50.10')
        self.assertEqual(len(self.rules[True]),1)
        self.manager.apply('upgrade')
        self.assertEqual(len(self.rules[True]),1)
        self.manager.uninstall()
        self.assertFalse(self.rules[True]);self.assertFalse(self.rules[False])

    def test_preexisting_identical_rules_are_not_owned_or_removed(self):
        record=self.manager.firewall_plan('192.168.50.10',8085)['desired'][0]
        key=('--zone=allstarlink',pkg.firewall_rule(record))
        self.rules[False].add(key);self.rules[True].add(key)
        self.install(bind='192.168.50.10')
        self.assertEqual(self.manager.firewall_owned(),[])
        self.manager.uninstall()
        self.assertIn(key,self.rules[True]);self.assertIn(key,self.rules[False])

    def test_reconcile_port_and_rollback_restores_owned_rule(self):
        self.install(bind='192.168.50.10')
        old=deepcopy(self.rules)
        config=self.manager.configuration();config['web']['port']=9090
        config['web']['allowed_origins']=['http://192.168.50.10:9090']
        pkg.atomic(self.host,pkg.CONF/'config.toml',pkg.dump_toml(config),0o640,0,self.host.groups['kc1ray-read'])
        result=self.manager.apply('upgrade')
        self.assertTrue(all('9090' in rule for zone,rule in self.rules[True]))
        self.manager.rollback(result['backup'])
        self.assertEqual(self.rules,old)

    def test_localhost_never_adds_rules(self):
        self.install()
        self.assertFalse(self.rules[True]);self.assertFalse(self.rules[False])

    def test_failure_rolls_back_new_rules_and_preserves_unrelated(self):
        unrelated=('--zone=allstarlink','operator rule')
        self.rules[True].add(unrelated);self.rules[False].add(unrelated)
        self.firewall_failure=True
        with self.assertRaisesRegex(pkg.InstallError,'firewalld'):
            self.install(bind='192.168.50.10')
        self.assertEqual(self.rules[True],{unrelated})
        self.assertEqual(self.rules[False],{unrelated})

    def test_ambiguous_existing_rule_and_missing_subnet_fail_closed(self):
        record=self.manager.firewall_plan('192.168.50.10',8085)['desired'][0]
        self.rules[True].add(('--zone=allstarlink',pkg.firewall_rule(record)))
        with self.assertRaises(pkg.InstallError):self.install(bind='192.168.50.10')
        self.host.lan_addresses=lambda:[dict(interface='eth0',address='192.168.50.10')]
        with self.assertRaises(pkg.InstallError):self.manager.firewall_plan('192.168.50.10',8085)


    def test_rule_change_to_localhost_removes_owned_rules_only(self):
        self.install(bind='192.168.50.10')
        config=self.manager.configuration()
        config['web'].update(bind='127.0.0.1',allow_lan_http=False,allowed_origins=[])
        pkg.atomic(self.host,pkg.CONF/'config.toml',pkg.dump_toml(config),0o640,0,self.host.groups['kc1ray-read'])
        self.manager.apply('upgrade')
        self.assertFalse(self.rules[True]);self.assertFalse(self.rules[False])

    def test_subnet_zone_interface_reconciliation(self):
        self.install(bind='192.168.50.10')
        new=dict(zone='lan2',interface='wlan0',address='192.168.50.10',subnet='192.168.50.0/25',port=8085)
        self.manager.firewall_set([new])
        self.assertEqual(self.manager.firewall_owned(),[new])
        self.assertEqual(self.rules[True],{('--zone=lan2',pkg.firewall_rule(new))})

    def test_unavailable_firewalld_with_owned_rules_refuses_uninstall(self):
        self.install(bind='192.168.50.10')
        self.host.firewall_running=lambda:False
        with self.assertRaises(pkg.InstallError):self.manager.uninstall()
        self.assertTrue(self.rules[True])
        self.assertTrue(self.manager.manifest()['installed'])

    def test_partial_addition_is_removed_after_failure(self):
        original=self.host.run
        def fail_runtime(args,check=True,env=None):
            if args[0]=='firewall-cmd' and '--permanent' not in args and any(arg.startswith('--add-rich-rule=') for arg in args):
                self.host.run=original
                raise pkg.InstallError('Runtime rule failed')
            return original(args,check=check,env=env)
        self.host.run=fail_runtime
        with self.assertRaises(pkg.InstallError):self.install(bind='192.168.50.10')
        self.assertFalse(self.rules[True]);self.assertFalse(self.rules[False])

    def test_older_snapshot_without_firewall_metadata_restores_safely(self):
        self.install(bind='192.168.50.10')
        snapshot=self.manager.snapshot(self.manager.states())
        path=self.host.path(pkg.REGISTRY/'backups'/snapshot/'snapshot.json')
        metadata=json.loads(path.read_text());metadata.pop('firewall');path.write_text(json.dumps(metadata))
        self.manager.rollback(snapshot)
        self.assertFalse(self.rules[True]);self.assertFalse(self.rules[False])


    def test_firewalld_detection_absent_stopped_and_failed(self):
        with patch.object(self.host,'command_exists',return_value=False),patch.object(self.host,'run') as run:
            self.assertFalse(pkg.Host.firewall_running(self.host));run.assert_not_called()
        for status,expected in ((0,True),(252,False)):
            with patch.object(self.host,'run',return_value=SimpleNamespace(returncode=status)):
                self.assertEqual(pkg.Host.firewall_running(self.host),expected)
        with patch.object(self.host,'run',return_value=SimpleNamespace(returncode=251)):
            with self.assertRaises(pkg.InstallError):pkg.Host.firewall_running(self.host)

    def test_all_loopback_bindings_skip_rules(self):
        for bind in ('localhost','127.0.0.1','127.0.1.1'):
            self.assertEqual(self.manager.firewall_plan(bind,8085)['desired'],[])

    def test_failed_removal_retains_ownership_for_recovery(self):
        self.install(bind='192.168.50.10')
        original=self.host.run
        def ignore_removal(args,check=True,env=None):
            if any(value.startswith('--remove-rich-rule=') for value in args):
                return SimpleNamespace(returncode=0,stdout='',stderr='')
            return original(args,check=check,env=env)
        self.host.run=ignore_removal
        with self.assertRaises(pkg.InstallError):self.manager.firewall_set([])
        self.assertTrue(self.manager.firewall_owned())


    def test_interactive_plan_can_defer_port_selection(self):
        plan=self.manager.plan('install',node='1000',bind='192.168.50.10')
        self.assertEqual(plan['firewall']['status'],'awaiting-port-selection')
        self.assertFalse(self.rules[True])


class ApacheLifecycleTests(PackagingCase):
    def setUp(self):
        super().setUp()
        self.sites=[dict(id='/etc/apache2/sites-enabled/web.conf:1',host='scanner.test',port=80,scheme='http',aliases=[],default=True),
                    dict(id='/etc/apache2/sites-enabled/ssl.conf:1',host='scanner.test',port=443,scheme='https',aliases=[],default=True)]
        self.host.apache_sites=lambda:deepcopy(self.sites)
        self.original_site=self.host.path('/etc/apache2/sites-enabled/web.conf')
        self.original_site.parent.mkdir(parents=True)
        self.original_site.write_text('# Existing AllScan and operator virtual host; never modify.\n')
        self.site_bytes=self.original_site.read_bytes()
        self.reloads=0
        self.fail_apache=None
        original=self.host.run
        def run(args,check=True,env=None):
            if args[0]=='apache2ctl' or args==['systemctl','reload','apache2.service']:
                self.host.commands.append(args)
                if self.fail_apache and self.fail_apache(args):
                    self.fail_apache=None
                    raise pkg.InstallError('Simulated Apache validation/reload failure')
                if args[0]=='systemctl':self.reloads+=1
                return SimpleNamespace(returncode=0,stdout='',stderr='')
            return original(args,check=check,env=env)
        self.host.run=run

    def proxy_install(self):
        return self.install(web_access='apache',apache_vhosts=[site['id'] for site in self.sites])

    def test_preferred_apache_requires_explicit_multiple_site_selection(self):
        plan=self.manager.plan('install',node='1000',port=8085)
        self.assertEqual(plan['web_access'],'selection-required')
        self.assertEqual(len(plan['apache_sites']),2)
        with self.assertRaises(pkg.InstallError):self.install(web_access='apache')
        self.assertFalse(self.host.users)

    def test_proxy_install_upgrade_uninstall_preserves_site_and_credentials(self):
        self.proxy_install()
        config=self.manager.configuration()
        self.assertEqual(config['web']['bind'],'127.0.0.1')
        self.assertEqual(config['web']['port'],8085)
        self.assertEqual(config['web']['url_prefix'],'/hubscanner')
        self.assertEqual(config['web']['allowed_origins'],['http://scanner.test','https://scanner.test'])
        self.assertEqual(config['web']['trusted_proxies'],['127.0.0.1/32'])
        self.assertEqual(self.manager.firewall_owned(),[])
        before=self.bytes_at(pkg.CONF/'credentials.json')
        config['web']['allowed_origins'].append('https://remote.test')
        config['web']['trusted_proxies'].append('127.0.0.2/32')
        pkg.atomic(self.host,pkg.CONF/'config.toml',pkg.dump_toml(config),0o640,0,self.host.groups['kc1ray-read'])
        toml_before=self.bytes_at(pkg.CONF/'config.toml')
        reloads=self.reloads
        self.manager.apply('upgrade')
        self.assertEqual(self.bytes_at(pkg.CONF/'config.toml'),toml_before)
        self.assertEqual(self.reloads,reloads)
        self.manager.uninstall()
        self.assertFalse(self.host.path(pkg.APACHE_CONFIG).exists())
        self.assertEqual(self.original_site.read_bytes(),self.site_bytes)
        self.assertEqual(self.bytes_at(pkg.CONF/'credentials.json'),before)

    def test_candidate_validation_failure_never_touches_original_apache(self):
        self.fail_apache=lambda args:args[0]=='apache2ctl' and '-t' in args
        with self.assertRaises(pkg.InstallError):self.proxy_install()
        self.assertFalse(self.host.path(pkg.APACHE_CONFIG).exists())
        self.assertEqual(self.original_site.read_bytes(),self.site_bytes)
        self.assertEqual(self.reloads,0)

    def test_activation_failure_restores_original_apache(self):
        self.fail_apache=lambda args:args==['systemctl','reload','apache2.service']
        with self.assertRaises(pkg.InstallError):self.proxy_install()
        self.assertFalse(self.host.path(pkg.APACHE_CONFIG).exists())
        self.assertEqual(self.original_site.read_bytes(),self.site_bytes)

    def test_switch_to_standalone_and_rollback_restores_proxy(self):
        self.proxy_install()
        before=self.host.path(pkg.APACHE_CONFIG).read_bytes()
        result=self.manager.apply('upgrade',web_access='standalone')
        self.assertFalse(self.host.path(pkg.APACHE_CONFIG).exists())
        self.assertEqual(self.manager.configuration()['web']['url_prefix'],'')
        self.manager.rollback(result['backup'])
        self.assertEqual(self.host.path(pkg.APACHE_CONFIG).read_bytes(),before)
        self.assertEqual(self.manager.configuration()['web']['url_prefix'],'/hubscanner')

    def test_unmanaged_or_modified_config_is_not_overwritten(self):
        self.host.path(pkg.APACHE_CONFIG).parent.mkdir(parents=True)
        self.host.path(pkg.APACHE_CONFIG).write_text('# Operator-owned config')
        with self.assertRaises(pkg.InstallError):self.proxy_install()
        self.host.path(pkg.APACHE_CONFIG).unlink()
        self.proxy_install()
        self.host.path(pkg.APACHE_CONFIG).write_text('# Modified by owner')
        with self.assertRaises(pkg.InstallError):self.manager.apply('upgrade')
        self.assertEqual(self.host.path(pkg.APACHE_CONFIG).read_text(),'# Modified by owner')

    def test_explicit_default_site_ip_and_wrong_site_origin(self):
        result=pkg.apache_selection(self.sites,[self.sites[0]['id']],['http://192.168.50.10'])
        self.assertEqual(result[0]['host'],'192.168.50.10')
        other=dict(self.sites[0],id='/etc/apache2/sites-enabled/other.conf:1',host='other.test',default=False)
        with self.assertRaises(pkg.InstallError):pkg.apache_selection(self.sites+[other],[self.sites[0]['id']],['http://other.test'])

    def test_apache_dump_parser_retains_default_alias_and_rejects_duplicates(self):
        output='*:80 is a NameVirtualHost\n default server scanner.test (/etc/apache2/sites-enabled/a.conf:1)\n port 80 namevhost scanner.test (/etc/apache2/sites-enabled/a.conf:1)\n alias scanner.local\n port 80 namevhost other.test (/etc/apache2/sites-enabled/b.conf:1)\n'
        sites=pkg.apache_sites(output)
        self.assertTrue(sites[0]['default'])
        self.assertEqual(sites[0]['aliases'],['scanner.local'])
        self.assertFalse(sites[1]['default'])
        with self.assertRaises(pkg.InstallError):pkg.apache_sites(output+output.replace('a.conf','c.conf').replace('b.conf','d.conf'))


    def test_transition_to_apache_removes_only_scanner_firewall_rules(self):
        rules={False:set(),True:set()}
        self.host.firewall_running=lambda:True
        self.host.firewall_has=lambda record,permanent:pkg.firewall_rule(record) in rules[permanent]
        original=self.host.run
        def run(args,check=True,env=None):
            if args[0]=='firewall-cmd':
                if '--get-zone-of-interface=eth0' in args:return SimpleNamespace(returncode=0,stdout='allstarlink')
                permanent='--permanent' in args
                arg=next(arg for arg in args if '-rich-rule=' in arg)
                operation,rule=arg.split('=',1)
                if operation=='--add-rich-rule':rules[permanent].add(rule)
                elif operation=='--remove-rich-rule':rules[permanent].discard(rule)
                else:raise AssertionError(args)
                return SimpleNamespace(returncode=0,stdout='')
            return original(args,check=check,env=env)
        self.host.run=run
        self.manager.apply('install',node='1000',port=9090,bind='192.168.50.10',web_access='standalone',credentials=self.credentials,favorites=self.favorites)
        self.assertEqual(len(rules[True]),1)
        self.manager.apply('upgrade',web_access='apache',apache_vhosts=[self.sites[0]['id']])
        self.assertFalse(rules[True]);self.assertFalse(rules[False])
        self.assertEqual(self.manager.configuration()['web']['bind'],'127.0.0.1')
        self.assertEqual(self.original_site.read_bytes(),self.site_bytes)

    def test_snapshot_without_apache_metadata_is_compatible(self):
        self.install(web_access='standalone')
        identifier=self.manager.snapshot(self.manager.states())
        path=self.host.path(pkg.REGISTRY/'backups'/identifier/'snapshot.json')
        metadata=json.loads(path.read_text());metadata.pop('apache');path.write_text(json.dumps(metadata))
        self.manager.apply('upgrade',web_access='apache',apache_vhosts=[self.sites[0]['id']])
        self.manager.rollback(identifier)
        self.assertFalse(self.host.path(pkg.APACHE_CONFIG).exists())
        self.assertEqual(self.manager.configuration()['web']['url_prefix'],'')


    def test_nonstandard_address_bindings_and_wildcard_aliases_are_refused(self):
        for output in ('127.0.0.1:80 scanner.test (/etc/apache2/sites-enabled/test.conf:1)', '*:8080 scanner.test (/etc/apache2/sites-enabled/test.conf:1)'):
            with self.assertRaises(pkg.InstallError):pkg.apache_sites(output)
        sites=deepcopy(self.sites);sites[0]['aliases']=['*.test']
        with self.assertRaises(pkg.InstallError):pkg.apache_selection(sites,[sites[0]['id']])


    def test_readonly_discovery_verifies_modules_includes_and_listeners(self):
        self.host.path('/etc/apache2/ports.conf').write_text('Listen 80\n')
        def run(args,check=True,env=None):
            stdout=''
            if args==['apache2ctl','-M']:stdout='proxy_module proxy_http_module headers_module rewrite_module'
            elif 'DUMP_INCLUDES' in args:stdout='Included configuration files:\n (*) /etc/apache2/ports.conf\n'
            elif args==['apache2ctl','-S']:stdout='*:80 scanner.test (/etc/apache2/sites-enabled/web.conf:1)\n'
            return SimpleNamespace(returncode=0,stdout=stdout)
        with patch.object(self.host,'run',side_effect=run):
            sites=pkg.Host.apache_sites(self.host)
            self.assertEqual(sites[0]['host'],'scanner.test')
            self.host.path('/etc/apache2/ports.conf').write_text('Listen 80\nListen 8080\n')
            with self.assertRaises(pkg.InstallError):pkg.Host.apache_sites(self.host)
            self.host.path('/etc/apache2/ports.conf').write_text('Listen 80\n')
            def external(args,check=True,env=None):
                if 'DUMP_INCLUDES' in args:return SimpleNamespace(returncode=0,stdout=' (*) /opt/operator/apache.conf\n')
                return run(args,check,env)
            with patch.object(self.host,'run',side_effect=external):
                with self.assertRaises(pkg.InstallError):pkg.Host.apache_sites(self.host)


    def test_retained_reinstall_recreates_proxy_without_resetting_operator_data(self):
        self.proxy_install()
        original=self.host.path(pkg.APACHE_CONFIG).read_bytes()
        config=self.bytes_at(pkg.CONF/'config.toml')
        credentials=self.bytes_at(pkg.CONF/'credentials.json')
        favorites=self.bytes_at(pkg.STATE/'favorites.json')
        self.manager.uninstall()
        self.assertFalse(self.host.path(pkg.APACHE_CONFIG).exists())
        self.install()
        self.assertEqual(self.host.path(pkg.APACHE_CONFIG).read_bytes(),original)
        self.assertEqual(self.bytes_at(pkg.CONF/'config.toml'),config)
        self.assertEqual(self.bytes_at(pkg.CONF/'credentials.json'),credentials)
        self.assertEqual(self.bytes_at(pkg.STATE/'favorites.json'),favorites)
