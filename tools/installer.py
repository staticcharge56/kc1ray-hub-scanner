#!/usr/bin/env python3
"""Explicit lifecycle packaging for Debian 12 ASL3. Defaults to read-only planning."""
import argparse
import ast
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import getpass
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE))
# Recovery must work even when the installed TOML is damaged. Import application
# validators under the shipped safe example, then load target config explicitly.
_import_config=os.environ.get('KC1RAY_CONFIG')
os.environ['KC1RAY_CONFIG']=str(SOURCE/'config/config.example.toml')
try:
    from configuration import DEFAULTS, load_config
    from favorites_store import validate as validate_favorites
    from security import Credentials, create_credentials
    from migrate_favorites import parse_legacy
finally:
    if _import_config is None:
        os.environ.pop('KC1RAY_CONFIG',None)
    else:
        os.environ['KC1RAY_CONFIG']=_import_config

APP=Path('/opt/kc1ray-hub-scanner')
CONF=Path('/etc/kc1ray-hub-scanner')
STATE=Path('/var/lib/kc1ray-hub-scanner')
MONITOR_STATE=Path('/var/lib/kc1ray-hub-scanner-monitor')
CACHE=Path('/var/cache/kc1ray-hub-scanner')
RUNTIME=Path('/run/kc1ray-hub-scanner')
REGISTRY=Path('/var/lib/kc1ray-hub-scanner-package')
UNIT_DIR=Path('/etc/systemd/system')
LAUNCHER=Path('/usr/local/sbin/kc1ray-hub-scanner')
TMPFILES=Path('/etc/tmpfiles.d/kc1ray-hub-scanner.conf')
PREFIX='kc1ray-hub-scanner-'
UNITS=tuple(PREFIX+x for x in ('broker.service','monitor.service','web.service','netwatch.service',
                             'allstarnets.service','netwatch.timer','allstarnets.timer'))
STOP_ORDER=tuple(PREFIX+x for x in ('netwatch.timer','allstarnets.timer','web.service',
                                  'monitor.service','netwatch.service','allstarnets.service','broker.service'))
MAIN_UNITS=tuple(PREFIX+x+'.service' for x in ('broker','monitor','web'))
APP_FILES=('radio_control.py','activity_history.py','broker.py','configuration.py','control_service.py','dashboard.py',
           'favorites_store.py','manage_admin.py','migrate_favorites.py','monitor.py','scanner.py',
           'security.py','stats_api.py','update-nets.py','update_netwatch.py','web_auth.py')
GROUPS=('kc1ray-read','kc1ray-control','kc1ray-web')
USERS=('kc1ray-web','kc1ray-radio','kc1ray-monitor')
SCHEMAS={'config':1,'favorites':1,'history':1,'credentials':1}
PURGE_PHRASE='PURGE KC1RAY HUB SCANNER'
# Only these locations can be backed up, replaced, restored or removed.
AREAS={'program':APP,'config':CONF,'state':STATE,'monitor':MONITOR_STATE,'cache':CACHE,
       'launcher':LAUNCHER,'tmpfiles':TMPFILES,'manifest':REGISTRY/'manifest.json'}
AREAS.update({'unit-'+name:UNIT_DIR/name for name in UNITS})
SAFE_ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
ASTERISK_SOCKET=Path('/run/asterisk/asterisk.ctl')
SOCKET_GUIDE='docs/asterisk-socket-access.md'


class InstallError(RuntimeError):
    pass


class RadioAccessError(InstallError):
    """Sanitized effective-access failure that remains visible after rollback."""


class Host:
    """Filesystem root is injectable for tests; a staged host cannot run commands."""
    def __init__(self,root='/'):
        self.root=Path(root).resolve()

    def path(self,path):
        path=Path(path)
        if not path.is_absolute() or '..' in path.parts:
            raise InstallError('Invalid managed path')
        return self.root/path.relative_to('/')

    def run(self,args,*,check=True,env=None):
        if self.root!=Path('/'):
            raise InstallError('Staged hosts cannot execute system commands')
        try:
            result=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=60,
                                  cwd='/',env=SAFE_ENV|(env or {}))
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise InstallError('Required command unavailable or timed out: '+Path(args[0]).name) from exc
        if check and result.returncode:
            raise InstallError('Command failed: '+Path(args[0]).name+'; inspect host/service logs')
        return result

    def user(self,name):
        try:
            entry=pwd.getpwnam(name)
        except KeyError:
            return None
        groups=[grp.getgrgid(gid).gr_name for gid in os.getgrouplist(name,entry.pw_gid)]
        status=self.run(['passwd','-S',name]).stdout.split()
        return dict(uid=entry.pw_uid,gid=entry.pw_gid,home=entry.pw_dir,shell=entry.pw_shell,
                    groups=groups,locked=len(status)>1 and status[1] in ('L','LK'))

    def group(self,name):
        try:
            return grp.getgrnam(name).gr_gid
        except KeyError:
            return None

    def command_exists(self,name):
        return shutil.which(name,path=SAFE_ENV['PATH']) is not None

    def info(self,path):
        return Path(path).lstat()

    def trusted_executable(self,logical):
        path=self.path(logical)
        for item in (path.resolve(),*path.resolve().parents):
            info=item.stat()
            if info.st_uid!=0 or info.st_mode & 0o022:
                raise InstallError('Executable and ancestors must be root-owned and not group/world writable')
        if not path.stat().st_mode & 0o111:
            raise InstallError('Asterisk file is not executable')

    def socket_info(self):
        path=self.path(ASTERISK_SOCKET)
        hint='; no Asterisk configuration or permissions were changed. See '+SOCKET_GUIDE
        try:
            info=self.info(path)
            directory=self.info(path.parent)
        except OSError:
            raise InstallError('Asterisk control socket/directory is missing or unreadable'+hint) from None
        if not stat.S_ISSOCK(info.st_mode):
            raise InstallError('Expected a real Unix socket (not a symlink) at '+str(ASTERISK_SOCKET)+hint)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_mode & stat.S_IWOTH:
            raise InstallError('Asterisk socket directory must be a real directory without world write'+hint)
        try:
            group=grp.getgrgid(info.st_gid).gr_name
        except KeyError:
            raise InstallError('Asterisk socket group has no account database entry'+hint) from None
        if info.st_gid==0 or group in ('root','sudo','adm','disk','shadow','docker','lxd',*GROUPS):
            raise InstallError('Asterisk socket uses an overprivileged or shared application group; use a separate Asterisk group'+hint)
        mode=stat.S_IMODE(info.st_mode)
        if not mode & stat.S_IWGRP:
            if mode==0o755 and group=='asterisk':
                raise InstallError('Recognized ASL3 owner-access socket mode 0755 with group asterisk: '
                                   'kc1ray-radio cannot connect through group membership. '
                                   'Operator setup: [files] astctlpermissions = 0660, astctlowner = asterisk, '
                                   'astctlgroup = asterisk in /etc/asterisk/asterisk.conf; '
                                   'apply only during an approved Asterisk maintenance restart'+hint)
            raise InstallError(f'Asterisk socket mode {mode:04o} lacks group write; restricted group access (recommended 0660) is required'+hint)
        if mode & 0o7007 or not mode & stat.S_IWUSR:
            raise InstallError(f'Asterisk socket mode {mode:04o} is not restricted owner/group access; use 0660 without special or other-user bits'+hint)
        return group

    def replace(self,source,target):
        os.replace(source,target)

    def free_bytes(self,path):
        candidate=self.path(path)
        while not candidate.exists():
            candidate=candidate.parent
        return shutil.disk_usage(candidate).free

    def chown(self,path,uid,gid):
        os.chown(path,uid,gid,follow_symlinks=False)

    def lan_addresses(self):
        """Offer RFC1918 addresses on up physical interfaces; never infer exposure."""
        command=shutil.which('ip',path=SAFE_ENV['PATH'])
        if not command:
            return []
        try:
            result=self.run([command,'-j','-4','address','show','up'],check=False)
            if result.returncode:
                return []
            return lan_candidates(json.loads(result.stdout), self)
        except (InstallError, OSError, ValueError, TypeError, KeyError, AttributeError):
            return []

    def port_available(self,port,bind='127.0.0.1'):
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
                probe.bind((bind,port))
        except OSError as exc:
            raise InstallError('Selected dashboard address/port is unavailable') from exc

    def service_state(self,name):
        enabled=self.run(['systemctl','is-enabled',name],check=False).stdout.strip()
        return {'enabled':enabled in ('enabled','enabled-runtime'),'enable_state':enabled,
                'active':self.run(['systemctl','is-active','--quiet',name],check=False).returncode==0}

    def validate_candidate(self,release):
        self.run(['/usr/bin/python3','-B','-E','-s',str(release/'tools/runtime_check.py'),'validate'],
                 env={'KC1RAY_CONFIG':str(CONF/'config.toml')})

    def check_radio_access(self,node,binary):
        if not isinstance(node,str) or not re.fullmatch(r'[0-9]{3,7}',node) or not Path(binary).is_absolute():
            raise RadioAccessError('Invalid radio-access check arguments; no radio command was issued')
        # Test actual AF_UNIX connection rights (including traversal and ACLs),
        # not os.access() as root. Send no CLI/control payload on this probe.
        probe=('import os,pwd,socket\n'
               'uid=pwd.getpwnam("kc1ray-radio").pw_uid\n'
               'if uid<1 or os.geteuid()!=uid or os.getuid()!=uid: raise SystemExit(1)\n'
               'with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:\n'
               ' connection.settimeout(5)\n'
               ' connection.connect("'+str(ASTERISK_SOCKET)+'")\n')
        hint='; check directory traversal, socket mode, group membership and ACLs; see '+SOCKET_GUIDE
        try:
            result=self.run(['runuser','-u','kc1ray-radio','--','/usr/bin/python3','-B','-I','-c',probe],check=False)
            if result.returncode:
                raise RadioAccessError('kc1ray-radio cannot connect to '+str(ASTERISK_SOCKET)+hint)
            result=self.run(['runuser','-u','kc1ray-radio','--',binary,'-rx',f'rpt show variables {node}'],check=False)
        except RadioAccessError:
            raise
        except InstallError:
            raise RadioAccessError('Radio identity/socket/node validation could not complete'+hint) from None
        if result.returncode or not re.search(r'^[ \t]*RPT_ALINKS=[^\r\n]*$',result.stdout,re.M):
            raise RadioAccessError('kc1ray-radio cannot read the selected ASL node; only a read-only node query was attempted'+hint)

    def verify_units(self,directory):
        self.run(['systemd-analyze','verify',*[str(directory/name) for name in UNITS]])


def atomic(host,path,content,mode=0o600,uid=0,gid=0):
    path=host.path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.is_symlink():
        raise InstallError('Refusing symlink destination')
    fd,temporary=tempfile.mkstemp(prefix='.package-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(content.encode() if isinstance(content,str) else content)
            stream.flush()
            os.fsync(stream.fileno())
        host.chown(temporary,uid,gid)
        os.chmod(temporary,mode)
        with open(temporary,'rb') as stream:
            os.fsync(stream.fileno())
        host.replace(temporary,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def json_write(host,path,data):
    atomic(host,path,json.dumps(data,indent=2,sort_keys=True)+'\n')


def read_json(host,path,default=None):
    try:
        return json.loads(host.path(path).read_bytes())
    except FileNotFoundError:
        return default


def mkdir(host,path,mode,uid=0,gid=0):
    target=host.path(path)
    if target.is_symlink():
        raise InstallError('Refusing symlink directory')
    target.mkdir(parents=True,exist_ok=True)
    host.chown(target,uid,gid)
    target.chmod(mode)


def value_toml(value):
    if type(value) is bool:
        return str(value).lower()
    if type(value) is int:
        return str(value)
    if isinstance(value,str):
        return json.dumps(value,ensure_ascii=False)
    if isinstance(value,list):
        return '['+', '.join(value_toml(item) for item in value)+']'
    raise InstallError('Unsupported TOML value')


def dump_toml(data):
    lines=['# Managed initial layout; preserve this file during upgrades.']
    def table(values,prefix):
        if prefix:
            lines.extend(['','['+'.'.join(prefix)+']'])
        for key,value in values.items():
            if not isinstance(value,dict):
                lines.append(key+' = '+value_toml(value))
        for key,value in values.items():
            if isinstance(value,dict):
                table(value,[*prefix,key])
    table(data,[])
    return '\n'.join(lines)+'\n'


def discover_nodes(host,start='/etc/asterisk/rpt.conf'):
    """Bounded read-only numeric-section discovery. Never evaluates #exec."""
    visited=set()
    nodes=set()
    dynamic=False
    def visit(logical):
        nonlocal dynamic
        path=host.path(logical)
        if path.is_symlink() or not path.resolve().is_relative_to(host.path('/etc/asterisk').resolve()):
            raise InstallError('rpt.conf includes must be regular files inside /etc/asterisk')
        if path in visited:
            return
        visited.add(path)
        if len(visited)>256:
            raise InstallError('Too many rpt.conf includes')
        raw=path.read_bytes()
        if len(raw)>1_048_576:
            raise InstallError('rpt.conf include too large')
        for line in raw.decode('utf-8').splitlines():
            text=line.split(';',1)[0].strip()
            match=re.match(r'^\[([0-9]{3,7})\](?:\(([^)]*)\))?',text)
            if match and '!' not in (match.group(2) or ''):
                nodes.add(match.group(1))
            if re.match(r'^#exec\b',text):
                dynamic=True
            include=re.match(r'^#(tryinclude|include)\s+["<]?([^">]+?)[">]?\s*$',text)
            if include:
                pattern=include.group(2).strip()
                logical_pattern=Path(pattern) if pattern.startswith('/') else Path(logical).parent/pattern
                if '..' in logical_pattern.parts:
                    raise InstallError('Parent traversal in rpt.conf include')
                parent=host.path(logical_pattern.parent)
                matches=sorted(parent.glob(logical_pattern.name))
                if not matches and include.group(1)=='include':
                    raise InstallError('Required rpt.conf include missing')
                for included in matches:
                    visit(Path('/')/included.relative_to(host.root))
    visit(Path(start))
    return sorted(nodes,key=int),dynamic


def lan_candidates(interfaces,host):
    """Physical LAN candidates only: no CGNAT, 44Net, VPN or wildcard address."""
    private=[ipaddress.ip_network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    candidates=set()
    for interface in interfaces:
        name=interface['ifname']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',name) or 'UP' not in interface.get('flags',[]):
            continue
        if not host.path('/sys/class/net/'+name+'/device').exists():
            continue
        for entry in interface.get('addr_info',[]):
            if entry.get('family')!='inet' or entry.get('scope')!='global':
                continue
            address=ipaddress.IPv4Address(entry['local'])
            if any(address in network for network in private):
                candidates.add((name,str(address)))
    return [dict(interface=name,address=address) for name,address in sorted(candidates)]


def inspect(host,binary='/usr/sbin/asterisk'):
    fields={}
    for line in host.path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key,value=line.split('=',1)
            fields[key]=value.strip('"\'')
    if fields.get('ID')!='debian' or fields.get('VERSION_ID')!='12':
        raise InstallError('Supported target is Debian 12 (not ID_LIKE derivatives); no installation performed')
    arch=host.run(['dpkg','--print-architecture']).stdout.strip()
    if arch not in ('arm64','amd64','armhf'):
        raise InstallError('Unsupported architecture: '+arch)
    version=host.run(['/usr/bin/python3','-c','import sys,tomllib,hashlib,ssl; assert hasattr(hashlib,"scrypt"); assert ssl.create_default_context().cert_store_stats()["x509_ca"]>0; print(".".join(map(str,sys.version_info[:3])))']).stdout.strip()
    if tuple(map(int,version.split('.')[:2]))<(3,11):
        raise InstallError('Python 3.11+ with tomllib and OpenSSL scrypt is required')
    for command in ('systemctl','systemd-analyze','groupadd','useradd','runuser','passwd','nologin'):
        if not host.command_exists(command):
            raise InstallError('Missing dependency: '+command+'; install it before retrying')
    package=host.run(['dpkg-query','-W','-f=${db:Status-Status} ${Version}','asl3-asterisk']).stdout.strip()
    if not package.startswith('installed '):
        raise InstallError('Install the ASL3 asl3-asterisk package first')
    if not Path(binary).is_absolute() or not host.path(binary).is_file():
        raise InstallError('Asterisk executable is missing')
    host.trusted_executable(binary)
    ast_version=host.run([binary,'-V']).stdout.strip()
    if host.run(['systemctl','is-active','--quiet','asterisk.service'],check=False).returncode:
        raise InstallError('Asterisk must already be running; installer will not start or alter it')
    group=host.socket_info()
    nodes,dynamic=discover_nodes(host)
    return dict(os='Debian 12',architecture=arch,python=version,asterisk=ast_version,
                asl_package=package,asterisk_group=group,nodes=nodes,dynamic_nodes=dynamic)


def source_inventory(source):
    release=json.loads((source/'packaging/release.json').read_bytes())
    if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}',release.get('version','')) or
            release.get('package_schema')!=1 or
            any(release.get(key+'_schema')!=value for key,value in SCHEMAS.items())):
        raise InstallError('Unsupported source/package schemas')
    names=[*APP_FILES,'tools/installer.py','tools/runtime_check.py','config/config.example.toml',
           'packaging/release.json','README.md']
    names += [str(path.relative_to(source)) for path in sorted((source/'docs').glob('*.md'))]
    names += ['packaging/systemd/'+name+'.in' for name in UNITS]
    inventory={}
    for name in names:
        path=source/name
        if path.is_symlink() or not path.is_file():
            raise InstallError('Source file missing or symlink: '+name)
        raw=path.read_bytes()
        if name.endswith('.py'):
            ast.parse(raw,filename=name)
        inventory[name]=hashlib.sha256(raw).hexdigest()
    identity=hashlib.sha256(json.dumps(inventory,sort_keys=True).encode()).hexdigest()[:16]
    return release,inventory,release['version']+'-'+identity


def check_schema(manifest):
    if manifest.get('package_schema')!=1:
        raise InstallError('Unsupported installation schema; explicit migration required')
    schemas=manifest.get('schemas',{})
    migrations=[]
    for name,current in SCHEMAS.items():
        previous=schemas.get(name,0 if name=='config' else None)
        if name=='config' and previous==0:
            migrations.append('config 0 -> 1: validate existing TOML with defaults; preserve original bytes')
        elif previous!=current:
            raise InstallError('Unsupported '+name+' schema; explicit reviewed migration required')
    return migrations


class Manager:
    def __init__(self,host,source=SOURCE):
        self.host,self.source=host,Path(source).resolve()

    def manifest(self):
        return read_json(self.host,REGISTRY/'manifest.json')

    @contextmanager
    def lock(self,allow_purge=False):
        mkdir(self.host,REGISTRY,0o700)
        lock=self.host.path(REGISTRY/'operation.lock').open('a+')
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            lock.close()
            raise InstallError('Another packaging operation is in progress') from None
        try:
            pending=read_json(self.host,REGISTRY/'transaction.json')
            if pending and not (allow_purge and pending.get('action')=='purge'):
                raise InstallError('An interrupted transaction needs explicit rollback first')
            yield
        finally:
            lock.close()

    def identities(self,asterisk_group,create=False):
        registry=read_json(self.host,REGISTRY/'accounts.json',{'groups':{},'users':{}})
        expected={'kc1ray-web':('kc1ray-web',{'kc1ray-read','kc1ray-control'}),
                  'kc1ray-radio':('kc1ray-read',{'kc1ray-control',asterisk_group}),
                  'kc1ray-monitor':('kc1ray-read',set())}
        for name in GROUPS:
            gid=self.host.group(name)
            if gid is not None and registry['groups'].get(name)!=gid:
                raise InstallError('Reserved group conflict: '+name)
            if gid is None:
                if not create:
                    continue
                self.host.run(['groupadd','--system',name])
                gid=self.host.group(name)
                registry['groups'][name]=gid
                json_write(self.host,REGISTRY/'accounts.json',registry)
        for name,(primary,extra) in expected.items():
            user=self.host.user(name)
            if user is not None:
                if registry['users'].get(name)!=user['uid']:
                    raise InstallError('Reserved account conflict: '+name)
                if (user['home']!='/nonexistent' or user['shell']!='/usr/sbin/nologin' or not user['locked'] or
                        set(user['groups'])!={primary,*extra}):
                    raise InstallError('Service account memberships/locking changed; review required: '+name)
            elif create:
                args=['useradd','--system','--no-create-home','--home-dir','/nonexistent',
                      '--shell','/usr/sbin/nologin','--gid',primary]
                if extra:
                    args+=['--groups',','.join(sorted(extra))]
                self.host.run([*args,name])
                user=self.host.user(name)
                registry['users'][name]=user['uid']
                json_write(self.host,REGISTRY/'accounts.json',registry)
        return registry

    def configuration(self):
        return load_config(self.host.path(CONF/'config.toml'))

    def validate_private_files(self,ids):
        checks=((CONF/'config.toml',0,ids['groups']['kc1ray-read']),
                (CONF/'credentials.json',0,ids['groups']['kc1ray-web']))
        for logical,uid,gid in checks:
            path=self.host.path(logical)
            info=self.host.info(path)
            if path.is_symlink() or info.st_uid!=uid or info.st_gid!=gid or stat.S_IMODE(info.st_mode)!=0o640:
                raise InstallError('Managed configuration/credential permissions require review')
        history=self.host.path(MONITOR_STATE/'monitor-history.json')
        if history.exists():
            try:
                saved=json.loads(history.read_bytes())
            except (ValueError,UnicodeError):
                saved=None # retain damaged history; monitor's documented cold-start behavior applies
            if isinstance(saved,dict) and saved.get('version',1)!=1:
                raise InstallError('Unsupported persisted history version; explicit migration required')

    def validate_layout(self,config,ids):
        expected={'state_dir':str(STATE),'monitor_state_dir':str(MONITOR_STATE),'cache_dir':str(CACHE),
                  'runtime_dir':str(RUNTIME),'scanner_script':str(APP/'current/scanner.py')}
        if any(config['paths'].get(key)!=value for key,value in expected.items()):
            raise InstallError('Unmanaged/custom data paths require explicit migration, not an automatic upgrade')
        if (config['broker']['web_uid']!=ids['users']['kc1ray-web'] or
                config['broker']['service_uid']!=ids['users']['kc1ray-radio'] or
                config['broker']['socket_gid']!=ids['groups']['kc1ray-control'] or
                config['broker']['socket_path']!=str(RUNTIME/'control.sock') or
                config['auth']['credentials_file']!=str(CONF/'credentials.json')):
            raise InstallError('Configured identities/paths do not match the managed installation')

    def verify_live_files(self,manifest):
        target=self.host.path(APP/'current')
        release=manifest.get('release','')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}',release) or not target.is_symlink() or os.readlink(target)!='releases/'+release:
            raise InstallError('Current release pointer is invalid')
        base=self.host.path(APP/'releases'/release)
        for name,digest in manifest['inventory'].items():
            path=base/name
            info=self.host.info(path)
            if info.st_uid!=0 or info.st_mode & 0o022:
                raise InstallError('Installed code permissions are unsafe')
            if '..' in Path(name).parts or Path(name).is_absolute() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                raise InstallError('Installed program was modified; use a reviewed restore instead of overwriting it')
        for name,digest in manifest.get('units',{}).items():
            if name not in UNITS or hashlib.sha256(self.host.path(UNIT_DIR/name).read_bytes()).hexdigest()!=digest:
                raise InstallError('Managed unit was modified; preserve customizations as drop-ins before upgrading')

    def plan(self,action,node=None,port=None,binary='/usr/sbin/asterisk',bind=None,config_template=None):
        manifest=self.manifest()
        if action in ('install','upgrade'):
            if manifest:
                registered=read_json(self.host,REGISTRY/'accounts.json')
                if not registered:
                    raise InstallError('Managed account registry missing')
                self.validate_private_files(registered)
                binary=self.configuration()['allstar']['asterisk_binary']
            env=inspect(self.host,binary)
            release,inventory,identity=source_inventory(self.source)
            if action=='upgrade' and (not manifest or not manifest.get('installed')):
                raise InstallError('No managed installation to upgrade')
            ids=self.identities(env['asterisk_group'])
            migrations=[]
            if manifest and manifest.get('installed'):
                if action=='install':
                    raise InstallError('Already installed; use upgrade')
                migrations=check_schema(manifest)
                self.validate_private_files(ids)
                config=self.configuration()
                self.validate_layout(config,ids)
                self.verify_live_files(manifest)
                validate_favorites(json.loads(self.host.path(STATE/'favorites.json').read_bytes()))
                Credentials(self.host.path(CONF/'credentials.json'))
                node=config['allstar']['local_node']
                port=config['web']['port']
                bind=config['web']['bind']
            elif manifest and not manifest.get('installed'):
                self.validate_private_files(ids)
                config=self.configuration()
                self.validate_layout(config,ids)
                if (node is not None and node!=config['allstar']['local_node']) or (port is not None and port!=config['web']['port']):
                    raise InstallError('Reinstallation retains existing node/port; edit retained config explicitly')
                if bind is not None and bind!=config['web']['bind']:
                    raise InstallError('Reinstallation retains existing bind address')
                bind=config['web']['bind']
                node,port=config['allstar']['local_node'],config['web']['port']
                Credentials(self.host.path(CONF/'credentials.json'))
                validate_favorites(json.loads(self.host.path(STATE/'favorites.json').read_bytes()))
            else:
                for logical in (APP,CONF,STATE,MONITOR_STATE,CACHE,RUNTIME,LAUNCHER,TMPFILES,*[UNIT_DIR/name for name in UNITS]):
                    if self.host.path(logical).exists() or self.host.path(logical).is_symlink():
                        raise InstallError('Unmanaged destination exists; explicit migration/review required: '+str(logical))
            if node is not None and (not re.fullmatch(r'[0-9]{3,7}',node) or (node not in env['nodes'] and not env['dynamic_nodes'])):
                raise InstallError('Selected node was not found in ASL configuration')
            if port is not None and (type(port) is not int or not 1024<=port<=65535):
                raise InstallError('Choose an unprivileged port from 1024 to 65535')
            candidates=self.host.lan_addresses() if action=='install' and not manifest else []
            if not manifest and bind is not None and bind!='127.0.0.1' and bind not in [item['address'] for item in candidates]:
                raise InstallError('Select 127.0.0.1 or an offered private physical LAN IPv4 address; wildcard/public/VPN binds are not install selections')
            if not manifest and bind is None and config_template is not None:
                bind=config_template['web']['bind']
            bind=bind or '127.0.0.1'
            if action=='install' and port is not None:
                self.host.port_available(port,bind)
            return dict(action=action,environment=env,node=node,port=port,bind=bind,lan_candidates=candidates,release=identity,migrations=migrations,
                        retained=bool(manifest and not manifest.get('installed')),schemas=SCHEMAS,
                        http_warning='LAN HTTP does not encrypt credentials or sessions' if bind!='127.0.0.1' else None,
                        paths={key:str(value) for key,value in AREAS.items() if not key.startswith('unit-')})
        if not manifest:
            raise InstallError('No managed installation registry')
        return dict(action=action,installed=manifest.get('installed'),data_retained_by_default=True)

    def stage(self,inventory,identity):
        releases=self.host.path(APP/'releases')
        mkdir(self.host,APP,0o755)
        mkdir(self.host,APP/'releases',0o755)
        target=releases/identity
        if target.exists():
            for name,digest in inventory.items():
                if hashlib.sha256((target/name).read_bytes()).hexdigest()!=digest:
                    raise InstallError('Existing release directory is inconsistent')
            return target
        temporary=Path(tempfile.mkdtemp(prefix='.staging-',dir=releases))
        try:
            for name,digest in inventory.items():
                raw=(self.source/name).read_bytes()
                if hashlib.sha256(raw).hexdigest()!=digest:
                    raise InstallError('Source changed during installation')
                out=temporary/name
                out.parent.mkdir(parents=True,exist_ok=True)
                with out.open('wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                self.host.chown(out,0,0)
                out.chmod(0o644)
            for directory in [temporary,*[p for p in temporary.rglob('*') if p.is_dir()]]:
                self.host.chown(directory,0,0)
                directory.chmod(0o755)
            for directory in sorted([temporary,*[p for p in temporary.rglob('*') if p.is_dir()]],key=lambda p:len(p.parts),reverse=True):
                descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            self.host.replace(temporary,target)
            descriptor=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        return target

    def write_units(self,group,ids):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',group):
            raise InstallError('Invalid Asterisk group name for unit rendering')
        digests={}
        for name in UNITS:
            text=(self.source/'packaging/systemd'/ (name+'.in')).read_text().replace('@ASTERISK_GROUP@',group)
            atomic(self.host,UNIT_DIR/name,text,0o644)
            digests[name]=hashlib.sha256(text.encode()).hexdigest()
        atomic(self.host,TMPFILES,f'd {RUNTIME} 2750 kc1ray-radio kc1ray-read -\n',0o644)
        launcher='#!/bin/sh\nexec /usr/bin/python3 -B -E -s /opt/kc1ray-hub-scanner/current/tools/installer.py "$@"\n'
        atomic(self.host,LAUNCHER,launcher,0o755)
        self.host.verify_units(self.host.path(UNIT_DIR))
        return digests

    def init_data(self,ids,node,port,binary,credentials,favorites,netwatch,allstarnets,template=None,history=None):
        groups,users=ids['groups'],ids['users']
        for directory,user in ((STATE,'kc1ray-radio'),(MONITOR_STATE,'kc1ray-monitor'),(CACHE,'kc1ray-monitor')):
            mkdir(self.host,directory,0o2750,users[user],groups['kc1ray-read'])
        mkdir(self.host,CONF,0o750,0,groups['kc1ray-read'])
        config=deepcopy(template if template is not None else DEFAULTS)
        config['allstar'].update(local_node=node,asterisk_binary=binary)
        config['paths'].update(state_dir=str(STATE),monitor_state_dir=str(MONITOR_STATE),cache_dir=str(CACHE),
                               runtime_dir=str(RUNTIME),scanner_script=str(APP/'current/scanner.py'))
        config['web']['port']=port
        config['broker'].update(web_uid=users['kc1ray-web'],service_uid=users['kc1ray-radio'],
                                socket_gid=groups['kc1ray-control'],socket_path=str(RUNTIME/'control.sock'))
        config['auth']['credentials_file']=str(CONF/'credentials.json')
        if template is None or netwatch:
            config['schedules']['netwatch']['enabled']=netwatch
        if template is None or allstarnets:
            config['schedules']['allstarnets']['enabled']=allstarnets
        atomic(self.host,CONF/'config.toml',dump_toml(config),0o640,0,groups['kc1ray-read'])
        atomic(self.host,CONF/'credentials.json',credentials,0o640,0,groups['kc1ray-web'])
        atomic(self.host,STATE/'favorites.json',json.dumps(validate_favorites(favorites),ensure_ascii=False)+'\n',
               0o640,users['kc1ray-radio'],groups['kc1ray-read'])
        if history is not None:
            atomic(self.host,MONITOR_STATE/'monitor-history.json',history,0o640,users['kc1ray-monitor'],groups['kc1ray-read'])
        return config

    def switch(self,identity):
        target=self.host.path(APP/'current')
        temporary=target.with_name('.current-'+uuid.uuid4().hex)
        try:
            temporary.symlink_to('releases/'+identity)
            self.host.chown(temporary,0,0)
            self.host.replace(temporary,target)
            descriptor=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    def states(self):
        return {name:self.host.service_state(name) for name in UNITS}

    def stop(self,states):
        for name in STOP_ORDER:
            if states[name]['active'] or self.host.path(UNIT_DIR/name).exists():
                self.host.run(['systemctl','stop',name])

    def activate(self,config):
        enabled=[*MAIN_UNITS]
        for key in ('netwatch','allstarnets'):
            timer=PREFIX+key+'.timer'
            if config['schedules'][key]['enabled']:
                enabled.append(timer)
            else:
                self.host.run(['systemctl','disable',timer])
        self.host.run(['systemctl','daemon-reload'])
        for name in enabled:
            self.host.run(['systemctl','enable',name])
        for name in enabled:
            self.host.run(['systemctl','start',name])
            if not self.host.service_state(name)['active']:
                raise InstallError('Application service failed to become active: '+name)

    def restore_services(self,states):
        self.host.run(['systemctl','daemon-reload'])
        for name in UNITS:
            if self.host.path(UNIT_DIR/name).exists():
                if states[name].get('enable_state') in ('static','indirect','generated','transient'):
                    continue
                command=['systemctl','enable' if states[name]['enabled'] else 'disable']
                if states[name].get('enable_state')=='enabled-runtime':
                    command.append('--runtime')
                self.host.run([*command,name])
        for name in [*MAIN_UNITS,*[n for n in UNITS if n not in MAIN_UNITS]]:
            if states[name]['active']:
                self.host.run(['systemctl','start',name])

    def snapshot(self,states):
        # All callers (including rollback/uninstall) need this preflight. Count
        # logical file bytes conservatively; snapshots are full private copies.
        needed=sum(path.stat().st_size for logical in AREAS.values()
                   for path in ([self.host.path(logical)] if self.host.path(logical).is_file() else
                                self.host.path(logical).rglob('*') if self.host.path(logical).is_dir() else [])
                   if path.is_file() and not path.is_symlink())
        if self.host.free_bytes(REGISTRY)<needed+16*1024*1024:
            raise InstallError('Insufficient disk space for a safe backup')
        identifier=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:12]
        base=REGISTRY/'backups'/identifier
        mkdir(self.host,base,0o700)
        metadata={'id':identifier,'areas':{},'services':states,'complete':False}
        for area,logical in AREAS.items():
            source=self.host.path(logical)
            records={}
            if source.exists() or source.is_symlink():
                nodes=[source,*sorted(source.rglob('*'))] if source.is_dir() and not source.is_symlink() else [source]
                for item in nodes:
                    relative='.' if item==source else str(item.relative_to(source))
                    info=self.host.info(item)
                    entry=dict(uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
                    out=self.host.path(base/area)/relative
                    if item.is_symlink():
                        link=os.readlink(item)
                        if area!='program' or relative!='current' or not re.fullmatch(r'releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}',link):
                            raise InstallError('Unexpected symlink in managed files; snapshot refused')
                        out.parent.mkdir(parents=True,exist_ok=True)
                        out.symlink_to(link)
                        entry.update(type='link',target=link)
                    elif item.is_dir():
                        out.mkdir(parents=True,exist_ok=True)
                        out.chmod(0o700)
                        entry['type']='dir'
                    elif item.is_file():
                        out.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copyfile(item,out)
                        with out.open('rb') as stream:
                            os.fsync(stream.fileno())
                        out.chmod(0o600)
                        entry.update(type='file',sha256=hashlib.sha256(out.read_bytes()).hexdigest())
                    else:
                        raise InstallError('Unexpected special file in persistent snapshot')
                    records[relative]=entry
            metadata['areas'][area]=records
        for directory in sorted([self.host.path(base),*[p for p in self.host.path(base).rglob('*') if p.is_dir() and not p.is_symlink()]],key=lambda p:len(p.parts),reverse=True):
            descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        metadata['complete']=True
        json_write(self.host,base/'snapshot.json',metadata)
        return identifier

    def validate_snapshot(self,identifier):
        if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}',identifier):
            raise InstallError('Invalid backup identifier')
        base=REGISTRY/'backups'/identifier
        metadata=read_json(self.host,base/'snapshot.json')
        if not metadata or metadata.get('complete') is not True or set(metadata.get('areas',{}))!=set(AREAS):
            raise InstallError('Backup is incomplete or unsupported')
        for area,records in metadata['areas'].items():
            for relative,entry in records.items():
                if Path(relative).is_absolute() or '..' in Path(relative).parts:
                    raise InstallError('Unsafe backup path')
                item=self.host.path(base/area)/relative
                if entry['type']=='file':
                    if item.is_symlink() or hashlib.sha256(item.read_bytes()).hexdigest()!=entry['sha256']:
                        raise InstallError('Backup checksum mismatch')
                elif entry['type']=='link':
                    if area!='program' or relative!='current' or not re.fullmatch(r'releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}',entry['target']) or not item.is_symlink() or os.readlink(item)!=entry['target']:
                        raise InstallError('Unsafe backup link')
                elif entry['type']!='dir' or not item.is_dir() or item.is_symlink():
                    raise InstallError('Invalid backup entry')
        return base,metadata

    def remove(self,logical):
        path=self.host.path(logical)
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)

    def restore(self,identifier):
        base,metadata=self.validate_snapshot(identifier)
        for area,logical in AREAS.items():
            self.remove(logical)
            records=metadata['areas'][area]
            target=self.host.path(logical)
            for relative,entry in sorted(records.items(),key=lambda pair:len(Path(pair[0]).parts)):
                destination=target/relative
                destination.parent.mkdir(parents=True,exist_ok=True)
                origin=self.host.path(base/area)/relative
                if entry['type']=='dir':
                    destination.mkdir(exist_ok=True)
                elif entry['type']=='file':
                    shutil.copyfile(origin,destination)
                else:
                    destination.symlink_to(entry['target'])
                self.host.chown(destination,entry['uid'],entry['gid'])
                if entry['type']!='link':
                    destination.chmod(entry['mode'])
        self.restore_services(metadata['services'])

    def apply(self,action,*,node=None,port=None,binary='/usr/sbin/asterisk',credentials=None,
              favorites=None,netwatch=False,allstarnets=False,config_template=None,history=None,bind=None):
        with self.lock():
            plan=self.plan(action,node,port,binary,bind,config_template)
            if not plan['node'] or plan['port'] is None:
                raise InstallError('Select node and port before execution')
            current=self.manifest()
            if action=='upgrade' and current['release']==plan['release'] and not plan['migrations']:
                return {'status':'unchanged','release':plan['release']}
            retained=plan['retained']
            if action=='install' and not retained:
                if credentials is None:
                    raise InstallError('Secure administrator credentials are required before installation')
                # Validate supplied hash without persisting any plaintext.
                with tempfile.TemporaryDirectory() as scratch:
                    path=Path(scratch)/'credentials.json'
                    path.write_bytes(credentials)
                    path.chmod(0o600)
                    Credentials(path)
                favorites=validate_favorites(favorites if favorites is not None else [])
                if history is not None:
                    if len(history)>2*1024*1024:
                        raise InstallError('Imported history exceeds the supported size limit')
                    saved=json.loads(history)
                    if not isinstance(saved,dict) or saved.get('version')!=1:
                        raise InstallError('Unsupported imported history schema')
            needed=sum(path.stat().st_size for logical in AREAS.values()
                       for path in ([self.host.path(logical)] if self.host.path(logical).is_file() else
                                    self.host.path(logical).rglob('*') if self.host.path(logical).is_dir() else [])
                       if path.is_file() and not path.is_symlink())
            if self.host.free_bytes(REGISTRY)<needed+16*1024*1024 or self.host.free_bytes(APP)<16*1024*1024:
                raise InstallError('Insufficient disk space for a safe backup and staged release')
            states=self.states()
            backup=None
            try:
                self.stop(states)
                backup=self.snapshot(states)
                json_write(self.host,REGISTRY/'transaction.json',{'action':action,'backup':backup,'phase':'prepared'})
                ids=self.identities(plan['environment']['asterisk_group'],create=True)
                self.identities(plan['environment']['asterisk_group'])
                if action=='install' and not retained:
                    if bind is not None:
                        config_template=deepcopy(config_template if config_template is not None else DEFAULTS)
                        config_template['web']['bind']=plan['bind']
                        config_template['web']['allow_lan_http']=plan['bind']!='127.0.0.1'
                        config_template['web']['allowed_origins']=[] if plan['bind']=='127.0.0.1' else [f"http://{plan['bind']}:{plan['port']}"]
                    config=self.init_data(ids,plan['node'],plan['port'],binary,credentials,favorites,netwatch,allstarnets,config_template,history)
                else:
                    config=self.configuration() # retain bytes, credentials, favorites and all operator settings
                self.host.check_radio_access(config['allstar']['local_node'],config['allstar']['asterisk_binary'])
                release,inventory,identity=source_inventory(self.source)
                if identity!=plan['release']:
                    raise InstallError('Source changed after preflight')
                stage=self.stage(inventory,identity)
                self.host.validate_candidate(stage)
                units=self.write_units(plan['environment']['asterisk_group'],ids)
                self.switch(identity)
                if action=='upgrade':
                    self.restore_services(states)
                    for name,state in states.items():
                        if state['active'] and not self.host.service_state(name)['active']:
                            raise InstallError('Previously active application unit failed after upgrade')
                else:
                    self.activate(config)
                manifest={'package_schema':1,'installed':True,'schemas':SCHEMAS,'release':identity,
                          'inventory':inventory,'units':units,'asterisk_group':plan['environment']['asterisk_group'],
                          'last_backup':backup,'migrations':plan['migrations']}
                json_write(self.host,REGISTRY/'manifest.json',manifest)
                self.clear_transaction()
                return {'status':'installed' if action=='install' else 'upgraded','release':identity,'backup':backup,
                        'migrations':plan['migrations']}
            except Exception as failure:
                if backup:
                    try:
                        self.stop(self.states())
                        self.restore(backup)
                        self.clear_transaction()
                    except Exception:
                        raise InstallError('Operation failed and automatic rollback needs attention; retained backup '+backup) from failure
                else:
                    self.restore_services(states)
                detail='; '+str(failure) if isinstance(failure,RadioAccessError) else ''
                raise InstallError('Operation failed; previous files/services restored'+(' from '+backup if backup else '')+detail) from failure

    def clear_transaction(self):
        self.host.path(REGISTRY/'transaction.json').unlink(missing_ok=True)
        descriptor=os.open(self.host.path(REGISTRY),os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def rollback(self,identifier):
        self.validate_snapshot(identifier)
        mkdir(self.host,REGISTRY,0o700)
        with self.host.path(REGISTRY/'operation.lock').open('a+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            states=self.states()
            original_journal=read_json(self.host,REGISTRY/'transaction.json')
            safety=None
            try:
                self.stop(states)
                safety=self.snapshot(states)
                json_write(self.host,REGISTRY/'transaction.json',{'action':'rollback','backup':safety,'target':identifier})
                self.restore(identifier)
                self.clear_transaction()
                return {'status':'rolled back','backup':identifier,'safety_backup':safety}
            except Exception as failure:
                try:
                    if safety:
                        self.stop(self.states())
                        self.restore(safety)
                    else:
                        self.restore_services(states)
                    if original_journal:
                        json_write(self.host,REGISTRY/'transaction.json',original_journal)
                    else:
                        self.clear_transaction()
                except Exception:
                    raise InstallError('Rollback needs attention; safety backup '+str(safety)) from failure
                raise InstallError('Rollback failed; prior files/services restored') from failure

    def purge_data(self,backup):
        json_write(self.host,REGISTRY/'transaction.json',{'action':'purge','backup':backup})
        try:
            for path in (CONF,STATE,MONITOR_STATE,CACHE):
                self.remove(path)
            for name in UNITS:
                self.remove(UNIT_DIR/(name+'.d'))
            self.remove(REGISTRY/'backups')
            self.remove(REGISTRY/'manifest.json')
            self.clear_transaction()
        except Exception as failure:
            raise InstallError('Application is uninstalled but purge is incomplete; rerun uninstall --purge with explicit confirmation to resume. Deleted backups cannot be recovered.') from failure

    def uninstall(self,*,purge=False,confirmation=None):
        if purge and confirmation!=PURGE_PHRASE:
            raise InstallError('Purge requires the exact explicit confirmation phrase')
        with self.lock(allow_purge=purge):
            pending=read_json(self.host,REGISTRY/'transaction.json')
            if pending and pending.get('action')=='purge':
                self.purge_data(pending.get('backup'))
                return {'status':'purged','data_retained':False,'backup':None,'service_accounts_retained':True}
            self.plan('uninstall')
            states=self.states()
            backup=None
            try:
                self.stop(states)
                backup=self.snapshot(states)
                json_write(self.host,REGISTRY/'transaction.json',{'action':'uninstall','backup':backup})
                for name in UNITS:
                    if self.host.path(UNIT_DIR/name).exists():
                        self.host.run(['systemctl','disable',name])
                        self.remove(UNIT_DIR/name)
                for path in (APP,LAUNCHER,TMPFILES):
                    self.remove(path)
                self.remove(RUNTIME)
                self.host.run(['systemctl','daemon-reload'])
                manifest=self.manifest()
                manifest['installed']=False
                manifest['last_backup']=backup
                json_write(self.host,REGISTRY/'manifest.json',manifest)
                self.clear_transaction()
            except Exception as failure:
                if backup:
                    self.restore(backup)
                    self.clear_transaction()
                else:
                    self.restore_services(states)
                raise InstallError('Uninstall failed; previous files/services restored'+(' from '+backup if backup else '')) from failure
            # Purge is explicitly irreversible, separate from the reversible uninstall.
            # Its marker permits confirmed retries after partial deletion.
            if purge:
                self.purge_data(backup)
            return {'status':'purged' if purge else 'uninstalled','data_retained':not purge,
                    'backup':None if purge else backup,'service_accounts_retained':True}


def credential_input(source=None,username='admin'):
    if source:
        Credentials(source)
        return Path(source).read_bytes()
    if not sys.stdin.isatty():
        raise InstallError('Use an interactive terminal for hidden administrator setup, or provide an existing private --admin-credentials file')
    password=getpass.getpass('Administrator passphrase (15+ characters): ')
    if password!=getpass.getpass('Confirm administrator passphrase: '):
        raise InstallError('Passphrases do not match')
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/'credentials.json'
        create_credentials(path,username,password)
        return path.read_bytes()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('inspect','install','upgrade','rollback','uninstall'))
    parser.add_argument('--execute',action='store_true',help='Explicitly authorize local system changes; omitted means read-only plan')
    parser.add_argument('--source',type=Path,default=SOURCE)
    parser.add_argument('--node')
    parser.add_argument('--port',type=int)
    parser.add_argument('--bind',help='Explicit offered private LAN IPv4 address, or 127.0.0.1; initial install only')
    parser.add_argument('--asterisk',help='Absolute Asterisk executable; defaults to imported config or /usr/sbin/asterisk')
    parser.add_argument('--admin-credentials',type=Path,help='Existing private scrypt credential file, not a plaintext password')
    parser.add_argument('--admin-name')
    parser.add_argument('--favorites-source',type=Path)
    parser.add_argument('--config-import',type=Path,help='Preserve settings from an explicit existing TOML, remapping only managed paths/identities')
    parser.add_argument('--history-source',type=Path,help='Explicit existing monitor-history.json (schema 1), copied without changing the source')
    parser.add_argument('--netwatch',action='store_true')
    parser.add_argument('--allstarnets',action='store_true')
    parser.add_argument('--backup',help='Backup ID required for rollback')
    parser.add_argument('--purge',action='store_true')
    parser.add_argument('--confirm-purge',help='Exact explicit purge phrase; otherwise prompted interactively')
    args=parser.parse_args()
    if args.action!='install' and (args.node is not None or args.port is not None or args.bind is not None or args.config_import or args.history_source or args.favorites_source or args.admin_credentials or args.admin_name is not None or args.netwatch or args.allstarnets):
        parser.error('Node/port/source imports and schedule selections are install-only; upgrades preserve current settings')
    if args.bind is not None and args.config_import:
        parser.error('--bind and --config-import are mutually exclusive; imports preserve reviewed network policy')
    if (args.purge or args.confirm_purge) and args.action!='uninstall':
        parser.error('Purge options are uninstall-only')
    if args.backup and args.action!='rollback':
        parser.error('--backup is rollback-only')
    host=Host()
    manager=Manager(host,args.source)
    try:
        template=load_config(args.config_import) if args.config_import else None
        binary=args.asterisk or (template['allstar']['asterisk_binary'] if template else '/usr/sbin/asterisk')
        if template:
            args.node=args.node or template['allstar']['local_node'] or None
            args.port=args.port if args.port is not None else template['web']['port']
        if args.action=='inspect':
            result=inspect(host,binary)
            result['lan_candidates']=host.lan_addresses()
        elif not args.execute:
            result=manager.plan(args.action,args.node,args.port,binary,args.bind,template)
            if args.action=='rollback':
                if not args.backup:
                    raise InstallError('Rollback requires --backup ID')
                manager.validate_snapshot(args.backup)
            result['changes_performed']=False
            if args.action=='uninstall':
                result['purge_requested']=args.purge
                result['explicit_confirmation_required']=args.purge
            if template:
                result['imported_settings_preserved']=True
                result['remapped_fields']=['paths','broker identities/socket','auth.credentials_file','selected node/port']
                result['view_policy']={'bind':template['web']['bind'],'anonymous_view':template['web']['anonymous_view']}
        else:
            if os.geteuid()!=0:
                raise InstallError('Execution requires root on the target; no changes performed')
            if args.action in ('install','upgrade'):
                plan=manager.plan(args.action,args.node,args.port,binary,args.bind,template)
                node,port=plan['node'],plan['port']
                if node is None:
                    if not sys.stdin.isatty():
                        raise InstallError('Specify --node or select interactively')
                    print('Detected local nodes: '+', '.join(plan['environment']['nodes']))
                    node=input('Select local node: ').strip()
                if port is None:
                    if not sys.stdin.isatty():
                        raise InstallError('Specify --port or select interactively')
                    port=int(input('Dashboard port [8085]: ').strip() or '8085')
                if args.action=='install' and not plan['retained'] and template is None and args.bind is None and sys.stdin.isatty():
                    print('LAN access is recommended only on a trusted LAN; HTTP does not encrypt credentials or sessions.')
                    for item in plan['lan_candidates']:
                        print(item['address']+' ('+item['interface']+')')
                    args.bind=input('Select an offered LAN IPv4 address, or Enter for localhost [127.0.0.1]: ').strip() or '127.0.0.1'
                    manager.plan(args.action,node,port,binary,args.bind)
                credentials=None
                favorites=None
                history=args.history_source.read_bytes() if args.history_source else None
                if args.action=='install' and not plan['retained']:
                    credentials=credential_input(args.admin_credentials,args.admin_name if args.admin_name is not None else 'admin')
                    if args.favorites_source:
                        text=args.favorites_source.read_text(encoding='utf-8')
                        try:
                            favorites=validate_favorites(json.loads(text))
                        except json.JSONDecodeError:
                            favorites=parse_legacy(text,node)
                result=manager.apply(args.action,node=node,port=port,binary=binary,credentials=credentials,
                                     favorites=favorites,netwatch=args.netwatch,allstarnets=args.allstarnets,config_template=template,history=history,bind=args.bind)
            elif args.action=='rollback':
                if not args.backup:
                    raise InstallError('Rollback requires --backup ID')
                result=manager.rollback(args.backup)
            else:
                confirmation=args.confirm_purge
                if args.purge and confirmation is None and sys.stdin.isatty():
                    confirmation=input('Delete configuration, favorites, history, credentials, caches and backups? Type '+PURGE_PHRASE+': ')
                result=manager.uninstall(purge=args.purge,confirmation=confirmation)
        print(json.dumps(result,indent=2))
    except (InstallError,OSError,ValueError,KeyError) as exc:
        parser.exit(1,'Packaging stopped: '+str(exc)+'\n')


if __name__=='__main__':
    main()
