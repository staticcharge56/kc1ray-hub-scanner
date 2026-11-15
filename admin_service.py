#!/usr/bin/env python3
"""Root-only, UID-restricted helper for approved settings, diagnostics and password changes. No radio operations."""
from contextlib import contextmanager,ExitStack
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import re
import signal
import socketserver
import socket
import errno
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import select
import admin_advanced as advanced
from configuration import DEFAULT_PATH,load_config,CONFIG
from security import Credentials,create_credentials,Denied,RateLimits
from admin_settings import RUNTIME,STATE,SOCKET,selected,validate,apply,FIELDS
from broker import Server,peer_uid,receive

PREFIX='kc1ray-hub-scanner-'
SERVICES=tuple(PREFIX+x+'.service' for x in ('web','broker','monitor','admin'))
TIMERS={key:PREFIX+key+'.timer' for key in ('netwatch','allstarnets')}
UNITS=(*SERVICES,*TIMERS.values())
PACKAGE=Path('/var/lib/kc1ray-hub-scanner-package')
UNIT_DIR=Path('/etc/systemd/system')
RESTARTABLE={PREFIX+'broker.service',PREFIX+'monitor.service'}


class Systemd:
    def command(self,action,unit,*,runtime=False,check=True):
        if unit not in UNITS or action not in ('is-active','is-enabled','enable','disable','start','stop','restart') or (action=='restart' and unit not in {*TIMERS.values(),*RESTARTABLE}) or (action not in ('is-active','is-enabled','restart') and unit not in TIMERS.values()):
            raise Denied(400,'Unsupported service operation')
        args=['/usr/bin/systemctl','--no-ask-password',action]+(['--runtime'] if runtime else [])+[unit]
        try:
            result=subprocess.run(args,capture_output=True,text=True,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        except (OSError,subprocess.TimeoutExpired):raise Denied(503,'Service operation unavailable: '+unit) from None
        if check and result.returncode:raise Denied(503,'Service operation failed: '+unit)
        return result

    def reload(self):
        try:
            result=subprocess.run(['/usr/bin/systemctl','--no-ask-password','daemon-reload'],capture_output=True,timeout=10)
        except (OSError,subprocess.TimeoutExpired):raise Denied(503,'Timer configuration reload failed') from None
        if result.returncode:raise Denied(503,'Timer configuration reload failed')

    def recent_logs(self):
        args=['/usr/bin/journalctl','--no-pager','--quiet','--output=json','--output-fields=MESSAGE,_SYSTEMD_UNIT,__REALTIME_TIMESTAMP','--since=-24h','-n','100']
        for name in ('web','broker','monitor','admin','netwatch','allstarnets'):args+=['--unit='+PREFIX+name+'.service']
        try:
            with subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as child:
                raw=bytearray();deadline=time.monotonic()+5
                try:
                    while len(raw)<65536 and time.monotonic()<deadline:
                        if not select.select([child.stdout],[],[],max(0,deadline-time.monotonic()))[0]:break
                        block=os.read(child.stdout.fileno(),min(8192,65536-len(raw)))
                        if not block:break
                        raw.extend(block)
                finally:
                    if child.poll() is None:child.kill()
                    child.wait(timeout=2)
            if child.returncode and len(raw)<65536:return None
            return advanced.safe_logs(raw.decode('utf-8',errors='replace'))
        except (OSError,subprocess.SubprocessError):return None

    def state(self,unit):
        active=self.command('is-active',unit,check=False).stdout.strip()
        enabled=self.command('is-enabled',unit,check=False).stdout.strip()
        allowed=('active','inactive','failed','activating','deactivating','reloading','enabled','enabled-runtime','disabled','static','masked','masked-runtime','not-found')
        return dict(active=active in ('active','reloading'),enabled=enabled in ('enabled','enabled-runtime'),
                    active_state=active if active in allowed else 'unknown',enabled_state=enabled if enabled in allowed else 'unknown')

    def restore(self,unit,state):
        current=self.state(unit)
        if current['enabled_state']!=state['enabled_state']:
            if state['enabled']:
                if state['enabled_state']=='enabled-runtime' and current['enabled']:
                    self.command('disable',unit)
                self.command('enable',unit,runtime=state['enabled_state']=='enabled-runtime')
            elif current['enabled']:
                self.command('disable',unit);self.command('disable',unit,runtime=True)
        current=self.state(unit)
        if current['active']!=state['active']:self.command('start' if state['active'] else 'stop',unit)
        actual=self.state(unit)
        if any(actual[key]!=state[key] for key in ('active','enabled','enabled_state')):
            raise Denied(503,'Timer rollback requires attention: '+unit)


def atomic(path,data,info=None,mode=0o600):
    path=Path(path)
    if path.is_symlink():raise ValueError('Refusing symlink administration destination')
    fd,tmp=tempfile.mkstemp(prefix='.admin-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush()
            os.fchown(stream.fileno(),info.st_uid if info else os.geteuid(),info.st_gid if info else os.getegid())
            os.fchmod(stream.fileno(),stat.S_IMODE(info.st_mode) if info else mode)
            os.fsync(stream.fileno())
        os.replace(tmp,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def encode_toml(data):
    # Configuration validation accepts only these existing schema types. Preserve
    # every unedited raw value; canonical formatting may replace operator comments.
    def value(item):
        if type(item) is bool:return str(item).lower()
        if type(item) is int:return str(item)
        if isinstance(item,str):return json.dumps(item,ensure_ascii=False)
        if isinstance(item,list):return '['+', '.join(value(v) for v in item)+']'
        raise ValueError('Unsupported configuration value')
    lines=[]
    def table(items,path=''):
        if path:lines.append('['+path+']')
        for key,item in items.items():
            if not isinstance(item,dict):lines.append(key+' = '+value(item))
        for key,item in items.items():
            if isinstance(item,dict):
                lines.append('');table(item,path+'.'+key if path else key)
    table(data)
    return ('\n'.join(lines)+'\n').encode()


class Administration:
    def __init__(self,config=DEFAULT_PATH,state=STATE,runtime=RUNTIME,package=PACKAGE,system=None,unit_dir=UNIT_DIR,node_discovery=None):
        self.config=Path(config);self.state=Path(state);self.runtime=Path(runtime);self.package=Path(package)
        self.system=system or Systemd();self.rates=RateLimits()
        self.journal=self.state/'transaction.json'
        self.unit_dir=Path(unit_dir);self.node_discovery=node_discovery or self.discover_nodes

    def discover_nodes(self):
        from tools.installer import discover_nodes,Host
        nodes,dynamic=discover_nodes(Host())
        return nodes,dynamic

    def local_nodes(self):
        try:
            nodes,dynamic=self.node_discovery()
            if not isinstance(nodes,list) or any(not isinstance(node,str) or not re.fullmatch(r'[0-9]{3,7}',node) for node in nodes):raise ValueError()
            return dict(nodes=nodes,dynamic=bool(dynamic),available=True)
        except Exception:return dict(nodes=[],dynamic=False,available=False)

    def dropin(self,source):return self.unit_dir/(TIMERS[source]+'.d')/advanced.DROPIN

    def schedules(self):
        result={};available={}
        for source,key,default in (('netwatch','netwatch_interval_minutes',30),('allstarnets','allstarnets_frequency','daily')):
            directory=self.dropin(source).parent;path=self.dropin(source)
            try:
                # Refuse administrator edits if any non-owned timer override exists.
                for root in (self.unit_dir,*map(Path,('/etc/systemd/system.control','/run/systemd/system','/run/systemd/system.control','/run/systemd/transient','/usr/local/lib/systemd/system','/usr/lib/systemd/system','/lib/systemd/system','/run/systemd/generator.early','/run/systemd/generator','/run/systemd/generator.late'))):
                    prefixes=('timer.d',TIMERS[source]+'.d','kc1ray-.timer.d','kc1ray-hub-.timer.d','kc1ray-hub-scanner-.timer.d')
                    for folder in (root/name for name in prefixes):
                        if folder.exists() and any(file.name!=advanced.DROPIN or folder!=directory for file in folder.glob('*.conf')):raise ValueError()
                info=directory.stat()
                if directory.is_symlink() or info.st_uid!=os.geteuid() or info.st_mode & 0o022:raise ValueError()
                template=(Path(__file__).parent/'packaging/systemd'/(TIMERS[source]+'.in')).read_bytes()
                if (self.unit_dir/TIMERS[source]).read_bytes()!=template:raise ValueError()
                value=default
                if path.exists() or path.is_symlink():
                    raw,_=self.read(path,4096);text=raw.decode()
                    choices=range(30,1441) if source=='netwatch' else advanced.CALENDARS
                    value=next((item for item in choices if text==advanced.timer_text(source,item)),None)
                    if value is None:raise ValueError()
                result[key]=value;available[source]=True
            except (OSError,ValueError,UnicodeError,Denied):result[key]=None;available[source]=False
        return result,available

    def revision(self,raw):
        digest=hashlib.sha256(raw)
        for source in TIMERS:
            path=self.dropin(source)
            try:contents,_=self.read(path,4096)
            except FileNotFoundError:contents=b'absent'
            except (OSError,Denied):contents=b'unavailable'
            digest.update(source.encode()+b'\0'+contents+b'\0')
        return digest.hexdigest()

    def handoff(self,previous,config):
        path=self.config.parent/'node-handoff.json'
        source=hashlib.sha256(config['monitor']['stats_url_template'].encode()).hexdigest()
        # An inactive monitor may not yet have republished under the last node.
        # Preserve the authorized predecessor chain without trusting cache input.
        predecessors=[previous]
        try:
            raw,_=self.read(path,4096);old=json.loads(raw)
            if old.get('current')==previous and old.get('source_sha256')==source:
                predecessors+=old.get('predecessors',[old.get('previous')])
        except (OSError,ValueError,TypeError,Denied):pass
        predecessors=[node for node in dict.fromkeys(node for node in predecessors if isinstance(node,str) and re.fullmatch(r'[0-9]{3,7}',node)) if node!=config['allstar']['local_node']][:256]
        record=dict(previous=previous,predecessors=predecessors,current=config['allstar']['local_node'],source_sha256=source)
        _,info=self.read(self.config)
        metadata=type('Owner',(),dict(st_uid=info.st_uid,st_gid=info.st_gid,st_mode=0o640))
        atomic(path,json.dumps(record).encode(),metadata)

    def capture_schedules(self,sources):
        saved={}
        for source in sources:
            path=self.dropin(source)
            if path.exists():
                raw,info=self.read(path,4096)
                saved[source]=dict(old=raw.hex(),uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
            else:saved[source]=None
        return saved

    def restore_schedules(self,record):
        for source,value in record.items():
            if source not in TIMERS:raise ValueError('Invalid timer recovery source')
            path=self.dropin(source)
            if value is None:path.unlink(missing_ok=True)
            else:
                info=type('Owner',(),dict(st_uid=value['uid'],st_gid=value['gid'],st_mode=value['mode']))
                atomic(path,bytes.fromhex(value['old']),info)
        if record:self.system.reload()

    def read(self,path,maximum=262144):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno());raw=stream.read(maximum+1)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o027 or len(raw)>maximum:
            raise Denied(503,'Private administration file permissions/content need review')
        return raw,info

    def publish(self,config,ready=True):
        raw,_=self.read(self.config)
        data=dict(ready=ready,revision=hashlib.sha256(raw).hexdigest(),settings=selected(config))
        atomic(self.runtime/'settings.json',json.dumps(data).encode(),mode=0o644)

    @contextmanager
    def locked(self,password=False,readonly=False):
        with ExitStack() as stack:
            for path in (self.package/'operation.lock',self.state/'operation.lock',self.runtime/'policy.lock',*([self.runtime/'password.lock'] if password else [])):
                stream=stack.enter_context(path.open('a+' if path.parent!=self.runtime else 'r'))
                try:fcntl.flock(stream,(fcntl.LOCK_SH if readonly else fcntl.LOCK_EX)|fcntl.LOCK_NB)
                except BlockingIOError:raise Denied(429,'Settings, login, radio or installation operation in progress',1) from None
            if (self.package/'transaction.json').exists():raise Denied(503,'Installation recovery must finish before administration')
            yield

    def timer_states(self):return {unit:self.system.state(unit) for unit in TIMERS.values()}

    def save_journal(self,path,raw,info,timers,services=None,schedules=None):
        record=dict(path='config' if path==self.config else 'credentials',old=raw.hex(),uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode),timers=timers,services=services or {},schedules=schedules or {})
        atomic(self.journal,json.dumps(record).encode())

    def clear_journal(self):
        self.journal.unlink()
        fd=os.open(self.state,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def undo(self):
        raw,_=self.read(self.journal,1048576);record=json.loads(raw)
        config=load_config(self.config)
        if record['path']=='config':target=self.config
        elif record['path']=='credentials':target=Path(config['auth']['credentials_file'])
        else:raise ValueError('Invalid administration recovery record')
        info=type('Owner',(),dict(st_uid=record['uid'],st_gid=record['gid'],st_mode=record['mode']))
        atomic(target,bytes.fromhex(record['old']),info)
        restored=load_config(self.config)
        if restored['allstar']['local_node']!=config['allstar']['local_node']:self.handoff(config['allstar']['local_node'],restored)
        self.restore_schedules(record.get('schedules',{}))
        for unit,state in record.get('services',{}).items():
            if unit not in RESTARTABLE:raise ValueError('Invalid recovery service')
            if state['active']:
                self.system.command('restart',unit)
                if not self.system.state(unit)['active']:raise Denied(503,'Application recovery requires attention')
        for unit,state in record['timers'].items():
            if unit not in TIMERS.values():raise ValueError('Invalid recovery unit')
            self.system.restore(unit,state)
        self.publish(load_config(self.config))
        self.clear_journal()

    def recover(self):
        if self.journal.exists():
            with self.locked():self.undo()
        else:self.publish(load_config(self.config))

    def last_update(self,path):
        try:
            with Path(path).open('rb') as stream:raw=stream.read(1048577)
            if len(raw)>1048576:return None
            data=json.loads(raw)
            stamp=data.get('updated')
            return stamp if type(stamp) in (int,float) and 0<stamp<=time.time() else None
        except (OSError,ValueError,TypeError,AttributeError):return None

    def snapshot(self):
        raw,_=self.read(self.config);config=load_config(self.config)
        try:version=json.loads((Path(__file__).parent/'packaging/release.json').read_text())['version']
        except (OSError,ValueError,KeyError):version='unknown'
        cache=Path(config['paths']['cache_dir'])
        last=None
        try:
            with (cache/'activity.json').open('rb') as stream:raw_cache=stream.read(1048577)
            if len(raw_cache)<=1048576:
                samples=json.loads(raw_cache).get('favorites',[])
                last=max((f['checked'] for f in samples if isinstance(f,dict) and type(f.get('checked')) in (int,float) and 0<f['checked']<=time.time() and type(f.get('stats_time')) in (int,float) and 0<f['stats_time']<=f['checked']),default=None)
        except (OSError,ValueError,TypeError):pass
        try:apache=bool(json.loads((self.package/'apache.json').read_text()).get('records'))
        except (OSError,ValueError,AttributeError):apache=False
        schedule_values,schedule_available=self.schedules()
        activity=advanced.diagnostics(config,cache)
        activity['sources']={}
        for source,file in (('netwatch','netwatch-nets.json'),('allstarnets','nets.json')):
            updated=self.last_update(cache/file);enabled=config['schedules'][source]['enabled']
            activity['sources'][source]=dict(last_success=updated,state='disabled' if not enabled else 'unavailable' if updated is None else 'healthy' if time.time()-updated<=config['schedules'][source]['max_age_seconds'] else 'stale')
        try:release=json.loads((self.package/'manifest.json').read_text()).get('release')
        except (OSError,ValueError,AttributeError):release=None
        return dict(revision=self.revision(raw),settings=selected(config)|schedule_values,recovery_required=self.journal.exists(),
                    local_nodes=self.local_nodes(),schedule_available=schedule_available,
                    diagnostics=activity|{'recent_events':self.system.recent_logs()},
                    source_updates={'netwatch':self.last_update(cache/'netwatch-nets.json'),'allstarnets':self.last_update(cache/'nets.json')},
                    status=dict(version=version,release=release if isinstance(release,str) and re.fullmatch(r'[A-Za-z0-9._-]{1,128}',release) else None,local_node=config['allstar']['local_node'],web_access='apache' if apache else 'standalone',
                                services={unit:self.system.state(unit) for unit in UNITS},last_monitor_update=last))

    def settings(self,payload):
        if not isinstance(payload,dict) or not {'revision','settings'}<=set(payload) or not set(payload)<={'revision','settings','confirm_disable','confirm_node_change'}:
            raise Denied(400,'Invalid settings request')
        if not isinstance(payload['revision'],str) or not re.fullmatch(r'[0-9a-f]{64}',payload['revision']) or any(key in payload and type(payload[key]) is not bool for key in ('confirm_disable','confirm_node_change')):
            raise Denied(400,'Invalid settings revision/confirmation')
        with self.locked():
            if self.journal.exists():raise Denied(503,'A previous administration change needs recovery')
            raw,info=self.read(self.config);config=load_config(self.config)
            if payload['revision']!=self.revision(raw):raise Denied(409,'Settings changed; reload before saving')
            current=selected(config);desired=validate(payload['settings'],current)
            if current['controls_enabled'] and not desired['controls_enabled'] and payload.get('confirm_disable') is not True:
                raise Denied(409,'Confirm disabling radio controls; existing links will remain unchanged')
            node_changed=desired['local_node']!=current['local_node']
            if node_changed:
                if payload.get('confirm_node_change') is not True:raise Denied(409,'Confirm changing local node; existing Asterisk links are not changed')
                discovered=self.local_nodes()
                if not discovered['available'] or desired['local_node'] not in discovered['nodes']:raise Denied(400,'Select a discovered local node; dynamic or unavailable nodes cannot be selected')
                selection=Path(config['paths']['state_dir'])/'scanner-state.json'
                if selection.exists():
                    state=advanced.bounded_json(selection)
                    if state is None or state.get('node') or state.get('pending_node'):raise Denied(409,'Use STOP to clear the scanner selection before changing local node')
            schedules,available=self.schedules()
            schedule_changes={source:desired[key] for source,key in zip(TIMERS,advanced.SCHEDULE_FIELDS) if key in payload['settings'] and desired[key]!=schedules[key]}
            if any(not available[source] for source in schedule_changes):raise Denied(409,'Custom or unavailable timer configuration requires manual review')
            data=tomllib.loads(raw.decode())
            for key in payload['settings']:
                if key in advanced.SCHEDULE_FIELDS:continue
                if key in advanced.PATHS:
                    section,field=advanced.PATHS[key];data.setdefault(section,{})[field]=desired[key];continue
                if key in ('netwatch_enabled','allstarnets_enabled'):
                    source=key.removesuffix('_enabled');data.setdefault('schedules',{}).setdefault(source,{})['enabled']=desired[key]
                else:data.setdefault('web',{})[key]=desired[key]
            encoded=encode_toml(data)
            with tempfile.TemporaryDirectory(dir=self.state) as folder:
                candidate=Path(folder)/'config.toml';candidate.write_bytes(encoded);load_config(candidate)
            timers=self.timer_states()
            restart=set()
            if node_changed or desired['cooldown_seconds']!=current['cooldown_seconds']:restart.add(PREFIX+'broker.service')
            if node_changed or any(desired[key]!=current[key] for key in ('poll_interval_seconds','max_stats_age_seconds','activity_window_seconds')):restart.add(PREFIX+'monitor.service')
            services={unit:self.system.state(unit) for unit in sorted(restart)}
            schedule_backup=self.capture_schedules(schedule_changes)
            self.save_journal(self.config,raw,info,timers,services,schedule_backup)
            try:
                self.publish(config,ready=False)
                atomic(self.config,encoded,info)
                if node_changed:self.handoff(current['local_node'],load_config(self.config))
                for source,value in schedule_changes.items():
                    path=self.dropin(source)
                    info_old=path.stat() if path.exists() else None
                    atomic(path,advanced.timer_text(source,value).encode(),info_old,mode=0o640)
                if schedule_changes:self.system.reload()
                for unit,state in services.items():
                    if state['active']:
                        self.system.command('restart',unit)
                        if not self.system.state(unit)['active']:raise Denied(503,'Application service did not become active: '+unit)
                for source,unit in TIMERS.items():
                    if source+'_enabled' not in payload['settings'] and source not in schedule_changes:continue
                    enabled=desired[source+'_enabled'];actual=self.system.state(unit)
                    if enabled and actual['enabled_state']!='enabled':self.system.command('enable',unit)
                    elif not enabled and actual['enabled']:
                        self.system.command('disable',unit);self.system.command('disable',unit,runtime=True)
                    if source in schedule_changes and enabled and actual['active']:self.system.command('restart',unit)
                    if actual['active']!=enabled:self.system.command('start' if enabled else 'stop',unit)
                    result=self.system.state(unit)
                    if result['enabled']!=enabled or result['active']!=enabled:raise Denied(503,'Timer did not reach requested state: '+unit)
                self.publish(load_config(self.config))
                self.clear_journal()
            except Exception as failure:
                detail=failure.message if isinstance(failure,Denied) else 'Configuration update failed'
                try:self.undo()
                except Exception:raise Denied(503,detail+'; configuration restored where possible, recovery required') from None
                raise Denied(503,detail+'; previous configuration and timer states restored') from None
            return self.snapshot() | {'message':'Settings saved; no Asterisk or radio-link changes were made'}

    def password(self,payload):
        if not isinstance(payload,dict) or set(payload)!={'current_password','new_password','confirmation'} or any(not isinstance(v,str) or len(v.encode('utf-8'))>1024 for v in payload.values()):
            raise Denied(400,'Invalid password change request')
        if payload['new_password']!=payload['confirmation'] or len(payload['new_password'])<8:raise Denied(400,'New passwords must match and contain at least 8 characters')
        with self.locked(password=True):
            if self.journal.exists():raise Denied(503,'A previous administration change needs recovery')
            config=load_config(self.config)
            self.rates.take('password-change',config['auth']['login_attempts'],config['auth']['login_window_seconds'])
            path=Path(config['auth']['credentials_file']);raw,info=self.read(path,4096)
            credentials=Credentials(path)
            try:valid=credentials.verify(credentials.username,payload['current_password'])
            except ValueError:valid=False
            if not valid:raise Denied(401,'Current administrator password is incorrect')
            with tempfile.TemporaryDirectory(dir=self.state) as folder:
                candidate=Path(folder)/'credentials.json'
                create_credentials(candidate,credentials.username,payload['new_password'])
                encoded=candidate.read_bytes()
            self.save_journal(path,raw,info,{})
            try:
                self.publish(config,ready=False);atomic(path,encoded,info);self.publish(config);self.clear_journal()
            except Exception:
                try:self.undo()
                except Exception:raise Denied(503,'Password update needs recovery; sign in again after repair') from None
                raise Denied(503,'Password update failed; previous password restored') from None
            return dict(message='Password changed. Sign in again; prior sessions are invalidated.',reauthenticate=True)

    def dispatch(self,request):
        if not isinstance(request,dict) or set(request)!={'op','payload'}:raise Denied(400,'Invalid administration request')
        if request['op']=='status' and request['payload'] is None:
            with self.locked(readonly=True):
                self.rates.take('status',30,60)
                return self.snapshot()
        if request['op']=='settings':return self.settings(request['payload'])
        if request['op']=='password':return self.password(request['payload'])
        raise Denied(400,'Unsupported administration operation')


class AdminHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            if peer_uid(self.request)!=self.server.web_uid:raise Denied(403,'Local peer not authorized')
            result=dict(status=200,body=self.server.router.dispatch(receive(self.request,32768)))
        except Denied as exc:result=dict(status=exc.status,body={'message':exc.message},retry_after=exc.retry_after)
        except Exception:result=dict(status=503,body={'message':'Administration operation unavailable; check helper state'})
        try:self.request.sendall(json.dumps(result).encode()+b'\n')
        except OSError:pass


def main(recover_only=False):
    if os.geteuid()!=0:raise ValueError('Administration service requires its restricted root service identity')
    for file in [*Path(__file__).parent.glob('*.py'),Path(__file__).parent/'tools/installer.py',DEFAULT_PATH,Path(sys.executable).resolve(),Path('/usr/bin/systemctl')]:
        for path in {file,file.resolve(),*file.resolve().parents}:
            info=path.stat()
            if info.st_uid!=0 or info.st_mode & 0o022:raise ValueError('Administration code/configuration must be root-owned and not writable by others')
    for path,mode in ((STATE,0o700),(RUNTIME,0o750)):
        if path.is_symlink():raise ValueError('Invalid administration directory')
        path.mkdir(parents=True,exist_ok=True);path.chmod(mode)
    gid=grp.getgrnam('kc1ray-control').gr_gid
    if pwd.getpwnam('kc1ray-web').pw_uid!=CONFIG['broker']['web_uid'] or gid!=CONFIG['broker']['socket_gid']:raise ValueError('Administration identity mismatch')
    for name in ('policy.lock','password.lock'):
        path=RUNTIME/name
        if path.is_symlink():raise ValueError('Invalid administration lock')
        path.touch(exist_ok=True);os.chown(path,0,gid);path.chmod(0o640)
    if not recover_only and (SOCKET.exists() or SOCKET.is_symlink()):
        info=SOCKET.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or info.st_gid!=gid or stat.S_IMODE(info.st_mode)!=0o660:raise ValueError('Untrusted administration socket')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
            try:probe.connect(str(SOCKET))
            except OSError as exc:
                if exc.errno not in (errno.ECONNREFUSED,errno.ENOENT):raise
                SOCKET.unlink(missing_ok=True)
            else:raise ValueError('Administration service is already running')
    service=Administration();service.recover()
    if recover_only:return
    with Server(str(SOCKET),service,CONFIG['broker']['web_uid'],2) as server:
        server.RequestHandlerClass=AdminHandler
        os.chown(SOCKET,0,gid);SOCKET.chmod(0o660)
        try:server.serve_forever()
        finally:SOCKET.unlink(missing_ok=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--recover-only',action='store_true');args=parser.parse_args()
    signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
    try:main(args.recover_only)
    except (OSError,ValueError,Denied):sys.exit('Administration startup/recovery failed; review private configuration and helper state')
