#!/usr/bin/env python3
"""Root-only, UID-restricted helper for five settings and password changes. No radio operations."""
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
from configuration import DEFAULT_PATH,load_config,CONFIG
from security import Credentials,create_credentials,Denied,RateLimits
from admin_settings import RUNTIME,STATE,SOCKET,selected,validate,apply,FIELDS
from broker import Server,peer_uid,receive

PREFIX='kc1ray-hub-scanner-'
SERVICES=tuple(PREFIX+x+'.service' for x in ('web','broker','monitor'))
TIMERS={key:PREFIX+key+'.timer' for key in ('netwatch','allstarnets')}
UNITS=(*SERVICES,*TIMERS.values())
PACKAGE=Path('/var/lib/kc1ray-hub-scanner-package')


class Systemd:
    def command(self,action,unit,*,runtime=False,check=True):
        if unit not in UNITS or action not in ('is-active','is-enabled','enable','disable','start','stop') or (action not in ('is-active','is-enabled') and unit not in TIMERS.values()):
            raise Denied(400,'Unsupported service operation')
        args=['/usr/bin/systemctl','--no-ask-password',action]+(['--runtime'] if runtime else [])+[unit]
        try:
            result=subprocess.run(args,capture_output=True,text=True,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        except (OSError,subprocess.TimeoutExpired):raise Denied(503,'Service operation unavailable: '+unit) from None
        if check and result.returncode:raise Denied(503,'Service operation failed: '+unit)
        return result

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
    def __init__(self,config=DEFAULT_PATH,state=STATE,runtime=RUNTIME,package=PACKAGE,system=None):
        self.config=Path(config);self.state=Path(state);self.runtime=Path(runtime);self.package=Path(package)
        self.system=system or Systemd();self.rates=RateLimits()
        self.journal=self.state/'transaction.json'

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

    def save_journal(self,path,raw,info,timers):
        record=dict(path='config' if path==self.config else 'credentials',old=raw.hex(),uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode),timers=timers)
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
        return dict(revision=hashlib.sha256(raw).hexdigest(),settings=selected(config),recovery_required=self.journal.exists(),
                    source_updates={'netwatch':self.last_update(cache/'netwatch-nets.json'),'allstarnets':self.last_update(cache/'nets.json')},
                    status=dict(version=version,local_node=config['allstar']['local_node'],web_access='apache' if apache else 'standalone',
                                services={unit:self.system.state(unit) for unit in UNITS},last_monitor_update=last))

    def settings(self,payload):
        if not isinstance(payload,dict) or not {'revision','settings'}<=set(payload) or not set(payload)<={'revision','settings','confirm_disable'}:
            raise Denied(400,'Invalid settings request')
        if not isinstance(payload['revision'],str) or not re.fullmatch(r'[0-9a-f]{64}',payload['revision']) or ('confirm_disable' in payload and type(payload['confirm_disable']) is not bool):
            raise Denied(400,'Invalid settings revision/confirmation')
        with self.locked():
            if self.journal.exists():raise Denied(503,'A previous administration change needs recovery')
            raw,info=self.read(self.config);config=load_config(self.config)
            if payload['revision']!=hashlib.sha256(raw).hexdigest():raise Denied(409,'Settings changed; reload before saving')
            current=selected(config);desired=validate(payload['settings'],current)
            if current['controls_enabled'] and not desired['controls_enabled'] and payload.get('confirm_disable') is not True:
                raise Denied(409,'Confirm disabling radio controls; existing links will remain unchanged')
            data=tomllib.loads(raw.decode())
            for key in payload['settings']:
                if key in ('netwatch_enabled','allstarnets_enabled'):
                    source=key.removesuffix('_enabled');data.setdefault('schedules',{}).setdefault(source,{})['enabled']=desired[key]
                else:data.setdefault('web',{})[key]=desired[key]
            encoded=encode_toml(data)
            with tempfile.TemporaryDirectory(dir=self.state) as folder:
                candidate=Path(folder)/'config.toml';candidate.write_bytes(encoded);load_config(candidate)
            timers=self.timer_states()
            self.save_journal(self.config,raw,info,timers)
            try:
                self.publish(config,ready=False)
                atomic(self.config,encoded,info)
                for source,unit in TIMERS.items():
                    if source+'_enabled' not in payload['settings']:continue
                    enabled=desired[source+'_enabled'];actual=self.system.state(unit)
                    if enabled and actual['enabled_state']!='enabled':self.system.command('enable',unit)
                    elif not enabled and actual['enabled']:
                        self.system.command('disable',unit);self.system.command('disable',unit,runtime=True)
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
    for file in [*Path(__file__).parent.glob('*.py'),DEFAULT_PATH,Path(sys.executable).resolve(),Path('/usr/bin/systemctl')]:
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
