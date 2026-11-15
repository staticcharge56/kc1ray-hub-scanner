"""Fixed administration IPC and read-only live policy propagation. No privileged operations."""
from contextlib import contextmanager
import fcntl
import functools
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import threading
from configuration import CONFIG,DEFAULT_PATH,load_config
from security import Credentials, Denied
import admin_advanced as advanced

RUNTIME=Path('/run/kc1ray-hub-scanner-admin')
STATE=Path('/var/lib/kc1ray-hub-scanner-admin')
SOCKET=RUNTIME/'admin.sock'
MARKER=RUNTIME/'settings.json'
REFRESH_CHOICES=(5,10,15,30,60)
PHASE1_FIELDS=('refresh_seconds','controls_enabled','anonymous_view','netwatch_enabled','allstarnets_enabled')
FIELDS=(*PHASE1_FIELDS,*advanced.PATHS)
_lock=threading.RLock()


def selected(config):
    return dict(refresh_seconds=config['web']['refresh_seconds'],controls_enabled=config['web']['controls_enabled'],
                anonymous_view=config['web']['anonymous_view'],netwatch_enabled=config['schedules']['netwatch']['enabled'],
                allstarnets_enabled=config['schedules']['allstarnets']['enabled']) | {key:config[section][field] for key,(section,field) in advanced.PATHS.items()}


def validate(changes,current):
    if not isinstance(changes,dict) or not set(changes)<=set(FIELDS+advanced.SCHEDULE_FIELDS):
        raise Denied(400,'Only approved Admin settings can be changed')
    advanced.validate({key:value for key,value in changes.items() if key in advanced.PATHS or key in advanced.SCHEDULE_FIELDS},current)
    for key,value in changes.items():
        if key in advanced.PATHS or key in advanced.SCHEDULE_FIELDS:continue
        if key=='refresh_seconds':
            if type(value) is not int or (value not in REFRESH_CHOICES and value!=current[key]):
                raise Denied(400,'Choose a refresh interval of 5, 10, 15, 30 or 60 seconds')
        elif type(value) is not bool:
            raise Denied(400,'Settings switches must be booleans')
    return current | changes


def apply(config,values):
    for key in ('refresh_seconds','controls_enabled','anonymous_view'):config['web'][key]=values[key]
    for key in ('netwatch','allstarnets'):config['schedules'][key]['enabled']=values[key+'_enabled']
    for key,(section,field) in advanced.PATHS.items():config[section][field]=values[key]


def trusted(path,owner=0):
    parent=path.parent.stat()
    if parent.st_uid!=owner or parent.st_mode & 0o022:raise ValueError('Untrusted administrative directory')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if info.st_uid!=owner or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
            raise ValueError('Untrusted administrative file')
        return fd
    except BaseException:
        os.close(fd);raise


@contextmanager
def guard(name='policy.lock',exclusive=False):
    """Legacy/manual deployments without the helper retain their existing behavior."""
    try:fd=trusted(RUNTIME/name)
    except FileNotFoundError:
        yield;return
    except (OSError,ValueError):
        raise Denied(503,'Administration policy is unavailable') from None
    try:
        try:fcntl.flock(fd,(fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)|fcntl.LOCK_NB)
        except BlockingIOError:raise Denied(429,'Settings or radio operation in progress; retry shortly',1) from None
        yield
    finally:os.close(fd)


def refresh(config,security=None,*,path=MARKER,owner=0):
    with _lock:
        try:
            try:fd=trusted(path,owner)
            except FileNotFoundError:return # Only a missing marker permits legacy mode.
            with os.fdopen(fd,'rb') as stream:raw=stream.read(16385)
            if len(raw)>16384:raise ValueError('Marker too large')
            data=json.loads(raw)
            values=data['settings']
            if set(values)!=set(FIELDS) or type(data['ready']) is not bool:raise ValueError('Invalid marker')
            # Marker contains a validated complete projection, not arbitrary config.
            validate(values,values)
            if not data['ready']:
                config['web'].update(controls_enabled=False,anonymous_view=False)
            else:
                source=Path(os.environ.get('KC1RAY_CONFIG',DEFAULT_PATH))
                current=source.read_bytes()
                apply(config,values if hashlib.sha256(current).hexdigest()==data['revision'] else selected(load_config(source)))
            if security is not None:
                path=Path(config['auth']['credentials_file'])
                credentials=Credentials(path)
                if credentials.fingerprint!=getattr(security.credentials,'fingerprint',None):
                    with security.hash_lock:
                        security.credentials=credentials
                        security.sessions.revoke_all()
        except (OSError,ValueError,TypeError,KeyError):
            config['web'].update(controls_enabled=False,anonymous_view=False)
            raise Denied(503,'Administration state needs recovery') from None


def policy_protected(method):
    @functools.wraps(method)
    def wrapped(self,*args,**kwargs):
        with guard():
            refresh(self.driver.CONFIG)
            return method(self,*args,**kwargs)
    return wrapped


def rpc(op,payload=None):
    from broker import peer_uid,receive
    if os.geteuid()!=CONFIG['broker']['web_uid'] or os.geteuid()==0:
        raise Denied(503,'Administration requires the configured web identity')
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(120)
            connection.connect(str(SOCKET))
            if peer_uid(connection)!=0:raise Denied(503,'Untrusted administration service')
            raw=json.dumps(dict(op=op,payload=payload),ensure_ascii=False).encode()+b'\n'
            if len(raw)>32768:raise Denied(413,'Administration request too large')
            connection.sendall(raw)
            result=receive(connection,262144)
        if not isinstance(result,dict) or type(result.get('status')) is not int or not isinstance(result.get('body'),dict):raise ValueError()
        if result['status']!=200:raise Denied(result['status'],result['body'].get('message','Administration failed'),result.get('retry_after'))
        return result['body']
    except (OSError,ValueError,TypeError):raise Denied(503,'Administration helper unavailable; check the installed admin service') from None
