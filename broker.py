#!/usr/bin/env python3
"""UID-restricted Unix-socket wrapper; existing radio command flow is unchanged."""
import json
import os
import signal
from pathlib import Path
import pwd
import grp
import socket
import socketserver
import stat
import sys
import struct
import threading
from configuration import CONFIG, require_node, DEFAULT_PATH
from control_service import ControlService
from security import Denied

MAX_REQUEST=8192
MAX_RESPONSE=262144


def peer_uid(connection):
    return struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]


def receive(connection,maximum):
    data=bytearray()
    while len(data)<=maximum:
        block=connection.recv(min(4096,maximum+1-len(data)))
        if not block:
            break
        data.extend(block)
        if b'\n' in block:
            break
    if len(data)>maximum or not data.endswith(b'\n') or b'\n' in data[:-1]:
        raise ValueError('Invalid RPC framing')
    return json.loads(data)


def rpc(op,payload=None):
    settings=CONFIG['broker']
    if settings['service_uid']<1 or settings['web_uid']!=os.geteuid() or settings['service_uid']==settings['web_uid']:
        raise Denied(503,'Local control service is not configured')
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(settings['timeout_seconds'])
            connection.connect(settings['socket_path'])
            if peer_uid(connection)!=settings['service_uid']:
                raise Denied(503,'Untrusted local control service')
            connection.sendall(json.dumps({'op':op,'payload':payload},ensure_ascii=False).encode()+b'\n')
            result=receive(connection,MAX_RESPONSE)
        if not isinstance(result,dict) or type(result.get('status')) is not int or not isinstance(result.get('body'),dict):
            raise ValueError('Invalid control response')
        if result['status']!=200:
            raise Denied(result['status'],result['body'].get('message','Operation failed'),result.get('retry_after'))
        return result['body']
    except (OSError,ValueError,TypeError):
        raise Denied(503,'Local control service unavailable') from None


class Router:
    def __init__(self,driver):
        self.driver=driver
        self.service=ControlService(driver)

    def dispatch(self,request):
        if not isinstance(request,dict) or set(request)!={'op','payload'}:
            raise Denied(400,'Invalid local request')
        op,payload=request['op'],request['payload']
        if op=='links' and payload is None:
            return self.service.links()
        if op=='control':
            return self.service.control(payload)
        if op=='favorites':
            if not self.driver.CONFIG['web']['controls_enabled']:
                raise Denied(403,'Mutations disabled by configuration')
            if not isinstance(payload,dict) or not set(payload)<= {'action','node','name'}:
                raise Denied(400,'Invalid favorites request')
            return {'favorites':self.driver.favorites_store.mutate(payload)}
        raise Denied(400,'Unsupported local operation')


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            if peer_uid(self.request)!=self.server.web_uid:
                raise Denied(403,'Local peer not authorized')
            request=receive(self.request,MAX_REQUEST)
            body=self.server.router.dispatch(request)
            result={'status':200,'body':body}
        except Denied as exc:
            result={'status':exc.status,'body':{'message':exc.message},'retry_after':exc.retry_after}
        except (ValueError,TypeError,KeyError):
            result={'status':400,'body':{'message':'Invalid local request'}}
        except (OSError,RuntimeError):
            result={'status':503,'body':{'message':'Local operation unavailable'}}
        raw=json.dumps(result,ensure_ascii=False).encode()+b'\n'
        if len(raw)>MAX_RESPONSE:
            raw=b'{"status":503,"body":{"message":"Local response too large"}}\n'
        try:
            self.request.sendall(raw)
        except OSError:
            pass


class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True
    def __init__(self,path,router,web_uid,workers):
        self.router,self.web_uid=router,web_uid
        self.slots=threading.BoundedSemaphore(workers)
        super().__init__(path,Handler)

    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request,address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self,request,address):
        try:
            super().process_request_thread(request,address)
        finally:
            self.slots.release()

    def handle_error(self,request,address):
        pass # no tracebacks with request data or credentials


def validate_web_identity():
    uid=os.geteuid()
    if uid==0 or uid!=CONFIG['broker']['web_uid'] or uid==CONFIG['broker']['service_uid']:
        raise ValueError('Web process must use its configured non-root, separate identity')
    try:
        account=pwd.getpwnam('asterisk')
    except KeyError:
        account=None
    if account and uid==account.pw_uid:
        raise ValueError('Web process must not have Asterisk identity access')
    try:
        group=grp.getgrnam('asterisk')
    except KeyError:
        group=None
    if group and group.gr_gid in [os.getegid(),*os.getgroups()]:
        raise ValueError('Web process must not have Asterisk group access')


def validate_service_identity():
    settings=CONFIG['broker']
    if (os.geteuid()<1 or os.geteuid()!=settings['service_uid'] or settings['web_uid']<1 or
            settings['web_uid']==settings['service_uid'] or settings['socket_gid']<0):
        raise ValueError('Configure separate non-root web/service UIDs and a private socket group')
    account=pwd.getpwuid(settings['web_uid'])
    groups=os.getgrouplist(account.pw_name,account.pw_gid)
    config=Path(os.environ.get('KC1RAY_CONFIG',DEFAULT_PATH))
    files=[*Path(__file__).resolve().parent.glob('*.py'),config,Path(CONFIG['paths']['scanner_script']),
           Path(sys.executable),Path(CONFIG['allstar']['asterisk_binary'])]
    files.append(Path(settings['socket_path']).parent)
    for key in ('state_dir','cache_dir','runtime_dir'):
        directory=Path(CONFIG['paths'][key])
        files.append(directory)
        files.extend(directory.iterdir())
    for file in files:
        for candidate in set([file,file.resolve(),*file.absolute().parents,*file.resolve().parents]):
            if candidate.is_symlink() and candidate.lstat().st_uid==settings['web_uid']:
                raise ValueError('Web-owned control-path symlinks are not trusted')
            info=candidate.stat()
            writable=(info.st_mode & stat.S_IWOTH or
                      (info.st_uid==settings['web_uid'] and info.st_mode & stat.S_IWUSR) or
                      (info.st_gid in groups and info.st_mode & stat.S_IWGRP))
            if writable:
                raise ValueError('Web identity must not be able to replace control code, configuration or socket directory')


def main():
    require_node()
    validate_service_identity()
    import dashboard # legacy driver only; no HTTP server is started by import
    path=Path(CONFIG['broker']['socket_path'])
    # Never unlink an existing socket automatically: it could be a live service.
    with Server(str(path),Router(dashboard),CONFIG['broker']['web_uid'],CONFIG['broker']['max_workers']) as server:
        os.chown(path,os.geteuid(),CONFIG['broker']['socket_gid'])
        os.chmod(path,0o660)
        try:
            server.serve_forever()
        finally:
            path.unlink(missing_ok=True)


if __name__=='__main__':
    def terminate(signum,frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM,terminate)
    main()
