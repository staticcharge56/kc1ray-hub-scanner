"""Local administrator credentials, bounded sessions and explicit HTTP trust."""
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import stat
import tempfile
import threading
import time
from http.cookies import SimpleCookie, CookieError
from urllib.parse import urlsplit

COOKIE = 'kc1ray_session'
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1


class Denied(Exception):
    def __init__(self, status, message, retry_after=None):
        super().__init__(message)
        self.status, self.message, self.retry_after = status, message, retry_after


def password_digest(password, salt):
    if not isinstance(password, str) or not 1 <= len(password.encode('utf-8')) <= 1024:
        raise ValueError('Invalid password length')
    return hashlib.scrypt(password.encode('utf-8'), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                          p=SCRYPT_P, maxmem=256*1024*1024, dklen=32)


def create_credentials(path, username, password, *, replace=False):
    if not isinstance(username, str) or not username.isascii() or not username or len(username)>64 or not all(c.isalnum() or c in '_.-' for c in username):
        raise ValueError('Administrator name must be 1–64 ASCII letters, digits, _, . or -')
    if not isinstance(password, str) or len(password)<15:
        raise ValueError('Use a passphrase of at least 15 characters')
    salt = secrets.token_bytes(16)
    data = dict(version=1, username=username, algorithm='scrypt', n=SCRYPT_N, r=SCRYPT_R,
                p=SCRYPT_P, salt=salt.hex(), digest=password_digest(password,salt).hex())
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refusing symlink credentials')
    fd, temporary = tempfile.mkstemp(prefix='.admin-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(data,stream)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary,path)
        else:
            os.link(temporary,path) # no clobber on initial setup
        directory = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Credentials:
    def __init__(self,path):
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o137:
                raise ValueError('Credentials must be a private regular file (0600 or 0640)')
            raw = stream.read(4097)
        if len(raw)>4096:
            raise ValueError('Invalid credentials file')
        data=json.loads(raw)
        if not isinstance(data,dict):
            raise ValueError('Invalid credentials schema')
        if (type(data.get('version')) is not int or data.get('version')!=1 or data.get('algorithm')!='scrypt' or
                (data.get('n'),data.get('r'),data.get('p'))!=(SCRYPT_N,SCRYPT_R,SCRYPT_P) or
                not isinstance(data.get('username'),str) or not data['username'].isascii() or not 1<=len(data['username'])<=64):
            raise ValueError('Invalid credentials schema')
        self.username=data['username']
        self.salt=bytes.fromhex(data['salt'])
        self.digest=bytes.fromhex(data['digest'])
        if len(self.salt)!=16 or len(self.digest)!=32:
            raise ValueError('Invalid credentials lengths')

    def verify(self,username,password):
        digest=password_digest(password,self.salt) # same work for an unknown username
        return (hmac.compare_digest(digest,self.digest) and isinstance(username,str) and
                hmac.compare_digest(username.encode('utf-8'),self.username.encode('utf-8')))


@dataclass(frozen=True)
class RequestContext:
    origin: str
    secure: bool
    client: str
    loopback: bool
    lan_http: bool = False

    @property
    def transport_allowed(self):
        return self.secure or self.loopback or self.lan_http


def request_context(headers,peer,web):
    hosts=headers.get_all('Host',[]) if hasattr(headers,'get_all') else [headers.get('Host','')]
    if len(hosts)!=1 or not hosts[0] or any(c.isspace() or ord(c)<32 for c in hosts[0]):
        raise Denied(403,'Host not permitted')
    address=ipaddress.ip_address(peer)
    trusted=any(address in ipaddress.ip_network(net) for net in web['trusted_proxies'])
    proto='http'
    client=address
    if trusted:
        for name in ('X-Forwarded-Proto','X-Forwarded-For'):
            if hasattr(headers,'get_all') and len(headers.get_all(name,[]))>1:
                raise Denied(403,'Ambiguous proxy header')
        forwarded=headers.get('X-Forwarded-Proto')
        if forwarded is not None:
            if forwarded not in ('http','https'):
                raise Denied(403,'Invalid proxy protocol')
            proto=forwarded
        forwarded=headers.get('X-Forwarded-For')
        if forwarded is not None:
            try:
                client=ipaddress.ip_address(forwarded.strip()) # one overwritten address, no chains
            except ValueError:
                raise Denied(403,'Invalid proxy client') from None
    origin=proto+'://'+hosts[0].lower()
    allowed=web['allowed_origins'] or [f'http://127.0.0.1:{web["port"]}',f'http://localhost:{web["port"]}']
    if origin not in allowed:
        raise Denied(403,'Host or protocol not permitted')
    hostname=urlsplit(origin).hostname
    loopback=address.is_loopback and client.is_loopback and hostname in ('localhost','127.0.0.1','::1')
    lan_http=(web.get('allow_lan_http',False) and proto=='http'
              and origin==f'http://{web["bind"]}:{web["port"]}'
              and any(client in ipaddress.ip_network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')))
    return RequestContext(origin,proto=='https',str(client),loopback,lan_http)


@dataclass
class Session:
    csrf: str
    username: str | None
    created: float
    touched: float
    secure: bool


class Sessions:
    def __init__(self,settings):
        self.settings=settings
        self.items={}
        self.lock=threading.RLock()

    def _prune(self):
        now=time.monotonic()
        for key,value in list(self.items.items()):
            idle=self.settings['session_idle_seconds'] if value.username else min(300,self.settings['session_idle_seconds'])
            if now-value.touched>=idle or now-value.created>=self.settings['session_max_seconds']:
                del self.items[key]

    def create(self,secure,username=None):
        with self.lock:
            self._prune()
            if len(self.items)>=self.settings['max_sessions']:
                raise Denied(429,'Session capacity reached',60)
            token=secrets.token_urlsafe(32)
            now=time.monotonic()
            session=Session(secrets.token_urlsafe(32),username,now,now,secure)
            self.items[hashlib.sha256(token.encode()).hexdigest()]=session
            return token,session

    def lookup(self,token,secure):
        if not isinstance(token,str) or len(token)!=43:
            return None
        with self.lock:
            self._prune()
            session=self.items.get(hashlib.sha256(token.encode()).hexdigest())
            return session if session and (secure or not session.secure) else None

    def revoke(self,token):
        if isinstance(token,str):
            with self.lock:
                self.items.pop(hashlib.sha256(token.encode()).hexdigest(),None)

    def rotate(self,token,secure,username):
        with self.lock:
            if self.lookup(token,secure) is None:
                raise Denied(401,'Session expired')
            self.revoke(token)
            return self.create(secure,username)

    def touch(self,session):
        with self.lock:
            self._prune()
            if not any(value is session for value in self.items.values()):
                raise Denied(401,'Session expired')
            session.touched=time.monotonic()


def cookie_token(headers):
    raw=headers.get('Cookie','')
    if len(raw)>4096 or raw.count(COOKIE+'=')!=1:
        return None
    cookie=SimpleCookie()
    try:
        cookie.load(raw)
        return cookie[COOKIE].value if COOKIE in cookie else None
    except CookieError:
        return None


def session_cookie(token,secure,*,delete=False):
    value=f'{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict'
    if secure:
        value+='; Secure'
    if delete:
        value+='; Max-Age=0'
    return value


class RateLimits:
    def __init__(self,capacity=4096):
        self.items=OrderedDict()
        self.lock=threading.Lock()
        self.capacity=capacity

    def take(self,key,limit,window):
        now=time.monotonic()
        with self.lock:
            for old,(start,count,old_window) in list(self.items.items()):
                if now-start>=old_window:
                    del self.items[old]
            if key not in self.items:
                if len(self.items)>=self.capacity:
                    raise Denied(429,'Request limit reached',window)
                self.items[key]=(now,0,window)
            start,count,span=self.items[key]
            if count>=limit:
                raise Denied(429,'Request limit reached',max(1,math.ceil(span-(now-start))))
            self.items[key]=(start,count+1,span)


def csrf_matches(value,expected):
    return isinstance(value,str) and value.isascii() and hmac.compare_digest(value,expected)


class Security:
    def __init__(self,settings,credentials):
        self.settings=settings
        self.credentials=credentials
        self.sessions=Sessions(settings)
        self.rates=RateLimits()
        self.hash_lock=threading.Lock()

    def authorize(self,session,csrf,*,mutation=False,anonymous=False):
        if session is None or session.username is None:
            if anonymous and not mutation:
                return
            raise Denied(401,'Administrator login required')
        if session.username!=self.credentials.username:
            raise Denied(403,'Administrator required')
        if mutation and (not csrf_matches(csrf,session.csrf)):
            raise Denied(403,'Invalid CSRF token')

    def login(self,context,token,session,csrf,payload):
        if not context.transport_allowed:
            raise Denied(403,'HTTPS required for login')
        if session is None or not csrf_matches(csrf,session.csrf):
            raise Denied(403,'Invalid CSRF token')
        self.rates.take('login-global',self.settings['login_global_attempts'],self.settings['login_window_seconds'])
        self.rates.take(('login',context.client),self.settings['login_attempts'],self.settings['login_window_seconds'])
        if not isinstance(payload,dict) or set(payload)!={'username','password'} or not isinstance(payload['username'],str) or len(payload['username'])>64:
            raise Denied(400,'Invalid login request')
        if not self.hash_lock.acquire(blocking=False):
            raise Denied(429,'Login busy',1)
        try:
            try:
                valid=self.credentials.verify(payload['username'],payload['password'])
            except (ValueError,TypeError,UnicodeError):
                valid=False
        finally:
            self.hash_lock.release()
        if not valid:
            raise Denied(401,'Invalid credentials')
        return self.sessions.rotate(token,context.secure,self.credentials.username)
