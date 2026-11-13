#!/usr/bin/env python3
"""DESTRUCTIVE ONLY INSIDE THE DISPOSABLE ACCEPTANCE IMAGE. Never host-run."""
from datetime import datetime, timezone, timedelta
import grp
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import sys
import time

ROOT = Path('/src')
REPORT = Path('/tmp/kc1ray-acceptance-results.json')
RESULTS = []


def run(*args, check=True):
    return subprocess.run(list(map(str,args)),check=check,capture_output=True,text=True,timeout=180)


def guard():
    if (os.geteuid()!=0 or Path('/etc/kc1ray-acceptance-only').read_text()!='KC1RAY DISPOSABLE ACCEPTANCE ONLY\n'
            or 'ID=debian' not in Path('/etc/os-release').read_text()
            or 'VERSION_ID="12"' not in Path('/etc/os-release').read_text()
            or Path('/proc/1/comm').read_text().strip()!='systemd'
            or run('systemd-detect-virt',check=False).returncode!=0):
        raise RuntimeError('Requires the marked disposable Debian 12 systemd image/VM')
    for path in ('/etc/asterisk','/opt/kc1ray-hub-scanner','/etc/kc1ray-hub-scanner',
                 '/var/lib/kc1ray-hub-scanner','/var/lib/kc1ray-hub-scanner-package'):
        if Path(path).exists():
            raise RuntimeError('Refusing nonempty acceptance target')


def check(name, condition):
    RESULTS.append({'test':name,'passed':bool(condition)})
    REPORT.write_text(json.dumps({'environment':'Debian 12 disposable; MOCK Asterisk; no hardware',
                                  'checks':RESULTS},indent=2)+'\n')
    if not condition:
        raise AssertionError(name)


def install_mock():
    run('groupadd','--system','asterisk')
    run('useradd','--system','--gid','asterisk','--no-create-home','--shell','/usr/sbin/nologin','asterisk')
    stage=Path('/tmp/mock-deb')
    (stage/'DEBIAN').mkdir(parents=True)
    (stage/'DEBIAN/control').write_text('Package: asl3-asterisk\nVersion: 1.0\nArchitecture: all\nMaintainer: Acceptance Test <test@example.invalid>\nDescription: NON RADIO ACCEPTANCE MOCK ONLY\n')
    binary=stage/'usr/sbin/asterisk'
    binary.parent.mkdir(parents=True)
    shutil.copyfile(ROOT/'acceptance/mock_asterisk.py',binary)
    binary.chmod(0o755)
    run('dpkg-deb','--build',stage,'/tmp/mock.deb')
    run('dpkg','-i','/tmp/mock.deb')
    Path('/etc/asterisk').mkdir()
    Path('/etc/asterisk/rpt.conf').write_text('[1000]\n; Synthetic acceptance node only\n')
    Path('/etc/systemd/system/asterisk.service').write_text('''[Unit]
Description=NON RADIO ACCEPTANCE MOCK
[Service]
User=asterisk
Group=asterisk
RuntimeDirectory=asterisk
RuntimeDirectoryMode=0770
ExecStartPre=/usr/bin/touch /run/asterisk/mock.lock /run/asterisk/mock-links.json
ExecStartPre=/usr/bin/chmod 0660 /run/asterisk/mock.lock /run/asterisk/mock-links.json
ExecStart=/usr/sbin/asterisk --socket-server
''')
    # Empty mock state is interpreted as an empty link list.
    run('systemctl','daemon-reload')
    run('systemctl','start','asterisk.service')
    for _ in range(100):
        if Path('/run/asterisk/asterisk.ctl').exists():
            return
        time.sleep(.1)
    raise RuntimeError('Mock socket failed to start')


class Client:
    def __init__(self):
        self.cookie=''
        self.csrf=''

    def request(self,method,path,body=None,csrf=True,extra=None):
        headers={'Host':'localhost:8085'}
        if self.cookie:
            headers['Cookie']=self.cookie
        if csrf and self.csrf:
            headers['X-CSRF-Token']=self.csrf
        if body is not None:
            headers['Content-Type']='application/json'
            body=json.dumps(body)
        headers.update(extra or {})
        connection=http.client.HTTPConnection('127.0.0.1',8085,timeout=35)
        try:
            connection.request(method,path,body,headers)
            response=connection.getresponse()
            raw=response.read()
            cookie=response.getheader('Set-Cookie')
            if cookie:
                self.cookie=cookie.split(';')[0]
                check('cookie flags', 'HttpOnly' in cookie and 'SameSite=Strict' in cookie)
            data=json.loads(raw) if response.getheader('Content-Type','').startswith('application/json') else raw.decode()
            if isinstance(data,dict) and data.get('csrf'):
                self.csrf=data['csrf']
            return response.status,data
        finally:
            connection.close()

    def login(self,password):
        check('session bootstrap',self.request('GET','/api/session')[0]==200)
        check('administrator login',self.request('POST','/api/auth/login',{'username':'operator','password':password})[0]==200)


def cli(action,*args,source=ROOT):
    result=run('/usr/bin/python3','-B',source/'tools/installer.py',action,'--execute',*args)
    return json.loads(result.stdout)


def readable_as(user,path):
    return run('runuser','-u',user,'--','test','-r',path,check=False).returncode==0


def writable_as(user,path):
    return run('runuser','-u',user,'--','test','-w',path,check=False).returncode==0


def main():
    guard()
    install_mock()
    sys.path.insert(0,str(ROOT))
    os.environ['KC1RAY_CONFIG']=str(ROOT/'config/config.example.toml')
    import security
    password=secrets.token_urlsafe(32)
    credentials=Path('/tmp/acceptance-admin.json')
    security.create_credentials(credentials,'operator',password)
    template=Path('/tmp/acceptance.toml')
    text=(ROOT/'config/config.example.toml').read_text().replace('controls_enabled = false','controls_enabled = true')
    text=text.replace('[schedules.netwatch]\nenabled = false','[schedules.netwatch]\nenabled = true')
    template.write_text(text)
    ast_before=hashlib.sha256(Path('/etc/asterisk/rpt.conf').read_bytes()).hexdigest()
    result=cli('install','--node','1000','--port','8085','--admin-credentials',credentials,'--config-import',template)
    credentials.unlink()
    check('fresh installation',result['status']=='installed')
    cf=Path('/etc/kc1ray-hub-scanner/config.toml')
    import tomllib
    config=tomllib.loads(cf.read_text())
    check('selected node and port',config['allstar']['local_node']=='1000' and config['web']['port']==8085)
    check('private defaults',config['web']['bind']=='127.0.0.1' and not config['web']['anonymous_view'])
    uids=[pwd.getpwnam(user).pw_uid for user in ('kc1ray-web','kc1ray-radio','kc1ray-monitor')]
    check('three distinct nonroot identities',len(set(uids))==3 and min(uids)>0)
    for user in ('kc1ray-web','kc1ray-radio','kc1ray-monitor'):
        check(user+' locked nologin',pwd.getpwnam(user).pw_shell=='/usr/sbin/nologin' and run('passwd','-S',user).stdout.split()[1]=='L')
    for path in (cf,'/var/lib/kc1ray-hub-scanner','/run/kc1ray-hub-scanner','/opt/kc1ray-hub-scanner/current'):
        check('web cannot write '+str(path),not writable_as('kc1ray-web',path))
    credential=Path('/etc/kc1ray-hub-scanner/credentials.json')
    check('only web can read credentials',readable_as('kc1ray-web',credential) and not readable_as('kc1ray-radio',credential) and not readable_as('kc1ray-monitor',credential))
    check('web cannot access Asterisk socket',not writable_as('kc1ray-web','/run/asterisk/asterisk.ctl'))
    sock=Path('/run/kc1ray-hub-scanner/control.sock').stat()
    check('restricted broker socket',sock.st_mode & 0o777==0o660 and sock.st_uid==uids[1] and sock.st_gid==grp.getgrnam('kc1ray-control').gr_gid)
    for service,uid in zip(('web','broker','monitor'),(uids[0],uids[1],uids[2])):
        pid=int(run('systemctl','show','--property=MainPID','--value','kc1ray-hub-scanner-'+service+'.service').stdout)
        status=Path('/proc/'+str(pid)+'/status').read_text()
        actual=[line.split()[1:] for line in status.splitlines() if line.startswith('Uid:')][0]
        check('running service UID '+service,all(int(value)==uid for value in actual))
    check('monitor cannot write broker socket',not writable_as('kc1ray-monitor','/run/kc1ray-hub-scanner/control.sock'))
    client=Client()
    for endpoint in ('/api/control','/api/favorites'):
        check('unauthenticated denied '+endpoint,client.request('POST',endpoint,{'action':'first'})[0]==401)
    client.login(password)
    check('CSRF denied',client.request('POST','/api/control',{'action':'first'},csrf=False)[0]==403)
    for node in ('1001','1002'):
        check('favorites over real broker '+node,client.request('POST','/api/favorites',{'action':'add','node':node,'name':'Synthetic '+node})[0]==200)
    check('favorites order', [x['node'] for x in client.request('GET','/api/favorites')[1]['favorites']]==['1001','1002'])
    check('Nets tab', 'Nets' in client.request('GET','/')[1])
    deadline=time.monotonic()+25
    live_cache=Path('/var/cache/kc1ray-hub-scanner/activity.json')
    while time.monotonic()<deadline:
        if {f['node'] for f in json.loads(live_cache.read_text()).get('favorites',[])}=={'1001','1002'}:
            break
        time.sleep(.2)
    check('live monitor favorites reload', {f['node'] for f in json.loads(live_cache.read_text()).get('favorites',[])}=={'1001','1002'})
    run('systemctl','stop','kc1ray-hub-scanner-netwatch.timer')
    now=datetime.now(timezone.utc)
    fixture={'generatedAt':now.isoformat(),'nets':[{'sourceName':'Netwatch directory',
        'statusBasis':'Approved schedule','name':'Synthetic acceptance net','listingId':'test',
        'start':(now-timedelta(minutes=1)).isoformat(),'end':(now+timedelta(hours=1)).isoformat(),
        'connections':[{'mode':'AllStar','connection':'2001'}]}]}
    # Actual importer and atomic file output; only its HTTPS response is mocked.
    code='import sys,io,contextlib; from unittest.mock import patch; sys.path.insert(0,"/opt/kc1ray-hub-scanner/current"); import update_netwatch as n; raw='+repr(json.dumps(fixture).encode())+'; response=io.BytesIO(raw); response.status=200; p=patch("urllib.request.urlopen",return_value=contextlib.nullcontext(response)); p.start(); n.main()'
    run('runuser','-u','kc1ray-monitor','--','env','KC1RAY_CONFIG='+str(cf),'/usr/bin/python3','-B','-c',code)
    status,data=client.request('GET','/api/activity')
    check('NetWatch imported schedule',status==200 and data['net_schedule']['nets'][0]['node']=='2001')
    # Inject fresh synthetic statistics only; no external API or transmitter.
    cache=Path('/var/cache/kc1ray-hub-scanner/activity.json')
    run('systemctl','stop','kc1ray-hub-scanner-monitor.service')
    now=int(time.time())
    history=Path('/var/lib/kc1ray-hub-scanner-monitor/monitor-history.json')
    record=dict(checked=now,stats_time=now,keyups=5,txtime=10,links=0,keyed=False,
                registered=True,last_activity=now-10,error=None)
    history.write_text(json.dumps(dict(version=1,saved_at=now,local_node='1000',
        source=config['monitor']['stats_url_template'],records={'1001':record},retry={})))
    os.chown(history,uids[2],grp.getgrnam('kc1ray-read').gr_gid)
    history.chmod(0o640)
    run('systemctl','start','kc1ray-hub-scanner-monitor.service')
    time.sleep(1)
    run('systemctl','stop','kc1ray-hub-scanner-monitor.service')
    restored=json.loads(history.read_text())['records']['1001']
    check('history counters survive monitor restart',restored['keyups']==5 and restored['txtime']==10 and restored['last_activity']==now-10)
    cache.write_text(json.dumps({'updated':now,'favorites':[dict(node=n,name='Synthetic',activity='active',registered=True,error=None,checked=now,stats_time=now) for n in ('1001','1002')]}))
    os.chown(cache,uids[2],grp.getgrnam('kc1ray-read').gr_gid)
    cache.chmod(0o640)
    # Application-managed transitions require no Asterisk hook.
    expected={'first':{'1001'},'next':{'1002'},'stop':set(),
              'connect-node':{'1002'},'disconnect-node':set(),
              'connect-net':{'2001'},'disconnect-net':set()}
    for action in ('first','next','stop','connect-node','disconnect-node','connect-net','disconnect-net'):
        payload={'action':action}
        if action.endswith('-node'):
            payload['node']='1002'
        elif action.endswith('-net'):
            payload['node']='2001'
        check('mock radio '+action,client.request('POST','/api/control',payload)[0]==200)
        status,reported=client.request('GET','/api/links')
        check('reported mock links '+action,status==200 and set(reported['links'])==expected[action])
        check('cooldown '+action,client.request('POST','/api/control',payload)[0]==429)
        time.sleep(15.1)
    check('logout',client.request('POST','/api/auth/logout',{})[0]==200)
    check('revoked session',client.request('POST','/api/control',{'action':'first'})[0]==401)
    # Short idle timeout only in this disposable test config.
    original=cf.read_text()
    cf.write_text(original.replace('session_idle_seconds = 1800','session_idle_seconds = 1'))
    run('systemctl','restart','kc1ray-hub-scanner-web.service')
    client=Client()
    client.login(password)
    time.sleep(1.1)
    check('idle session expiry',client.request('GET','/api/favorites')[0]==401)
    cf.write_text(original)
    run('systemctl','restart','kc1ray-hub-scanner-web.service')
    retained=[cf,credential,Path('/var/lib/kc1ray-hub-scanner/favorites.json'),history]
    before={str(p):p.read_bytes() for p in retained}
    source=Path('/tmp/upgrade-source')
    shutil.copytree(ROOT,source)
    release=source/'packaging/release.json'
    metadata=json.loads(release.read_text()); metadata['version']='0.4.1-acceptance'
    release.write_text(json.dumps(metadata))
    upgraded=cli('upgrade',source=source)
    check('upgrade',upgraded['status']=='upgraded')
    check('upgrade preserves operator data',all(Path(p).read_bytes()==raw for p,raw in before.items()))
    rollback=cli('rollback','--backup',upgraded['backup'],source=source)
    check('rollback',rollback['status']=='rolled back')
    check('rollback preserves operator data',all(Path(p).read_bytes()==raw for p,raw in before.items()))
    client=Client(); client.login(password)
    uninstalled=cli('uninstall')
    check('uninstall retention',uninstalled['data_retained'] and all(Path(p).read_bytes()==raw for p,raw in before.items()))
    check('identities retained',[pwd.getpwnam(user).pw_uid for user in ('kc1ray-web','kc1ray-radio','kc1ray-monitor')]==uids)
    check('program removed',not Path('/opt/kc1ray-hub-scanner').exists())
    check('Asterisk config preserved',hashlib.sha256(Path('/etc/asterisk/rpt.conf').read_bytes()).hexdigest()==ast_before)


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        # Never print request/password/credential contents or captured command output.
        RESULTS.append({'test':'runner completed','passed':False,'error_type':type(exc).__name__})
        REPORT.write_text(json.dumps({'checks':RESULTS,'hardware_verified':False},indent=2)+'\n')
        print('Acceptance failed; inspect assertion names in '+str(REPORT),file=sys.stderr)
        sys.exit(1)
    print('Installed acceptance passed; mock Asterisk only. Report: '+str(REPORT))
