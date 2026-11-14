"""Local real HTTP/filesystem integration; NOT installed Debian/multi-UID evidence."""
from copy import deepcopy
import http.client
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import socket
import http.server
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import configuration
import dashboard
import favorites_store
import security
from test_baseline import ROOT
from test_packaging import PackagingCase, pkg


def module(name, path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    loaded=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class BackupCapacityTests(PackagingCase):
    def setUp(self):
        super().setUp()
        self.install()

    def test_snapshot_capacity_guard_creates_no_partial_backup(self):
        directory=self.host.path(pkg.REGISTRY/'backups')
        before=set(directory.iterdir())
        with patch.object(self.host,'free_bytes',return_value=0):
            with self.assertRaisesRegex(pkg.InstallError,'disk space'):
                self.manager.snapshot(self.manager.states())
        self.assertEqual(set(directory.iterdir()),before)

    def test_uninstall_capacity_failure_restores_services_and_data(self):
        before=self.bytes_at(pkg.CONF/'config.toml')
        services=deepcopy(self.host.services)
        with patch.object(self.host,'free_bytes',return_value=0):
            with self.assertRaises(pkg.InstallError):
                self.manager.uninstall()
        self.assertEqual(self.bytes_at(pkg.CONF/'config.toml'),before)
        self.assertEqual(self.host.services,services)
        self.assertTrue(self.host.path(pkg.APP/'current').exists())

    def test_rollback_capacity_failure_preserves_current_release(self):
        self.change_release()
        upgraded=self.manager.apply('upgrade')
        before=os.readlink(self.host.path(pkg.APP/'current'))
        services=deepcopy(self.host.services)
        with patch.object(self.host,'free_bytes',return_value=0):
            with self.assertRaises(pkg.InstallError):
                self.manager.rollback(upgraded['backup'])
        self.assertEqual(os.readlink(self.host.path(pkg.APP/'current')),before)
        self.assertEqual(self.host.services,services)


class AcceptanceArtifactsTests(unittest.TestCase):
    def test_context_contains_only_explicit_sources_and_no_runtime_data(self):
        prepare=module('context_prepare','acceptance/prepare.py')
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'context'
            prepare.prepare(target)
            manifest=json.loads((target/'context-manifest.json').read_text())
            self.assertIn('acceptance/installed.py',manifest['sha256'])
            fixture='tests/fixtures/legacy-favorites.ini'
            self.assertIn(fixture,manifest['sha256'])
            self.assertEqual((target/'source'/fixture).read_bytes(),(ROOT/fixture).read_bytes())
            for name in manifest['sha256']:
                self.assertFalse(any(x in name for x in ('.before-', '.backup.', '.git/', '.aws/', '.codex/')))
                self.assertNotIn(name,('credentials.json','favorites.json','scanner-state.json','config/config.toml'))
            with self.assertRaises(ValueError):
                prepare.prepare(target)

    def test_runner_refuses_normal_development_host_before_commands(self):
        runner=module('installed_acceptance','acceptance/installed.py')
        with patch.object(runner.os,'geteuid',return_value=1000), \
             patch.object(runner,'run',side_effect=AssertionError('must not execute')):
            with self.assertRaises(RuntimeError):
                runner.guard()

    def test_release_payload_contains_no_private_keys_or_operator_home(self):
        _,inventory,_=pkg.source_inventory(ROOT)
        for name in inventory:
            raw=(ROOT/name).read_text()
            with self.subTest(name=name):
                self.assertNotIn('/home/admin/',raw)
                self.assertNotIn('-----BEGIN PRIVATE KEY-----',raw)
                self.assertNotIn('-----BEGIN OPENSSH PRIVATE KEY-----',raw)


class RealHttpIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory()
        cls.folder=Path(cls.directory.name)
        cls.password='Synthetic acceptance passphrase only!'
        cls.credentials=cls.folder/'credentials.json'
        security.create_credentials(cls.credentials,'operator',cls.password)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.enterContext(patch('subprocess.run',side_effect=AssertionError('No external commands')))
        self.enterContext(patch('urllib.request.urlopen',side_effect=AssertionError('No external APIs')))
        self.enterContext(patch.dict(configuration.CONFIG['web'],deepcopy(configuration.DEFAULTS['web'])))
        configuration.CONFIG['web']['controls_enabled']=True
        self.enterContext(patch.object(favorites_store,'JSON_PATH',self.folder/'favorites.json'))
        favorites_store.JSON_PATH.write_text('[{"node":"1001","name":"Synthetic"}]')
        self.auth=security.Security(deepcopy(configuration.DEFAULTS['auth']),security.Credentials(self.credentials))
        self.server=dashboard.WebServer(('127.0.0.1',0),self.auth)
        configuration.CONFIG['web']['port']=self.server.server_address[1]
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.01})
        self.thread.start()
        self.addCleanup(self.stop)
        self.cookie=''
        self.csrf=''

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.assertFalse(self.thread.is_alive())

    def request(self,method,path,body=None,csrf=True,extra=None):
        connection=http.client.HTTPConnection(*self.server.server_address,timeout=10)
        headers={'Cookie':self.cookie,'Host':'localhost:'+str(self.server.server_address[1])}
        if csrf:
            headers['X-CSRF-Token']=self.csrf
        if body is not None:
            headers['Content-Type']='application/json'
            body=json.dumps(body)
        headers.update(extra or {})
        try:
            connection.request(method,path,body,headers)
            response=connection.getresponse()
            data=response.read()
            cookie=response.getheader('Set-Cookie')
            if cookie:
                self.assertIn('HttpOnly',cookie)
                self.assertIn('SameSite=Strict',cookie)
                if headers.get('X-Forwarded-Proto')=='https' and configuration.CONFIG['web']['trusted_proxies']:
                    self.assertIn('Secure',cookie)
                self.cookie=cookie.split(';')[0]
            result=json.loads(data) if response.getheader('Content-Type','').startswith('application/json') else data.decode()
            if isinstance(result,dict) and result.get('csrf'):
                self.csrf=result['csrf']
            return response.status,result
        finally:
            connection.close()

    def login(self):
        self.assertEqual(self.request('GET','/api/session')[0],200)
        self.assertEqual(self.request('POST','/api/auth/login',{'username':'operator','password':self.password})[0],200)

    def test_real_hash_login_favorites_read_and_logout_over_tcp(self):
        self.login()
        status,result=self.request('GET','/api/favorites')
        self.assertEqual(status,200)
        self.assertEqual(result['favorites'][0]['node'],'1001')
        self.assertEqual(self.request('POST','/api/auth/logout',{})[0],200)
        self.assertEqual(self.request('GET','/api/favorites')[0],401)

    def test_real_transport_unauthorized_csrf_and_proxy_spoofing_fail_closed(self):
        for endpoint in ('/api/control','/api/favorites'):
            self.assertEqual(self.request('POST',endpoint,{'action':'first'},extra={'X-Forwarded-User':'operator','X-Forwarded-Proto':'https'})[0],401)
        self.login()
        for endpoint in ('/api/control','/api/favorites'):
            self.assertEqual(self.request('POST',endpoint,{'action':'first'},csrf=False)[0],403)
        self.assertEqual(self.request('POST','/api/control',{'action':'first'},extra={'Origin':'https://evil.example'})[0],403)

    def test_actual_http_login_rate_limit(self):
        self.request('GET','/api/session')
        for _ in range(5):
            self.assertEqual(self.request('POST','/api/auth/login',{'username':'operator','password':'incorrect'})[0],401)
        self.assertEqual(self.request('POST','/api/auth/login',{'username':'operator','password':self.password})[0],429)

    def test_real_http_session_expiration(self):
        self.auth.settings['session_idle_seconds']=1
        self.login()
        time.sleep(1.1)
        self.assertEqual(self.request('GET','/api/favorites')[0],401)
        self.assertEqual(self.request('POST','/api/control',{'action':'first'})[0],401)

    def test_explicit_https_proxy_over_real_http_sets_secure_cookie(self):
        configuration.CONFIG['web'].update(trusted_proxies=['127.0.0.1/32'],
                                           allowed_origins=['https://scanner.example'])
        headers={'Host':'scanner.example','X-Forwarded-Proto':'https',
                 'X-Forwarded-For':'198.51.100.2'}
        self.assertEqual(self.request('GET','/api/session',extra=headers)[0],200)
        self.assertEqual(self.request('POST','/api/auth/login',
            {'username':'operator','password':self.password},extra=headers)[0],200)
        # Actual cookie flags are checked by the shared request helper below.
        self.assertTrue(self.auth.sessions.items)


@unittest.skipUnless(shutil.which('apache2') and Path('/usr/lib/apache2/modules/mod_proxy_http.so').exists(), 'Apache2 binary/modules unavailable for isolated proxy test')
class IsolatedApacheTests(unittest.TestCase):
    def test_real_apache_preserves_prefix_headers_and_other_site(self):
        class Backend(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                raw=json.dumps(dict(path=self.path,host=self.headers.get('Host'),proto=self.headers.get('X-Forwarded-Proto'),client=self.headers.get('X-Forwarded-For'))).encode()
                self.send_response(200);self.end_headers();self.wfile.write(raw)
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Backend)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='kc1ray-isolated-apache-') as directory:
                folder=Path(directory)
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
                (folder/'allscan').mkdir();(folder/'allscan/index.html').write_text('unchanged AllScan fixture')
                (folder/'hubscanner/api').mkdir(parents=True);(folder/'hubscanner/api/session').write_text('other site fixture')
                text=f'ServerRoot "{folder}"\nServerName localhost\nDefaultRuntimeDir "{folder}"\nPidFile "{folder}/pid"\nErrorLog "{folder}/error.log"\nListen 127.0.0.1:{port}\n'
                for name in ('mpm_event','authz_core','proxy','proxy_http','headers','rewrite'):
                    text+=f'LoadModule {name}_module /usr/lib/apache2/modules/mod_{name}.so\n'
                text+=f'User #{os.getuid()}\nGroup #{os.getgid()}\nDocumentRoot "{folder}"\n<Directory "{folder}">\nRequire all granted\n</Directory>\n'
                text+=f'<VirtualHost 127.0.0.1:{port}>\nServerName localhost:80\n</VirtualHost>\n<VirtualHost 127.0.0.1:{port}>\nServerName other.test:80\n</VirtualHost>\n'
                text+=pkg.apache_text([dict(id='/etc/apache2/sites-enabled/test.conf:1',host='localhost',port=80,scheme='http')]).replace(':8085',':'+str(server.server_port))
                config=folder/'httpd.conf';config.write_text(text)
                subprocess.run([shutil.which('apache2'),'-t','-f',str(config)],check=True,capture_output=True,timeout=5)
                process=subprocess.Popen([shutil.which('apache2'),'-X','-f',str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                try:
                    deadline=time.monotonic()+5
                    while True:
                        try:
                            connection=socket.create_connection(('127.0.0.1',port),timeout=.2);connection.close();break
                        except OSError:
                            if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Isolated Apache startup failed')
                            time.sleep(.03)
                    for path in ('/hubscanner/','/hubscanner/api/session?x=1','/hubscanner/login'):
                        connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
                        connection.request('GET',path,headers={'Host':'localhost','X-Forwarded-Proto':'https','X-Forwarded-For':'192.168.50.99'})
                        response=connection.getresponse();data=json.loads(response.read());connection.close()
                        self.assertEqual(response.status,200)
                        self.assertEqual(data,dict(path=path,host='localhost',proto='http',client='127.0.0.1'))
                    for path,host,status in (('/hubscanner/api/session','other.test',200),('/allscan/index.html','localhost',200)):
                        connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3);connection.request('GET',path,headers={'Host':host})
                        response=connection.getresponse();raw=response.read();connection.close();self.assertEqual(response.status,status)
                        if status==200:self.assertEqual(raw,b'other site fixture' if host=='other.test' else b'unchanged AllScan fixture')
                finally:
                    process.terminate()
                    try:process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.communicate(timeout=5)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)
