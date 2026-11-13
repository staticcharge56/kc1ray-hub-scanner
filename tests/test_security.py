"""Offline security tests. Wire tests use Unix socket pairs, never a listening port."""
from copy import deepcopy
from email.message import Message
import io
import json
import os
from pathlib import Path
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest

import broker
import configuration
import control_service
import dashboard
import security
from test_baseline import OfflineCase, ROOT

PASSWORD='A long synthetic test passphrase!'


class CredentialsTests(OfflineCase):
    def test_real_scrypt_hash_and_verification_without_plaintext(self):
        path=self.tmp/'credentials.json'
        security.create_credentials(path,'admin',PASSWORD)
        raw=path.read_text()
        self.assertNotIn(PASSWORD,raw)
        record=json.loads(raw)
        self.assertEqual(record['n'],2**17)
        credentials=security.Credentials(path)
        self.assertTrue(credentials.verify('admin',PASSWORD))
        self.assertFalse(credentials.verify('wrong-user',PASSWORD))
        self.assertFalse(credentials.verify('admin','wrong password'))
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        before=path.read_bytes()
        with self.assertRaises(FileExistsError):
            security.create_credentials(path,'admin',PASSWORD)
        self.assertEqual(path.read_bytes(),before)

    def test_unique_salts_and_explicit_reset(self):
        with patch.object(security,'password_digest',return_value=b'x'*32):
            a,b=self.tmp/'a.json',self.tmp/'b.json'
            security.create_credentials(a,'admin',PASSWORD)
            security.create_credentials(b,'admin',PASSWORD)
            self.assertNotEqual(json.loads(a.read_text())['salt'],json.loads(b.read_text())['salt'])
            security.create_credentials(a,'new-admin',PASSWORD,replace=True)
            self.assertEqual(security.Credentials(a).username,'new-admin')

    def test_rejects_weak_password_and_symlink_or_public_credentials(self):
        with self.assertRaises(ValueError):
            security.create_credentials(self.tmp/'a.json','admin','short')
        source=self.tmp/'source'
        source.write_text('{}')
        target=self.tmp/'credentials.json'
        target.symlink_to(source)
        with self.assertRaises((ValueError,OSError)):
            security.create_credentials(target,'admin',PASSWORD)
        source.chmod(0o644)
        with self.assertRaises(ValueError):
            security.Credentials(source)
        with self.assertRaises(OSError):
            security.Credentials(target)


class SessionTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.now=100
        self.enterContext(patch('time.monotonic',side_effect=lambda:self.now))
        self.settings=deepcopy(configuration.DEFAULTS['auth'])
        self.settings.update(session_idle_seconds=10,session_max_seconds=30,max_sessions=3)
        self.sessions=security.Sessions(self.settings)

    def test_session_rotation_prevents_fixation_and_replay(self):
        token,pre=self.sessions.create(False)
        rotated,admin=self.sessions.rotate(token,False,'admin')
        self.assertNotEqual(token,rotated)
        self.assertNotEqual(pre.csrf,admin.csrf)
        self.assertIsNone(self.sessions.lookup(token,False))
        self.assertIs(self.sessions.lookup(rotated,False),admin)
        self.assertNotIn(rotated,self.sessions.items) # only token digests are stored

    def test_expiration_read_polling_does_not_extend_idle_timeout(self):
        token,session=self.sessions.create(False,'admin')
        self.now=109
        self.assertIs(self.sessions.lookup(token,False),session)
        self.now=110
        self.assertIsNone(self.sessions.lookup(token,False))

    def test_touch_extends_idle_but_absolute_lifetime_still_expires(self):
        token,session=self.sessions.create(False,'admin')
        for now in (109,118,127):
            self.now=now
            self.sessions.touch(session)
        self.assertIs(self.sessions.lookup(token,False),session)
        self.now=130
        self.assertIsNone(self.sessions.lookup(token,False))

    def test_secure_session_cannot_be_used_over_http(self):
        token,session=self.sessions.create(True,'admin')
        self.assertIsNone(self.sessions.lookup(token,False))
        self.assertIs(self.sessions.lookup(token,True),session)

    def test_session_capacity_and_logout(self):
        tokens=[self.sessions.create(False)[0] for _ in range(3)]
        with self.assertRaises(security.Denied):
            self.sessions.create(False)
        self.sessions.revoke(tokens[0])
        self.assertIsNone(self.sessions.lookup(tokens[0],False))
        self.sessions.create(False)

    def test_cookie_flags_and_invalid_cookie(self):
        cookie=security.session_cookie('test',True)
        for attribute in ('HttpOnly','SameSite=Strict','Secure','Path=/'):
            self.assertIn(attribute,cookie)
        self.assertNotIn('Secure',security.session_cookie('test',False))
        self.assertIn('Max-Age=0',security.session_cookie('',True,delete=True))
        self.assertIsNone(security.cookie_token({'Cookie':'kc1ray_session=a; kc1ray_session=b'}))


class ProxyTests(OfflineCase):
    def headers(self,**values):
        headers=Message()
        for name,value in values.items():
            headers[name.replace('_','-')]=value
        return headers

    def test_untrusted_forwarded_headers_never_change_client_or_protocol(self):
        web=deepcopy(configuration.DEFAULTS['web'])
        context=security.request_context(self.headers(Host='localhost:8085',X_Forwarded_Proto='https',
            X_Forwarded_For='198.51.100.2'),'127.0.0.1',web)
        self.assertFalse(context.secure)
        self.assertEqual(context.client,'127.0.0.1')

    def test_explicit_trusted_proxy_allows_https_but_not_identity_headers(self):
        web=deepcopy(configuration.DEFAULTS['web'])
        web.update(trusted_proxies=['127.0.0.1/32'],allowed_origins=['https://scanner.example'])
        context=security.request_context(self.headers(Host='scanner.example',X_Forwarded_Proto='https',
            X_Forwarded_For='198.51.100.2',Tailscale_User_Login='admin'),'127.0.0.1',web)
        self.assertTrue(context.secure)
        self.assertEqual(context.client,'198.51.100.2')
        self.assertFalse(context.loopback)
        self.assertFalse(hasattr(context,'username'))

    def test_untrusted_proxy_cannot_spoof_https_on_allowed_external_host(self):
        web=deepcopy(configuration.DEFAULTS['web'])
        web['allowed_origins']=['https://scanner.example']
        with self.assertRaises(security.Denied):
            security.request_context(self.headers(Host='scanner.example',X_Forwarded_Proto='https'),'198.51.100.2',web)

    def test_proxy_chains_ambiguous_protocol_and_host_injection_rejected(self):
        web=deepcopy(configuration.DEFAULTS['web'])
        web['trusted_proxies']=['127.0.0.1/32']
        for values in ({'Host':'evil.example'}, {'Host':'localhost:8085','X_Forwarded_For':'198.51.100.1, 198.51.100.2'},
                       {'Host':'localhost:8085','X_Forwarded_Proto':'https,http'}):
            with self.subTest(values=values),self.assertRaises(security.Denied):
                security.request_context(self.headers(**values),'127.0.0.1',web)
        headers=self.headers(Host='localhost:8085')
        headers['Host']='evil.example'
        with self.assertRaises(security.Denied):
            security.request_context(headers,'127.0.0.1',web)
        headers=self.headers(Host='localhost:8085',X_Forwarded_Proto='http')
        headers['X-Forwarded-Proto']='https'
        with self.assertRaises(security.Denied):
            security.request_context(headers,'127.0.0.1',web)


class HttpSecurityTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.now=100
        self.enterContext(patch('time.monotonic',side_effect=lambda:self.now))
        self.enterContext(patch.dict(configuration.CONFIG['web'],deepcopy(configuration.DEFAULTS['web'])))
        self.enterContext(patch.dict(configuration.CONFIG['web'],{'controls_enabled':True}))
        self.enterContext(patch.dict(configuration.CONFIG['auth'],deepcopy(configuration.DEFAULTS['auth'])))
        self.credentials=Mock(username='admin')
        self.credentials.verify.side_effect=lambda username,password: username=='admin' and password==PASSWORD
        self.auth=security.Security(configuration.CONFIG['auth'],self.credentials)
        self.server=SimpleNamespace(security=self.auth)
        self.rpc=self.enterContext(patch.object(dashboard,'rpc',return_value={'message':'Submitted'}))

    def request(self,method,path,body=None,headers=None,peer='127.0.0.1',host='localhost:8085'):
        # Exercise BaseHTTPRequestHandler's actual HTTP parsing over a Unix socket pair.
        client,connection=socket.socketpair()
        client.settimeout(3)
        connection.settimeout(3)
        payload=b'' if body is None else (body if isinstance(body,bytes) else json.dumps(body).encode())
        lines=[f'{method} {path} HTTP/1.0','Host: '+host]
        supplied=dict(headers or {})
        if body is not None:
            supplied.setdefault('Content-Type','application/json')
            supplied.setdefault('Content-Length',str(len(payload)))
        lines.extend(name+': '+value for name,value in supplied.items())
        errors=[]
        def run():
            try:
                dashboard.Handler(connection,(peer,10000),self.server)
            except BaseException as error:
                errors.append(error)
            finally:
                connection.close()
        thread=threading.Thread(target=run)
        thread.start()
        try:
            client.sendall(('\r\n'.join(lines)+'\r\n\r\n').encode()+payload)
            client.shutdown(socket.SHUT_WR)
            raw=bytearray()
            while True:
                part=client.recv(65536)
                if not part:
                    break
                raw.extend(part)
        finally:
            client.close()
            thread.join(3)
        if errors:
            raise errors[0]
        self.assertFalse(thread.is_alive())
        head,content=bytes(raw).split(b'\r\n\r\n',1)
        status=int(head.split(b' ',2)[1])
        response={}
        for line in head.decode().split('\r\n')[1:]:
            name,value=line.split(':',1)
            response[name.lower()]=value.strip()
        data=json.loads(content) if response.get('content-type','').startswith('application/json') else content.decode()
        return status,response,data

    def login(self):
        status,headers,data=self.request('GET','/api/session')
        self.assertEqual(status,200)
        cookie=headers['set-cookie'].split(';')[0]
        status,headers,result=self.request('POST','/api/auth/login',{'username':'admin','password':PASSWORD},
            {'Cookie':cookie,'X-CSRF-Token':data['csrf']})
        self.assertEqual(status,200)
        return headers['set-cookie'].split(';')[0],result['csrf']

    def test_default_private_views_and_all_mutations_require_authentication(self):
        self.assertNotIn('AllStarLink Node',self.request('GET','/')[2])
        for path in ('/api/activity','/api/links','/api/favorites'):
            self.assertEqual(self.request('GET',path)[0],401)
        for path in ('/api/control','/api/favorites','/api/auth/logout','/api/session/touch'):
            self.assertEqual(self.request('POST',path,{'action':'first'})[0],401)
        self.rpc.assert_not_called()

    def test_anonymous_mode_is_read_only_and_does_not_expose_manager(self):
        with patch.dict(configuration.CONFIG['web'],{'anonymous_view':True}), \
             patch.object(dashboard,'activity_payload',return_value={'favorites':[]}):
            self.assertEqual(self.request('GET','/api/activity')[0],200)
            self.assertEqual(self.request('GET','/api/links')[0],200)
            self.assertEqual(self.request('GET','/api/favorites')[0],401)
            self.assertEqual(self.request('POST','/api/control',{'action':'first'})[0],401)
            self.assertEqual(self.request('POST','/api/favorites',{'action':'add','node':'1001','name':'Test'})[0],401)
        self.rpc.assert_called_once_with('links')

    def test_login_rotates_cookie_and_authenticates_control(self):
        cookie,csrf=self.login()
        for path,payload,op in (('/api/control',{'action':'first'},'control'),
                                ('/api/favorites',{'action':'up','node':'1001'},'favorites')):
            status,_,_=self.request('POST',path,payload,{'Cookie':cookie,'X-CSRF-Token':csrf})
            self.assertEqual(status,200)
            self.rpc.assert_called_with(op,payload)
        with patch.object(dashboard.favorites_store,'read',return_value=[]):
            self.assertEqual(self.request('GET','/api/favorites',headers={'Cookie':cookie})[0],200)

    def test_csrf_required_for_every_mutation_even_with_a_valid_admin_cookie(self):
        cookie,csrf=self.login()
        for path in ('/api/control','/api/favorites','/api/auth/logout','/api/session/touch'):
            for token in (None,'wrong'):
                headers={'Cookie':cookie}
                if token:
                    headers['X-CSRF-Token']=token
                self.assertEqual(self.request('POST',path,{},headers)[0],403)
        self.rpc.assert_not_called()

    def test_login_itself_requires_preauth_csrf_and_correct_origin(self):
        payload={'username':'admin','password':PASSWORD}
        self.assertEqual(self.request('POST','/api/auth/login',payload)[0],403)
        _,headers,session=self.request('GET','/api/session')
        values={'Cookie':headers['set-cookie'].split(';')[0],'X-CSRF-Token':session['csrf'],'Origin':'https://evil.example'}
        self.assertEqual(self.request('POST','/api/auth/login',payload,values)[0],403)
        self.credentials.verify.assert_not_called()

    def test_cross_site_post_with_real_csrf_is_rejected(self):
        cookie,csrf=self.login()
        for values in ({'Origin':'https://evil.example'},{'Sec-Fetch-Site':'cross-site'}):
            headers={'Cookie':cookie,'X-CSRF-Token':csrf}|values
            self.assertEqual(self.request('POST','/api/control',{'action':'stop'},headers)[0],403)
        self.rpc.assert_not_called()

    def test_logout_revokes_session_and_old_csrf(self):
        cookie,csrf=self.login()
        status,headers,_=self.request('POST','/api/auth/logout',{}, {'Cookie':cookie,'X-CSRF-Token':csrf})
        self.assertEqual(status,200)
        self.assertIn('Max-Age=0',headers['set-cookie'])
        self.assertEqual(self.request('POST','/api/control',{'action':'first'},{'Cookie':cookie,'X-CSRF-Token':csrf})[0],401)

    def test_expiration_not_extended_by_background_reads(self):
        with patch.dict(self.auth.settings,{'session_idle_seconds':10}):
            cookie,csrf=self.login()
            with patch.object(dashboard,'activity_payload',return_value={'favorites':[]}):
                self.now=109
                self.assertEqual(self.request('GET','/api/activity',headers={'Cookie':cookie})[0],200)
                self.now=110
                self.assertEqual(self.request('GET','/api/activity',headers={'Cookie':cookie})[0],401)
            self.assertEqual(self.request('POST','/api/control',{'action':'first'},{'Cookie':cookie,'X-CSRF-Token':csrf})[0],401)

    def test_explicit_user_activity_refreshes_idle_timeout(self):
        with patch.dict(self.auth.settings,{'session_idle_seconds':10}):
            cookie,csrf=self.login()
            self.now=109
            self.assertEqual(self.request('POST','/api/session/touch',{}, {'Cookie':cookie,'X-CSRF-Token':csrf})[0],200)
            self.now=115
            self.assertEqual(self.request('POST','/api/control',{'action':'first'}, {'Cookie':cookie,'X-CSRF-Token':csrf})[0],200)

    def test_login_attempt_limits_include_username_changes_and_have_retry_after(self):
        _,headers,data=self.request('GET','/api/session')
        values={'Cookie':headers['set-cookie'].split(';')[0],'X-CSRF-Token':data['csrf']}
        for number in range(5):
            self.assertEqual(self.request('POST','/api/auth/login',{'username':'wrong'+str(number),'password':PASSWORD},values)[0],401)
        status,headers,data=self.request('POST','/api/auth/login',{'username':'admin','password':PASSWORD},values)
        self.assertEqual(status,429)
        self.assertIn('retry-after',headers)
        self.assertNotIn(PASSWORD,json.dumps(data))
        self.assertEqual(self.credentials.verify.call_count,5)

    def test_sensitive_limit_survives_cookie_rotation_and_favorites_actions(self):
        cookie,csrf=self.login()
        with patch.dict(configuration.CONFIG['auth'],{'sensitive_attempts':2}):
            for _ in range(2):
                self.assertEqual(self.request('POST','/api/favorites',{'action':'up','node':'1001'}, {'Cookie':cookie,'X-CSRF-Token':csrf})[0],200)
            self.assertEqual(self.request('POST','/api/control',{'action':'first'}, {'Cookie':cookie,'X-CSRF-Token':csrf})[0],429)

    def test_malformed_bodies_duplicate_keys_and_unexpected_types_are_controlled(self):
        cookie,csrf=self.login()
        headers={'Cookie':cookie,'X-CSRF-Token':csrf}
        for body in (b'null',b'[]',b'{broken',b'{"action":"stop","action":"first"}',b'{"action":NaN}'):
            with self.subTest(body=body):
                self.assertEqual(self.request('POST','/api/control',body,headers)[0],400)
        self.assertEqual(self.request('POST','/api/control',b'x'*4097,headers)[0],400)
        self.assertEqual(self.request('POST','/api/control',{},headers|{'Transfer-Encoding':'chunked'})[0],400)
        self.assertEqual(self.request('POST','/api/control',{},headers|{'Content-Type':'text/plain'})[0],415)
        self.rpc.assert_not_called()

    def test_forged_forwarded_identity_cannot_authorize_control(self):
        self.assertEqual(self.request('POST','/api/control',{'action':'first'},
            {'Tailscale-User-Login':'admin','X-Forwarded-User':'admin','X-Forwarded-Proto':'https'})[0],401)

    def test_security_headers_use_nonce_and_no_sensitive_html_for_private_view(self):
        status,headers,html=self.request('GET','/')
        self.assertEqual(status,200)
        self.assertEqual(headers['cache-control'],'no-store')
        self.assertEqual(headers['x-frame-options'],'DENY')
        self.assertNotIn('unsafe-inline',headers['content-security-policy'].split('script-src')[1].split(';')[0])
        self.assertNotIn('__NONCE__',html)
        self.assertNotIn(str(dashboard.CACHE),html)

    def test_tokens_and_passwords_not_in_json_or_access_logs(self):
        _,headers,data=self.request('GET','/api/session')
        raw_token=headers['set-cookie'].split(';')[0].split('=',1)[1]
        self.assertNotIn(raw_token,json.dumps(data))
        self.assertNotIn(PASSWORD,json.dumps(data))
        handler=object.__new__(dashboard.Handler)
        with patch('sys.stderr',new_callable=io.StringIO) as stderr:
            handler.log_message('request %s','password='+PASSWORD+' cookie='+raw_token)
        self.assertEqual(stderr.getvalue(),'')

    def test_https_proxy_login_sets_secure_cookie_and_ignores_identity_headers(self):
        configuration.CONFIG['web'].update(trusted_proxies=['127.0.0.1/32'],allowed_origins=['https://scanner.example'])
        proxy={'X-Forwarded-Proto':'https','X-Forwarded-For':'198.51.100.2','Tailscale-User-Login':'admin'}
        status,headers,session=self.request('GET','/api/session',headers=proxy,host='scanner.example')
        self.assertEqual(status,200)
        self.assertIn('; Secure',headers['set-cookie'])
        self.assertFalse(session['authenticated'])
        values=proxy|{'Cookie':headers['set-cookie'].split(';')[0],'X-CSRF-Token':session['csrf'],'Origin':'https://scanner.example'}
        status,headers,data=self.request('POST','/api/auth/login',{'username':'admin','password':PASSWORD},values,host='scanner.example')
        self.assertEqual(status,200)
        self.assertIn('; Secure',headers['set-cookie'])
        self.assertTrue(data['authenticated'])

    def test_explicit_lan_http_login_csrf_cookie_and_authorization(self):
        configuration.CONFIG['web'].update(bind='192.168.50.10',allow_lan_http=True,allowed_origins=['http://192.168.50.10:8085'])
        peer='192.168.50.11'
        host='192.168.50.10:8085'
        _,headers,session=self.request('GET','/api/session',peer=peer,host=host)
        self.assertTrue(session['transport_safe'])
        self.assertTrue(session['unencrypted_lan'])
        values={'Cookie':headers['set-cookie'].split(';')[0],'X-CSRF-Token':session['csrf'],'Origin':'http://'+host}
        self.assertEqual(self.request('POST','/api/auth/login',{'username':'admin','password':PASSWORD},values|{'X-CSRF-Token':'bad'},peer=peer,host=host)[0],403)
        status,headers,data=self.request('POST','/api/auth/login',{'username':'admin','password':PASSWORD},values,peer=peer,host=host)
        self.assertEqual(status,200)
        self.assertIn('HttpOnly',headers['set-cookie'])
        self.assertIn('SameSite=Strict',headers['set-cookie'])
        self.assertNotIn('; Secure',headers['set-cookie'])
        cookie={'Cookie':headers['set-cookie'].split(';')[0]}
        self.assertEqual(self.request('GET','/api/session',headers=cookie,peer=peer,host=host)[2]['authenticated'],True)
        self.assertEqual(self.request('POST','/api/control',{'action':'first'},cookie,peer=peer,host=host)[0],403)
        self.assertEqual(self.request('POST','/api/favorites',{'action':'up','node':'1001'},peer=peer,host=host)[0],401)
        self.assertEqual(self.request('POST','/api/control',{'action':'first'},cookie|{'X-CSRF-Token':data['csrf'],'Origin':'http://'+host},peer=peer,host=host)[0],200)


    def test_private_lan_login_is_denied_without_explicit_opt_in(self):
        configuration.CONFIG['web'].update(bind='192.168.50.10',allowed_origins=['http://192.168.50.10:8085'])
        _,headers,session=self.request('GET','/api/session',peer='192.168.50.11',host='192.168.50.10:8085')
        self.assertFalse(session['transport_safe'])
        values={'Cookie':headers['set-cookie'].split(';')[0],'X-CSRF-Token':session['csrf']}
        self.assertEqual(self.request('POST','/api/auth/login',{'username':'admin','password':PASSWORD},values,peer='192.168.50.11',host='192.168.50.10:8085')[0],403)
        self.credentials.verify.assert_not_called()

    def test_lan_http_does_not_allow_public_client_or_forwarded_spoof(self):
        configuration.CONFIG['web'].update(bind='192.168.50.10',allow_lan_http=True,allowed_origins=['http://192.168.50.10:8085'])
        _,_,session=self.request('GET','/api/session',headers={'X-Forwarded-For':'192.168.50.11','X-Forwarded-Proto':'https'},peer='198.51.100.2',host='192.168.50.10:8085')
        self.assertFalse(session['transport_safe'])

    def test_external_plain_http_login_is_denied(self):
        configuration.CONFIG['web']['allowed_origins']=['http://scanner.example']
        status,headers,session=self.request('GET','/api/session',peer='198.51.100.2',host='scanner.example')
        self.assertEqual(status,200)
        self.assertFalse(session['transport_safe'])
        values={'Cookie':headers['set-cookie'].split(';')[0],'X-CSRF-Token':session['csrf']}
        self.assertEqual(self.request('POST','/api/auth/login',{'username':'admin','password':PASSWORD},values,peer='198.51.100.2',host='scanner.example')[0],403)
        self.credentials.verify.assert_not_called()

    def test_global_login_rate_limit_cannot_be_bypassed_by_client_ip_changes(self):
        configuration.CONFIG['web'].update(trusted_proxies=['127.0.0.1/32'],allowed_origins=['https://scanner.example'])
        proxy={'X-Forwarded-Proto':'https'}
        _,headers,session=self.request('GET','/api/session',headers=proxy,host='scanner.example')
        values=proxy|{'Cookie':headers['set-cookie'].split(';')[0],'X-CSRF-Token':session['csrf']}
        for number in range(20):
            self.assertEqual(self.request('POST','/api/auth/login',{'username':'admin','password':'wrong'},values|{'X-Forwarded-For':f'198.51.100.{number+1}'},host='scanner.example')[0],401)
        self.assertEqual(self.request('POST','/api/auth/login',{'username':'admin','password':PASSWORD},values|{'X-Forwarded-For':'198.51.100.99'},host='scanner.example')[0],429)
        self.assertEqual(self.credentials.verify.call_count,20)

    def test_hash_concurrency_is_bounded(self):
        _,headers,session=self.request('GET','/api/session')
        values={'Cookie':headers['set-cookie'].split(';')[0],'X-CSRF-Token':session['csrf']}
        self.auth.hash_lock.acquire()
        try:
            self.assertEqual(self.request('POST','/api/auth/login',{'username':'admin','password':PASSWORD},values)[0],429)
        finally:
            self.auth.hash_lock.release()
        self.credentials.verify.assert_not_called()

    def test_maintenance_switch_cannot_be_bypassed_by_authenticated_admin(self):
        cookie,csrf=self.login()
        with patch.dict(configuration.CONFIG['web'],{'controls_enabled':False}):
            for path in ('/api/control','/api/favorites'):
                self.assertEqual(self.request('POST',path,{'action':'first'},{'Cookie':cookie,'X-CSRF-Token':csrf})[0],403)
        self.rpc.assert_not_called()

    def test_http_radio_dispatch_enforces_the_shared_destination_policy(self):
        import control_service
        driver=SimpleNamespace(CONFIG=configuration.CONFIG,LOCAL_NODE='1000',
            SCANNER_STATE=self.tmp/'state.json',LOCK=self.tmp/'control.lock',
            LAST_COMMAND=self.tmp/'last.json',SCANNER=self.tmp/'scanner.py',COOLDOWN_SECONDS=15,
            favorite_numbers=Mock(return_value={'1001'}),scheduled_net_numbers=Mock(return_value={'2001'}),
            direct_links=Mock(return_value=[]),run_link_action=Mock(return_value='Requested'),
            scan_action=Mock(return_value='Reported link confirmed'))
        service=control_service.ControlService(driver)
        self.rpc.side_effect=lambda op,payload: service.control(payload)
        cookie,csrf=self.login()
        headers={'Cookie':cookie,'X-CSRF-Token':csrf}
        with patch('subprocess.run',return_value=SimpleNamespace(returncode=0,stdout='Connection requested',stderr='')):
            for action in sorted(control_service.ACTIONS):
                driver.LAST_COMMAND.unlink(missing_ok=True)
                payload={'action':action}
                if action.endswith('-node'):
                    payload['node']='1001'
                elif action.endswith('-net'):
                    payload['node']='2001'
                self.assertEqual(self.request('POST','/api/control',payload,headers)[0],200)
            driver.LAST_COMMAND.unlink(missing_ok=True)
            for action in ('connect-node','disconnect-node','connect-net','disconnect-net'):
                self.assertEqual(self.request('POST','/api/control',{'action':action,'node':'9999'},headers)[0],403)
            self.assertEqual(self.request('POST','/api/control',{'action':'shell','command':'anything'},headers)[0],400)

    def test_http_favorites_actions_all_use_the_same_authorization_guard(self):
        cookie,csrf=self.login()
        for action in ('add','edit','remove','up','down'):
            payload={'action':action,'node':'1001','name':'Example'}
            self.assertEqual(self.request('POST','/api/favorites',payload)[0],401)
            self.assertEqual(self.request('POST','/api/favorites',payload,{'Cookie':cookie})[0],403)
            self.assertEqual(self.request('POST','/api/favorites',payload,{'Cookie':cookie,'X-CSRF-Token':csrf})[0],200)
            self.rpc.assert_called_with('favorites',payload)

    def test_http_session_cannot_authorize_remote_cleartext_access(self):
        cookie,csrf=self.login()
        configuration.CONFIG['web']['allowed_origins']=['http://scanner.example']
        self.assertEqual(self.request('POST','/api/control',{'action':'first'},
            {'Cookie':cookie,'X-CSRF-Token':csrf},peer='198.51.100.2',host='scanner.example')[0],403)
        self.rpc.assert_not_called()

    def test_logout_remains_available_after_sensitive_operation_limit(self):
        cookie,csrf=self.login()
        headers={'Cookie':cookie,'X-CSRF-Token':csrf}
        with patch.dict(configuration.CONFIG['auth'],{'sensitive_attempts':1}):
            self.assertEqual(self.request('POST','/api/control',{'action':'first'},headers)[0],200)
            self.assertEqual(self.request('POST','/api/control',{'action':'first'},headers)[0],429)
            self.assertEqual(self.request('POST','/api/auth/logout',{},headers)[0],200)

    def test_anonymous_preauth_csrf_cannot_authorize_writes(self):
        _,headers,session=self.request('GET','/api/session')
        values={'Cookie':headers['set-cookie'].split(';')[0],'X-CSRF-Token':session['csrf']}
        for path in ('/api/control','/api/favorites'):
            self.assertEqual(self.request('POST',path,{'action':'first'},values)[0],401)
        self.rpc.assert_not_called()

    def test_authorized_markup_has_no_inline_event_attributes_and_has_auth_controls(self):
        cookie,_=self.login()
        status,headers,html=self.request('GET','/',headers={'Cookie':cookie})
        self.assertEqual(status,200)
        self.assertNotIn('onclick="',html)
        self.assertIn('data-action="first"',html)
        self.assertIn('X-CSRF-Token',html)
        self.assertIn('Keep Screen Awake',html)
        self.assertIn('Manage Favorites',html)

    def test_session_bootstrap_is_rate_limited_to_bound_anonymous_allocations(self):
        for _ in range(10):
            self.assertEqual(self.request('GET','/api/session')[0],200)
        self.assertEqual(self.request('GET','/api/session')[0],429)
        self.assertEqual(len(self.auth.sessions.items),10)



class SecurityConfigTests(OfflineCase):
    def test_new_security_schema_and_invalid_settings(self):
        path=self.tmp/'config.toml'
        invalid=('[auth]\nsession_idle_seconds=0','[auth]\nsession_max_seconds=1',
                 '[auth]\nlogin_attempts=0','[auth]\ncredentials_file="relative"',
                 '[web]\nallowed_origins=["https://example.org/path"]',
                 '[web]\nallowed_origins=["https://user:secret@example.org"]',
                 '[web]\nallowed_origins=[123]','[web]\ntrusted_proxies=["arbitrary"]',
                 '[broker]\nweb_uid=-2','[broker]\nsocket_path="relative"')
        for text in invalid:
            path.write_text(text)
            with self.subTest(text=text),self.assertRaises(ValueError):
                configuration.load_config(path)
        path.write_text('[web]\nanonymous_view=true\nallowed_origins=["https://scanner.example"]\ntrusted_proxies=["127.0.0.1/32"]')
        result=configuration.load_config(path)
        self.assertTrue(result['web']['anonymous_view'])
        self.assertEqual(result['controls']['cooldown_seconds'],15)

    def test_bounded_rate_table_does_not_evict_buckets_to_allow_bypass(self):
        rates=security.RateLimits(capacity=1)
        rates.take('first',1,60)
        with self.assertRaises(security.Denied):
            rates.take('second',1,60)
        with self.assertRaises(security.Denied):
            rates.take('first',1,60)

    def test_only_administrator_principal_is_authorized(self):
        auth=security.Security(deepcopy(configuration.DEFAULTS['auth']),Mock(username='admin'))
        _,session=auth.sessions.create(False,'other-user')
        with self.assertRaises(security.Denied) as error:
            auth.authorize(session,session.csrf,mutation=True)
        self.assertEqual(error.exception.status,403)


class LanConfigurationTests(OfflineCase):
    def test_lan_http_requires_private_bind_and_exact_origin(self):
        for bind,origins in [('0.0.0.0',[]),('44.1.2.3',['http://44.1.2.3:8085']),('192.168.50.10',[])]:
            data=deepcopy(configuration.DEFAULTS)
            data['web'].update(bind=bind,allowed_origins=origins,allow_lan_http=True)
            path=self.tmp/'lan.toml'
            # JSON strings are also TOML strings for these simple values.
            path.write_text('[web]\nbind = '+json.dumps(bind)+'\nallow_lan_http = true\nallowed_origins = '+json.dumps(origins)+'\n')
            with self.subTest(bind=bind),self.assertRaises(ValueError):
                configuration.load_config(path)
