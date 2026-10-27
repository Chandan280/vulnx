import http.cookiejar
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
import jwt
from backend import server,auth


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.data=Path(self.temp.name)
        self.patches=[patch.object(server,'DATA',self.data),patch.object(server,'DB',self.data/'test.sqlite')]
        for p in self.patches:p.start()
        server.initialize()
        self.http=server.LocalHTTPServer(('127.0.0.1',0),server.Handler)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
        self.base=f'http://127.0.0.1:{self.http.server_port}/api/'

    def tearDown(self):
        self.http.shutdown();self.http.server_close();self.thread.join()
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()

    def client(self):
        client={'jar':http.cookiejar.CookieJar(),'csrf':''}
        client['op']=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(client['jar']))
        _,body=self.call(client,'session');client['csrf']=body['csrf'];return client

    def call(self,c,path,body=None):
        req=urllib.request.Request(self.base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','X-VulnX-CSRF':c['csrf']})
        try:r=c['op'].open(req,timeout=5)
        except urllib.error.HTTPError as exc:r=exc
        with r:
            raw=r.read();body=json.loads(raw) if 'json' in r.headers.get('Content-Type','') else raw
            if isinstance(body,dict) and 'csrf' in body:c['csrf']=body['csrf']
            return r.status,body

    def signup(self,email='one@example.test'):
        c=self.client();code,body=self.call(c,'auth/signup',{'email':email,'password':'Safe test password 123!'})
        self.assertEqual(code,201);return c,body['user']

    def test_signup_login_and_hashed_password(self):
        c,user=self.signup()
        with server.connection() as db:
            stored=db.execute('SELECT password_hash FROM users WHERE id=?',(user['id'],)).fetchone()[0]
        self.assertTrue(stored.startswith('$2b$12$'));self.assertNotIn('Safe test',stored)
        self.assertEqual(self.call(c,'auth/logout',{})[0],200)
        self.assertEqual(self.call(c,'auth/login',{'email':'ONE@example.test','password':'Safe test password 123!'})[0],200)
        self.assertEqual(self.call(c,'auth/me')[1]['id'],user['id'])

    def test_invalid_credentials_and_unauthenticated_access(self):
        c,_=self.signup()
        self.call(c,'auth/logout',{})
        for email,password in [('one@example.test','wrong'),('absent@example.test','Safe test password 123!')]:
            self.assertEqual(self.call(c,'auth/login',{'email':email,'password':password})[0],401)
        self.assertEqual(self.call(c,'state')[0],401)

    def test_expired_and_tampered_jwt_rejected(self):
        c,_=self.signup();cookie=next(k for k in c['jar'] if k.name.startswith('vulnx_auth_'));original=cookie.value
        claims=jwt.decode(original,auth.secret(self.data),algorithms=['HS256'],audience=auth.AUDIENCE)
        claims['exp']=int(time.time())-1
        cookie.value=jwt.encode(claims,auth.secret(self.data),algorithm='HS256')
        self.assertEqual(self.call(c,'state')[0],401)
        cookie.value=original[:-6]+'broken'
        self.assertEqual(self.call(c,'state')[0],401)

    def test_logout_revokes_copied_token(self):
        c,_=self.signup();cookie=next(k for k in c['jar'] if k.name.startswith('vulnx_auth_'))
        token=cookie.value;self.call(c,'auth/logout',{});cookie.value=token;c['jar'].set_cookie(cookie)
        self.assertEqual(self.call(c,'state')[0],401)

    def test_cross_user_reads_writes_exports_and_cancellation_rejected(self):
        a,user=self.signup();b,_=self.signup('two@example.test')
        body={'kind':'domain','domain':'example.test','authorized':True}
        self.assertEqual(self.call(a,'assets',body)[0],201)
        asset=self.call(a,'state')[1]['assets'][0]['id']
        with server.connection() as db:
            db.execute("INSERT INTO scans(id,asset_id,status,profile,domain) VALUES ('private-scan',?,'completed','email','example.test')",(asset,))
            db.execute("INSERT INTO findings(id,asset_id,title,status) VALUES ('private-finding',?,'Private fixture','open')",(asset,))
        self.assertEqual(self.call(b,'state')[1],{'assets':[],'scans':[],'findings':[]})
        for path,body in [('reports/private-scan.json',None),('reports/private-scan.pdf',None),('cancel/private-scan',{}),('findings/private-finding',{'status':'open'}),('scans',{'asset_id':asset,'profile':'email'})]:
            with self.subTest(path=path):self.assertEqual(self.call(b,path,body)[0],404)
        self.assertEqual(self.call(b,'workspace/clear',{'confirmation':'DELETE ALL DATA'})[0],200)
        self.assertEqual(len(self.call(a,'state')[1]['assets']),1)
        self.assertEqual(len(self.call(a,'state')[1]['findings']),1)
        self.assertEqual(self.call(b,'assets',{'kind':'domain','domain':'example.test','authorized':True})[0],201)

    def test_non_admin_cannot_change_lab_and_bad_csrf_rejected(self):
        c,_=self.signup()
        self.assertEqual(self.call(c,'lab-mode',{'fixed':True})[0],403)
        c['csrf']='bad'
        self.assertEqual(self.call(c,'workspace/clear',{'confirmation':'DELETE ALL DATA'})[0],403)

    def test_legacy_migration_preserves_rows_and_admin(self):
        # Independent legacy database, using the same migration entrypoint.
        legacy=self.data/'legacy.sqlite'
        with sqlite3.connect(legacy) as db:
            db.execute('CREATE TABLE assets(id TEXT PRIMARY KEY,domain TEXT UNIQUE,label TEXT,created TEXT,kind TEXT)')
            db.execute("INSERT INTO assets VALUES ('old','legacy.test','Legacy','yesterday','domain')")
        with patch.object(server,'DB',legacy):
            server.initialize();server.initialize()
            self.assertTrue((self.data/'legacy-before-auth.sqlite').exists())
            with sqlite3.connect(self.data/'legacy-before-auth.sqlite') as original:
                self.assertEqual(original.execute('SELECT id FROM assets').fetchone()[0],'old')
            with server.connection() as db:
                self.assertEqual(db.execute("SELECT owner_id FROM assets WHERE id='old'").fetchone()[0],auth.ADMIN_ID)
                self.assertEqual(db.execute('SELECT count(*) FROM users').fetchone()[0],1)
                self.assertEqual(db.execute('SELECT count(*) FROM schema_migrations').fetchone()[0],1)

    def test_password_limits_and_auth_rate_limit(self):
        for password in ['short','x'*73]:
            with self.assertRaises(ValueError):auth.password_hash(password)
        with server.connection() as db:
            for _ in range(20):self.assertTrue(auth.rate_limit(db,'test-peer'))
            self.assertFalse(auth.rate_limit(db,'test-peer'))
