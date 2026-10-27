import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from backend import server


class ResetTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.patches=[patch.object(server,'DATA',self.root),patch.object(server,'DB',self.root/'test.sqlite'),patch.object(server,'EVENTS',{})]
        for p in self.patches:p.start()
        server.initialize()
        with server.connection() as db:
            db.execute("INSERT INTO assets(id,domain,label,created,kind,owner_id) VALUES (?,?,?,?,?,'migration-admin')",('a','mail.vulnx.test','Lab',server.now(),'domain'))
            db.execute('INSERT INTO scans(id,status,asset_id) VALUES (?,?,?)',('s','completed','a'))
            server.audit(db,'test','private target')
        for folder in ('validation','nvd','tools'):
            (self.root/folder).mkdir()
            (self.root/folder/'owned.txt').write_text('test fixture')
        (self.root/'email-validation.json').write_text('{}')

    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.tmp.cleanup()

    def test_confirmation_required_without_side_effects(self):
        with self.assertRaises(ValueError):server.clear_workspace('delete')
        self.assertEqual(len(server.state()['assets']),1)
        self.assertTrue((self.root/'validation/owned.txt').exists())

    def test_active_worker_blocks_reset(self):
        server.EVENTS['s']=threading.Event()
        with self.assertRaises(ValueError):server.clear_workspace('DELETE ALL DATA')
        self.assertEqual(len(server.state()['assets']),1)

    def test_queued_row_blocks_reset_even_before_registration(self):
        with server.connection() as db:db.execute("UPDATE scans SET status='queued'")
        with self.assertRaises(ValueError):server.clear_workspace('DELETE ALL DATA')
        self.assertEqual(len(server.state()['assets']),1)

    def test_reset_removes_records_evidence_and_cache_but_keeps_tools(self):
        result=server.clear_workspace('DELETE ALL DATA')
        self.assertEqual(result['deleted']['assets'],1)
        self.assertEqual(server.state(),{'assets':[],'scans':[],'findings':[]})
        with server.connection() as db:
            for table in ('audit','occurrences','findings','scans','assets'):
                self.assertEqual(db.execute('SELECT count(*) FROM '+table).fetchone()[0],0)
        self.assertFalse((self.root/'validation').exists())
        self.assertFalse((self.root/'nvd').exists())
        self.assertFalse((self.root/'email-validation.json').exists())
        self.assertTrue((self.root/'tools/owned.txt').exists())
        server.initialize()
        self.assertEqual(server.state()['assets'],[])
        self.assertTrue(server.clear_workspace('DELETE ALL DATA')['ok'])

    def test_reset_endpoint_requires_csrf(self):
        h=object.__new__(server.Handler)
        h.headers={'Host':'127.0.0.1:8787','Content-Length':'35'}
        h.server=type('Server',(),{'server_port':8787})()
        h.path='/api/workspace/clear'
        h.rfile=io.BytesIO(b'{"confirmation":"DELETE ALL DATA"}')
        h.reply=lambda *args:setattr(h,'response',args)
        h.do_POST()
        self.assertEqual(h.response[0],403)
        self.assertEqual(len(server.state()['assets']),1)

    def test_reset_through_http_with_real_session(self):
        import urllib.request,http.cookiejar
        httpd=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        worker=threading.Thread(target=httpd.serve_forever,daemon=True);worker.start()
        try:
            jar=http.cookiejar.CookieJar()
            client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            base='http://127.0.0.1:'+str(httpd.server_port)+'/api/'
            session=json.load(client.open(base+'session'))
            self.assertIn('vulnx_session_'+str(httpd.server_port),[c.name for c in jar])
            credentials=json.loads((self.root/'bootstrap-admin.json').read_text())
            login=urllib.request.Request(base+'auth/login',data=json.dumps(credentials).encode(),headers={'Content-Type':'application/json','X-VulnX-CSRF':session['csrf']})
            session=json.load(client.open(login))
            request=urllib.request.Request(base+'workspace/clear',data=json.dumps({'confirmation':'DELETE ALL DATA'}).encode(),headers={'Content-Type':'application/json','X-VulnX-CSRF':session['csrf']})
            self.assertTrue(json.load(client.open(request))['ok'])
            self.assertEqual(json.load(client.open(base+'state')),{'assets':[],'scans':[],'findings':[]})
        finally:
            httpd.shutdown();httpd.server_close();worker.join()
