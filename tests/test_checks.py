import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from backend.checks import assess, domain_name, selector_name, parse_dns, Cancelled
from backend import server


class DNSChecks(unittest.TestCase):
    def test_domain_input_rejects_commands_urls_ips(self):
        for value in ['https://example.com', 'example.com;id', '-foo.com', '127.0.0.1', 'localhost', 'a.local', 'x..com']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                domain_name(value)
        self.assertEqual(domain_name(' EXAMPLE.COM. '), 'example.com')

    def test_selector_rejects_option_injection(self):
        for value in ['a b', 'a;id', '@resolver', 'x'*64]:
            with self.assertRaises(ValueError):
                selector_name(value)

    def test_txt_chunks_join_without_dropping_quotes(self):
        result = parse_dns(';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nexample.com. 60 IN TXT "v=spf1 " "-all"\n')
        self.assertEqual(result['records'], ['v=spf1 -all'])

    def test_nxdomain_distinct_from_servfail(self):
        self.assertEqual(parse_dns(';; status: NXDOMAIN')['status'], 'absent')
        self.assertEqual(parse_dns(';; status: SERVFAIL')['status'], 'error')
        self.assertEqual(parse_dns('', 'bind: Operation not permitted', 10)['status'], 'error')

    def test_network_failure_does_not_fabricate_missing_records(self):
        result = assess('example.com', '', threading.Event(), resolver=lambda *_: {'status':'error','records':[],'error':'timeout'})
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['checks'][-1]['status'], 'skipped')

    def test_realistic_records_and_scoped_dkim(self):
        records = {'example.com':['v=spf1 +all'], '_dmarc.example.com':['v=DMARC1; p=none'], 'mail._domainkey.example.com':['v=DKIM1; p=']}
        result = assess('example.com', 'mail', threading.Event(), resolver=lambda name,_: {'status':'ok','records':records[name]})
        self.assertEqual(result['status'], 'completed')
        self.assertEqual([f['severity'] for f in result['findings']], ['High','Low','Info'])
        self.assertTrue(all(f['cve'] is None for f in result['findings']))

    def test_partial_assessment_keeps_evidence(self):
        result = assess('example.com','',threading.Event(),resolver=lambda name,_: {'status':'ok','records':['v=spf1 -all']} if name=='example.com' else {'status':'error','records':[],'error':'SERVFAIL'})
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['findings'],[])

    def test_cancellation_not_a_clean_scan(self):
        event=threading.Event();event.set()
        with self.assertRaises(Cancelled):
            assess('example.com','',event)


class StorageAndReports(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.data=patch.object(server,'DATA',Path(self.tmp.name));self.data.start()
        self.db=patch.object(server,'DB',Path(self.tmp.name)/'test.sqlite');self.db.start()
        server.initialize()

    def tearDown(self):
        self.data.stop();self.db.stop();self.tmp.cleanup()

    def test_restart_marks_unfinished_jobs_failed(self):
        with server.connection() as db:
            db.execute('INSERT INTO scans(id,asset_id,domain,selector,status,stage,created,finished,result) VALUES (?,?,?,?,?,?,?,?,?)',('test','asset','example.com','','running','Querying SPF',server.now(),None,None))
        server.initialize()
        self.assertEqual(server.state()['scans'][0]['status'],'failed')

    def test_real_worker_persists_failed_dns_without_findings(self):
        with server.connection() as db:
            db.execute('INSERT INTO scans(id,asset_id,domain,selector,status,stage,created,finished,result) VALUES (?,?,?,?,?,?,?,?,?)',('test','asset','example.com','','queued','Waiting',server.now(),None,None))
        result={'status':'failed','checks':[],'findings':[],'limitations':['Resolver unavailable']}
        with patch.object(server,'assess',return_value=result):
            server.execute_scan('test','example.com','',threading.Event())
        saved=server.state()['scans'][0]
        self.assertEqual(saved['status'],'failed')
        self.assertEqual(saved['result']['findings'],[])
        self.assertIsNotNone(saved['finished'])

    def test_pdf_contains_a_real_document(self):
        result=assess('example.com','',threading.Event(),resolver=lambda *_:{'status':'error','records':[],'error':'timeout'})
        raw=server.pdf_report({'id':'test','domain':'example.com','status':'failed','result':result})
        self.assertTrue(raw.startswith(b'%PDF-'))
        self.assertGreater(len(raw),1000)


class HTTPGuards(unittest.TestCase):
    def handler(self,headers):
        h=object.__new__(server.Handler)
        h.headers=headers
        h.server=type('Server',(),{'server_port':8787})()
        h.reply=lambda *args: setattr(h,'response',args)
        return h

    def test_reject_dns_rebinding_host(self):
        h=self.handler({'Host':'attacker.example:8787'})
        self.assertFalse(h.allowed())
        self.assertEqual(h.response[0],403)

    def test_reject_cross_origin_mutation(self):
        h=self.handler({'Host':'127.0.0.1:8787','Origin':'https://attacker.example'})
        self.assertFalse(h.allowed(mutation=True))

    def test_sessions_are_isolated_by_port(self):
        h=self.handler({'Host':'127.0.0.1:8787','Cookie':'vulnx_session_8788='+server.TOKEN,'X-VulnX-CSRF':server.TOKEN})
        self.assertFalse(h.allowed(mutation=True))
        self.assertEqual(h.response[1]['code'],'session_expired')
        self.assertEqual(h.session_cookie_name(),'vulnx_session_8787')
        h.server.server_port=8788
        self.assertEqual(h.session_cookie_name(),'vulnx_session_8788')

    def test_mutation_requires_session_and_csrf(self):
        h=self.handler({'Host':'127.0.0.1:8787'})
        self.assertFalse(h.allowed(mutation=True))
        h=self.handler({'Host':'127.0.0.1:8787','Cookie':'vulnx_session_8787='+server.TOKEN,'X-VulnX-CSRF':server.TOKEN})
        self.assertTrue(h.allowed(mutation=True))


if __name__=='__main__':
    unittest.main()
