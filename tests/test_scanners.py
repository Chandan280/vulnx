import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from backend import scope,scanners,server


class ScopeTests(unittest.TestCase):
    def test_reject_metadata_reserved_and_large_networks(self):
        for target in ['169.254.169.254','0.0.0.0','127.0.0.0/30','10.0.0.0/8','224.0.0.1','::1']:
            with self.subTest(target=target),self.assertRaises(ValueError):scope.network_target(target)
        self.assertEqual(scope.network_target('192.168.1.16/28'),'192.168.1.16/28')

    def test_restrict_local_control_ports(self):
        for url in ['http://127.0.0.1:8787/','http://169.254.169.254/','http://localhost:8787/','http://user:secret@example.com/']:
            with self.subTest(url=url),self.assertRaises(ValueError):scope.url_target(url)
        self.assertEqual(scope.url_target('http://127.0.0.1:18080/'),'http://127.0.0.1:18080/')

    def test_dns_rebinding_is_blocked_before_connect(self):
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',80))]):
            with self.assertRaises(ValueError):scope.resolved_url('http://example.com/')

    def test_ports_cannot_inject_flags(self):
        for value in ['80;id','-sV','0','65536',','.join(map(str,range(1,35)))]:
            with self.assertRaises(ValueError):scope.ports(value)

    def test_active_profile_is_lab_only(self):
        with self.assertRaises(ValueError):scope.validate_profile({'kind':'website','domain':'https://example.com:443/'},'web_active','80')


class InventoryTests(unittest.TestCase):
    def test_service_banner_is_preserved_without_inventing_a_cve(self):
        xml='<nmaprun version="test"><host><status state="up"/><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="18080"><state state="open"/><service name="http" product="Fixture" version="1.0" conf="10"><cpe>cpe:/a:fixture:fixture:1.0</cpe></service></port></ports></host></nmaprun>'
        hosts,version=scanners.parse_nmap(xml)
        self.assertEqual(hosts[0]['services'][0]['state'],'open')
        self.assertEqual(hosts[0]['services'][0]['cpes'],['cpe:/a:fixture:fixture:1.0'])
        self.assertNotIn('cve',hosts[0]['services'][0])


class RetestTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.data=patch.object(server,'DATA',Path(self.tmp.name));self.data.start()
        self.db=patch.object(server,'DB',Path(self.tmp.name)/'test.sqlite');self.db.start()
        server.initialize()
        with server.connection() as db:
            db.execute('INSERT INTO assets VALUES (?,?,?,?,?)',('a','http://127.0.0.1:18080/','Lab',server.now(),'website'))

    def tearDown(self):self.data.stop();self.db.stop();self.tmp.cleanup()

    def record(self,id,result,profile='web'):
        with server.connection() as db:
            db.execute('INSERT INTO scans(id,asset_id,domain,selector,status,stage,created,profile,ports) VALUES (?,?,?,?,?,?,?,?,?)',(id,'a','http://127.0.0.1:18080/','','running','Testing',server.now(),profile,'80'))
        server.reconcile(id,result)

    def finding(self):return scanners.finding('Missing header','Low','Response lacks header','Set header','http-header',endpoint='http://127.0.0.1:18080/')

    def test_failed_or_redirected_scan_never_verifies_fix(self):
        self.record('one',{'status':'completed','findings':[self.finding()],'coverage':{'content_assessed':True}})
        for i,result in enumerate([{'status':'failed','findings':[]},{'status':'completed','findings':[],'coverage':{'content_assessed':False}}]):
            self.record(str(i),result)
            self.assertEqual(server.state()['findings'][0]['status'],'open')

    def test_successful_comparable_retest_verifies_and_recurrence_reopens(self):
        self.record('one',{'status':'completed','findings':[self.finding()],'coverage':{'content_assessed':True}})
        self.record('two',{'status':'completed','findings':[],'coverage':{'content_assessed':True}})
        self.assertEqual(server.state()['findings'][0]['status'],'verified_fixed')
        self.record('three',{'status':'completed','findings':[self.finding()],'coverage':{'content_assessed':True}})
        self.assertEqual(server.state()['findings'][0]['status'],'reopened')
        self.assertEqual(len(server.state()['findings']),1)

    def test_active_zap_absence_does_not_establish_fix(self):
        self.record('one',{'status':'completed','findings':[self.finding()]},'web_active')
        self.record('two',{'status':'completed','findings':[]},'web_active')
        self.assertEqual(server.state()['findings'][0]['status'],'open')

    def test_multiple_payload_occurrences_share_one_finding(self):
        result={'status':'completed','findings':[self.finding(),self.finding()],'coverage':{'content_assessed':True}}
        self.record('one',result)
        self.assertEqual(len(server.state()['findings']),1)
        self.assertEqual(result['comparison']['new'],1)
