import base64
import threading
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa,ec
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from backend.checks import assess
from backend.email_validation import spf_syntax,dkim_key
from backend import scanners


class EmailValidationTests(unittest.TestCase):
    def check_records(self,spf='v=spf1 -all',dkim='v=DKIM1; p='):
        records={'example.test':[spf],'_dmarc.example.test':['v=DMARC1; p=reject'],'test._domainkey.example.test':[dkim]}
        return assess('example.test','test',threading.Event(),resolver=lambda name,_:{'status':'ok','records':records[name]})

    def test_reproduced_bad_spf_and_dkim_create_findings(self):
        r=self.check_records('v=spf1 INVALID-MECHANISM','v=DKIM1; p=not-a-real-key')
        self.assertEqual({f['title'] for f in r['findings']},{'SPF record malformed','DKIM key record malformed'})
        self.assertEqual(r['status'],'completed') # Successful assessment that found defects.

    def test_spf_invalid_mechanisms_addresses_and_prefixes(self):
        for term in ['bogus','ip4:999.1.1.1','ip4:192.0.2.1/33','ip6:2001:db8::/129','ip4:2001:db8::','ip4:192.0.2.1/255.255.255.0','include','include:','exists:bad..test','all:example.test','a/33','mx//129','ptr/24','++all']:
            with self.subTest(term=term):self.assertTrue(spf_syntax('v=spf1 '+term)[0])

    def test_spf_valid_syntax_and_unknown_modifiers(self):
        for record in ['v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all','v=spf1 a mx:mail.example.test/24//64 include:_spf.example.test ~all','v=spf1 ptr exists:example.test ?all','v=spf1 redirect=example.test exp=explain.example.test','v=spf1 a//64 future=x future=y -all','v=spf1']:
            with self.subTest(record=record):self.assertEqual(spf_syntax(record),([],[]))

    def test_duplicate_known_modifier_rejected(self):
        self.assertTrue(spf_syntax('v=spf1 redirect=a.test redirect=b.test')[0])

    def test_macro_is_incomplete_not_fabricated_pass(self):
        r=self.check_records('v=spf1 exists:%{i}.spf.example.test -all')
        self.assertEqual(r['status'],'partial')
        self.assertIn('macro',r['checks'][0]['error'])
        self.assertFalse(any(f['title']=='SPF record malformed' for f in r['findings']))

    def test_spf_version_prefix_is_not_valid_version(self):
        r=self.check_records('v=spf10 -all')
        self.assertIn('SPF record not found',[f['title'] for f in r['findings']])

    def test_dkim_rejects_base64_der_and_wrong_key_type(self):
        wrong=ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
        for value in ['@@@',base64.b64encode(b'not DER').decode(),base64.b64encode(wrong).decode()]:
            with self.subTest(value=value):self.assertTrue(dkim_key('v=DKIM1; p='+value)[1])

    def test_dkim_valid_rsa_spki_and_pkcs1(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=1024).public_key()
        for fmt in [PublicFormat.SubjectPublicKeyInfo,PublicFormat.PKCS1]:
            value=base64.b64encode(key.public_bytes(Encoding.DER,fmt)).decode()
            self.assertEqual(dkim_key('v=DKIM1; k=rsa; p='+value)[1:],([],[]))

    def test_dkim_ed25519_length(self):
        for size in [31,32,33]:
            errors=dkim_key('v=DKIM1; k=ed25519; p='+base64.b64encode(bytes(range(size))).decode())[1]
            self.assertEqual(bool(errors),size!=32)

    def test_dkim_tags_and_revocation(self):
        for record in ['v=DKIM2; p=','p=; v=DKIM1','v=DKIM1; p=; p=','v=DKIM1; invalid; p=','v=DKIM1; k=rsa']:
            with self.subTest(record=record):self.assertTrue(dkim_key(record)[1])
        self.assertIn('DKIM selector key revoked',[f['title'] for f in self.check_records()['findings']])

    def test_unknown_key_algorithm_is_not_assessed(self):
        r=self.check_records(dkim='v=DKIM1; k=future; p=YWJj')
        self.assertEqual(r['status'],'partial')
        self.assertEqual(r['checks'][-1]['assessment'],'DKIM validation incomplete')


class NetworkCoverageTests(unittest.TestCase):
    def xml(self,hosts='',exit='success'):
        return '<nmaprun version="test">'+hosts+'<runstats><finished exit="'+exit+'"/></runstats></nmaprun>'

    def host(self,state='open',status='up',timedout=False):
        return '<host timedout="'+str(timedout).lower()+'"><status state="'+status+'"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="18080"><state state="'+state+'"/></port></ports></host>'

    def scan(self,xml):
        with patch.object(scanners,'command',return_value=xml):return scanners.network('127.0.0.1','18080',threading.Event(),lambda _:None)

    def test_zero_hosts_has_explicit_partial_coverage(self):
        r=self.scan(self.xml());self.assertEqual(r['status'],'partial');self.assertEqual(r['coverage']['outcome'],'no_hosts_observed');self.assertFalse(r['coverage']['complete'])

    def test_failed_or_unfinished_xml_is_failure(self):
        for xml in [self.xml(exit='error'),'<nmaprun/>','broken']:
            with self.subTest(xml=xml),self.assertRaises(Exception):self.scan(xml)

    def test_open_and_closed_ports_are_assessed(self):
        for state in ['open','closed']:
            self.assertEqual(self.scan(self.xml(self.host(state)))['status'],'completed')

    def test_down_timedout_and_filtered_are_partial(self):
        for host in [self.host(status='down'),self.host(timedout=True),self.host('filtered')]:
            r=self.scan(self.xml(host));self.assertEqual(r['status'],'partial');self.assertEqual(r['findings'],[])

    def test_grouped_closed_ports_are_complete(self):
        host='<host><status state="up"/><address addr="127.0.0.1"/><ports><extraports state="closed" count="1"/></ports></host>'
        self.assertEqual(self.scan(self.xml(host))['status'],'completed')

    def test_missing_ports_are_partial(self):
        host='<host><status state="up"/><address addr="127.0.0.1"/><ports/></host>'
        self.assertEqual(self.scan(self.xml(host))['status'],'partial')

    def test_process_error_propagates_to_worker_failure(self):
        with patch.object(scanners,'command',side_effect=RuntimeError('Nmap failed')):
            with self.assertRaisesRegex(RuntimeError,'Nmap failed'):scanners.network('127.0.0.1','18080',threading.Event(),lambda _:None)
