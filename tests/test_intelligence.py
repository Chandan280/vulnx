import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from backend import intelligence


class IntelligenceTests(unittest.TestCase):
    def test_missing_version_is_not_a_cve_match(self):
        for cpe in ['cpe:/a:apache:log4j','cpe:/a:apache:log4j:*','apache log4j','../../secret']:
            self.assertIsNone(intelligence.normalize_cpe(cpe))

    def test_nmap_cpe_conversion_preserves_product_version(self):
        self.assertEqual(intelligence.normalize_cpe('cpe:/a:apache:log4j:2.14.1'),'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*')

    def test_real_api_shape_stays_candidate_not_confirmed(self):
        payload={'totalResults':1,'vulnerabilities':[{'cve':{'id':'CVE-2021-44228','descriptions':[{'lang':'en','value':'Fixture for parser test only.'}],'metrics':{}}}]}
        with tempfile.TemporaryDirectory() as temp,patch.object(intelligence,'CACHE',Path(temp)),patch.object(intelligence,'request_nvd',return_value=payload) as request:
            result=intelligence.by_cpe('cpe:/a:apache:log4j:2.14.1')
            self.assertEqual(result['candidates'][0]['id'],'CVE-2021-44228')
            self.assertIn('Candidate association',result['applicability'])
            self.assertEqual(request.call_args.args[0]['isVulnerable'],'')
            cached=intelligence.by_cpe('cpe:/a:apache:log4j:2.14.1')
            self.assertTrue(cached['cached']);self.assertEqual(request.call_count,1)
