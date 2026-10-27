import os
from pathlib import Path
import unittest
from unittest.mock import patch
from backend import deployment
from backend.runtime import configured_port


class DeploymentTests(unittest.TestCase):
    def test_public_binding_requires_explicit_security_configuration(self):
        with patch.dict(os.environ,{'VULNX_BIND':'0.0.0.0'},clear=True):
            with self.assertRaises(ValueError):deployment.validate(Path('/data'))

    def test_public_host_origin_and_target_are_exact_allowlists(self):
        settings={'VULNX_BIND':'0.0.0.0','VULNX_PUBLIC_ORIGIN':'https://frontend.example','VULNX_ALLOWED_HOSTS':'backend.example','VULNX_ALLOWED_TARGETS':'https://authorized.example:443/','VULNX_JWT_SECRET':'x'*48}
        with patch.dict(os.environ,settings,clear=True):
            deployment.validate(Path('/data'))
            self.assertEqual(deployment.allowed_hosts(8080),{'backend.example'})
            self.assertEqual(deployment.allowed_origins('backend.example'),{'https://frontend.example'})
            self.assertTrue(deployment.target_allowed('https://authorized.example:443/'))
            self.assertFalse(deployment.target_allowed('http://169.254.169.254/'))

    def test_missing_persistent_volume_prevents_startup(self):
        with patch.dict(os.environ,{'VULNX_REQUIRE_PERSISTENT_STORAGE':'1'},clear=True):
            with self.assertRaises(ValueError):deployment.validate(Path('/data'))
            with patch.dict(os.environ,{'RAILWAY_VOLUME_MOUNT_PATH':'/data'}):deployment.validate(Path('/data'))

    def test_provider_port_is_used_without_local_override(self):
        with patch.dict(os.environ,{'PORT':'8080'},clear=True):self.assertEqual(configured_port(),8080)
