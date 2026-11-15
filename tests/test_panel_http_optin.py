import sys, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.panel import Panel
from vpsmanager.core import Error

class HttpOptInTests(unittest.TestCase):
    def test_remote_http_still_denied_without_optin(self):
        with patch.object(Panel,'get_csrf') as csrf:
            with self.assertRaises(Error): Panel('http://192.0.2.1:23020/base/','user','password')
            csrf.assert_not_called()
    def test_remote_http_accepted_with_explicit_optin(self):
        with patch.object(Panel,'get_csrf',return_value=None), patch.object(Panel,'request') as request:
            panel=Panel('http://192.0.2.1:23020/base/','user','password',allow_remote_http=True)
            self.assertEqual(panel.url,'http://192.0.2.1:23020/base/')
            request.assert_called_once_with('login',{'username':'user','password':'password','twoFactorCode':''})
