import json, sys, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager import releases, xui
from vpsmanager.core import Error

class ReleaseSelectionTests(unittest.TestCase):
    def test_stable_and_arch_filter(self):
        items=[{'tag_name':'v3.4.5','assets':[{'name':'x-ui-linux-amd64.tar.gz'}]}, {'tag_name':'v3.4.6','prerelease':True,'assets':[{'name':'x-ui-linux-amd64.tar.gz'}]}, {'tag_name':'v3.4.7','assets':[{'name':'x-ui-linux-arm64.tar.gz'}]}]
        with patch.object(releases,'fetch',return_value=json.dumps(items).encode()): self.assertEqual([x['tag_name'] for x in releases.stable_releases('MHSanaei/3x-ui','amd64')],['v3.4.5'])
    def test_choose_and_verify_exact_tag(self):
        items=[{'tag_name':'v3.4.5'},{'tag_name':'v3.4.2'}]
        with patch.object(releases,'stable_releases',return_value=items), patch.object(releases,'release',return_value=items[1]) as fetch, patch('builtins.input',return_value='2'):
            self.assertEqual(xui.choose_release('amd64'),items[1]); fetch.assert_called_once_with('MHSanaei/3x-ui','v3.4.2')
    def test_manual_does_not_fallback(self):
        with patch.object(releases,'stable_releases',side_effect=Error('offline')), patch.object(releases,'release',side_effect=Error('missing')) as fetch, patch('builtins.input',side_effect=['0','v3.4.5']):
            with self.assertRaises(Error): xui.choose_release('amd64')
            fetch.assert_called_once_with('MHSanaei/3x-ui','v3.4.5')
    def test_cancel(self):
        with patch.object(releases,'stable_releases',return_value=[]),patch('builtins.input',return_value='q'),patch.object(releases,'release') as fetch:
            with self.assertRaises(Error): xui.choose_release('amd64')
            fetch.assert_not_called()
