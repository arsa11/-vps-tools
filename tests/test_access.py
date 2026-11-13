import sys, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.core import Error
from vpsmanager.xui import choose_access

class AccessChoiceTests(unittest.TestCase):
    def test_default_is_tunnel(self):
        with patch('builtins.input',return_value=''): self.assertEqual(choose_access(),'127.0.0.1')
    def test_external_requires_confirmation(self):
        with patch('builtins.input',side_effect=['2','да']): self.assertEqual(choose_access(),'0.0.0.0')
        with patch('builtins.input',side_effect=['2','']):
            with self.assertRaises(Error): choose_access()
    def test_invalid_fails(self):
        with patch('builtins.input',return_value='3'):
            with self.assertRaises(Error): choose_access()
