import os, stat, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch, Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager import core, panel

class CredentialsTests(unittest.TestCase):
    def test_save_and_reuse_without_password_prompt(self):
        with tempfile.TemporaryDirectory() as d, patch.object(core,'STATE',Path(d)), patch.object(panel,'Panel') as api:
            with patch('builtins.input',side_effect=['admin','']), patch.object(panel.getpass,'getpass',side_effect=['secret','']):
                panel.authenticate('https://127.0.0.1/base/')
            path=Path(d)/'panel-access/credentials.json'
            self.assertEqual(core.read(path)['password'],'secret')
            if os.name=='posix': self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            api.reset_mock()
            with patch('builtins.input',return_value=''), patch.object(panel.getpass,'getpass',return_value='') as prompt:
                panel.authenticate('https://127.0.0.1/base/')
            api.assert_called_once_with('https://127.0.0.1/base/','admin','secret','')
            self.assertEqual(prompt.call_count,1)

    def test_failed_login_does_not_save_password(self):
        with tempfile.TemporaryDirectory() as d, patch.object(core,'STATE',Path(d)), patch.object(panel,'Panel',side_effect=core.Error('failed')):
            with patch('builtins.input',return_value='admin'), patch.object(panel.getpass,'getpass',return_value='secret'):
                with self.assertRaises(core.Error): panel.authenticate('https://127.0.0.1/')
            self.assertFalse((Path(d)/'panel-access/credentials.json').exists())

