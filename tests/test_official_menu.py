import sys, unittest
from pathlib import Path
from unittest.mock import patch, Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager import xui
from vpsmanager.core import Error
class OfficialMenuTests(unittest.TestCase):
    @patch('vpsmanager.xui.supported')
    @patch('vpsmanager.xui.BINARY')
    def test_missing_panel(self,binary,supported):
        binary.is_file.return_value=False
        with self.assertRaises(Error): xui.official_menu()
    @patch('vpsmanager.xui.supported')
    @patch('vpsmanager.xui.BINARY')
    @patch('vpsmanager.xui.shutil.which',return_value='/usr/bin/x-ui')
    @patch('vpsmanager.xui.os.access',return_value=True)
    @patch('vpsmanager.xui.Path.is_file',return_value=True)
    @patch('vpsmanager.xui.Path.resolve',side_effect=lambda: Path('/usr/bin/x-ui'))
    @patch('vpsmanager.xui.subprocess.run',return_value=Mock(returncode=0))
    def test_existing_menu_runs_interactively(self,process,resolve,is_file,access,which,binary,supported):
        binary.is_file.return_value=True; binary.resolve.return_value=Path('/usr/local/x-ui/x-ui')
        xui.official_menu(); process.assert_called_once_with([str(Path('/usr/bin/x-ui'))])
