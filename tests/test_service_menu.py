import sys, unittest
from pathlib import Path
from unittest.mock import patch, Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager import cli
class ServiceMenuTests(unittest.TestCase):
    @patch('vpsmanager.cli.supported')
    @patch('vpsmanager.cli.active',return_value=False)
    @patch('vpsmanager.cli.run',return_value=Mock(stdout='disabled'))
    @patch('vpsmanager.cli.service_command')
    @patch('builtins.input',side_effect=['4','0'])
    def test_enable_is_separate_from_start(self,_,command,run,active,supported):
        cli.service_action(); command.assert_called_once_with('enable','Включить автозапуск для')
    @patch('vpsmanager.cli.supported')
    @patch('vpsmanager.cli.confirm')
    @patch('vpsmanager.cli.run')
    @patch('vpsmanager.cli.active',return_value=True)
    @patch('vpsmanager.cli.xui.panel_health')
    def test_start_checks_health(self,health,active,run,confirm,supported):
        cli.service_command('start','Запустить'); run.assert_called_once_with(['systemctl','start','x-ui']); health.assert_called_once()
