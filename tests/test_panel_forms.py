import copy, sys, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.panel_forms import find_target, sniffing_form, transport_form

class PanelFormsTests(unittest.TestCase):
    def test_target_selection_updates_both_sni_fields(self):
        value={'dest':'old.example:443','serverNames':['old.example'],'settings':{'serverName':'old.example','publicKey':'preserve'}}
        result={'domain':'new.example','address':'192.0.2.1','alpn':'h2','ms':10}
        with patch('builtins.input',side_effect=['new.example','1']), patch('vpsmanager.panel_forms.target_probe',return_value=result):
            find_target(value)
        self.assertEqual(value['dest'],'new.example:443')
        self.assertEqual(value['serverNames'],['new.example'])
        self.assertEqual(value['settings']['serverName'],'new.example')
        self.assertEqual(value['settings']['publicKey'],'preserve')
    def test_cancel_target_selection_does_not_change_settings(self):
        value={'dest':'old.example:443','serverNames':['old.example']}
        before=copy.deepcopy(value)
        result={'domain':'new.example','address':'192.0.2.1','alpn':'h2','ms':10}
        with patch('builtins.input',side_effect=['new.example','0']), patch('vpsmanager.panel_forms.target_probe',return_value=result):
            find_target(value)
        self.assertEqual(value,before)
    def test_sniffing_menu_toggles_independently(self):
        value={'custom':42}
        with patch('builtins.input',side_effect=['1','2','4','1,2','0']):
            sniffing_form(value)
        self.assertTrue(value['enabled'])
        self.assertTrue(value['routeOnly'])
        self.assertEqual(value['destOverride'],['http','tls'])
        self.assertEqual(value['custom'],42)
    def test_grpc_preserves_reality_keys(self):
        value={'network':'tcp','realitySettings':{'privateKey':'preserve'}}
        with patch('builtins.input',side_effect=['3','service','0']):
            transport_form(value)
        self.assertEqual(value['grpcSettings']['serviceName'],'service')
        self.assertEqual(value['realitySettings']['privateKey'],'preserve')

    def test_null_inactive_transport_settings(self):
        value={'network':'tcp','wsSettings':None}
        with patch('builtins.input',side_effect=['2','/ws','example.com','0']):
            transport_form(value)
        self.assertEqual(value['wsSettings']['path'],'/ws')
        self.assertEqual(value['wsSettings']['headers']['Host'],'example.com')
