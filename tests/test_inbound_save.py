import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.inbound_editor import unsaved_fields

class SaveVerificationTests(unittest.TestCase):
    def test_unchanged_server_fields_may_be_normalized(self):
        before={'remark':'old','settings':{'clients':[]},'listen':''}
        expected={'remark':'new','settings':{'clients':[]},'listen':''}
        actual={'remark':'new','settings':{'clients':[],'defaults':True},'listen':'0.0.0.0'}
        self.assertEqual(unsaved_fields(before,expected,actual),[])
    def test_missing_client_is_rejected(self):
        old={'clients':[{'id':'a'}]}
        new={'clients':[{'id':'a'},{'id':'b','enable':True}]}
        self.assertEqual(unsaved_fields(old,new,old),['clients'])
    def test_added_client_defaults_and_order_are_allowed(self):
        old={'clients':[{'id':'a'}]}
        new={'clients':[{'id':'a'},{'id':'b','enable':True}]}
        actual={'clients':[{'id':'b','enable':True,'default':0},{'id':'a'}]}
        self.assertEqual(unsaved_fields(old,new,actual),[])
    def test_rejected_change_reports_path_not_value(self):
        self.assertEqual(unsaved_fields({'password':'old'},{'password':'secret'},{'password':'old'}),['password'])
    def test_removed_client_is_verified(self):
        old={'clients':[{'id':'a'},{'id':'b'}]}
        new={'clients':[{'id':'a'}]}
        self.assertEqual(unsaved_fields(old,new,old),['clients'])

    def test_unchanged_clients_must_not_disappear(self):
        before={'remark':'old','settings':{'clients':[{'id':'a'}]}}
        expected={'remark':'new','settings':{'clients':[{'id':'a'}]}}
        actual={'remark':'new','settings':{'clients':[]}}
        self.assertEqual(unsaved_fields(before,expected,actual),['settings.clients'])
    def test_unchanged_private_key_must_be_preserved(self):
        before={'remark':'old','streamSettings':{'realitySettings':{'privateKey':'secret'}}}
        expected={'remark':'new','streamSettings':{'realitySettings':{'privateKey':'secret'}}}
        actual={'remark':'new','streamSettings':{'realitySettings':{'privateKey':''}}}
        self.assertEqual(unsaved_fields(before,expected,actual),['streamSettings.realitySettings.privateKey'])
