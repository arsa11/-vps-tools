import copy, json, sys, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.inbound_editor import draft, payload, edit, sniffing, target_address, clients
from vpsmanager.proxy import build_reality

class InboundEditorTests(unittest.TestCase):
    def entry(self): return build_reality(443,'example.com',443,'private','public','11111111-1111-4111-8111-111111111111','abcd','email')[0]
    def test_roundtrip_preserves_secrets_and_unknown_fields(self):
        entry=self.entry(); entry['streamSettings']=json.loads(entry['streamSettings'])
        entry['streamSettings']['extra']={'preserve':True}
        before=copy.deepcopy(entry)
        value=draft(entry); value['sniffing']['routeOnly']=False
        result=draft(payload(value))
        self.assertEqual(value,result)
        self.assertEqual(entry,before)
        self.assertEqual(result['settings']['clients'],draft(entry)['settings']['clients'])
    def test_cancel_leaves_original_unchanged(self):
        entry=self.entry(); before=copy.deepcopy(entry)
        with patch('builtins.input',return_value='0'): self.assertIsNone(edit(entry))
        self.assertEqual(entry,before)
    def test_sniffing_preserves_unknown_fields(self):
        value={'custom':42}
        with patch('builtins.input',side_effect=['да','да','нет','http,tls','example.com']): sniffing(value)
        self.assertTrue(value['enabled']); self.assertTrue(value['routeOnly'])
        self.assertEqual(value['domainsExcluded'],['example.com']); self.assertEqual(value['custom'],42)
    def test_clients_can_delete_without_exposing_id(self):
        value={'clients':[{'id':'secret','email':'fixture'}]}
        with patch('builtins.input',side_effect=['3','1','да','0']): clients(value)
        self.assertEqual(value['clients'],[])
    def test_ipv6_target(self):
        self.assertEqual(target_address('[::1]:443'),('::1',443,'[::1]:443'))
