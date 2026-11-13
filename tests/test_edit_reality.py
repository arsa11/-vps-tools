import copy, json, sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.proxy import build_reality, reality_payload

class EditRealityTests(unittest.TestCase):
    def test_preserves_clients_keys_and_transport(self):
        original,_=build_reality(443,'example.com',443,'private','public','client','abcd','email')
        before=copy.deepcopy(original)
        result=reality_payload(original,8443,'changed','example.org','example.org:443')
        self.assertEqual(original,before)
        self.assertEqual(result['settings'],original['settings'])
        stream=json.loads(result['streamSettings'])
        previous=json.loads(original['streamSettings'])
        self.assertEqual(stream['network'],previous['network'])
        self.assertEqual(stream['realitySettings']['privateKey'],'private')
        self.assertEqual(stream['realitySettings']['shortIds'],['abcd'])
        self.assertEqual(stream['realitySettings']['serverNames'],['example.org'])
        self.assertEqual(result['port'],8443)

