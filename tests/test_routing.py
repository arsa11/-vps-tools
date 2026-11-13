import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from routing import parse_vless, cascade
URI='vless://11111111-1111-4111-8111-111111111111@example.com:443?security=reality&type=tcp&sni=example.com&pbk='+('a'*43)+'&sid=abcd&flow=xtls-rprx-vision'
class RoutingTests(unittest.TestCase):
    def test_valid(self): self.assertEqual(parse_vless(URI)['protocol'],'vless')
    def test_invalid(self):
        for value in ['http://example.com',URI+'&security=tls',URI.replace('sid=abcd','sid=abc'),URI+'&unknown=secret']:
            with self.assertRaises(ValueError) as error: parse_vless(value)
            self.assertNotIn('secret',str(error.exception))
    def test_preserve(self):
        config={'inbounds':[{'tag':'entry'}],'routing':{'rules':[{'outboundTag':'block'}]}}
        result=cascade(config,parse_vless(URI),['entry'])
        self.assertEqual(result['routing']['rules'][0],config['routing']['rules'][0])
        self.assertNotIn('outbounds',config)
        with self.assertRaises(ValueError): cascade(result,parse_vless(URI),['entry'])
    def test_unknown_inbound(self):
        with self.assertRaises(ValueError): cascade({},parse_vless(URI),['missing'])
