import json, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch, Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager import network
class AddressesTests(unittest.TestCase):
    def test_collect_local_routes_and_external(self):
        interfaces=[{'ifname':'eth0','addr_info':[{'local':'192.0.2.10','prefixlen':24},{'local':'fe80::1','prefixlen':64}]}]
        outputs=[json.dumps(interfaces),json.dumps([{'gateway':'192.0.2.1','dev':'eth0'}]),'ip=8.8.8.8\n',json.dumps([]),'']
        def run(args,**kwargs):
            result=outputs.pop(0);return Mock(stdout=result,returncode=1 if args[0]=='curl' and '-6' in args else 0)
        with patch.object(network,'run',side_effect=run): result=network.collect_addresses()
        self.assertEqual(result['families']['4']['external_ip'],'8.8.8.8');self.assertEqual(result['families']['6']['external_status'],'unavailable')
        self.assertEqual(result['interfaces'][0]['addresses'][1]['category'],'link-local')
    def test_save_and_show(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as folder:
            state=Path(folder); snapshot=state/'snapshot.json'
            result={'checked_utc':'now','interfaces_status':'ok','interfaces':[],'families':{'4':{'external_ip':None,'default_routes':[]},'6':{'external_ip':None,'default_routes':[]}}}
            with patch.object(network,'STATE',state),patch.object(network,'IP_SNAPSHOT',snapshot),patch.object(network,'collect_addresses',return_value=result):
                network.check_addresses();self.assertTrue(snapshot.exists());network.show_saved_addresses()
