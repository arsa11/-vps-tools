import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.security import explain_listeners
class ListenerExplanationTests(unittest.TestCase):
    def test_local_and_public_are_distinguished(self):
        output='Netid State Recv-Q Send-Q Local Peer Process\ntcp LISTEN 0 4096 127.0.0.1:1234 0.0.0.0:* users:(("xray",pid=1,fd=1))\ntcp LISTEN 0 4096 *:443 *:* users:(("xray",pid=1,fd=2))\n'
        result=explain_listeners(output)
        self.assertIn('только на сервере',result[0]); self.assertIn('доступ извне зависит',result[1]); self.assertIn('xray',result[1])
