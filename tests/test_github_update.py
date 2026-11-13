import io, json, sys, tarfile, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager import updates
from vpsmanager.core import Error
class GitHubUpdateTests(unittest.TestCase):
    def metadata(self,sha): return json.dumps({'sha':sha,'commit':{'message':'Test update\nmore'}}).encode()
    @patch('vpsmanager.updates.supported')
    def test_invalid_sha_does_not_download(self,supported):
        with patch.object(updates.releases,'fetch',return_value=self.metadata('../../bad')) as fetch, patch.object(updates,'deploy') as deploy:
            with self.assertRaises(Error): updates.github_update()
            self.assertEqual(fetch.call_count,1); deploy.assert_not_called()
    @patch('vpsmanager.updates.supported')
    def test_no_changes_skips_install(self,supported):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as d:
            root=Path(d); (root/'current').mkdir(); (root/'current/vpsmanager-source.json').write_text(json.dumps({'commit':'a'*40}))
            with patch.object(updates,'INSTALL',root),patch.object(updates.releases,'fetch',return_value=self.metadata('a'*40)) as fetch,patch.object(updates,'deploy') as deploy:
                updates.github_update(); self.assertEqual(fetch.call_count,1); deploy.assert_not_called()
    @patch('vpsmanager.updates.supported')
    def test_download_is_pinned_and_deployed(self,supported):
        sha='b'*40; buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w:gz') as tar:
            for name,data in [('repo/vps_manager.py',b'print(1)'),('repo/vps-manager.sh',b'#!/bin/sh'),('repo/vpsmanager/cli.py',b'pass')]:
                entry=tarfile.TarInfo(name); entry.size=len(data); tar.addfile(entry,io.BytesIO(data))
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as d:
            root=Path(d)
            with patch.object(updates,'INSTALL',root/'install'),patch.object(updates,'STATE',root/'state'),patch.object(updates,'confirm'),patch.object(updates,'run'),patch.object(updates.releases,'fetch',side_effect=[self.metadata(sha),buf.getvalue()]) as fetch,patch.object(updates,'deploy') as deploy:
                updates.github_update(); self.assertEqual(fetch.call_args_list[1].args[0],'https://codeload.github.com/arsa11/-vps-tools/tar.gz/'+sha); deploy.assert_called_once()
