import json, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager import core
class VersionDisplayTests(unittest.TestCase):
    def test_known_revision(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as folder:
            root=Path(folder); (root/'vpsmanager').mkdir(); (root/'vpsmanager-source.json').write_text(json.dumps({'commit':'a'*40,'dirty':True}))
            with patch.object(core,'__file__',str(root/'vpsmanager/core.py')):
                self.assertIn('aaaaaaaaaaaa',core.display_version()); self.assertIn('локальные изменения',core.display_version())
    def test_no_metadata(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as folder, patch.object(core,'__file__',str(Path(folder)/'vpsmanager/core.py')):
            self.assertIn('неизвестна',core.display_version())
