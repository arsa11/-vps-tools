import sqlite3, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.panel import detect_local_url
class PanelDiscoveryTests(unittest.TestCase):
    def test_read_existing_http_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            db=Path(folder)/'panel.db'; c=sqlite3.connect(db)
            c.execute('CREATE TABLE settings (key TEXT, value TEXT)')
            c.executemany('INSERT INTO settings VALUES (?,?)',[('webPort','2096'),('webListen','0.0.0.0'),('webBasePath','/example/')]); c.commit(); c.close()
            self.assertEqual(detect_local_url(db),'http://127.0.0.1:2096/example/')
    def test_https_without_domain_not_guessed(self):
        with tempfile.TemporaryDirectory() as folder:
            db=Path(folder)/'panel.db'; c=sqlite3.connect(db); c.execute('CREATE TABLE settings (key TEXT, value TEXT)'); c.execute("INSERT INTO settings VALUES ('webCertFile','/cert.pem')"); c.commit(); c.close()
            self.assertIsNone(detect_local_url(db))
    def test_missing_database(self): self.assertIsNone(detect_local_url(Path('missing-file.db')))
