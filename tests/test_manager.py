import contextlib, io, json, os, sqlite3, sys, tarfile, tempfile, unittest, zipfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager import backup, core, releases, transaction, proxy, network

class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]); self.root=Path(self.tmp.name); self.source=self.root/'source'; self.source.mkdir(); self.store=self.root/'backups'
    def tearDown(self): self.tmp.cleanup()
    def test_restore_preserves_sqlite_wal_snapshot(self):
        db=self.source/'panel.db'; connection=sqlite3.connect(db)
        try:
            connection.execute('PRAGMA journal_mode=WAL'); connection.execute('CREATE TABLE clients(id TEXT)'); connection.execute("INSERT INTO clients VALUES('original')"); connection.commit()
            snapshot=backup.create([str(self.source)],base=self.store)
            connection.execute("INSERT INTO clients VALUES('later')"); connection.commit()
        finally: connection.close()
        (self.source/'extra.txt').write_text('new')
        backup.restore(snapshot)
        with contextlib.closing(sqlite3.connect(db)) as restored: self.assertEqual(restored.execute('SELECT id FROM clients').fetchall(),[('original',)])
        self.assertFalse((self.source/'extra.txt').exists())
    def test_missing_file_removed_on_restore(self):
        file=self.source/'new'; snapshot=backup.create([str(file)],base=self.store); file.write_text('added'); backup.restore(snapshot); self.assertFalse(file.exists())
    def test_checksum_failure_does_not_modify_source(self):
        file=self.source/'config'; file.write_text('original'); snapshot=backup.create([str(file)],base=self.store); (snapshot/'data/0').write_text('tampered'); file.write_text('current')
        with self.assertRaises(core.Error): backup.restore(snapshot)
        self.assertEqual(file.read_text(),'current')
    def test_path_traversal_manifest_rejected(self):
        file=self.source/'config'; file.write_text('original'); snapshot=backup.create([str(file)],base=self.store); m=core.read(snapshot/'manifest.json'); m['records'][0]['rel']='../../escape'; core.write(snapshot/'manifest.json',m)
        with self.assertRaises(core.Error): backup.verify(snapshot)
    def test_dangerous_root_rejected(self):
        file=self.source/'config'; file.write_text('original'); snapshot=backup.create([str(file)],base=self.store); m=core.read(snapshot/'manifest.json'); m['roots']=['/']; core.write(snapshot/'manifest.json',m)
        with self.assertRaises(core.Error): backup.verify(snapshot)
    def test_permissions(self):
        if os.name!='posix': self.skipTest('POSIX mode test runs in Linux CI')
        file=self.source/'config'; file.write_text('secret'); snapshot=backup.create([str(file)],base=self.store)
        self.assertEqual((snapshot/'data/0').stat().st_mode&0o777,0o600)
        self.assertEqual(snapshot.stat().st_mode&0o777,0o700)

class ArchiveTests(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]); self.root=Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def test_zip_traversal(self):
        archive=self.root/'bad.zip'
        with zipfile.ZipFile(archive,'w') as z: z.writestr('../escape','bad')
        with self.assertRaises(core.Error): releases.extract(archive,self.root/'out')
        self.assertFalse((self.root/'escape').exists())
    def test_tar_symlink(self):
        archive=self.root/'bad.tar'
        with tarfile.open(archive,'w') as t:
            entry=tarfile.TarInfo('link'); entry.type=tarfile.SYMTYPE; entry.linkname='/etc'; t.addfile(entry)
        with self.assertRaises(core.Error): releases.extract(archive,self.root/'out')
    def test_valid_tar(self):
        archive=self.root/'good.tar'
        with tarfile.open(archive,'w') as t:
            entry=tarfile.TarInfo('x-ui/x-ui'); entry.size=3; entry.mode=0o755; t.addfile(entry,io.BytesIO(b'bin'))
        releases.extract(archive,self.root/'out'); self.assertEqual((self.root/'out/x-ui/x-ui').read_bytes(),b'bin')
    @patch('vpsmanager.releases.fetch')
    def test_missing_release_never_falls_back(self,fetch):
        fetch.return_value=json.dumps({'tag_name':'v9','assets':[]}).encode()
        with self.assertRaises(core.Error): releases.release('MHSanaei/3x-ui','v1')
        self.assertEqual(fetch.call_count,1)

class ValidationTests(unittest.TestCase):
    def test_redaction(self):
        secret='vless://abc@example.com:443?pbk=abc'
        data=core.redact({'password':'secret','nested':{'privateKey':'secret'},'message':secret+' token=secret 11111111-1111-4111-8111-111111111111'})
        output=json.dumps(data); self.assertNotIn('secret',output); self.assertNotIn('vless://',output); self.assertNotIn('11111111',output)
    def test_port(self):
        for bad in [0,65536,'443; reboot',None]:
            with self.assertRaises(core.Error): core.port(bad)
        self.assertEqual(core.port('443'),443)
    def test_address(self):
        addr,gw=network.validate_address('203.0.113.2/32','203.0.113.1','eth0'); self.assertEqual(addr.network.prefixlen,32)
        for ip,gw,iface in [('fe80::1/64','fe80::2','eth0'),('1.2.3.4/24','::1','eth0'),('1.2.3.4','1.2.3.1','eth0'),('1.2.3.4/24','1.2.3.1','eth0;id')]:
            with self.assertRaises(core.Error): network.validate_address(ip,gw,iface)
    def test_cascade_idempotence(self):
        cfg={'routing':{'rules':[{'type':'field','domain':['blocked.example'],'outboundTag':'block'}]},'outbounds':[{'tag':'block','protocol':'blackhole'}]}
        outbound={'tag':'to-eu','protocol':'vless','settings':{}}
        first=proxy.build_cascade(cfg,outbound,['inbound-443']); second=proxy.build_cascade(first,outbound,['inbound-443'])
        self.assertEqual(first,second); self.assertEqual(cfg['outbounds'],[{'tag':'block','protocol':'blackhole'}]); self.assertEqual(len(first['routing']['rules']),4)
    def test_cascade_last_preserves_policy(self):
        cfg={'routing':{'rules':[{'outboundTag':'block'}]}}
        result=proxy.build_cascade(cfg,{'protocol':'vless'},['a'],mode='all-eu',priority='last')
        self.assertEqual(result['routing']['rules'][0],{'outboundTag':'block'})

class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]); self.root=Path(self.tmp.name)
        self.data={'id':'a'*32,'status':'armed','backup':'snapshot','name':'test','undo':[{'phase':'before','args':['stop']},{'args':['start']}],'deadline':10**12}
        core.write(self.root/'transaction.json',self.data)
    def tearDown(self): self.tmp.cleanup()
    @patch('vpsmanager.transaction.log')
    @patch('vpsmanager.transaction.cleanup')
    @patch('vpsmanager.transaction.run')
    @patch('vpsmanager.transaction.backup.restore')
    @patch('vpsmanager.transaction.lock',lambda *a:contextlib.nullcontext())
    def test_rollback_order_and_idempotence(self,restore,run,cleanup,log):
        sequence=[]; restore.side_effect=lambda *a:sequence.append('restore'); run.side_effect=lambda args,**kw:sequence.append(args[0])
        transaction.rollback(self.root); self.assertEqual(sequence,['stop','restore','systemctl','start']); self.assertEqual(core.read(self.root/'transaction.json')['status'],'rolled_back')
        transaction.rollback(self.root); self.assertEqual(restore.call_count,1)
    @patch('vpsmanager.transaction.log')
    @patch('vpsmanager.transaction.cleanup')
    @patch('vpsmanager.transaction.run')
    @patch('vpsmanager.transaction.backup.restore',side_effect=core.Error('disk failed'))
    @patch('vpsmanager.transaction.lock',lambda *a:contextlib.nullcontext())
    def test_failed_restore_retains_retry_state(self,restore,run,cleanup,log):
        with self.assertRaises(core.Error): transaction.rollback(self.root)
        self.assertEqual(core.read(self.root/'transaction.json')['status'],'failed'); cleanup.assert_not_called()
    @patch('vpsmanager.transaction.lock',lambda *a:contextlib.nullcontext())
    def test_expired_cannot_commit(self):
        self.data['deadline']=0; core.write(self.root/'transaction.json',self.data)
        tx=object.__new__(transaction.Transaction); tx.path=self.root
        with self.assertRaises(core.Error): tx.commit()

if __name__=='__main__': unittest.main()
