"""Optional tests against the actual official Xray binary."""
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.proxy import build_reality, build_cascade
from routing import parse_vless
BINARY=os.environ.get('VPS_MANAGER_TEST_XRAY')
@unittest.skipUnless(BINARY,'Set VPS_MANAGER_TEST_XRAY to a trusted Xray executable')
class RealXrayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary=Path(BINARY).resolve()
        result=subprocess.run([str(cls.binary),'x25519'],capture_output=True,text=True,check=True)
        fields={line.split(':',1)[0].strip().lower().replace(' ',''):line.split(':',1)[1].strip() for line in result.stdout.splitlines() if ':' in line}
        cls.private=fields['privatekey']; cls.public=fields.get('publickey') or fields.get('password') or fields['password(publickey)']
    def validate(self,config):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as d:
            path=Path(d)/'config.json'; path.write_text(json.dumps(config),encoding='utf-8')
            env={**os.environ,'XRAY_LOCATION_ASSET':str(self.binary.parent)}
            result=subprocess.run([str(self.binary),'run','-test','-config',str(path)],capture_output=True,text=True,env=env,timeout=30)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
    def test_reality_inbound(self):
        _,config=build_reality(23456,'www.microsoft.com',443,self.private,self.public,'11111111-1111-4111-8111-111111111111','0123456789abcdef','fixture')
        self.validate(config)
    def outbound(self,transport='tcp'):
        uri='vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443?security=reality&type='+transport+'&sni=www.microsoft.com&pbk='+self.public+'&sid=abcd'
        return parse_vless(uri)
    def test_reality_outbound(self): self.validate({'outbounds':[self.outbound()]})
    def test_cascade_ru_geodata(self):
        base={'inbounds':[{'tag':'entry','listen':'127.0.0.1','port':23456,'protocol':'socks','settings':{'auth':'noauth'}}],'outbounds':[{'tag':'direct','protocol':'freedom'}]}
        self.validate(build_cascade(base,self.outbound(),['entry']))
    def test_grpc_transport(self): self.validate({'outbounds':[self.outbound('grpc')]})
# End-to-end loopback test: an isolated TLS target, Reality server, SOCKS client,
# and HTTP origin. It neither contacts a real VPS nor uses live credentials.
import http.server, shutil, socket, ssl, threading, time
@unittest.skipUnless(BINARY,'Set VPS_MANAGER_TEST_XRAY to a trusted Xray executable')
class LoopbackRealityTests(unittest.TestCase):
    setUpClass=classmethod(RealXrayTests.setUpClass.__func__)
    def test_real_vless_handshake(self):
        openssl=os.environ.get('VPS_MANAGER_TEST_OPENSSL') or shutil.which('openssl')
        if not openssl: self.skipTest('OpenSSL executable is required for local TLS fixture')
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                self.send_response(200); self.end_headers(); self.wfile.write(b'VPS-MANAGER-E2E-OK')
        def free():
            with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as d:
            d=Path(d); cert=d/'cert.pem'; key=d/'key.pem'
            subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost'],capture_output=True,check=True,timeout=30)
            target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler); origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version=ssl.TLSVersion.TLSv1_3; ctx.load_cert_chain(cert,key); ctx.set_alpn_protocols(['h2','http/1.1']); target.socket=ctx.wrap_socket(target.socket,server_side=True)
            threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (target,origin)]
            for t in threads:t.start()
            server_port=free(); socks_port=free(); ident='11111111-1111-4111-8111-111111111111'; sid='0123456789abcdef'
            _,server=build_reality(server_port,'localhost',target.server_port,self.private,self.public,ident,sid,'e2e')
            server['inbounds'][0]['streamSettings']['realitySettings']['dest']='127.0.0.1:'+str(target.server_port)
            server['outbounds'][0]['settings']={'finalRules':[{'action':'allow','network':'tcp','ip':['127.0.0.1/32'],'port':str(origin.server_port)}]}
            uri='vless://'+ident+'@127.0.0.1:'+str(server_port)+'?security=reality&type=tcp&sni=localhost&pbk='+self.public+'&sid='+sid+'&flow=xtls-rprx-vision'
            client={'inbounds':[{'listen':'127.0.0.1','port':socks_port,'protocol':'socks','settings':{'auth':'noauth'}}],'outbounds':[parse_vless(uri)]}
            processes=[]; logs=[]
            try:
                for name,cfg in [('server',server),('client',client)]:
                    cfg['log']={'loglevel':'debug'}; file=d/(name+'.json'); file.write_text(json.dumps(cfg),encoding='utf-8')
                    log=open(d/(name+'.log'),'w',encoding='utf-8'); logs.append(log)
                    processes.append(subprocess.Popen([str(self.binary),'run','-config',str(file)],stdout=log,stderr=log))
                time.sleep(1)
                with socket.create_connection(('127.0.0.1',socks_port),timeout=10) as s:
                    s.sendall(b'\x05\x01\x00'); self.assertEqual(s.recv(2),b'\x05\x00')
                    s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+origin.server_port.to_bytes(2,'big'))
                    response=s.recv(10); self.assertEqual(response[1],0)
                    s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n'); data=b''
                    while True:
                        block=s.recv(4096)
                        if not block: break
                        data+=block
                    self.assertIn(b'VPS-MANAGER-E2E-OK',data)
            except Exception as e:
                details='\n'.join((d/(name+'.log')).read_text(encoding='utf-8',errors='replace') for name in ('server','client'))
                raise AssertionError(str(e)+'\n'+details) from e
            finally:
                for process in processes:
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
                for log in logs: log.close()
                for s in (target,origin): s.shutdown(); s.server_close()
                for t in threads:t.join()
