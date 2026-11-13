import http.server, json, sys, threading, unittest
from pathlib import Path
from urllib.parse import parse_qs
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.panel import Panel
from vpsmanager.core import Error

class PanelAPITests(unittest.TestCase):
    def server(self,modern):
        case=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def answer(self,obj,status=200,cookie=None):
                self.send_response(status); self.send_header('Content-Type','application/json')
                if cookie: self.send_header('Set-Cookie',cookie)
                self.end_headers(); self.wfile.write(json.dumps(obj).encode())
            def do_GET(self):
                if self.path=='/secret/csrf-token':
                    if not modern: return self.answer({},404)
                    return self.answer({'success':True,'obj':'test-csrf'},cookie='session=test; Path=/')
                if self.path=='/secret/panel/api/inbounds/list':
                    if 'session=test' not in self.headers.get('Cookie',''): return self.answer({'success':False})
                    return self.answer({'success':True,'obj':[{'port':443}]})
                return self.answer({'success':False,'msg':'password=do-not-echo'})
            def do_POST(self):
                data=parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
                if modern and self.headers.get('X-CSRF-Token')!='test-csrf': return self.answer({'success':False},403)
                if self.path=='/secret/login':
                    case.assertEqual(data['username'],['admin']); case.assertEqual(data['password'],['secret'])
                    return self.answer({'success':True},cookie='session=test; Path=/')
                if self.path=='/secret/panel/xray/': return self.answer({'success':True,'obj':json.dumps({'xraySetting':{'outbounds':[]},'outboundTestUrl':'https://example.org/'})})
                if self.path=='/secret/panel/xray/update':
                    case.assertEqual(data['outboundTestUrl'],['https://example.org/']); return self.answer({'success':True})
                return self.answer({'success':False,'msg':'password=do-not-echo'})
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        return server,thread
    def exercise(self,modern):
        server,thread=self.server(modern)
        try:
            panel=Panel('http://127.0.0.1:'+str(server.server_port)+'/secret/','admin','secret')
            self.assertEqual(panel.inbounds(),[{'port':443}]); cfg=panel.template(); panel.save_template(cfg)
            with self.assertRaises(Error) as error: panel.request('failure')
            self.assertNotIn('do-not-echo',str(error.exception))
        finally: server.shutdown(); server.server_close(); thread.join()
    def test_modern_csrf(self): self.exercise(True)
    def test_legacy_session(self): self.exercise(False)
    def test_plaintext_remote_rejected(self):
        with self.assertRaises(Error): Panel('http://example.com/path/','admin','secret')
