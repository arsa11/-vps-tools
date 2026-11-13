"""3x-ui authenticated API. Credentials remain in memory."""
import contextlib, getpass, http.cookiejar, ipaddress, json, socket, sqlite3, ssl, urllib.parse, urllib.request, urllib.error
from pathlib import Path
from .core import Error
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None
class Panel:
    def __init__(self,url,username,password,two_factor=''):
        p=urllib.parse.urlsplit(url)
        if p.scheme not in ('http','https') or not p.hostname or p.username or p.query or p.fragment: raise Error('Неверный URL панели.')
        if p.scheme=='http':
            try: local=ipaddress.ip_address(p.hostname).is_loopback
            except ValueError: local=p.hostname=='localhost'
            if not local: raise Error('HTTP разрешён только для localhost. Для удалённой панели используйте HTTPS.')
        self.url=url.rstrip('/')+'/'
        self.username=username; self.password=password; self.two_factor=two_factor
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),NoRedirect())
        self.csrf = self.get_csrf()
        self.request('login',{'username':username,'password':password,'twoFactorCode':two_factor})
        self.csrf = self.get_csrf()
    def get_csrf(self):
        try:
            with self.opener.open(self.url+'csrf-token',timeout=15) as response: obj=json.loads(response.read(65536))
            if obj.get('success') is not True or not isinstance(obj.get('obj'),str): raise Error('Некорректный CSRF-ответ панели.')
            return obj['obj']
        except urllib.error.HTTPError as e:
            if e.code==404: return None  # Older releases have no CSRF endpoint.
            raise Error('Не удалось получить CSRF-токен.') from None
        except (OSError,ValueError): raise Error('Ошибка связи при получении CSRF-токена.') from None
    def request(self,path,data=None):
        body=urllib.parse.urlencode({k:json.dumps(v) if isinstance(v,(dict,list,bool)) else v for k,v in data.items()}).encode() if data is not None else None
        req=urllib.request.Request(self.url+path.lstrip('/'),body,headers={'Accept':'application/json','X-Requested-With':'XMLHttpRequest',**({'X-CSRF-Token':self.csrf} if self.csrf else {})})
        try:
            with self.opener.open(req,timeout=20) as response:
                raw=response.read(16*1024*1024)
            obj=json.loads(raw)
        except (OSError,ValueError,urllib.error.URLError): raise Error('Ошибка API панели: проверьте URL, HTTPS, учётные данные и совместимость версии. Секреты не записаны в журнал.') from None
        if not isinstance(obj,dict) or obj.get('success') is not True: raise Error('Панель отклонила запрос '+path.split('/')[0]+'. Проверьте совместимость и права.')
        return obj.get('obj')
    def inbounds(self): return self.request('panel/api/inbounds/list')
    def settings(self): return self.request('panel/setting/all',{})
    def template(self):
        obj=self.request('panel/xray/',{})
        if isinstance(obj,str): obj=json.loads(obj)
        if not isinstance(obj,dict) or 'xraySetting' not in obj: raise Error('Несовместимый ответ API шаблона Xray.')
        self.outbound_test_url=obj.get('outboundTestUrl')
        config=obj['xraySetting']
        return json.loads(config) if isinstance(config,str) else config
    def save_template(self,config): return self.request('panel/xray/update',{'xraySetting':json.dumps(config),**({'outboundTestUrl':self.outbound_test_url} if getattr(self,'outbound_test_url',None) else {})})
    def restart_xray(self): return self.request('panel/api/server/restartXrayService',{})
    def status(self): return self.request('panel/api/server/status')

def detect_local_url(db=Path('/etc/x-ui/x-ui.db')):
    """Read non-secret panel settings only; never alter the panel database."""
    try:
        if not db.is_file(): return None
        with contextlib.closing(sqlite3.connect(db.resolve().as_uri()+'?mode=ro',uri=True)) as connection:
            rows=connection.execute("SELECT key,value FROM settings WHERE key IN ('webPort','webBasePath','webListen','webCertFile','webDomain')").fetchall()
        settings=dict(rows)
        number=int(settings.get('webPort') or 2053)
        if not 1<=number<=65535: return None
        path=settings.get('webBasePath') or '/'
        if not path.startswith('/') or any(c in path for c in ('?','#','\\','\n','\r')): return None
        if not path.endswith('/'): path+='/'
        listen=settings.get('webListen') or '127.0.0.1'
        if listen in ('0.0.0.0','::','::0'): listen='127.0.0.1' if listen=='0.0.0.0' else '::1'
        if settings.get('webCertFile'):
            # Certificate verification must use its actual hostname, never silently disable TLS checks.
            domain=settings.get('webDomain')
            if not domain:
                # Panel versions may omit webDomain, including certificates issued to a public IP.
                # Only suggest certificate identities actually belonging to this host.
                try:
                    from .core import run
                    interfaces=json.loads(run(['ip','-j','address']).stdout)
                    local={ipaddress.ip_address(a['local']) for iface in interfaces for a in iface.get('addr_info',[]) if a.get('local')}
                    local.update((ipaddress.ip_address('127.0.0.1'),ipaddress.ip_address('::1')))
                    cert=ssl._ssl._test_decode_cert(settings['webCertFile'])
                    for kind,value in cert.get('subjectAltName',[]):
                        if kind=='IP Address':
                            try:
                                if ipaddress.ip_address(value) in local: domain=value; break
                            except ValueError: continue
                        elif kind=='DNS' and not value.startswith('*.'):
                            try:
                                resolved={ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(value,None)}
                                if resolved and resolved<=local: domain=value; break
                            except (socket.gaierror,ValueError): continue
                except (OSError,ValueError,KeyError,TypeError,ssl.SSLError,Error): pass
            if not domain: return None
            host=domain
            scheme='https'
        else:
            try: host=str(ipaddress.ip_address(listen))
            except ValueError: return None
            scheme='http'
            if not ipaddress.ip_address(host).is_loopback:
                # Plain HTTP is deliberately limited to loopback by Panel.
                return None
        if ':' in host: host='['+host+']'
        return f'{scheme}://{host}:{number}{path}'
    except (OSError,ValueError,sqlite3.Error): return None

def connect():
    import socket
    from .core import run
    detected=detect_local_url()
    if detected:
        print('Обнаружен адрес панели:',detected)
        url=input('Нажмите Enter для него или введите другой URL: ').strip() or detected
    else:
        print('Адрес не определён автоматически (например, для HTTPS нужен домен сертификата).')
        url=input('URL ЛОКАЛЬНОЙ панели с webBasePath: ').strip()
    host=urllib.parse.urlsplit(url).hostname
    try:
        addresses={item[4][0] for item in socket.getaddrinfo(host,None)}
        local={'127.0.0.1','::1'}
        for item in json.loads(run(['ip','-j','address']).stdout):
            local.update(a['local'] for a in item.get('addr_info',[]))
        if not addresses or not addresses<=local: raise Error('Панель должна находиться на этом VPS: резервирование и откат выполняются локально.')
    except socket.gaierror: raise Error('Домен панели не разрешается.') from None
    return Panel(url,input('Логин: ').strip(),getpass.getpass('Пароль: '),getpass.getpass('Код 2FA, если включён (иначе Enter): '))
