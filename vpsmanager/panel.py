"""3x-ui authenticated API. Credentials remain in memory."""
import getpass, http.cookiejar, ipaddress, json, urllib.parse, urllib.request, urllib.error
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

def connect():
    import socket
    from .core import run
    url=input('URL ЛОКАЛЬНОЙ панели (с webBasePath, например http://127.0.0.1:2053/path/): ').strip()
    host=urllib.parse.urlsplit(url).hostname
    try:
        addresses={item[4][0] for item in socket.getaddrinfo(host,None)}
        local={'127.0.0.1','::1'}
        for item in json.loads(run(['ip','-j','address']).stdout):
            local.update(a['local'] for a in item.get('addr_info',[]))
        if not addresses or not addresses<=local: raise Error('Панель должна находиться на этом VPS: резервирование и откат выполняются локально.')
    except socket.gaierror: raise Error('Домен панели не разрешается.') from None
    return Panel(url,input('Логин: ').strip(),getpass.getpass('Пароль: '),getpass.getpass('Код 2FA, если включён (иначе Enter): '))
