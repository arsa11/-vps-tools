"""VPS Manager runtime: no shell interpolation, private state, redacted logs."""
import contextlib, datetime, hashlib, ipaddress, json, os, re, socket, subprocess, tempfile, time
from pathlib import Path
VERSION = '1.0.0'
STATE = Path(os.environ.get('VPS_MANAGER_STATE', '/var/lib/vps-manager'))
LOG = Path('/var/log/vps-manager/events.jsonl')
class Error(RuntimeError): pass

def private_dir(path):
    path=Path(path)
    if path.is_symlink(): raise Error('Каталог состояния не должен быть ссылкой.')
    path.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.name=='posix':
        if path.stat().st_uid != os.geteuid(): raise Error('Неверный владелец каталога состояния.')
        os.chmod(path,0o700)
    return path

def write(path, data, mode=0o600):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    if isinstance(data,(dict,list)): data=json.dumps(data,ensure_ascii=False,indent=2)+'\n'
    if isinstance(data,str): data=data.encode()
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.chmod(name,mode); os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)

def read(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def redact(value):
    if isinstance(value,dict):
        return {k:('[REDACTED]' if re.search(r'password|private|token|secret|uuid|shortid|publickey|webbasepath|^(id|sid|pbk)$',k,re.I) else redact(v)) for k,v in value.items()}
    if isinstance(value,list): return [redact(v) for v in value]
    if not isinstance(value,str): return value
    value=re.sub(r'vless://[^\s"\']+', '[VLESS REDACTED]',value)
    value=re.sub(r'(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b','[UUID REDACTED]',value)
    value=re.sub(r'(?is)-----BEGIN .*?PRIVATE KEY-----.*?-----END .*?PRIVATE KEY-----','[KEY REDACTED]',value)
    value=re.sub(r'(?i)((?:password|private[ _-]*key|token|secret|authorization|cookie|short[ _-]*id|public[ _-]*key|webbasepath)\s*[=:]\s*)[^\s,;]+',r'\1[REDACTED]',value)
    return value

def log(event,**fields):
    private_dir(STATE)
    target=LOG if os.name=='posix' and os.geteuid()==0 else STATE/'events.jsonl'
    private_dir(target.parent)
    fd=os.open(target,os.O_WRONLY|os.O_APPEND|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'a',encoding='utf-8') as f:
        f.write(json.dumps({'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'event':event,**redact(fields)},ensure_ascii=False)+'\n')

def run(args,check=True,timeout=30,input=None,cwd=None,env=None):
    try: p=subprocess.run([str(a) for a in args],capture_output=True,text=True,errors='replace',timeout=timeout,input=input,cwd=cwd,env=env)
    except (OSError,subprocess.TimeoutExpired): raise Error('Не удалось выполнить '+str(args[0])+' (отсутствует команда или превышен таймаут).') from None
    if check and p.returncode: raise Error(str(args[0])+' завершилась с ошибкой: '+redact(p.stderr[-1200:] or p.stdout[-1200:]))
    return p

def root():
    if os.name!='posix' or os.geteuid()!=0: raise Error('Изменения требуют Linux и root.')

def os_info():
    info={}
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                k,v=line.split('=',1); info[k]=v.strip('"')
    except OSError: pass
    return info

def supported():
    root(); i=os_info()
    if (i.get('ID'),i.get('VERSION_ID')) not in {('debian','12'),('debian','13'),('ubuntu','22.04'),('ubuntu','24.04')}: raise Error('Нужен Debian 12/13 или Ubuntu 22.04/24.04.')
    if not Path('/run/systemd/system').exists(): raise Error('Нужна система с работающим systemd.')

def confirm(message):
    if input(message+' [да/НЕТ]: ').strip().lower() not in ('да','yes','y'): raise Error('Операция отменена.')

def port(value):
    try: n=int(value)
    except (TypeError,ValueError): raise Error('Некорректный порт.') from None
    if not 1<=n<=65535: raise Error('Порт должен быть 1–65535.')
    return n

def hostname(value):
    try: return str(ipaddress.ip_address(value))
    except ValueError: pass
    value=value.encode('idna').decode('ascii')
    if len(value)>253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?',s) for s in value.split('.')): raise Error('Некорректный адрес/домен.')
    return value

def free_port(number,host='0.0.0.0'):
    number=port(number)
    family=socket.AF_INET6 if ':' in host else socket.AF_INET
    try:
        with socket.socket(family) as s: s.bind((host,number))
    except OSError: raise Error('Порт занят или адрес недоступен: '+str(number)+'. Посмотрите ss -lntup.') from None

def active(name):
    try: return run(['systemctl','is-active',name],check=False).returncode==0
    except Error: return False

def wait_active(name,seconds=15):
    for _ in range(seconds):
        if active(name): return
        time.sleep(1)
    raise Error('Служба '+name+' не запустилась.')

@contextlib.contextmanager
def lock(path=None):
    import fcntl
    path=Path(path or STATE/'manager.lock'); private_dir(path.parent)
    fd=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Error('Уже выполняется другая операция.') from None
        yield
    finally: os.close(fd)
