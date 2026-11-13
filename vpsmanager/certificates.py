import ipaddress, os, re, socket, tempfile
from pathlib import Path
from .core import Error, STATE, active, confirm, free_port, hostname, private_dir, run, supported, write
from . import releases
from .transaction import Transaction, finish
from .xui import BINARY, PANEL_PATHS, undo_panel, panel_health
ACME=Path('/opt/vps-manager-acme/acme.sh')

def ensure_acme():
    if ACME.exists(): return
    confirm('Установить официальный acme.sh из проверяемого релиза GitHub в /opt/vps-manager-acme')
    rel=releases.release('acmesh-official/acme.sh'); tag=rel['tag_name']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',tag): raise Error('Неверный тег acme.sh.')
    data=releases.fetch('https://raw.githubusercontent.com/acmesh-official/acme.sh/'+tag+'/acme.sh',2*1024*1024)
    private_dir(ACME.parent); write(ACME,data,0o700)

def check_certificate(cert,key,identity):
    run(['openssl','x509','-in',cert,'-noout','-checkend','3600'])
    flag='-checkip' if is_ip(identity) else '-checkhost'
    run(['openssl','x509','-in',cert,'-noout',flag,identity])
    san=run(['openssl','x509','-in',cert,'-noout','-ext','subjectAltName']).stdout
    if 'DNS:' not in san and 'IP Address:' not in san: raise Error('В сертификате отсутствует SAN.')
    pub=run(['openssl','x509','-in',cert,'-noout','-pubkey']).stdout.strip()
    keypub=run(['openssl','pkey','-in',key,'-pubout'],input='').stdout.strip()
    if pub!=keypub: raise Error('Сертификат не соответствует приватному ключу.')
    # Parse every PEM certificate; CA trust is checked using system trust roots.
    text=Path(cert).read_text(); blocks=re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',text,re.S)
    if not blocks: raise Error('Нет PEM-сертификата.')
    private_dir(STATE/'tmp')
    with tempfile.TemporaryDirectory(dir=STATE/'tmp') as d:
        leaf=Path(d)/'leaf.pem'; chain=Path(d)/'chain.pem'; write(leaf,blocks[0]); write(chain,'\n'.join(blocks[1:]))
        cmd=['openssl','verify','-CApath','/etc/ssl/certs']
        if len(blocks)>1: cmd+=['-untrusted',str(chain)]
        run(cmd+[str(leaf)])
    return run(['openssl','x509','-in',cert,'-noout','-dates','-ext','subjectAltName']).stdout

def is_ip(identity):
    try: ipaddress.ip_address(identity); return True
    except ValueError: return False

def certificates():
    supported(); identity=hostname(input('Домен или публичный IP сертификата: ').strip())
    mode=input('issue — выпуск / existing — существующий [issue]: ').strip() or 'issue'
    if mode not in ('issue','existing'): raise Error('Неизвестный режим.')
    destination=private_dir(Path('/etc/vps-manager/certs')/identity)
    cert=destination/'fullchain.pem'; key=destination/'privkey.pem'
    paths=PANEL_PATHS+[str(destination),'/etc/systemd/system/vps-manager-acme.service','/etc/systemd/system/vps-manager-acme.timer','/etc/systemd/system/timers.target.wants/vps-manager-acme.timer',str(STATE/'acme')]
    source_cert=source_key=None
    if mode=='existing':
        source_cert=Path(input('Полная цепочка PEM: ').strip()).resolve(); source_key=Path(input('Приватный ключ PEM: ').strip()).resolve()
        print(check_certificate(source_cert,source_key,identity))
        if source_cert==cert or source_key==key: raise Error('Выберите исходные файлы вне каталога назначения.')
    else:
        if is_ip(identity) and not ipaddress.ip_address(identity).is_global: raise Error('Для IP-сертификата нужен публичный IP.')
        try: socket.getaddrinfo(identity,80); socket.getaddrinfo('acme-v02.api.letsencrypt.org',443)
        except socket.gaierror: raise Error('Ошибка DNS; сначала исправьте резолвер.') from None
        run(['curl','--fail','--silent','--max-time','15','https://acme-v02.api.letsencrypt.org/directory'])
        if run(['timedatectl','show','-p','NTPSynchronized','--value']).stdout.strip()!='yes': raise Error('Сначала синхронизируйте время.')
        free_port(80)
        confirm('TCP 80 разрешён снаружи в firewall VPS и у провайдера; локальная проверка этого не доказывает')
        ensure_acme()
        if is_ip(identity) and '--certificate-profile' not in run([ACME,'--help']).stdout: raise Error('Установленный acme.sh не поддерживает профили IP-сертификатов.')
    confirm('Подключить сертификат к 3x-ui с резервной копией')
    renewal_active=active('vps-manager-acme.timer')
    undo=undo_panel()+[{'args':['systemctl','enable' if renewal_active else 'disable','--now','vps-manager-acme.timer'],'required':False}]
    tx=Transaction('SSL certificate',paths,undo,600).arm()
    try:
        if mode=='existing': write(cert,source_cert.read_bytes()); write(key,source_key.read_bytes())
        else:
            email=input('Email ACME: ').strip()
            if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email): raise Error('Некорректный email.')
            home=private_dir(STATE/'acme')
            run([ACME,'--register-account','--server','letsencrypt','--home',home,'-m',email],timeout=120)
            cmd=[ACME,'--issue','--server','letsencrypt','--home',home,'--standalone','-d',identity,'--keylength','ec-256']
            if is_ip(identity): cmd+=['--certificate-profile','shortlived','--days','2']
            issued=run(cmd,timeout=240,check=False)
            if issued.returncode not in (0,2): raise Error('Выпуск ACME не удался. Проверьте DNS, доступность TCP 80 извне и лимиты CA.')
            run([ACME,'--install-cert','--home',home,'-d',identity,'--ecc','--key-file',key,'--fullchain-file',cert,'--reloadcmd','systemctl try-restart x-ui.service'],timeout=60)
            os.chmod(key,0o600); os.chmod(cert,0o600)
        print(check_certificate(cert,key,identity))
        run([BINARY,'cert','-webCert',cert,'-webCertKey',key],cwd=BINARY.parent)
        run(['systemctl','restart','x-ui']); panel_health()
        if mode=='issue':
            service=f'[Unit]\nDescription=Renew VPS Manager ACME certificates\nAfter=network-online.target\n[Service]\nType=oneshot\nUMask=0077\nExecStart={ACME} --cron --home {STATE}/acme\n'
            timer='[Unit]\nDescription=Frequent ACME renewal checks\n[Timer]\nOnCalendar=*-*-* 00,06,12,18:00:00\nRandomizedDelaySec=300\nPersistent=true\n[Install]\nWantedBy=timers.target\n'
            write('/etc/systemd/system/vps-manager-acme.service',service,0o644); write('/etc/systemd/system/vps-manager-acme.timer',timer,0o644)
            run(['systemctl','daemon-reload']); run(['systemctl','enable','--now','vps-manager-acme.timer'])
        finish(tx,'Проверьте HTTPS панели. Сертификат принят')
    except BaseException: tx.rollback(); raise
