import ipaddress, os, platform, re, shutil
from pathlib import Path
from .core import Error, VERSION, active, confirm, log, os_info, redact, run, supported, wait_active, write
from .transaction import Transaction, finish
PACKAGES=['curl','wget','ca-certificates','openssl','jq','iproute2','iputils-ping','dnsutils','socat','tar','unzip','python3','whiptail']

def install_packages(packages):
    supported(); missing=[]
    for package in packages:
        if not re.fullmatch(r'[a-z0-9+.-]+',package): raise Error('Некорректное имя пакета.')
        p=run(['dpkg-query','-W','-f=${Status}',package],check=False)
        if p.returncode or p.stdout.strip()!='install ok installed': missing.append(package)
    print('Отсутствуют:',', '.join(missing) or 'нет')
    if not missing: return
    confirm('Выполнить apt update и установить только отсутствующие пакеты')
    run(['apt-get','-o','DPkg::Lock::Timeout=120','update'],timeout=600)
    run(['apt-get','-o','DPkg::Lock::Timeout=120','install','-y',*missing],timeout=1200)
    for package in missing:
        if run(['dpkg-query','-W','-f=${Status}',package]).stdout.strip()!='install ok installed': raise Error('Пакет не установлен: '+package)
    log('packages_installed',packages=missing)

def diagnostics(online=False):
    checks=[]
    def add(name,cmd,required=False,predicate=None):
        try:
            p=run(cmd,check=False,timeout=20); ok=p.returncode==0 and (predicate(p.stdout) if predicate else True)
            checks.append({'name':name,'status':'OK' if ok else ('ERROR' if required else 'WARN'),'detail':redact(p.stdout[-6000:] or p.stderr[-1000:])})
        except Error as e: checks.append({'name':name,'status':'WARN','detail':str(e)})
    info=os_info(); checks.append({'name':'ОС','status':'OK' if (info.get('ID'),info.get('VERSION_ID')) in {('debian','12'),('debian','13'),('ubuntu','22.04'),('ubuntu','24.04')} else 'ERROR','detail':info.get('PRETTY_NAME',platform.platform())})
    usage=shutil.disk_usage('/'); checks.append({'name':'Диск','status':'OK' if usage.free>1024**3 else 'WARN','detail':str(usage.free//1024**2)+' MiB свободно'})
    for name,cmd in [('Память',['free','-m']),('Интерфейсы',['ip','-brief','addr']),('IPv4 default',['ip','-4','route','show','default']),('IPv6 default',['ip','-6','route','show','default']),('NTP',['timedatectl','show','-p','NTPSynchronized','--value']),('Порты',['ss','-lntup']),('3x-ui',['systemctl','is-active','x-ui']),('Ошибки пакетов',['dpkg','--audit']),('DNS',['resolvectl','status'])]:
        add(name,cmd,predicate=(lambda x:x.strip()=='yes') if name=='NTP' else (lambda x:bool(x.strip())) if 'default' in name else None)
    # Do not collect application journal lines: arbitrary user-defined log content may contain secrets.
    add('Состояние службы',['systemctl','show','x-ui','-p','ActiveState','-p','SubState','-p','Result','-p','NRestarts'])
    if online:
        for host in ('github.com','acme-v02.api.letsencrypt.org','deb.debian.org'):
            add('DNS '+host,['getent','ahosts',host])
            add('HTTPS '+host,['curl','--head','--fail','--silent','--show-error','--max-time','10','https://'+host])
        for family in ('-4','-6'):
            add('Исходящий адрес '+family,['curl',family,'--fail','--silent','--max-time','10','https://www.cloudflare.com/cdn-cgi/trace'])
    return {'version':VERSION,'checks':checks,'recommendations':['При DNS-ошибке сначала проверьте владельца /etc/resolv.conf и split DNS.','Пустой IPv6 default допустим, если IPv6 не предоставлен.','Доступность портов извне проверяется внешним клиентом.']}

def print_report(report):
    for item in report['checks']: print('['+item['status']+'] '+item['name']+': '+item['detail'])

def prepare():
    supported(); print_report(diagnostics(True)); install_packages(PACKAGES)
    if input('Настроить синхронизацию времени? [y/N]: ').lower()=='y': ntp()
    print_report(diagnostics(True))

def ntp():
    supported()
    running=[s for s in ('chrony','systemd-timesyncd','ntp','ntpsec') if active(s)]
    print('Активные службы времени:',running)
    if len(running)>1: raise Error('Работают конфликтующие службы NTP. Сначала выберите и отключите лишнюю вручную.')
    if running:
        print(run(['timedatectl','status']).stdout); return
    choice=input('Служба systemd-timesyncd / chrony [systemd-timesyncd]: ').strip() or 'systemd-timesyncd'
    if choice not in ('systemd-timesyncd','chrony'): raise Error('Неверная служба NTP.')
    install_packages([choice]); confirm('Включить '+choice)
    if choice=='systemd-timesyncd': run(['timedatectl','set-ntp','true'])
    run(['systemctl','enable','--now',choice]); wait_active(choice)
    print(run(['timedatectl','status']).stdout)

def dns():
    supported()
    path=Path('/etc/resolv.conf'); print('resolv.conf →',path.resolve()); print(path.read_text(errors='replace'))
    resolved=active('systemd-resolved')
    if resolved: print(run(['resolvectl','status']).stdout)
    iface=input('Интерфейс для DNS: ').strip()
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',iface): raise Error('Неверный интерфейс.')
    dns_values=[str(ipaddress.ip_address(s)) for s in input('DNS-серверы через пробел: ').split()]
    if not dns_values: raise Error('Нужны DNS-серверы.')
    confirm('Этот интерфейс должен обслуживать все DNS-запросы; это не VPN/split DNS')
    if active('NetworkManager'):
        conn=run(['nmcli','-g','GENERAL.CON-UUID','device','show',iface]).stdout.strip()
        if not re.fullmatch('[0-9a-fA-F-]{36}',conn): raise Error('Активный профиль NetworkManager не найден.')
        paths=['/etc/NetworkManager/system-connections']
        undo=[{'args':['nmcli','connection','reload']},{'args':['nmcli','device','reapply',iface]}]
        def apply():
            for family in (4,6):
                servers=[v for v in dns_values if ipaddress.ip_address(v).version==family]
                if servers:
                    prefix='ipv'+str(family)
                    run(['nmcli','connection','modify',conn,prefix+'.dns',','.join(servers),prefix+'.ignore-auto-dns','yes',prefix+'.dns-search','~.',prefix+'.dns-priority','-50'])
            run(['nmcli','device','reapply',iface])
    elif list(Path('/etc/netplan').glob('*.yaml')):
        ident=input('ID интерфейса в netplan: ').strip()
        if not re.fullmatch('[A-Za-z0-9_.-]+',ident): raise Error('Неверный netplan ID.')
        current=run(['netplan','get','ethernets.'+ident],check=False)
        if current.returncode or current.stdout.strip() in ('null',''): raise Error('ID не найден.')
        try: import yaml
        except ImportError: raise Error('Для чтения netplan нужен пакет python3-yaml (установите через apt).') from None
        original=yaml.safe_load(current.stdout)
        if not isinstance(original,dict): raise Error('Некорректный netplan профиль.')
        file=Path('/etc/netplan/99-vps-manager-dns.yaml'); paths=[str(file)]
        entry={'nameservers':{'addresses':dns_values,'search':['~.']}}
        for family in (4,6):
            if original.get('dhcp'+str(family)): entry['dhcp'+str(family)+'-overrides']={'use-dns':False,'use-domains':False}
        undo=[{'args':['netplan','apply']}]
        def apply():
            write(file,{'network':{'version':2,'ethernets':{ident:entry}}})
            run(['netplan','generate']); run(['netplan','apply'],timeout=60)
    elif resolved and active('systemd-networkd'):
        output=run(['networkctl','status',iface,'--no-pager'],env={**os.environ,'LC_ALL':'C'}).stdout
        match=re.search(r'Network File:\s+(\S+\.network)',output)
        if not match: raise Error('Не найден исходный networkd профиль.')
        file=Path('/etc/systemd/network')/(Path(match.group(1)).name+'.d')/'91-vps-manager-dns.conf'
        paths=[str(file)]; undo=[{'args':['networkctl','reload']},{'args':['networkctl','reconfigure',iface]}]
        def apply():
            write(file,'[Network]\nDNS=\n'+''.join('DNS='+v+'\n' for v in dns_values)+'Domains=\nDomains=~.\nDNSDefaultRoute=yes\n[DHCPv4]\nUseDNS=no\nUseDomains=no\n[DHCPv6]\nUseDNS=no\nUseDomains=no\n',0o644)
            run(['networkctl','reload']); run(['networkctl','reconfigure',iface])
    else:
        if path.is_symlink(): raise Error('resolv.conf принадлежит неизвестному менеджеру. Исправьте его исходный профиль.')
        confirm('Подтверждаете статический resolv.conf без DHCP/resolvconf/VPN, которые его перезаписывают')
        paths=[str(path)]; undo=[]
        def apply(): write(path,''.join('nameserver '+v+'\n' for v in dns_values),0o644)
    tx=Transaction('DNS configuration',paths,undo,180).arm()
    try:
        apply()
        if resolved: run(['resolvectl','flush-caches'])
        run(['getent','ahosts','github.com']); run(['curl','--fail','--silent','--max-time','15','https://github.com'])
        finish(tx)
    except BaseException: tx.rollback(); raise

def upgrade():
    supported(); print('APT upgrade не имеет универсального отката пакетов. Сначала создайте снимок VPS у провайдера.')
    confirm('Снимок создан; выполнить обычный apt upgrade без full-upgrade/reboot')
    run(['apt-get','-o','DPkg::Lock::Timeout=120','update'],timeout=600)
    # apt may require interactive conffile decisions, so leave its terminal attached.
    import subprocess
    result=subprocess.run(['apt-get','-o','DPkg::Lock::Timeout=120','upgrade'])
    if result.returncode: raise Error('APT upgrade завершился с ошибкой; проверьте журнал APT.')
