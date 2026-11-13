"""Add provider-assigned addresses without deleting the existing SSH address."""
import datetime, ipaddress, json, re, secrets
from pathlib import Path
from .core import Error, STATE, active, confirm, os, private_dir, read, run, supported, write
from .transaction import Transaction, finish

def inspect():
    result={}
    for label,args in [('addresses',['ip','-j','address']),('routes4',['ip','-j','-4','route']),('routes6',['ip','-j','-6','route'])]:
        try: result[label]=json.loads(run(args).stdout)
        except Error as e: result[label]=str(e)
    result['manager']='NetworkManager' if active('NetworkManager') else 'netplan' if list(Path('/etc/netplan').glob('*.yaml')) else 'systemd-networkd' if active('systemd-networkd') else 'unknown'
    return result

IP_SNAPSHOT = STATE/'network-addresses.json'

def collect_addresses():
    """Read local addresses and routes, then independently probe external IPs."""
    result={'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'interfaces':[], 'families':{}}
    try:
        interfaces=json.loads(run(['ip','-j','address']).stdout)
        for interface in interfaces:
            addresses=[]
            for item in interface.get('addr_info',[]):
                value=item.get('local')
                try: ip=ipaddress.ip_address(value)
                except ValueError: continue
                if ip.is_loopback: continue
                category='link-local' if ip.is_link_local else ('глобальный' if ip.is_global else 'неглобальный')
                addresses.append({'address':value,'prefix':item.get('prefixlen'),'family':ip.version,'category':category})
            if addresses: result['interfaces'].append({'name':interface.get('ifname','?'),'addresses':addresses})
        result['interfaces_status']='ok'
    except (Error,ValueError,TypeError): result['interfaces_status']='unknown'
    for family in (4,6):
        entry={'default_routes':None,'external_ip':None,'external_status':'unknown'}
        try:
            routes=json.loads(run(['ip','-j','-'+str(family),'route','show','default']).stdout)
            entry['default_routes']=[{'gateway':r.get('gateway'),'dev':r.get('dev'),'metric':r.get('metric')} for r in routes]
        except (Error,ValueError,TypeError): pass
        try:
            response=run(['curl','-'+str(family),'--noproxy','*','--fail','--silent','--show-error','--max-time','10','https://www.cloudflare.com/cdn-cgi/trace'],timeout=12,check=False)
            values=[line[3:] for line in response.stdout.splitlines() if line.startswith('ip=')]
            address=ipaddress.ip_address(values[0]) if response.returncode==0 and len(values)==1 else None
            if address and address.version==family:
                entry['external_ip']=str(address); entry['external_status']='ok'
            else: entry['external_status']='unavailable'
        except (Error,ValueError): entry['external_status']='unavailable'
        result['families'][str(family)]=entry
    return result

def print_addresses(result):
    print('\nПроверено (UTC):',result.get('checked_utc','неизвестно'))
    if result.get('interfaces_status')!='ok': print('Не удалось прочитать адреса интерфейсов.')
    elif not result.get('interfaces'): print('На интерфейсах не найдено адресов кроме loopback.')
    for interface in result.get('interfaces',[]):
        print('Интерфейс',interface['name']+':')
        for address in interface['addresses']:
            print('  IPv'+str(address['family'])+': '+address['address']+'/'+str(address['prefix'])+' ('+address['category']+')')
    for family in ('4','6'):
        item=result.get('families',{}).get(family,{})
        routes=item.get('default_routes')
        if routes is None: route='не удалось определить'
        elif not routes: route='нет'
        else: route='; '.join('через '+str(r.get('gateway') or 'без шлюза')+' / '+str(r.get('dev') or '?') for r in routes)
        print('IPv'+family+' — маршрут по умолчанию:',route)
        print('IPv'+family+' — внешний IP:',item.get('external_ip') or 'не удалось определить')
    print('Внешний IP виден проверочному сервису Cloudflare. Неудачная проверка сама по себе не доказывает отсутствие IPv6.')

def check_addresses():
    result=collect_addresses()
    private_dir(STATE)
    previous=None
    try: previous=read(IP_SNAPSHOT) if IP_SNAPSHOT.is_file() else None
    except (OSError,ValueError): print('Предыдущий сохранённый результат не удалось прочитать.')
    print_addresses(result)
    if previous:
        for family in ('4','6'):
            old=previous.get('families',{}).get(family,{}).get('external_ip')
            new=result['families'][family].get('external_ip')
            if old and new and old!=new: print('Внешний IPv'+family+' изменился:',old,'→',new)
    write(IP_SNAPSHOT,result)
    print('Результат сохранён:',IP_SNAPSHOT,'(только последний результат, права 0600).')

def show_saved_addresses():
    try: result=read(IP_SNAPSHOT)
    except FileNotFoundError: raise Error('Сохранённого результата ещё нет. Сначала выберите проверку IPv4 и IPv6.') from None
    except (OSError,ValueError): raise Error('Не удалось прочитать сохранённый результат.') from None
    print('Последний сохранённый результат; состояние сети могло измениться:')
    print_addresses(result)

def validate_address(address,gateway,interface):
    try: addr=ipaddress.ip_interface(address); gw=ipaddress.ip_address(gateway)
    except ValueError: raise Error('Нужны корректные IP/CIDR и шлюз.') from None
    if '/' not in address or addr.version!=gw.version: raise Error('Укажите CIDR и шлюз того же семейства.')
    if addr.ip.is_loopback or addr.ip.is_multicast or addr.ip.is_unspecified or addr.ip.is_link_local: raise Error('Нужен маршрутизируемый адрес, не loopback/link-local.')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',interface): raise Error('Некорректное имя интерфейса.')
    return addr,gw

def change():
    supported(); state=inspect(); print(json.dumps(state,ensure_ascii=False,indent=2))
    iface=input('Интерфейс: ').strip(); address=input('Выделенный провайдером IP/CIDR: ').strip(); gateway=input('Шлюз провайдера: ').strip()
    addr,gw=validate_address(address,gateway,iface); family='-'+str(addr.version); src=str(addr.ip)
    run(['ip','link','show','dev',iface]); confirm('Подтверждаете, что этот адрес выделен и маршрутизируется вашим провайдером')
    onlink=gw not in addr.network and not gw.is_link_local
    if onlink: confirm('Шлюз вне префикса. Провайдер требует on-link маршрут (например /32)')
    defaults=json.loads(run(['ip','-j',family,'route','show','default']).stdout)
    policy=any(r.get('metric',0)<=5 for r in defaults)
    policy_table=30300
    if policy:
        existing_rules=run(['ip',family,'rule','show']).stdout
        if any(int(line.split(':',1)[0]) not in (0,32766,32767) for line in existing_rules.splitlines() if ':' in line):
            raise Error('Обнаружена нестандартная policy routing/VPN; требуется индивидуальная проверка приоритетов.')
        if run(['ip',family,'route','show','table',str(policy_table)],check=False).stdout.strip(): raise Error('Таблица 30300 уже используется.')
    current=json.loads(run(['ip','-j','addr','show','dev',iface]).stdout)
    if any(a.get('local')==src for i in current for a in i.get('addr_info',[])): raise Error('Адрес уже назначен; повторное добавление не требуется.')
    manager=state['manager']; paths=[]; persist=None; reload=[]; extra_undo=[]
    route_table=policy_table if policy else 254
    route=['ip',family,'route','add','default','via',str(gw),'dev',iface,'src',src,'metric','5','table',str(route_table)]+(['onlink'] if onlink else [])
    if manager=='netplan':
        ident=input('ID интерфейса в netplan (не имя устройства; посмотрите netplan get): ').strip()
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',ident): raise Error('Некорректный ID netplan.')
        existing=run(['netplan','get','ethernets.'+ident],check=False)
        if existing.returncode or existing.stdout.strip() in ('null','', '{}'): raise Error('ID не найден в netplan.')
        path=Path('/etc/netplan/99-vps-manager-'+iface+'.yaml'); paths=[str(path)]
        entry={'addresses':[str(addr)],'routes':[{'to':'default','via':str(gw),'metric':5,'on-link':onlink,'from':src,**({'table':route_table} if policy else {})}]}
        persist=lambda:write(path,{'network':{'version':2,'ethernets':{ident:entry}}})
        reload=[['netplan','generate'],['netplan','apply']]; extra_undo=[{'args':['netplan','apply']}]
    elif manager=='systemd-networkd':
        output=run(['networkctl','status',iface,'--no-pager'],env={**os.environ,'LC_ALL':'C'}).stdout
        match=re.search(r'Network File:\s+(\S+\.network)',output)
        if not match: raise Error('Не найден активный .network файл.')
        name=Path(match.group(1)).name; path=Path('/etc/systemd/network')/(name+'.d')/'90-vps-manager.conf'; paths=[str(path)]
        text=f'[Address]\nAddress={addr}\n\n[Route]\nDestination={"0.0.0.0/0" if addr.version==4 else "::/0"}\nGateway={gw}\nPreferredSource={src}\nMetric=5\nTable={route_table}\nGatewayOnLink={"yes" if onlink else "no"}\n'
        persist=lambda:write(path,text,0o644); reload=[['networkctl','reload'],['networkctl','reconfigure',iface]]
        extra_undo=[{'args':['networkctl','reload']},{'args':['networkctl','reconfigure',iface]}]
    elif manager=='NetworkManager':
        conn=run(['nmcli','-g','GENERAL.CON-UUID','device','show',iface]).stdout.strip()
        if not re.fullmatch(r'[0-9a-fA-F-]{36}',conn): raise Error('Не найдена активная связь NetworkManager.')
        prop='ipv'+str(addr.version)
        paths=['/etc/NetworkManager/system-connections']
        def persist():
            run(['nmcli','connection','modify',conn,'+'+prop+'.addresses',str(addr),'+'+prop+'.routes',f'{"0.0.0.0/0" if addr.version==4 else "::/0"} {gw} 5 src={src}'+(f' table={route_table}' if policy else '')+(' onlink=true' if onlink else '')])
        reload=[['nmcli','device','reapply',iface]]
        extra_undo=[{'args':['nmcli','connection','reload']},{'args':['nmcli','device','reapply',iface]}]
    else: raise Error('Неизвестный менеджер сети. Изменения не выполнены.')
    policy_file=Path('/etc/vps-manager/network-policy.json')
    policy_script=Path('/etc/vps-manager/network-policy.py')
    policy_unit=Path('/etc/systemd/system/vps-manager-network-policy.service')
    if policy:
        if policy_file.exists(): raise Error('Уже существует управляемый policy-профиль. Сначала восстановите предыдущую сетевую копию.')
        paths += [str(policy_file),str(policy_script),str(policy_unit),'/etc/systemd/system/multi-user.target.wants/vps-manager-network-policy.service']
        old_addresses=[a['local'] for i in current for a in i.get('addr_info',[]) if a.get('family')==('inet' if addr.version==4 else 'inet6') and a.get('scope')=='global']
        policy_rules=[]
        for index,old in enumerate(old_addresses): policy_rules.append(['priority',str(30200+index),'from',old,'lookup','main'])
        policy_rules += [['priority','30300','lookup','main','suppress_prefixlength','0'],['priority','30301','lookup',str(policy_table)]]
        extra_undo.insert(0,{'phase':'before','args':['systemctl','disable','--now','vps-manager-network-policy.service'],'required':False})
    table=31000+secrets.randbelow(500); priority=31000+secrets.randbelow(500)
    if run(['ip',family,'route','show','table',str(table)],check=False).stdout.strip(): raise Error('Пробная таблица занята; повторите.')
    if str(priority)+':' in run(['ip',family,'rule','show']).stdout: raise Error('Пробный приоритет занят; повторите.')
    undo=[{'args':['ip',family,'rule','del','priority',str(priority)],'required':False},{'args':['ip',family,'route','flush','table',str(table)],'required':False},{'args':['ip',family,'route','del','default','via',str(gw),'dev',iface,'metric','5','table',str(route_table)],'required':False},{'args':['ip',family,'addr','del',str(addr),'dev',iface],'required':False}]+extra_undo
    print('Будет добавлен адрес',addr,'и default route metric 5 в таблице',route_table,'. Старый адрес сохраняется. Файлы:',paths)
    confirm('Начать сетевую транзакцию с автоматическим откатом через 5 минут')
    tx=Transaction('network address',paths,undo,300).arm()
    try:
        run(['ip',family,'addr','add',str(addr),'dev',iface])
        # A private source-policy table tests the new source before touching default routing.
        run(['ip',family,'route','add','default','via',str(gw),'dev',iface,'onlink','table',str(table)])
        run(['ip',family,'rule','add','priority',str(priority),'from',src,'lookup',str(table)])
        if run(['ping',family,'-c','2','-W','2','-I',src,str(gw)+('%'+iface if gw.is_link_local else '')],check=False).returncode:
            raise Error('Шлюз не ответил. Default route не изменён; уточните ICMP/шлюз у провайдера.')
        run(['curl',family,'--interface',src,'--fail','--silent','--show-error','--max-time','15','https://www.cloudflare.com/cdn-cgi/trace'])
        run(['ip',family,'rule','del','priority',str(priority)]); run(['ip',family,'route','flush','table',str(table)])
        run(route); persist()
        for command in reload: run(command,timeout=60)
        if policy:
            write(policy_file,{'family':family,'rules':policy_rules})
            script='import json, subprocess, sys\np=json.load(open("/etc/vps-manager/network-policy.json"))\nfor rule in p["rules"]:\n    subprocess.run(["ip",p["family"],"rule","del",*rule],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n    if sys.argv[1]=="start": subprocess.run(["ip",p["family"],"rule","add",*rule],check=True)\n'
            write(policy_script,script)
            unit='[Unit]\nDescription=VPS Manager source policy\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 /etc/vps-manager/network-policy.py start\nExecStop=/usr/bin/python3 /etc/vps-manager/network-policy.py stop\n[Install]\nWantedBy=multi-user.target\n'
            write(policy_unit,unit,0o644); run(['systemctl','daemon-reload']); run(['systemctl','enable','--now','vps-manager-network-policy.service'])
        run(['curl',family,'--interface',src,'--fail','--silent','--show-error','--max-time','15','https://www.cloudflare.com/cdn-cgi/trace'])
        destination='1.1.1.1' if addr.version==4 else '2606:4700:4700::1111'
        selected=json.loads(run(['ip','-j',family,'route','get',destination]).stdout)
        if not selected or selected[0].get('prefsrc',selected[0].get('src'))!=src: raise Error('Система не выбрала новый исходящий IP; изменения отменяются.')
        write(STATE/'network-last.json',{'interface':iface,'address':str(addr),'gateway':str(gw),'manager':manager})
        finish(tx,'Откройте НОВОЕ SSH-подключение на '+src+'. Вход на новый адрес проверен')
    except BaseException: tx.rollback(); raise

def verify_persistent():
    p=read(STATE/'network-last.json'); family='-'+str(ipaddress.ip_interface(p['address']).version)
    output=run(['ip',family,'addr','show','dev',p['interface']]).stdout
    if str(ipaddress.ip_interface(p['address']).ip) not in output: raise Error('Адрес после перезагрузки отсутствует.')
    run(['curl',family,'--interface',str(ipaddress.ip_interface(p['address']).ip),'--fail','--silent','--max-time','15','https://www.cloudflare.com/cdn-cgi/trace'])
    print('Адрес и исходящее HTTPS-соединение проверены.')
