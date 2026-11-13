"""Menu-based forms for Reality, sniffing and transport settings."""
import copy
import socket
import ssl
import time
from .core import Error, hostname, port

def choose(title, options):
    print('\n'+title)
    for key, label in options: print(str(key)+'. '+label)
    print('0. Назад')
    return input('Выбор: ').strip()

def target_probe(domain):
    domain=hostname(domain)
    context=ssl.create_default_context()
    context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2','http/1.1'])
    start=time.monotonic()
    with socket.create_connection((domain,443),timeout=5) as connection:
        address=connection.getpeername()[0]
        with context.wrap_socket(connection,server_hostname=domain) as tls:
            return {'domain':domain,'address':address,'alpn':tls.selected_alpn_protocol(),'ms':round((time.monotonic()-start)*1000)}

def find_target(reality):
    print('Проверка TLS 1.3, сертификата и ALPN с этого VPS. Это предварительный подбор; итог проверяется Reality-клиентом.')
    raw=input('Домены через запятую; Enter — текущие SNI и встроенный список: ').strip()
    domains=raw.split(',') if raw else list(reality.get('serverNames',[]))+['www.microsoft.com','www.apple.com','www.cloudflare.com']
    domains=list(dict.fromkeys(x.strip() for x in domains if x.strip()))
    if len(domains)>10: raise Error('Максимум 10 доменов за проверку.')
    results=[]
    for domain in domains:
        print('Проверка:',domain,flush=True)
        try:
            result=target_probe(domain)
            results.append(result)
            print('  TLS 1.3 OK;',result['address'],'ALPN:',result['alpn'],'время:',result['ms'],'мс')
        except (OSError,ValueError,Error): print('  TLS-проверка не пройдена.')
    results.sort(key=lambda x:x['ms'])
    if not results: return
    answer=choose('Результаты: выбрать домен для SNI и target',[(n,str(r['domain'])+' — '+str(r['ms'])+' мс') for n,r in enumerate(results,1)])
    if answer=='0': return
    if not answer.isdigit() or not 1<=int(answer)<=len(results): raise Error('Выберите номер результата.')
    domain=results[int(answer)-1]['domain']
    reality['serverNames']=[domain]
    reality['target' if 'target' in reality else 'dest']=domain+':443'
    if 'serverName' in reality.get('settings',{}): reality['settings']['serverName']=domain
    print('Добавлено в черновик:',domain)

def reality_form(value):
    from .inbound_editor import reality
    while True:
        selected=choose('Reality: SNI '+', '.join(value.get('serverNames',[]))+'; target '+str(value.get('target',value.get('dest',''))),[
            ('1','Найти и выбрать TLS target'),('2','Вручную: SNI, target, short IDs и параметры Reality')])
        if selected=='0': return
        if selected=='1': find_target(value)
        elif selected=='2': reality(value)

def sniffing_form(value):
    while True:
        action=choose('Sniffing',[
            ('1','Включён: '+str(value.get('enabled',False))),
            ('2','Только маршрутизация: '+str(value.get('routeOnly',False))),
            ('3','Только метаданные: '+str(value.get('metadataOnly',False))),
            ('4','Протоколы: '+', '.join(value.get('destOverride',[]))),
            ('5','Исключённые домены: '+str(len(value.get('domainsExcluded',[]))))])
        if action=='0': return
        flags={'1':'enabled','2':'routeOnly','3':'metadataOnly'}
        if action in flags:
            key=flags[action]; value[key]=not value.get(key,False)
        elif action=='4':
            options=['http','tls','quic','fakedns','fakedns+others']
            print(' '.join(str(n)+'='+x for n,x in enumerate(options,1)))
            raw=input('Номера через запятую; 0 — очистить; Enter — оставить: ').strip()
            if raw=='0': value['destOverride']=[]
            elif raw:
                indices=[int(x.strip()) for x in raw.split(',')]
                if any(n<1 or n>len(options) for n in indices): raise Error('Неизвестный протокол.')
                value['destOverride']=list(dict.fromkeys(options[n-1] for n in indices))
        elif action=='5':
            raw=input('Домены через запятую; - — очистить; Enter — оставить: ').strip()
            if raw: value['domainsExcluded']=[] if raw=='-' else [x.strip() for x in raw.split(',') if x.strip()]

def transport_form(value):
    while True:
        action=choose('Transport: '+value.get('network','tcp'),[
            ('1','TCP / RAW'),('2','WebSocket: path и Host'),('3','gRPC: serviceName'),('4','XHTTP: path, host, mode')])
        if action=='0': return
        candidate=copy.deepcopy(value)
        if action=='1': candidate['network']='tcp'
        elif action=='2':
            candidate['network']='ws'; settings=candidate.setdefault('wsSettings',{})
            settings['path']=input('Path ['+settings.get('path','/')+']: ').strip() or settings.get('path','/')
            headers=settings.setdefault('headers',{})
            raw=input('Host ['+headers.get('Host','')+'], - — очистить: ').strip()
            if raw: headers['Host']='' if raw=='-' else hostname(raw)
        elif action=='3':
            candidate['network']='grpc'; settings=candidate.setdefault('grpcSettings',{})
            settings['serviceName']=input('Service name ['+settings.get('serviceName','')+']: ').strip() or settings.get('serviceName','')
        elif action=='4':
            candidate['network']='xhttp'; settings=candidate.setdefault('xhttpSettings',{})
            settings['path']=input('Path ['+settings.get('path','/')+']: ').strip() or settings.get('path','/')
            raw=input('Host ['+settings.get('host','')+'], - — очистить: ').strip()
            if raw: settings['host']='' if raw=='-' else hostname(raw)
            mode=input('Mode: auto / packet-up / stream-up / stream-one [auto]: ').strip() or 'auto'
            if mode not in ('auto','packet-up','stream-up','stream-one'): raise Error('Неверный XHTTP mode.')
            settings['mode']=mode
        else: continue
        print('Transport изменён в черновике. Совместимость с Reality и flow будет проверена установленным Xray при применении.')
        value.clear(); value.update(candidate)
