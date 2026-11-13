"""Interactive edits to a detached inbound draft; apply through proxy transactions."""
import copy, datetime, getpass, ipaddress, json, secrets, ssl, socket, uuid
from .core import Error, hostname, port

JSON_FIELDS=('settings','streamSettings','sniffing','allocate')
FIELDS=('remark','enable','expiryTime','listen','port','protocol','settings','streamSettings','sniffing','allocate','total')

def decode(value):
    value=json.loads(value) if isinstance(value,str) else value
    if not isinstance(value,dict): raise Error('Ожидался JSON-объект настроек.')
    return copy.deepcopy(value)

def draft(entry):
    result={k:copy.deepcopy(entry[k]) for k in FIELDS if k in entry}
    for k in JSON_FIELDS:
        if k in result: result[k]=decode(result[k])
    return result

def payload(value):
    result=copy.deepcopy(value)
    for k in JSON_FIELDS:
        if k in result: result[k]=json.dumps(result[k])
    return result

def yes(label,current):
    answer=input(label+' ['+('да' if current else 'нет')+']: ').strip().lower()
    if not answer: return current
    if answer in ('да','д','yes','y','1'): return True
    if answer in ('нет','н','no','n','0'): return False
    raise Error('Введите да или нет.')

def number(label,current):
    answer=input(label+' ['+str(current)+']: ').strip()
    value=int(answer) if answer else current
    if value<0: raise Error('Значение должно быть неотрицательным.')
    return value

def expiry(current):
    answer=input('Срок UTC YYYY-MM-DD, 0 — бессрочно, Enter — оставить: ').strip()
    if not answer: return current
    if answer=='0': return 0
    return int(datetime.datetime.strptime(answer,'%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp()*1000)

def clients(settings):
    items=settings.setdefault('clients',[])
    while True:
        for index,c in enumerate(items,1):
            print(index,c.get('email',''), 'включён' if c.get('enable',True) else 'выключен', 'лимит байт:',c.get('totalGB',0),'срок ms:',c.get('expiryTime',0))
        print('1. Добавить\n2. Изменить\n3. Удалить\n0. Назад')
        action=input('Выбор: ').strip()
        if action=='0': return
        if action not in ('1','2','3'): continue
        if action=='1':
            c={'id':str(uuid.uuid4()),'email':'client-'+secrets.token_hex(4),'enable':True,'flow':'xtls-rprx-vision','limitIp':0,'totalGB':0,'expiryTime':0,'subId':secrets.token_hex(8),'reset':0}
        else:
            index=int(input('Номер клиента: '))-1
            if not 0<=index<len(items): raise Error('Неизвестный клиент.')
            if action=='3':
                if yes('Удалить клиента',False): items.pop(index)
                continue
            c=copy.deepcopy(items[index])
        c['email']=input('Email/название ['+c.get('email','')+']: ').strip() or c.get('email','')
        if any(x.get('email')==c['email'] for x in items if action=='1' or x is not items[index]): raise Error('Email уже используется.')
        ident=getpass.getpass('UUID (Enter — сохранить, ввод скрыт): ').strip()
        if ident: c['id']=str(uuid.UUID(ident))
        c['enable']=yes('Клиент включён',c.get('enable',True))
        c['totalGB']=number('Лимит трафика в байтах, 0 — без лимита',c.get('totalGB',0))
        c['limitIp']=number('Лимит IP, 0 — без лимита',c.get('limitIp',0))
        c['expiryTime']=expiry(c.get('expiryTime',0))
        flow=input('Flow: 1 — vision, 2 — none, Enter — оставить: ').strip().lower()
        flow={'1':'vision','2':'none','xtls-rprx-vision':'vision'}.get(flow,flow)
        if flow:
            if flow not in ('vision','none'): raise Error('Flow: введите 1 (vision) или 2 (none), либо нажмите Enter.')
            c['flow']='xtls-rprx-vision' if flow=='vision' else ''
        if action=='1': items.append(c)
        else: items[index]=c

def sniffing(value):
    value['enabled']=yes('Sniffing включён',value.get('enabled',False))
    value['routeOnly']=yes('Только маршрутизация (routeOnly)',value.get('routeOnly',False))
    value['metadataOnly']=yes('Только метаданные',value.get('metadataOnly',False))
    raw=input('destOverride через запятую (http,tls,quic,fakedns), Enter — оставить: ').strip()
    if raw:
        options=[x.strip() for x in raw.split(',')]
        if not set(options)<={'http','tls','quic','fakedns','fakedns+others'}: raise Error('Неизвестный протокол sniffing.')
        value['destOverride']=options
    raw=input('Исключённые домены через запятую, - — очистить, Enter — оставить: ').strip()
    if raw: value['domainsExcluded']=[] if raw=='-' else [x.strip() for x in raw.split(',') if x.strip()]

def target_address(value):
    host,sep,number=value.rpartition(':')
    if not sep: raise Error('Нужен target host:port.')
    host=hostname(host.strip('[]')); number=port(number)
    return host,number,('['+host+']' if ':' in host else host)+':'+str(number)

def check_target(value,sni):
    host,number,_=target_address(value)
    context=ssl.create_default_context(); context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2','http/1.1'])
    with socket.create_connection((host,number),timeout=8) as sock:
        with context.wrap_socket(sock,server_hostname=hostname(sni)) as tls:
            print('TLS:',tls.version(),'ALPN:',tls.selected_alpn_protocol(),'сертификат до:',tls.getpeercert().get('notAfter'))
    print('TLS 1.3 и сертификат проверены; совместимость с Reality требует теста клиентом.')

def reality(value):
    names=input('SNI через запятую (Enter — оставить): ').strip()
    if names:
        value['serverNames']=[hostname(x.strip()) for x in names.split(',')]
        if 'serverName' in value.get('settings',{}): value['settings']['serverName']=value['serverNames'][0]
    key='target' if 'target' in value else 'dest'
    raw=input('TLS target ['+str(value.get(key,''))+']: ').strip()
    if raw: value[key]=target_address(raw)[2]
    raw=getpass.getpass('Short IDs через запятую, Enter — оставить (ввод скрыт): ').strip()
    if raw:
        ids=[x.strip() for x in raw.split(',')]
        if any(len(x)>16 or len(x)%2 or any(c not in '0123456789abcdefABCDEF' for c in x) for x in ids): raise Error('Short ID: чётное число hex-символов, максимум 16.')
        value['shortIds']=ids
    value['show']=yes('Диагностика Reality (show)',value.get('show',False))
    value['xver']=number('Proxy protocol xver (0,1,2)',value.get('xver',0))
    if value['xver'] not in (0,1,2): raise Error('xver должен быть 0, 1 или 2.')

def edit(entry):
    value=draft(entry)
    while True:
        print('\n1. Основное: имя, порт, адрес, лимиты\n2. Клиенты\n3. Reality: SNI, target, short IDs\n4. Sniffing\n5. Transport / расширенные JSON-настройки\n6. Проверить TLS target\n7. Проверить список доменов-кандидатов\n8. Применить изменения\n0. Отменить')
        action=input('Выбор: ').strip()
        before=copy.deepcopy(value)
        try:
            if action=='0': return None
            if action=='8': return value
            if action=='1':
                value['remark']=input('Название ['+value.get('remark','')+']: ').strip() or value.get('remark','')
                value['enable']=yes('Inbound включён',value.get('enable',True))
                value['port']=port(input('Порт ['+str(value['port'])+']: ').strip() or value['port'])
                raw=input('Listen — локальный IP ['+value.get('listen','')+'], * — все адреса, Enter — оставить: ').strip()
                if raw:
                    if raw=='*': value['listen']=''
                    else:
                        try: value['listen']=str(ipaddress.ip_address(raw))
                        except ValueError: raise Error('Listen — полный IP-адрес, например 0.0.0.0 или ::. Это не порт. Для всех адресов введите *.') from None
                value['total']=number('Общий лимит байт, 0 — без лимита',value.get('total',0))
                value['expiryTime']=expiry(value.get('expiryTime',0))
            elif action=='2': clients(value['settings'])
            elif action=='3': reality(value['streamSettings']['realitySettings'])
            elif action=='4': sniffing(value.setdefault('sniffing',{}))
            elif action=='5':
                print('Раздел: settings / streamSettings / sniffing / allocate. JSON заменяет весь раздел; содержит секреты. Enter — назад.')
                key=input('Раздел: ').strip()
                if key not in JSON_FIELDS: continue
                raw=getpass.getpass('Полный JSON раздела (ввод скрыт; Enter — отмена): ')
                if raw: value[key]=decode(raw)
            elif action=='6':
                r=value['streamSettings']['realitySettings']
                check_target(r.get('target',r.get('dest','')),r['serverNames'][0])
            elif action=='7':
                domains=input('До 10 доменов через запятую для проверки TLS на 443: ').split(',')
                if len(domains)>10: raise Error('Максимум 10 доменов.')
                for name in domains:
                    name=hostname(name.strip()); print('Проверка:',name)
                    try: check_target(name+':443',name)
                    except (OSError,ValueError,Error): print('Проверка TLS не пройдена.')
        except (OSError,ValueError,KeyError,Error) as exc:
            value=before
            reason=str(exc) if isinstance(exc,Error) else {'ValueError':'Некорректный формат числа, даты, UUID или JSON.','KeyError':'В ответе панели отсутствует обязательное поле.','SSLError':'Не удалось проверить TLS-сертификат.'}.get(type(exc).__name__,'Ошибка соединения или недоступный TLS target.')
            print('Настройки раздела не изменены. '+reason+' [тип: '+type(exc).__name__+']')
