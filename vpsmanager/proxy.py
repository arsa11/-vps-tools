"""Reality provisioning and panel-persisted cascade routing."""
import copy, getpass, json, secrets, socket, subprocess, tempfile, time, uuid
from pathlib import Path
from urllib.parse import urlencode
from .core import Error, STATE, confirm, free_port, hostname, os, port, private_dir, read, redact, run, supported, write
from .panel import connect
from .xui import validate_config, xray_binary, PANEL_PATHS, undo_panel, panel_health
from .transaction import Transaction, finish
from routing import parse_vless

def build_reality(number,sni,target_port,private,public,ident,sid,email):
    client={'id':ident,'flow':'xtls-rprx-vision','email':email,'enable':True,'limitIp':0,'totalGB':0,'expiryTime':0,'subId':secrets.token_hex(8),'reset':0}
    stream={'network':'tcp','security':'reality','realitySettings':{'show':False,'dest':f'{sni}:{target_port}','xver':0,'serverNames':[sni],'privateKey':private,'shortIds':[sid],'settings':{'publicKey':public,'fingerprint':'chrome','serverName':sni,'spiderX':'/'}}}
    payload={'remark':'VPS Manager Reality','enable':True,'listen':'','port':number,'protocol':'vless','settings':json.dumps({'clients':[client],'decryption':'none','fallbacks':[]}), 'streamSettings':json.dumps(stream),'sniffing':json.dumps({'enabled':True,'destOverride':['http','tls','quic'],'routeOnly':True}),'allocate':json.dumps({'strategy':'always','refresh':5,'concurrency':3})}
    probe={'inbounds':[{'listen':'127.0.0.1','port':number,'protocol':'vless','settings':{'clients':[{'id':ident,'flow':'xtls-rprx-vision'}],'decryption':'none'},'streamSettings':stream}],'outbounds':[{'protocol':'freedom'}]}
    return payload,probe

def reality():
    supported(); panel=connect(); inbounds=panel.inbounds()
    number=port(input('Порт Reality [443]: ') or 443)
    if any(int(i['port'])==number for i in inbounds): raise Error('Inbound с этим портом уже существует.')
    free_port(number); sni=hostname(input('SNI/target домен с TLS 1.3: ').strip()); target_port=port(input('Порт target [443]: ') or 443)
    run(['openssl','s_client','-connect',f'{sni}:{target_port}','-servername',sni,'-tls1_3','-brief'],input='',timeout=15)
    keys=run([xray_binary(),'x25519']).stdout
    values={line.split(':',1)[0].strip().lower():line.split(':',1)[1].strip() for line in keys.splitlines() if ':' in line}
    private=values.get('private key') or values.get('privatekey'); public=values.get('public key') or values.get('password') or values.get('password (publickey)') or values.get('publickey')
    if not private or not public: raise Error('Не удалось разобрать ключи Xray; несовместимая версия.')
    ident=str(uuid.uuid4()); sid=secrets.token_hex(8); email='vps-manager-'+secrets.token_hex(4)
    payload,probe=build_reality(number,sni,target_port,private,public,ident,sid,email)
    validate_config(probe)
    host=hostname(input('Адрес этого VPS для клиентской ссылки: ').strip()); authority='['+host+']' if ':' in host else host
    uri=f'vless://{ident}@{authority}:{number}?'+urlencode({'encryption':'none','security':'reality','sni':sni,'fp':'chrome','pbk':public,'sid':sid,'type':'tcp','flow':'xtls-rprx-vision'})+'#VPS-Manager'
    confirm('Создать Reality inbound на порту '+str(number))
    tx=Transaction('Reality inbound',PANEL_PATHS,undo_panel(),300).arm()
    try:
        panel.request('panel/api/inbounds/add',payload); panel.restart_xray(); time.sleep(3); panel_health()
        after=panel.inbounds()
        if not any(i.get('port')==number and i.get('enable') for i in after): raise Error('Inbound не появился.')
        private_dir(STATE/'clients'); output=STATE/'clients'/f'reality-{number}.txt'; write(output,uri+'\n')
        print('VLESS URI сохранён в',output,'(0600).')
        if input('Показать URI в терминале? [y/N]: ').lower()=='y': print(uri)
        if input('Показать QR (нужен qrencode)? [y/N]: ').lower()=='y':
            try: print(run(['qrencode','-t','ANSIUTF8'],input=uri).stdout)
            except Error: print('QR недоступен: установите qrencode. Клиентская ссылка уже сохранена.')
        finish(tx,'Подключение клиентом проверено и inbound нужно сохранить')
    except BaseException: tx.rollback(); raise

def outbound_probe(outbound,url='https://www.cloudflare.com/cdn-cgi/trace'):
    # Real VLESS handshake through an isolated local Xray client, not merely TCP connect.
    with socket.socket() as sock: sock.bind(('127.0.0.1',0)); local=sock.getsockname()[1]
    config={'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':local,'protocol':'socks','settings':{'auth':'noauth','udp':False}}],'outbounds':[outbound]}
    validate_config(config); private_dir(STATE/'tmp')
    with tempfile.TemporaryDirectory(dir=STATE/'tmp') as d:
        path=Path(d)/'probe.json'; write(path,config)
        env=os.environ.copy(); env['XRAY_LOCATION_ASSET']='/usr/local/x-ui/bin'
        process=subprocess.Popen([str(xray_binary()),'run','-config',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)
        try:
            time.sleep(1)
            if process.poll() is not None: raise Error('Тестовый Xray не запустился.')
            result=run(['curl','--fail','--silent','--show-error','--max-time','20','--socks5-hostname',f'127.0.0.1:{local}',url],timeout=25)
            return result.stdout
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()

def build_cascade(config,outbound,tags,mode='ru-direct-eu',exceptions=None,priority='first'):
    if mode not in ('ru-direct-eu','all-eu','custom') or not tags: raise Error('Нужны шаблон и inbound.')
    result=copy.deepcopy(config)
    out=result.setdefault('outbounds',[])
    # Only replace an explicitly named manager-owned pair; preserve every other outbound.
    managed={'vps-manager-eu','vps-manager-direct'}
    out[:]=[o for o in out if o.get('tag') not in managed]
    outbound=copy.deepcopy(outbound); outbound['tag']='vps-manager-eu'; out.extend([outbound,{'tag':'vps-manager-direct','protocol':'freedom'}])
    routing=result.setdefault('routing',{}); rules=routing.setdefault('rules',[])
    rules[:]=[r for r in rules if not str(r.get('ruleTag','')).startswith('vps-manager-')]
    new=[]
    def rule(kind,values):
        new.append({'type':'field','ruleTag':'vps-manager-'+kind,'inboundTag':tags,kind:values,'outboundTag':'vps-manager-direct'})
    if mode=='ru-direct-eu': rule('domain',['domain:ru','domain:su','domain:xn--p1ai']); rule('ip',['geoip:ru'])
    for kind,values in (exceptions or {}).items():
        if kind not in ('domain','ip') or not isinstance(values,list) or not all(isinstance(v,str) and v for v in values): raise Error('Исключения: domain/ip → список строк.')
        rule(kind,values)
    new.append({'type':'field','ruleTag':'vps-manager-default','inboundTag':tags,'outboundTag':'vps-manager-eu'})
    routing['domainStrategy']='IPIfNonMatch'
    routing['rules']=new+rules if priority=='first' else rules+new
    return result

def routing():
    supported(); panel=connect(); entries=panel.inbounds()
    for i in entries: print(i['id'],i.get('tag'),i.get('port'),i.get('remark'))
    tags=[s.strip() for s in input('Теги inbound через запятую: ').split(',') if s.strip()]
    known={i.get('tag') for i in entries}
    if not tags or not set(tags)<=known: raise Error('Неизвестный inbound.')
    outbound=parse_vless(getpass.getpass('Полная EU VLESS-ссылка (ввод скрыт): '))
    print('Проверка реального VLESS-подключения RU → EU…')
    try: print(redact(outbound_probe(outbound)))
    except Error:
        confirm('EU не прошёл тест подключения. Применить несмотря на недоступность EU')
    mode=input('Шаблон ru-direct-eu / all-eu / custom [ru-direct-eu]: ').strip() or 'ru-direct-eu'
    exceptions={}
    if mode=='custom': exceptions=read(input('JSON-файл исключений {"domain": [...], "ip": [...]}: ').strip())
    old=panel.template(); print('Существующих правил:',len(old.get('routing',{}).get('rules',[])))
    priority=input('Приоритет каскада first (перед старыми) / last (после старых) [last]: ').strip() or 'last'
    if priority not in ('first','last'): raise Error('Неверный приоритет.')
    if priority=='first': confirm('Каскад получит приоритет перед существующими блокирующими и другими правилами выбранных inbound')
    new=build_cascade(old,outbound,tags,mode,exceptions,priority)
    # Test using the panel template plus real inbound definitions for route tag validation.
    validate_config(new)
    print('Системные маршруты не изменяются. DNS strategy: IPIfNonMatch. Для RU нужны geoip.dat с RU; домены .ru/.su/.рф идут напрямую, остальные классифицируются по IP.')
    if priority=='last': print('Старые широкие правила могут перехватить трафик раньше каскада; проверьте порядок в панели.')
    confirm('Сохранить каскад через API шаблона 3x-ui')
    tx=Transaction('cascade',PANEL_PATHS,undo_panel(),300).arm()
    try:
        if panel.template()!=old: raise Error('Шаблон изменён другим пользователем. Повторите операцию с актуальным состоянием.')
        panel.save_template(new); panel.restart_xray(); time.sleep(3); panel_health()
        if panel.template().get('routing')!=new['routing']: raise Error('Панель не сохранила правила.')
        finish(tx,'Проверьте RU и зарубежный домен через подключённый клиент. Маршруты работают')
    except BaseException: tx.rollback(); raise
