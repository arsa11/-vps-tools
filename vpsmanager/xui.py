import contextlib, http.client, json, os, ssl, platform, secrets, shutil, socket, sqlite3, tempfile, time
from pathlib import Path
from .core import Error, STATE, active, confirm, free_port, port, private_dir, run, sha, supported, wait_active, write
from . import releases
from .transaction import Transaction, finish
BINARY=Path('/usr/local/x-ui/x-ui')
PANEL_PATHS=['/usr/local/x-ui','/etc/x-ui','/etc/systemd/system/x-ui.service','/etc/systemd/system/x-ui.service.d','/usr/bin/x-ui','/etc/systemd/system/multi-user.target.wants/x-ui.service']

def undo_panel():
    return [{'phase':'before','args':['systemctl','stop','x-ui'],'required':False},{'args':['systemctl','start' if active('x-ui') else 'stop','x-ui'],'required':False}]

def xray_binary():
    for p in Path('/usr/local/x-ui/bin').glob('xray*'):
        if p.is_file() and os.access(p,os.X_OK) and p.name not in ('xray.json',): return p
    p=shutil.which('xray')
    if p: return Path(p)
    raise Error('Xray не найден.')

def validate_config(config):
    private_dir(STATE/'tmp')
    with tempfile.TemporaryDirectory(dir=STATE/'tmp') as d:
        path=Path(d)/'config.json'; write(path,config)
        env=os.environ.copy(); env['XRAY_LOCATION_ASSET']='/usr/local/x-ui/bin'
        run([xray_binary(),'run','-test','-config',path],env=env,timeout=30)

def panel_health():
    wait_active('x-ui'); time.sleep(2)
    if not active('x-ui'): raise Error('Панель завершилась после старта.')
    db=Path('/etc/x-ui/x-ui.db')
    if not db.exists(): raise Error('SQLite панели не найдена; нестандартная БД требует отдельной проверки.')
    with contextlib.closing(sqlite3.connect(db.as_uri()+'?mode=ro',uri=True)) as c:
        if c.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise Error('Проверка БД не пройдена.')
        settings=dict(c.execute('SELECT key,value FROM settings'))
    listen=settings.get('webListen') or '127.0.0.1'
    if listen in ('0.0.0.0','::'): listen='127.0.0.1' if listen=='0.0.0.0' else '::1'
    number=int(settings.get('webPort','2053'))
    with socket.create_connection((listen,number),timeout=5): pass
    if settings.get('webCertFile'):
        context=ssl.create_default_context(); context.check_hostname=False
        connection=http.client.HTTPSConnection(listen,number,timeout=8,context=context)
    else: connection=http.client.HTTPConnection(listen,number,timeout=8)
    try:
        connection.request('GET',settings.get('webBasePath') or '/')
        response=connection.getresponse(); response.read(4096)
        if response.status not in (200,301,302,303,401): raise Error('Локальная HTTP(S)-проверка панели не пройдена.')
    finally: connection.close()
    config=Path('/usr/local/x-ui/bin/config.json')
    if config.exists():
        validate_config(json.loads(config.read_text()))
        expected=xray_binary().resolve(); running=False
        for executable in Path('/proc').glob('[0-9]*/exe'):
            try:
                if executable.resolve()==expected: running=True; break
            except OSError: continue
        if not running: raise Error('Конфигурация есть, но процесс Xray не найден.')

def ensure_standard():
    unit=run(['systemctl','show','x-ui','-p','ExecStart','--value'],check=False).stdout
    if unit.strip() and str(BINARY) not in unit: raise Error('Нестандартный unit x-ui. Мастер работает только с /usr/local/x-ui/x-ui.')
    if BINARY.exists() and not Path('/etc/x-ui/x-ui.db').exists(): raise Error('Стандартная SQLite БД не найдена. PostgreSQL/перенесённые пути требуют отдельного адаптера.')


def choose_access():
    print('Доступ к панели:')
    print('1. Только через SSH-туннель (127.0.0.1)')
    print('2. Обычный доступ по IP и порту (0.0.0.0)')
    choice=input('Выбор [1]: ').strip() or '1'
    if choice not in ('1','2'): raise Error('Выберите 1 или 2.')
    if choice=='2':
        print('Без настроенного сертификата панель будет доступна по HTTP: логин и пароль передаются без HTTPS. Настройте SSL в разделе 6.')
        confirm('Открыть доступ к панели по сети')
    return '127.0.0.1' if choice=='1' else '0.0.0.0'

def choose_release(arch):
    repo='MHSanaei/3x-ui'
    print('Загружаем стабильные релизы 3x-ui с GitHub…')
    try: available=releases.stable_releases(repo,arch)
    except Error as e:
        print('Не удалось получить список:',e)
        print('Можно попробовать точный тег или вернуться и выбрать локальный архив.')
        available=[]
    if available:
        print('Доступные стабильные версии (порядок публикации на GitHub):')
        for i,item in enumerate(available,1):
            print(f"{i}. {item['tag_name']}  {str(item.get('published_at') or '')[:10]}")
        print('Enter — последняя стабильная версия; 0 — ввести тег вручную; q — отмена.')
    else:
        print('Список пуст. Enter — последняя стабильная версия; 0 — ввести тег; q — отмена.')
    while True:
        choice=input('Версия: ').strip()
        if choice.lower() in ('q','й'): raise Error('Выбор версии отменён.')
        if not choice: tag='latest'; break
        if choice=='0':
            tag=input('Точный тег версии (например v3.4.5): ').strip()
            if not tag: print('Тег не указан.'); continue
            break
        if choice.isdigit() and 1<=int(choice)<=len(available): tag=available[int(choice)-1]['tag_name']; break
        if not choice.isdigit(): tag=choice; break
        print('Нет версии с таким номером. Выберите номер из списка, 0 или q.')
    # Re-fetch the selected release; do not substitute latest for an unavailable tag.
    return releases.release(repo,tag)

def install():
    supported(); ensure_standard(); arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
    if not arch: raise Error('Неподдерживаемая архитектура.')
    private_dir(STATE/'downloads')
    local=input('Локальный архив (Enter — официальный GitHub): ').strip()
    with tempfile.TemporaryDirectory(dir=STATE/'downloads') as d:
        d=Path(d)
        if local:
            archive=Path(local).resolve(); expected=input('SHA256 из доверенного источника: ').strip().lower()
            if len(expected)!=64 or sha(archive)!=expected: raise Error('SHA256 не совпадает.')
            version='local'
        else:
            rel=choose_release(arch); version=rel['tag_name']; print('Выбран релиз:',version)
            archive=d/'x-ui.tar.gz'
            verified=releases.download_asset('MHSanaei/3x-ui',rel,'x-ui-linux-'+arch+'.tar.gz',archive)
            if not verified: confirm('Издатель не указал SHA256 через API. Архив получен по HTTPS с официального GitHub. Продолжить')
        stage=releases.extract(archive,d/'stage'); candidates=list(stage.rglob('x-ui'))
        bins=[p for p in candidates if p.is_file()]
        if len(bins)!=1: raise Error('Неверная структура дистрибутива.')
        binary=bins[0]; run([binary,'-v'],cwd=binary.parent)
        fresh=not BINARY.exists() and not Path('/etc/x-ui/x-ui.db').exists(); print('Операция:', 'установка' if fresh else 'замена версии с резервной копией БД и бинарников')
        access=choose_access() if fresh else None
        confirm('Применить выбранный дистрибутив '+version)
        tx=Transaction('3x-ui install '+version,PANEL_PATHS,undo_panel(),600).arm()
        try:
            run(['systemctl','stop','x-ui'],check=False)
            target=BINARY.parent
            if target.exists(): shutil.rmtree(target)
            shutil.copytree(binary.parent,target)
            os.chmod(BINARY,0o755)
            service='[Unit]\nDescription=3x-ui panel\nAfter=network.target\n[Service]\nType=simple\nWorkingDirectory=/usr/local/x-ui\nExecStart=/usr/local/x-ui/x-ui\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n'
            if not Path('/etc/systemd/system/x-ui.service').exists(): write('/etc/systemd/system/x-ui.service',service,0o644)
            run(['systemctl','daemon-reload'])
            if fresh:
                number=port(input('Порт панели [2053]: ') or 2053); free_port(number)
                username=input('Логин [admin]: ').strip() or 'admin'; password=secrets.token_urlsafe(24); base='/'+secrets.token_urlsafe(18)+'/'
                # Official CLI is used only before the service is exposed. Output is captured.
                run([BINARY,'setting','-username',username,'-password',password,'-port',str(number),'-webBasePath',base,'-listenIP',access],cwd=target)
                write(STATE/'panel-access.json',{'username':username,'password':password,'url':f'http://127.0.0.1:{number}{base}'})
                if access=='127.0.0.1':
                    print('Панель доступна через SSH-туннель. Данные входа: /var/lib/vps-manager/panel-access.json (0600).')
                else:
                    print('Панель слушает все IPv4-адреса. Откройте http://IP_СЕРВЕРА:'+str(number)+base)
                    print('Данные входа: /var/lib/vps-manager/panel-access.json (0600). Для внешнего подключения может потребоваться разрешить порт в firewall.')
            run(['systemctl','enable','--now','x-ui']); panel_health(); finish(tx)
        except BaseException: tx.rollback(); raise

def configure():
    from .panel import connect
    supported(); p=connect(); old=p.settings(); new=dict(old)
    new['webPort']=port(input('Порт ['+str(old.get('webPort'))+']: ') or old.get('webPort'))
    new['webListen']=str(__import__('ipaddress').ip_address(input('Адрес привязки ['+str(old.get('webListen') or '0.0.0.0')+']: ') or old.get('webListen') or '0.0.0.0'))
    if new['webPort']!=old.get('webPort'): free_port(new['webPort'],new['webListen'])
    if input('Создать случайный webBasePath? [y/N]: ').lower()=='y': new['webBasePath']='/'+secrets.token_urlsafe(18)+'/'
    if new['webListen'] not in ('127.0.0.1','::1') and not new.get('webCertFile'):
        print('Панель будет доступна по HTTP без шифрования. Для HTTPS настройте сертификат в разделе 6.')
        confirm('Разрешить внешний доступ без HTTPS')
    confirm('Изменить настройки доступа к панели')
    tx=Transaction('panel settings',PANEL_PATHS,undo_panel(),300).arm()
    try:
        p.request('panel/setting/update',new); run(['systemctl','restart','x-ui']); panel_health()
        write(STATE/'panel-url.txt',str(new['webPort'])+' '+str(new.get('webBasePath')))
        print('Новый порт и путь сохранены в',STATE/'panel-url.txt'); finish(tx,'Проверьте вход по новому URL в другом окне. Доступ подтверждён')
    except BaseException: tx.rollback(); raise

def xray_update():
    supported(); binary=xray_binary(); arch='64' if platform.machine()=='x86_64' else 'arm64-v8a'
    tag=input('Точный тег Xray или latest: ').strip() or 'latest'; rel=releases.release('XTLS/Xray-core',tag)
    private_dir(STATE/'downloads')
    with tempfile.TemporaryDirectory(dir=STATE/'downloads') as d:
        d=Path(d); archive=d/'xray.zip'
        if not releases.download_asset('XTLS/Xray-core',rel,'Xray-linux-'+arch+'.zip',archive): confirm('SHA256 издателя отсутствует; продолжить с официальным HTTPS-архивом')
        stage=releases.extract(archive,d/'stage'); candidate=stage/'xray'; run([candidate,'version'])
        config=Path('/usr/local/x-ui/bin/config.json')
        env=os.environ.copy(); env['XRAY_LOCATION_ASSET']=str(binary.parent)
        if config.exists(): run([candidate,'run','-test','-config',config],env=env)
        confirm('Заменить только Xray на '+rel['tag_name'])
        tx=Transaction('Xray update',PANEL_PATHS,undo_panel(),300).arm()
        try:
            run(['systemctl','stop','x-ui']); write(binary,candidate.read_bytes(),0o755); run(['systemctl','start','x-ui']); panel_health(); finish(tx)
        except BaseException: tx.rollback(); raise


def credentials():
    from .panel import connect
    supported(); panel=connect()
    username=input('Новый логин: ').strip()
    if not username or len(username)>64: raise Error('Некорректный логин.')
    password=secrets.token_urlsafe(24)
    confirm('Установить новый логин и случайный стойкий пароль')
    output=STATE/'panel-access.json'
    tx=Transaction('panel credentials',PANEL_PATHS+[str(output)],undo_panel(),300).arm()
    try:
        panel.request('panel/setting/updateUser',{'oldUsername':panel.username,'oldPassword':panel.password,'newUsername':username,'newPassword':password,'twoFactorCode':panel.two_factor})
        write(output,{'username':username,'password':password,'url':panel.url})
        print('Новые данные сохранены в',output,'(0600).')
        finish(tx,'Новый вход в панель проверен')
    except BaseException: tx.rollback(); raise
