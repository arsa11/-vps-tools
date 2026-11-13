import ipaddress, os, re, shutil
from pathlib import Path
from .core import Error, STATE, active, confirm, port, private_dir, run, supported, write
from .transaction import Transaction, finish
from .system import install_packages

def ssh_ports():
    out=run(['sshd','-T']).stdout
    ports={int(line.split()[1]) for line in out.splitlines() if line.startswith('port ')}
    connection=os.environ.get('SSH_CONNECTION','').split()
    if len(connection)==4: ports.add(port(connection[3]))
    if not ports: raise Error('Не удалось определить порт SSH.')
    return sorted(ports)

def explain_listeners(output):
    lines=[]
    for row in output.splitlines()[1:]:
        parts=row.split()
        if len(parts)<5: continue
        address=parts[4]
        match=re.search(r'users:\(\("([^"\n]+)',row)
        process=match.group(1) if match else 'служба не определена'
        local=address.startswith(('127.','[::1]:','::1:'))
        scope='только на сервере' if local else 'слушает на сетевом адресе; доступ извне зависит от firewall и сети'
        lines.append(f'  {address} — {process}: {scope}')
    return lines

def audit():
    print('АУДИТ БЕЗОПАСНОСТИ — только просмотр, настройки не меняются.\n')
    results={}
    for cmd in (['ss','-lntup'],['ufw','status','verbose'],['nft','list','ruleset'],['iptables','-S'],['ip6tables','-S']):
        name=cmd[0]
        try:
            result=run(cmd,check=False,env={**os.environ,'LC_ALL':'C'})
            results[name]=result
            print('$',' '.join(cmd))
            print((result.stdout or result.stderr or '(пусто)')[:16000])
            if result.returncode: print('Команда завершилась с ошибкой; состояние не определено.')
        except Error:
            print('$',' '.join(cmd)); print('Команда недоступна; состояние не определено.')
    print('\nКАК ПОНИМАТЬ РЕЗУЛЬТАТ:')
    sockets=results.get('ss')
    if sockets and sockets.returncode==0:
        print('Адреса и службы:')
        print('\n'.join(explain_listeners(sockets.stdout)) or '  Слушающие порты не обнаружены.')
    else: print('Не удалось получить список портов.')
    ufw=results.get('ufw')
    if ufw and ufw.returncode==0:
        if re.search(r'^Status:\s+inactive',ufw.stdout,re.M): print('UFW выключен. Другие правила или firewall провайдера могут действовать.')
        elif re.search(r'^Status:\s+active',ufw.stdout,re.M): print('UFW включён. Разрешённые порты смотрите в правилах выше.')
        else: print('Не удалось распознать состояние UFW.')
    else: print('Состояние UFW неизвестно; отсутствие команды не означает отсутствие firewall.')
    for name in ('iptables','ip6tables'):
        result=results.get(name)
        if result and result.returncode==0 and re.search(r'^-P INPUT ACCEPT$',result.stdout,re.M):
            print(name+': политика INPUT — ACCEPT; дополнительные правила выше могут ограничивать трафик.')
    nft=results.get('nft')
    if nft and nft.returncode==0 and not nft.stdout.strip(): print('nftables: команда не показала правил.')
    print('SSH порты:',', '.join(map(str,ssh_ports())))
    print('Важно: аудит не проверяет firewall провайдера и не доказывает доступность портов извне.')
    print('Прежде чем включать firewall, определите порты панели и клиентских подключений; SSH-порт нужно сохранить.')

def firewall():
    supported(); audit(); ports=ssh_ports()
    extra=[port(s) for s in input('Дополнительные TCP-порты (панель/Reality/80), через пробел: ').split()]
    udp=[port(s) for s in input('Дополнительные UDP-порты, через пробел (можно пусто): ').split()]
    tcp=sorted(set(ports+extra))
    ufw=shutil.which('ufw'); ufw_active=False
    if ufw: ufw_active='Status: active' in run(['ufw','status'],env={**os.environ,'LC_ALL':'C'}).stdout
    rules=run(['nft','list','ruleset'],check=False).stdout if shutil.which('nft') else ''
    iptables=run(['iptables','-S'],check=False).stdout if shutil.which('iptables') else ''
    ip6tables=run(['ip6tables','-S'],check=False).stdout if shutil.which('ip6tables') else ''
    if not ufw_active and (active('firewalld') or active('nftables') or rules.strip() or any(line.startswith('-A ') or line.endswith(' DROP') for line in (iptables+'\n'+ip6tables).splitlines())):
        raise Error('Найдены существующие nftables/iptables правила. Чтобы не создавать параллельный firewall, используйте действующий менеджер; мастер не заменяет его правила.')
    install_packages(['ufw'])
    print('Разрешённые TCP:',tcp,'UDP:',udp,'; входящие по умолчанию deny, исходящие allow.')
    confirm('Применить UFW с откатом через 3 минуты')
    undo=[{'args':['ufw','reload' if ufw_active else 'disable']}]
    tx=Transaction('UFW',['/etc/ufw','/etc/default/ufw'],undo,180).arm()
    try:
        for number in tcp: run(['ufw','insert','1','allow',str(number)+'/tcp'])
        for number in udp: run(['ufw','allow',str(number)+'/udp'])
        run(['ufw','default','deny','incoming']); run(['ufw','default','allow','outgoing']); run(['ufw','--force','enable'])
        print(run(['ufw','status','verbose']).stdout)
        finish(tx,'Откройте новое SSH-подключение. Вход и нужные сервисы доступны')
    except BaseException: tx.rollback(); raise

def restrict_panel():
    supported()
    if not shutil.which('ufw') or 'Status: active' not in run(['ufw','status'],env={**os.environ,'LC_ALL':'C'}).stdout: raise Error('Для этой операции нужен действующий UFW.')
    number=port(input('Порт панели: ')); network=str(ipaddress.ip_network(input('Разрешённый адрес/CIDR администратора: ').strip(),strict=False))
    if number in ssh_ports(): raise Error('Порт панели совпадает с SSH; ограничение не применено.')
    print('Правила будут вставлены перед существующими: allow из',network,', deny остальных на TCP',number)
    confirm('Применить ограничение панели')
    tx=Transaction('panel firewall',['/etc/ufw','/etc/default/ufw'],[{'args':['ufw','reload']}],180).arm()
    try:
        run(['ufw','insert','1','deny',str(number)+'/tcp']); run(['ufw','insert','1','allow','from',network,'to','any','port',str(number),'proto','tcp'])
        finish(tx,'Доступ к панели с разрешённого адреса проверен')
    except BaseException: tx.rollback(); raise

def ssh_keys():
    supported(); public=input('Публичный SSH-ключ (ssh-ed25519 или ssh-rsa): ').strip()
    if not re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]+(?: [^\r\n]*)?',public): raise Error('Неверный публичный ключ; опции authorized_keys не допускаются.')
    private_dir(STATE/'tmp'); probe=STATE/'tmp'/'ssh-public-key'; write(probe,public+'\n')
    try: run(['ssh-keygen','-l','-f',probe])
    finally: probe.unlink(missing_ok=True)
    import pwd
    username=input('Локальный пользователь [root]: ').strip() or 'root'; account=pwd.getpwnam(username)
    home=Path(account.pw_dir); folder=home/'.ssh'; target=folder/'authorized_keys'
    if folder.is_symlink() or target.is_symlink(): raise Error('Ссылки в пути authorized_keys не поддерживаются.')
    previous=target.read_text() if target.exists() else ''
    if public.split()[:2] in [line.split()[:2] for line in previous.splitlines()]: print('Ключ уже установлен.'); return
    confirm('Добавить ключ пользователю '+username)
    from .backup import create
    snapshot=create([str(target)],'SSH key')
    folder.mkdir(mode=0o700,exist_ok=True); write(target,previous.rstrip()+'\n'+public+'\n')
    os.chown(folder,account.pw_uid,account.pw_gid); os.chown(target,account.pw_uid,account.pw_gid); os.chmod(folder,0o700)
    print('Ключ добавлен. Резервная копия:',snapshot)

def harden_ssh():
    supported(); print('Сначала выполните в другом терминале ssh -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no user@server.')
    confirm('Вход по ключу в НОВОМ SSH-сеансе успешно выполнен')
    file=Path('/etc/ssh/sshd_config.d/00-vps-manager.conf')
    main=Path('/etc/ssh/sshd_config').read_text()
    if not re.search(r'^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf',main,re.M): raise Error('В sshd_config нет стандартного Include. Автоматическая правка неоднозначна.')
    service='ssh' if active('ssh') else 'sshd'
    tx=Transaction('SSH key-only',[str(file)],[{'args':['systemctl','reload',service]}],180).arm()
    try:
        write(file,'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n',0o644)
        run(['sshd','-t']); out=run(['sshd','-T']).stdout
        if 'passwordauthentication no' not in out or 'kbdinteractiveauthentication no' not in out: raise Error('Другие директивы имеют приоритет; изменения отменены.')
        run(['systemctl','reload',service]); finish(tx,'Ещё один новый вход по ключу успешен')
    except BaseException: tx.rollback(); raise

def fail2ban():
    supported(); install_packages(['fail2ban']); ports=ssh_ports(); path=Path('/etc/fail2ban/jail.d/vps-manager.local')
    confirm('Включить Fail2ban sshd jail на портах '+','.join(map(str,ports)))
    was=active('fail2ban')
    tx=Transaction('Fail2ban',[str(path)],[{'args':['systemctl','restart' if was else 'stop','fail2ban']}],180).arm()
    try:
        write(path,'[sshd]\nenabled = true\nbackend = systemd\nport = '+','.join(map(str,ports))+'\nmaxretry = 5\nfindtime = 600\nbantime = 600\n',0o644)
        run(['fail2ban-client','-t']); run(['systemctl','enable','--now','fail2ban']); run(['systemctl','restart','fail2ban']); print(run(['fail2ban-client','status','sshd']).stdout); finish(tx)
    except BaseException: tx.rollback(); raise
