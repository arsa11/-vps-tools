"""Interactive Russian CLI and automation-friendly read-only commands."""
import argparse, json, os, sys
from pathlib import Path
from .core import Error, STATE, VERSION, active, confirm, lock, private_dir, read, redact, root, run, supported, write
from . import backup, system, network, xui, proxy, certificates, security, updates
from .transaction import Transaction, finish, rollback

def select(title,choices):
    while True:
        print('\n'+title)
        for index,(label,_) in enumerate(choices,1): print(str(index)+'. '+label)
        print('0. Назад / выход')
        answer=input('Выбор: ').strip()
        if answer=='0': return
        if not answer.isdigit() or not 1<=int(answer)<=len(choices): print('Неизвестный пункт.'); continue
        try: choices[int(answer)-1][1]()
        except (Error,OSError,ValueError,KeyError) as e: print('Ошибка:',redact(str(e)))
        except KeyboardInterrupt: print('\nОперация прервана; проверьте список транзакций, если был запущен откат.')

def report(): system.print_report(system.diagnostics(input('Включить внешние DNS/HTTPS-проверки? [y/N]: ').lower()=='y'))
def backup_create():
    root(); print('Создана копия:',backup.create())
def backup_list():
    root=STATE/'backups'
    for path in sorted(root.iterdir()) if root.exists() else []:
        if path.is_dir():
            try: m=backup.verify(path); print(path.name,m.get('label'),'OK')
            except (Error,OSError,ValueError,KeyError): print(path.name,'ERROR — неполная или повреждённая копия')
def backup_verify(): print('OK:',len(backup.verify(input('Каталог копии: ').strip())['records']),'записей')
def backup_restore():
    supported(); source=Path(input('Каталог копии: ').strip()).resolve(); manifest=backup.verify(source)
    print('Будут восстановлены:',*manifest['roots'],sep='\n'); confirm('Заменить перечисленные пути содержимым копии')
    # Snapshot the current state before restoring another point in time.
    undo=xui.undo_panel()+[{'args':['networkctl','reload'],'required':False},{'args':['systemctl','try-restart','systemd-resolved'],'required':False}]
    tx=Transaction('manual restore',manifest['roots'],undo,300).arm()
    try:
        was=active('x-ui'); run(['systemctl','stop','x-ui'],check=False); backup.restore(source); run(['systemctl','daemon-reload'])
        if was: run(['systemctl','start','x-ui']); xui.panel_health()
        if input('Копия включает сеть. Применить netplan/networkd/NetworkManager сейчас? [y/N]: ').lower()=='y':
            if list(Path('/etc/netplan').glob('*.yaml')): run(['netplan','apply'],timeout=60)
            elif active('NetworkManager'): run(['nmcli','connection','reload'])
            elif active('systemd-networkd'): run(['networkctl','reload'])
        finish(tx,'Восстановленное состояние проверено, SSH доступен')
    except BaseException: tx.rollback(); raise

def transactions():
    root=STATE/'transactions'
    for path in sorted(root.iterdir()) if root.exists() else []:
        if (path/'transaction.json').exists():
            d=read(path/'transaction.json'); print(d['id'],d['label'],d['status'])
def transaction_rollback():
    root(); ident=input('ID транзакции: ').strip()
    if not __import__('re').fullmatch('[0-9a-f]{32}',ident): raise Error('Некорректный ID.')
    rollback(STATE/'transactions'/ident)

def service_command(action, label):
    supported()
    confirm(label+' службу x-ui')
    run(['systemctl',action,'x-ui'])
    if action in ('start','restart'): xui.panel_health()
    print('Готово. Текущее состояние:', 'работает' if active('x-ui') else 'не работает')

def service_action():
    supported()
    while True:
        state='работает' if active('x-ui') else 'не работает'
        enabled=run(['systemctl','is-enabled','x-ui'],check=False).stdout.strip() or 'неизвестно'
        enabled={'enabled':'включён','disabled':'выключен','static':'управляется системой','not-found':'служба не найдена','masked':'заблокирован'}.get(enabled,enabled)
        print('\nСлужба x-ui: '+state+'; автозапуск: '+enabled)
        print('1. Запустить панель')
        print('2. Остановить панель')
        print('3. Перезапустить панель')
        print('4. Включить автозапуск при включении сервера')
        print('5. Отключить автозапуск')
        print('0. Назад')
        choice=input('Выбор: ').strip()
        if choice=='0': return
        actions={'1':('start','Запустить'),'2':('stop','Остановить'),'3':('restart','Перезапустить'),'4':('enable','Включить автозапуск для'),'5':('disable','Отключить автозапуск для')}
        if choice not in actions:
            print('Выберите число от 0 до 5.'); continue
        action,label=actions[choice]
        try:
            service_command(action,label)
            if action=='enable': print('Автозапуск включён; чтобы запустить панель сейчас, выберите пункт 1.')
        except (Error,OSError,ValueError) as e: print('Ошибка:',redact(str(e)))

def xray_check():
    print(run([xui.xray_binary(),'version']).stdout)
    path=Path(input('JSON Xray [/usr/local/x-ui/bin/config.json]: ').strip() or '/usr/local/x-ui/bin/config.json'); xui.validate_config(read(path)); print('Xray configuration OK')
def xray_logs():
    # Explicit display only, no persistent raw log collection.
    print(redact(run(['journalctl','-u','x-ui','-n','80','--no-pager']).stdout))
def client_probe():
    import getpass
    from routing import parse_vless
    print(redact(proxy.outbound_probe(parse_vless(getpass.getpass('VLESS-ссылка: ')))))

def quick():
    supported(); file=STATE/'quick-setup.json'; progress=read(file) if file.exists() else {'completed':[]}
    steps=[('prepare','Подготовка сервера',system.prepare),('panel','Установка 3x-ui',xui.install),('https','HTTPS',certificates.certificates),('access','Настройки доступа панели',xui.configure),('reality','VLESS Reality',proxy.reality),('client','Проверка клиента',client_probe),('cascade','Каскад RU → EU (для роли RU)',proxy.routing),('diagnostics','Итоговая диагностика',report)]
    index=0
    while index<len(steps):
        key,label,action=steps[index]; print('\nШаг',index+1,label,'—', 'выполнен' if key in progress['completed'] else 'ожидает')
        choice=input('run — выполнить / skip — пропустить / back — назад / exit — сохранить и выйти: ').strip()
        if choice=='exit': return
        if choice=='back': index=max(0,index-1); continue
        if choice=='skip': index+=1; continue
        if choice!='run': continue
        try: action()
        except (Error,OSError,ValueError) as e: print('Шаг не завершён:',redact(str(e))); continue
        if key not in progress['completed']: progress['completed'].append(key)
        private_dir(STATE); write(file,progress); index+=1
    print('Мастер завершён. Результаты шагов сохранены:',file)

def menu():
    select('VPS Manager '+VERSION,[
      ('Подготовка сервера',lambda:select('Подготовка',[('Проверить и установить пакеты',system.prepare),('DNS Manager',system.dns),('NTP',system.ntp),('APT upgrade отдельно',system.upgrade)])),
      ('Установка / управление 3x-ui',lambda:select('3x-ui',[('Установить / обновить / сменить версию',xui.install),('Настройки панели',xui.configure),('Сменить логин и пароль',xui.credentials),('Служба x-ui',service_action),('Версия и проверка Xray',xray_check),('Обновить Xray отдельно',xui.xray_update),('Журнал (с маскированием)',xray_logs),('Открыть оригинальное меню 3x-ui (x-ui)',xui.official_menu)])),
      ('Управление IPv4 / IPv6',lambda:select('Сеть',[('Текущее состояние',lambda:print(json.dumps(network.inspect(),ensure_ascii=False,indent=2))),('Добавить адрес и изменить исходящий IP',network.change),('Проверить после перезагрузки',network.verify_persistent)])),
      ('Настройка VLESS Reality',proxy.reality),('Каскад RU → EU',proxy.routing),('SSL-сертификаты',certificates.certificates),
      ('Безопасность VPS',lambda:select('Безопасность',[('Аудит — посмотреть порты и firewall, без изменений',security.audit),('Firewall — настроить правила UFW',security.firewall),('Ограничить доступ к панели по IP',security.restrict_panel),('Добавить публичный SSH-ключ',security.ssh_keys),('Отключить парольный SSH после проверки ключа',security.harden_ssh),('Fail2ban — защита SSH от подбора пароля',security.fail2ban)])),
      ('Диагностика',lambda:select('Диагностика',[('Общий отчёт',report),('Тест VLESS-клиента',client_probe),('Проверка Xray JSON',xray_check)])),
      ('Резервные копии и восстановление',lambda:select('Копии',[('Создать',backup_create),('Список',backup_list),('Проверить',backup_verify),('Восстановить',backup_restore),('Транзакции',transactions),('Откатить транзакцию',transaction_rollback)])),
      ('Обновление VPS Manager',lambda:select('Обновление',[('Проверить и установить изменения с GitHub',updates.github_update),('Установить релиз из файла или другого настроенного источника',updates.update),('Вернуть предыдущую версию',updates.previous)])),
      ('Быстрая настройка нового VPS',quick)])

def main():
    parser=argparse.ArgumentParser(description='VPS Manager — Debian 12/13, Ubuntu 22.04/24.04')
    parser.add_argument('--version',action='version',version=VERSION)
    sub=parser.add_subparsers(dest='command')
    d=sub.add_parser('diagnose'); d.add_argument('--online',action='store_true'); d.add_argument('--json',action='store_true'); d.add_argument('--output')
    for command in ('menu','prepare','dns','ntp','backup','list-backups','restore','transactions','network','network-verify','xui','reality','routing','ssl','security','update','quick-setup','install-local'): sub.add_parser(command)
    v=sub.add_parser('verify'); v.add_argument('directory')
    r=sub.add_parser('rollback'); r.add_argument('id')
    args=parser.parse_args(); os.umask(0o077)
    try:
        if args.command=='diagnose':
            result=system.diagnostics(args.online)
            if args.output: write(args.output,redact(result))
            if args.json: print(json.dumps(redact(result),ensure_ascii=False,indent=2))
            else: system.print_report(result)
            return 1 if any(i['status']=='ERROR' for i in result['checks']) else 0
        if args.command=='verify': print('OK',len(backup.verify(args.directory)['records'])); return 0
        if args.command=='rollback':
            root()
            if not __import__('re').fullmatch('[0-9a-f]{32}',args.id): raise Error('Неверный ID.')
            rollback(STATE/'transactions'/args.id); return 0
        functions={'prepare':system.prepare,'dns':system.dns,'ntp':system.ntp,'backup':backup_create,'list-backups':backup_list,'restore':backup_restore,'transactions':transactions,'network':network.change,'network-verify':network.verify_persistent,'xui':xui.install,'reality':proxy.reality,'routing':proxy.routing,'ssl':certificates.certificates,'security':security.firewall,'update':updates.update,'quick-setup':quick,'install-local':lambda:(supported(),updates.deploy(Path(__file__).resolve().parents[1]))}
        if args.command in ('list-backups','transactions'): functions[args.command](); return 0
        root()
        with lock(): functions.get(args.command,menu)()
    except (Error,OSError,ValueError,KeyError) as e:
        print('Ошибка:',redact(str(e)),file=sys.stderr); return 1
    except (KeyboardInterrupt,EOFError): print('\nВыход. Незавершённые сетевые транзакции откатятся по таймеру.'); return 130
    return 0
