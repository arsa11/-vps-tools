"""Local/official release updates: immutable releases and atomic current symlink."""
import os, re, shutil, tempfile, uuid
from pathlib import Path
from .core import Error, STATE, confirm, private_dir, read, run, sha, supported, write
from . import releases
INSTALL=Path('/opt/vps-manager')

def update():
    supported(); config=read('/etc/vps-manager/update.json') if Path('/etc/vps-manager/update.json').exists() else {}
    local=input('Локальный .tar.gz/.zip (Enter — настроенный официальный репозиторий): ').strip()
    private_dir(STATE/'downloads')
    with tempfile.TemporaryDirectory(dir=STATE/'downloads') as d:
        d=Path(d)
        if local:
            archive=Path(local).resolve(); expected=input('Доверенный SHA256: ').strip().lower()
            if not re.fullmatch(r'[0-9a-f]{64}',expected) or sha(archive)!=expected: raise Error('SHA256 не совпал.')
        else:
            repo=config.get('repository')
            if not repo: raise Error('Официальный репозиторий этого проекта ещё не опубликован. Используйте локальный релиз; неизвестные зеркала не выбираются автоматически.')
            rel=releases.release(repo,input('Тег или latest [latest]: ').strip() or 'latest'); print(rel['tag_name']); print(rel.get('body',''))
            archive=d/'release.tar.gz'
            if not releases.download_asset(repo,rel,config.get('asset','vps-manager.tar.gz'),archive): raise Error('Для самообновления требуется SHA256 издателя либо локальный проверенный архив.')
        stage=releases.extract(archive,d/'stage')
        candidates=list(stage.rglob('vps-manager.sh'))
        if len(candidates)!=1: raise Error('Неверный дистрибутив VPS Manager.')
        source=candidates[0].parent
        if not (source/'vpsmanager/cli.py').is_file(): raise Error('В дистрибутиве нет CLI.')
        run(['/usr/bin/python3','-m','compileall','-q',str(source)],timeout=60)
        run(['/usr/bin/python3',str(source/'vps_manager.py'),'--version'],cwd=source)
        confirm('Атомарно переключить VPS Manager на выбранный релиз, сохранив предыдущий')
        deploy(source)
        print('Обновление установлено. Конфигурация /etc/vps-manager и состояние /var/lib/vps-manager сохранены.')

def deploy(source):
    INSTALL.mkdir(parents=True,exist_ok=True); root=INSTALL/'releases'; root.mkdir(exist_ok=True)
    destination=root/uuid.uuid4().hex; shutil.copytree(source,destination,ignore=shutil.ignore_patterns('__pycache__','research','tmp*','.git','.devtools','.test-tools','dist'))
    current=INSTALL/'current'
    if current.exists() and not current.is_symlink(): raise Error('/opt/vps-manager/current должен быть ссылкой.')
    previous=os.readlink(current) if current.is_symlink() else None
    temp=INSTALL/('.current-'+uuid.uuid4().hex); temp.symlink_to(destination); os.replace(temp,current)
    if previous:
        old=INSTALL/('.previous-'+uuid.uuid4().hex); old.symlink_to(previous); os.replace(old,INSTALL/'previous')
    launcher='#!/bin/sh\nexec /usr/bin/python3 /opt/vps-manager/current/vps_manager.py "$@"\n'
    write('/usr/local/bin/vps-manager',launcher,0o755)
    return destination

def previous():
    supported(); old=INSTALL/'previous'
    if not old.is_symlink() or not old.resolve().is_dir(): raise Error('Предыдущая версия отсутствует.')
    confirm('Вернуться к предыдущей версии менеджера')
    target=os.readlink(old); current=INSTALL/'current'; current_target=os.readlink(current)
    temp=INSTALL/('.switch-'+uuid.uuid4().hex); temp.symlink_to(target); os.replace(temp,current)
    temp.symlink_to(current_target); os.replace(temp,old)
