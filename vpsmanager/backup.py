"""Private directory snapshots with SQLite backup, inventory and exact restoration."""
import contextlib, datetime, os, shutil, sqlite3, stat, tempfile
from pathlib import Path, PurePosixPath
from .core import STATE, Error, private_dir, read, write, sha
DEFAULT_PATHS=['/etc/x-ui','/usr/local/x-ui','/etc/systemd/system/x-ui.service','/etc/systemd/system/x-ui.service.d','/usr/bin/x-ui','/etc/netplan','/etc/systemd/network','/etc/NetworkManager/system-connections','/etc/network/interfaces','/etc/network/interfaces.d','/etc/resolv.conf','/etc/systemd/resolved.conf','/etc/systemd/resolved.conf.d','/etc/ssh/sshd_config','/etc/ssh/sshd_config.d','/etc/ufw','/etc/nftables.conf','/etc/letsencrypt','/root/.acme.sh','/etc/vps-manager']

def create(paths=None,label='manual',base=None):
    root=private_dir(base or STATE/'backups')
    dest=Path(tempfile.mkdtemp(prefix=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-'),dir=root))
    private_dir(dest); private_dir(dest/'data')
    records=[]; roots=[]
    def capture(path,rel):
        if not path.exists() and not path.is_symlink(): records.append({'path':str(path),'rel':rel,'kind':'missing'}); return
        st=path.lstat(); entry={'path':str(path),'rel':rel,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid}
        if path.is_symlink(): entry.update(kind='symlink',target=os.readlink(path))
        elif path.is_dir():
            entry['kind']='directory'; records.append(entry)
            for child in sorted(path.iterdir()):
                if child.name.endswith(('-wal','-shm')) and Path(str(child)[:-4]).suffix in ('.db','.sqlite','.sqlite3'): continue
                capture(child,rel+'/'+child.name)
            return
        elif path.is_file():
            entry['kind']='file'; out=dest/'data'/rel; out.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            if path.suffix.lower() in ('.db','.sqlite','.sqlite3'):
                with contextlib.closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)) as source, contextlib.closing(sqlite3.connect(out)) as target:
                    source.backup(target)
                    if target.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise Error('Повреждена SQLite: '+str(path))
            else:
                with open(path,'rb') as src, open(out,'xb') as dst: shutil.copyfileobj(src,dst)
            os.chmod(out,0o600); entry.update(sha256=sha(out),size=out.stat().st_size)
        else: raise Error('Неподдерживаемый тип файла: '+str(path))
        records.append(entry)
    selected=sorted({Path(p).absolute() for p in (paths if paths is not None else DEFAULT_PATHS)},key=lambda p:(len(p.parts),str(p)))
    selected=[p for p in selected if not any(parent in selected for parent in p.parents)]
    for idx,path in enumerate(selected):
        if str(path) in roots: continue
        if path==Path(path.anchor) or str(path) in ('/','/etc','/usr','/var','/root'): raise Error('Слишком широкий путь резервирования.')
        roots.append(str(path)); capture(path,str(idx))
    write(dest/'manifest.json',{'format':2,'label':label,'roots':roots,'records':records,'complete':True})
    return dest

def verify(directory):
    directory=Path(directory); manifest=read(directory/'manifest.json')
    if manifest.get('format')!=2 or not manifest.get('complete'): raise Error('Неполная или неподдерживаемая копия.')
    roots=[Path(p) for p in manifest['roots']]; seen=set()
    if not roots: raise Error('Пустой список корней копии.')
    for root in roots:
        if not root.is_absolute() or root==Path(root.anchor) or str(root) in ('/etc','/usr','/var','/root','/home','/boot','/opt') or '..' in root.parts:
            raise Error('Опасный корень восстановления.')
    links={Path(e['path']) for e in manifest['records'] if e.get('kind')!='directory'}
    for e in manifest['records']:
        path=Path(e['path']); rel=PurePosixPath(e['rel'])
        if not path.is_absolute() or not any(path==r or r in path.parents for r in roots): raise Error('Путь вне корней копии.')
        if rel.is_absolute() or '..' in rel.parts or '\\' in e['rel'] or ':' in e['rel']: raise Error('Некорректный путь в манифесте.')
        if any(parent in links for parent in path.parents): raise Error('Запись внутри символической ссылки запрещена.')
        if str(path) in seen: raise Error('Повторяющийся путь в манифесте.')
        seen.add(str(path))
        if e['kind']=='file':
            source=directory/'data'/e['rel']
            if source.is_symlink() or not source.is_file() or directory.resolve() not in source.resolve().parents or sha(source)!=e['sha256']: raise Error('Контрольная сумма не совпала: '+str(path))
        elif e['kind'] not in ('missing','directory','symlink'): raise Error('Неизвестный тип записи.')
    return manifest

def restore(directory):
    manifest=verify(directory)
    # A snapshot can restore only its own roots. Never traverse a symlink ancestor.
    for root in manifest['roots']:
        for parent in Path(root).parents:
            if parent.is_symlink(): raise Error('Ссылка в родительском пути восстановления: '+str(parent))
    for root in manifest['roots']:
        p=Path(root)
        if p.is_symlink() or p.is_file(): p.unlink()
        elif p.is_dir(): shutil.rmtree(p)
    for e in sorted(manifest['records'],key=lambda x:len(Path(x['path']).parts)):
        p=Path(e['path']); kind=e['kind']
        if kind=='missing': continue
        p.parent.mkdir(parents=True,exist_ok=True)
        if kind=='directory': p.mkdir(exist_ok=True)
        elif kind=='symlink': p.symlink_to(e['target'])
        else: write(p,(Path(directory)/'data'/e['rel']).read_bytes(),e['mode'])
        if os.name=='posix':
            os.chown(p,e['uid'],e['gid'],follow_symlinks=False)
            if kind!='symlink': os.chmod(p,e['mode'])
    return manifest
