"""Official release downloads and safe archive staging."""
import json, re, tarfile, urllib.request, urllib.error, zipfile
from pathlib import Path, PurePosixPath
from .core import Error, sha, write

def fetch(url,limit=512*1024*1024):
    if not url.startswith('https://'): raise Error('Загрузка требует HTTPS.')
    try:
        req=urllib.request.Request(url,headers={'User-Agent':'VPS-Manager/1.0'})
        with urllib.request.urlopen(req,timeout=45) as r:
            if not r.url.startswith('https://'): raise Error('Небезопасное перенаправление.')
            data=r.read(limit+1)
            if len(data)>limit: raise Error('Файл превышает допустимый размер.')
            return data
    except (OSError,urllib.error.URLError): raise Error('Официальный ресурс недоступен. Проверьте DNS/HTTPS или используйте локальный архив с SHA256.') from None

def release(repo,tag='latest'):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo): raise Error('Некорректный репозиторий.')
    if tag!='latest' and not re.fullmatch(r'[A-Za-z0-9_.-]+',tag): raise Error('Некорректный тег.')
    suffix='latest' if tag=='latest' else 'tags/'+tag
    obj=json.loads(fetch('https://api.github.com/repos/'+repo+'/releases/'+suffix,4*1024*1024))
    if obj.get('draft') or obj.get('prerelease'): raise Error('Выбран нестабильный релиз.')
    if tag!='latest' and obj.get('tag_name')!=tag: raise Error('Релиз не совпал с запрошенным.')
    return obj

def download_asset(repo,rel,name,destination):
    matches=[a for a in rel['assets'] if a['name']==name]
    if len(matches)!=1: raise Error('В этом релизе нет архива '+name)
    asset=matches[0]; url=asset['browser_download_url']
    if not url.startswith('https://github.com/'+repo+'/releases/download/'): raise Error('Неофициальный URL архива.')
    write(destination,fetch(url))
    expected=asset.get('digest') or ''
    if expected.startswith('sha256:'):
        if sha(destination)!=expected[7:]: raise Error('Контрольная сумма релиза не совпала.')
        return True
    # Explicitly tell callers when the publisher did not provide a digest.
    return False

def extract(archive,destination):
    destination=Path(destination); destination.mkdir(parents=True,exist_ok=True)
    seen=set(); total=0
    def target(name,size):
        nonlocal total
        p=PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name or name in seen: raise Error('Небезопасный путь в архиве.')
        total+=size
        if total>2*1024**3: raise Error('Распакованный архив слишком велик.')
        seen.add(name); return destination.joinpath(*p.parts)
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for item in z.infolist():
                if (item.external_attr>>16)&0o170000==0o120000: raise Error('Ссылки в дистрибутиве запрещены.')
                out=target(item.filename,item.file_size)
                if item.is_dir(): out.mkdir(parents=True,exist_ok=True)
                else: write(out,z.read(item),0o755 if item.filename.endswith(('xray','x-ui')) else 0o644)
    else:
        with tarfile.open(archive) as t:
            for item in t:
                out=target(item.name,item.size)
                if item.isdir(): out.mkdir(parents=True,exist_ok=True)
                elif item.isfile():
                    with t.extractfile(item) as f: write(out,f.read(),0o755 if item.mode&0o111 else 0o644)
                else: raise Error('Ссылки и специальные файлы в дистрибутиве запрещены.')
    return destination
