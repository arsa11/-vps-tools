#!/usr/bin/env python3
"""Build portable source releases without downloads, backups or development tools."""
import hashlib, tarfile, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
ALLOW={'vpsmanager','tests','templates','modules','lib','.github','vps_manager.py','vps-manager.sh','install.sh','routing.py','README.md','ACCEPTANCE.md','CHANGELOG.md','build_release.py','.gitignore','LICENSE'}
def main():
    dist=ROOT/'dist'; dist.mkdir(exist_ok=True)
    paths=sorted(p for p in ROOT.rglob('*') if p.is_file() and p.relative_to(ROOT).parts[0] in ALLOW and '__pycache__' not in p.parts and not p.name.endswith('.pyc'))
    with tarfile.open(dist/'vps-manager.tar.gz','w:gz') as tar, zipfile.ZipFile(dist/'VPS-Manager-1.0.0.zip','w',zipfile.ZIP_DEFLATED) as z:
        for p in paths:
            name='VPS-Manager/'+p.relative_to(ROOT).as_posix(); data=p.read_bytes()
            info=tarfile.TarInfo(name); info.size=len(data); info.mode=0o755 if p.suffix=='.sh' else 0o644; info.mtime=0
            import io
            tar.addfile(info,io.BytesIO(data)); z.writestr(name,data)
    hashes=[]
    for name in ('vps-manager.tar.gz','VPS-Manager-1.0.0.zip'):
        p=dist/name; digest=hashlib.sha256(p.read_bytes()).hexdigest(); hashes.append(digest+'  '+name); print(name,p.stat().st_size,digest)
    (dist/'SHA256SUMS').write_text('\n'.join(hashes)+'\n',encoding='ascii')
if __name__=='__main__': main()
