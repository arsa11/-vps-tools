"""Real timer/worker-death test. Run only in a disposable root systemd container."""
import os, subprocess, sys, tempfile, time
from pathlib import Path
if os.environ.get('VPS_MANAGER_DISPOSABLE_TEST')!='1' or os.name!='posix' or os.geteuid()!=0 or not Path('/run/systemd/system').exists():
    raise SystemExit('Requires explicit disposable Linux/systemd test environment.')
root=Path(__file__).resolve().parents[1]
# Docker exec and systemd services may see different /tmp mounts.
with tempfile.TemporaryDirectory(prefix='vps-manager-smoke-',dir='/var/lib') as d:
    d=Path(d); target=d/'fixture'; target.write_text('before'); state=d/'state'
    worker=d/'worker.py'
    worker.write_text('import sys,time\nfrom pathlib import Path\nsys.path.insert(0,'+repr(str(root))+')\nfrom vpsmanager.transaction import Transaction\nfrom vpsmanager.core import write\nt=Transaction("test",['+repr(str(target))+'],seconds=12).arm()\nwrite('+repr(str(target))+',"changed")\nprint(t.id,flush=True)\ntime.sleep(90)\n')
    env={**os.environ,'VPS_MANAGER_STATE':str(state)}
    process=subprocess.Popen([sys.executable,str(worker)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
    ident=process.stdout.readline().strip()
    if len(ident)!=32: raise RuntimeError(process.stderr.read())
    deadline=time.monotonic()+40
    while time.monotonic()<deadline and target.read_text()!='before': time.sleep(1)
    assert target.read_text()=='before','timer did not restore file'
    process.wait(timeout=5)
    assert process.returncode!=0,'timer did not terminate applying worker'
    import json
    data=json.loads((state/'transactions'/ident/'transaction.json').read_text()); assert data['status']=='rolled_back',data
    print('PASS: independent systemd timer restored state and terminated worker')
    worker.write_text(worker.read_text().replace('time.sleep(90)','t.commit()'))
    subprocess.run([sys.executable,str(worker)],env=env,check=True)
    time.sleep(15)
    assert target.read_text()=='changed','committed transaction rolled back unexpectedly'
    print('PASS: commit cancelled timer and retained new state')
