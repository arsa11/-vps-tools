"""Persistent systemd rollback, independent of the SSH process and reboot."""
import datetime, os, signal, shutil, time, uuid
from pathlib import Path
from .core import STATE, Error, private_dir, read, write, run, log, lock
from . import backup

class Transaction:
    def __init__(self,label,paths,undo=None,seconds=180):
        existing=STATE/'transactions'
        for item in existing.glob('*/transaction.json') if existing.exists() else []:
            previous=read(item)
            if previous.get('status') in ('armed','rolling_back','failed'):
                raise Error('Есть незавершённая транзакция '+previous['id']+'. Сначала проверьте или откатите её.')
        self.id=uuid.uuid4().hex
        self.path=private_dir(STATE/'transactions'/self.id)
        self.name='vps-manager-rollback-'+self.id
        snap=backup.create(paths,label)
        backup.verify(snap)
        self.data={'id':self.id,'label':label,'backup':str(snap),'undo':undo or [],'status':'prepared','deadline':time.time()+seconds,'name':self.name,'worker_pid':os.getpid(),'worker_start':process_start(os.getpid())}
        write(self.path/'transaction.json',self.data)
    def arm(self):
        # Keep an immutable runner alongside the transaction so self-update cannot break rollback.
        runner=self.path/'runner'; runner.mkdir()
        shutil.copytree(Path(__file__).parent,runner/'vpsmanager',ignore=shutil.ignore_patterns('__pycache__'))
        write(runner/'rollback.py',"from vpsmanager.transaction import rollback\nimport sys\nrollback(sys.argv[1])\n")
        when=datetime.datetime.fromtimestamp(self.data['deadline'],datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        service=f'[Unit]\nDescription=VPS Manager emergency rollback\n[Service]\nType=oneshot\nRestart=on-failure\nRestartSec=5s\nExecStart=/usr/bin/python3 {runner}/rollback.py {self.path}\n'
        timer=f'[Unit]\nDescription=VPS Manager rollback deadline\n[Timer]\nOnCalendar={when}\nPersistent=true\nAccuracySec=1s\n[Install]\nWantedBy=timers.target\n'
        write('/etc/systemd/system/'+self.name+'.service',service,0o644)
        write('/etc/systemd/system/'+self.name+'.timer',timer,0o644)
        self.data['status']='armed'; write(self.path/'transaction.json',self.data)
        run(['systemctl','daemon-reload']); run(['systemctl','enable','--now',self.name+'.timer'])
        run(['systemctl','is-active',self.name+'.timer'])
        log('transaction_armed',id=self.id,label=self.data['label'])
        return self
    def commit(self):
        with lock(self.path/'lock'):
            data=read(self.path/'transaction.json')
            if data['status']!='armed' or time.time()>=data['deadline']: raise Error('Транзакция истекла или уже откачена. Изменения не подтверждены.')
            data['status']='committed'; write(self.path/'transaction.json',data)
            cleanup(data['name'])
        log('transaction_committed',id=self.id)
    def rollback(self): rollback(self.path)

def cleanup(name):
    run(['systemctl','disable','--now',name+'.timer'],check=False)
    for suffix in ('.timer','.service'):
        Path('/etc/systemd/system/'+name+suffix).unlink(missing_ok=True)
    run(['systemctl','daemon-reload'],check=False)

def process_start(pid):
    try: return Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
    except (OSError,IndexError): return None

def terminate_worker(data):
    pid=data.get('worker_pid')
    if not pid or pid==os.getpid() or not data.get('worker_start') or process_start(pid)!=data['worker_start']: return
    # Prevent a late apply from writing over the restored state after the timer fires.
    descendants=set(); pending=[pid]
    while pending:
        parent=pending.pop()
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit(): continue
            try:
                fields=(entry/'stat').read_text().rsplit(')',1)[1].split()
                child=int(entry.name)
                if int(fields[1])==parent and child not in descendants:
                    descendants.add(child); pending.append(child)
            except (OSError,ValueError,IndexError): continue
    starts={target:process_start(target) for target in [*descendants,pid]}
    for target in [*descendants,pid]:
        try: os.kill(target,signal.SIGTERM)
        except ProcessLookupError: pass
    time.sleep(0.3)
    for target,start in starts.items():
        if start and process_start(target)==start:
            try: os.kill(target,signal.SIGKILL)
            except ProcessLookupError: pass

def rollback(directory):
    directory=Path(directory)
    with lock(directory/'lock'):
        data=read(directory/'transaction.json')
        if data['status'] not in ('armed','rolling_back','failed'): return
        terminate_worker(data)
        data['status']='rolling_back'; write(directory/'transaction.json',data)
        try:
            # Stop producers before restoring files (e.g. SQLite writer).
            for cmd in data.get('undo',[]):
                if cmd.get('phase')=='before': run(cmd['args'],check=cmd.get('required',True),timeout=60)
            backup.restore(data['backup'])
            run(['systemctl','daemon-reload'],check=False)
            for cmd in data.get('undo',[]):
                if cmd.get('phase','after')=='after': run(cmd['args'],check=cmd.get('required',True),timeout=60)
            data['status']='rolled_back'; write(directory/'transaction.json',data); cleanup(data['name'])
            log('transaction_rolled_back',id=data['id'])
        except Exception:
            data['status']='failed'; write(directory/'transaction.json',data)
            log('transaction_rollback_failed',id=data['id']); raise

def finish(tx,message='Проверка успешна. Подтвердить изменения'):
    from .core import confirm
    print('Резервная копия:',tx.data['backup'])
    print('При потере SSH автоматический откат останется активным.')
    try: confirm(message); tx.commit()
    except BaseException:
        tx.rollback(); raise
