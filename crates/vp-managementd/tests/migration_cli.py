#!/usr/bin/env python3
"""Deferred real old-binary/new-binary offline payload migration test.
No systemd, public bind, data-plane listener or restore. Actual ephemeral vault retirement is verified after migration. Only ephemeral synthetic login.
Do not run until the parent allocates the build/test lane and supplies binaries.
"""
import argparse,hashlib,http.client,json,os,secrets,signal,socket,sqlite3,subprocess,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--old-daemon',type=Path,required=True);p.add_argument('--new-daemon',type=Path,required=True);p.add_argument('--worker',type=Path,required=True);p.add_argument('--evidence',type=Path);a=p.parse_args()
old=a.old_daemon.resolve();new=a.new_daemon.resolve();worker=a.worker.resolve();assert old.is_file() and new.is_file() and worker.is_file()
worker_hash=hashlib.sha256(worker.read_bytes()).hexdigest();master=secrets.token_hex(32)
token=secrets.token_urlsafe(32);username='synthetic-migration-operator'
with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
host=f'127.0.0.1:{port}';origin=f'http://{host}';processes=[]
def safe(data):
    assert token.encode() not in data and master.encode() not in data and bytes.fromhex(master) not in data, 'sensitive fixture exposed in process output'
def start(binary,root,vault_action=None):
    command=[str(binary),'--state-root',str(root),'--bind',host,'--origin',origin]
    supplied={'username':username,'token':token}
    if vault_action:
        command += ['--runtime-profile','loopback-vless-v1','--runtime-root',str(root.parent/'runtime'),'--worker',str(worker),'--worker-sha256',worker_hash,'--vault-root',str(root.parent/'vault'),'--vault-namespace','migration-retirement-test','--vault-action',vault_action,'--probe-bind','127.0.0.1:0']
        supplied['vault']={'masterKeyHex':master,'credentials':[]}
    proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    processes.append(proc);proc.stdin.write(json.dumps(supplied).encode());proc.stdin.close();proc.stdin=None;return proc
def request(method,path,body=None,auth=None,match=None):
    headers={'Host':host,'Origin':origin,'Content-Type':'application/json'}
    if auth:headers.update({'Cookie':auth[0],'X-VP-CSRF':auth[1]})
    if match is not None:headers['If-Match']=f'"{match}"'
    c=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
    try:
        c.request(method,path,None if body is None else json.dumps(body),headers);r=c.getresponse();data=r.read(1024*1024);safe(data);return r.status,dict(r.getheaders()),json.loads(data)
    finally:c.close()
def ready(proc):
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        if proc.poll() is not None:out,err=proc.communicate();safe(out+err);raise AssertionError('daemon exited before authentication boundary')
        try:
            if request('GET','/api/v1/build')[0]==401:return
        except (OSError,ValueError):pass
        time.sleep(.03)
    raise AssertionError('daemon startup deadline')
def stop(proc):
    if proc.poll() is None:proc.send_signal(signal.SIGTERM)
    out,err=proc.communicate(timeout=25);safe(out+err);assert proc.returncode==0,'daemon did not stop cleanly'
def refused(proc):
    out,err=proc.communicate(timeout=20);safe(out+err);assert proc.returncode!=0,'incompatible payload unexpectedly accepted'
def login():
    status,headers,body=request('POST','/api/v1/auth/login',{'username':username,'password':token,'secondFactor':None});assert status==200
    return headers['set-cookie'].split(';')[0],body['result']['csrfToken']
def command(method,key,revision,payload):return {'schemaVersion':1,'requestId':'migration-test','idempotencyKey':key,'expectedRevision':revision,'method':method,'payload':payload}
def state(root):
    c=sqlite3.connect(f'file:{root}/control.db?mode=ro',uri=True)
    try:
        version,payload,digest=c.execute('SELECT version,payload,digest FROM control_state WHERE singleton=1').fetchone();payload=bytes(payload);assert hashlib.sha256(payload).hexdigest()==digest;return version,payload,json.loads(payload)
    finally:c.close()
def migrate(root):
    result=subprocess.run([str(new),'--state-root',str(root),'--state-upgrade','v1-to-v2'],input=b'',capture_output=True,timeout=20);safe(result.stdout+result.stderr);assert result.returncode==0,'offline migration failed';assert not result.stderr;return json.loads(result.stdout)
record={'status':'not-run','scope':'temporary old/new daemon payload migration; no vault restore'}
try:
 with tempfile.TemporaryDirectory(prefix='vp-payload-migration-') as directory:
    root=Path(directory)/'control';root.mkdir(mode=0o700)
    (root.parent/'runtime').mkdir(mode=0o700);(root.parent/'vault').mkdir(mode=0o700)
    proc=start(old,root);ready(proc);auth=login()
    config={'schemaVersion':1,'minimumReaderVersion':1,'nodes':[],'listeners':[],'subscriptions':[]}
    status,_,response=request('POST','/api/v1/drafts',command('draft_create','fixture-old-draft',0,config),auth);assert status==200;draft=response['result']
    stop(proc);old_version,old_payload,old_state=state(root);assert old_state['schemaVersion']==1 and old_version>0
    refused(start(new,root));assert state(root)[1]==old_payload;assert not(root/'control.v1-before-v2.db').exists()
    receipt=migrate(root);assert receipt['sourceFormat']==1 and receipt['targetFormat']==2 and receipt['sourceStateVersion']==old_version and receipt['targetStateVersion']==old_version+1
    backup=root/'control.v1-before-v2.db';assert hashlib.sha256(backup.read_bytes()).hexdigest()==receipt['backupDigest']
    assert receipt['sourcePayloadDigest']==hashlib.sha256(old_payload).hexdigest()
    migrated_version,migrated_payload,migrated_state=state(root);assert migrated_state['schemaVersion']==2 and migrated_state['secrets']=={'credentials':{},'publications':{},'actions':[]}
    assert receipt['targetPayloadDigest']==hashlib.sha256(migrated_payload).hexdigest();assert migrated_state['drafts']==old_state['drafts']
    refused(start(old,root));assert state(root)[1]==migrated_payload
    proc=start(new,root,'initialize');ready(proc);auth=login();status,_,response=request('GET',f"/api/v1/drafts/{draft['id']}",auth=auth);assert status==200 and response['result']==draft
    status,_,response=request('PUT',f"/api/v1/drafts/{draft['id']}",command('draft_replace','fixture-after-migration',draft['revision'],config),auth,match=draft['revision']);assert status==200 and response['result']['revision']==draft['revision']+1
    status,_,created=request('POST','/api/v1/credentials',command('credential_create','post-migration-node',0,{'kind':{'kind':'uuid'},'confirmGenerate':True}),auth);assert status==200
    credential=created['result']
    retire_command=command('credential_retire','post-migration-retire',credential['revision'],{'confirmRetire':True})
    status,_,retired=request('POST',f"/api/v1/credentials/{credential['id']}/retire",retire_command,auth,match=credential['revision']);assert status==200 and retired['result']['state']=='retired'
    stop(proc);post_version,post_payload,post_state=state(root);assert post_version>migrated_version
    assert post_state['secrets']['credentials'][credential['id']]['summary']['state']=='retired'
    vault_before={str(path.relative_to(root.parent/'vault')):hashlib.sha256(path.read_bytes()).hexdigest() for path in (root.parent/'vault').rglob('*') if path.is_file()}
    assert migrate(root)==receipt;assert state(root)[1]==post_payload,'migration replay discarded later business write'
    refused(start(old,root));assert state(root)[1]==post_payload
    assert {str(path.relative_to(root.parent/'vault')):hashlib.sha256(path.read_bytes()).hexdigest() for path in (root.parent/'vault').rglob('*') if path.is_file()}==vault_before,'maintenance changed retired vault'
    proc=start(new,root,'open');ready(proc);auth=login()
    status,_,inventory=request('GET','/api/v1/credentials',auth=auth);assert status==200 and inventory['result']['credentials']==[retired['result']]
    status,_,replayed=request('POST',f"/api/v1/credentials/{credential['id']}/retire",retire_command,auth,match=credential['revision']);assert status==200 and replayed==retired
    stop(proc);assert state(root)[1]==post_payload,'restart or retirement replay rewrote history'

    record.update(status='passed',oldDaemonSha256=hashlib.sha256(old.read_bytes()).hexdigest(),newDaemonSha256=hashlib.sha256(new.read_bytes()).hexdigest(),oldStateVersion=old_version,migratedStateVersion=migrated_version,postMigrationStateVersion=post_version,offlineReceipt=receipt,crossFormatRollback='refused',vaultRestore='never invoked',actualVaultRetirement='preserved across migration replay, downgrade refusal and vault reopen',workerSha256=worker_hash)
finally:
 for proc in processes:
    if proc.poll() is None:
        proc.terminate()
        try:out,err=proc.communicate(timeout=25)
        except subprocess.TimeoutExpired:proc.kill();out,err=proc.communicate()
        safe(out+err)
if a.evidence:a.evidence.write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
