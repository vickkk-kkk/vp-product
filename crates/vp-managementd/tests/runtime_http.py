#!/usr/bin/env python3
"""Actual authenticated HTTP -> control/SQLite -> encrypted vault -> pinned worker.
Synthetic temporary credentials only; all listeners/targets on loopback. This is
local integration evidence, NOT independent VLESS certification or public service.
"""
import argparse
import hashlib
import http.client
import json
import os
import re
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from jsonschema import Draft202012Validator

parser=argparse.ArgumentParser()
parser.add_argument('--daemon',required=True,type=Path)
parser.add_argument('--worker',required=True,type=Path)
parser.add_argument('--evidence',type=Path)
args=parser.parse_args()
daemon=args.daemon.resolve(); worker=args.worker.resolve()
assert daemon.is_file() and worker.is_file()
worker_hash=hashlib.sha256(worker.read_bytes()).hexdigest()
repo=Path(__file__).resolve().parents[3]
openapi=json.loads((repo/'contracts/openapi/v1.yaml').read_text())
defs=json.loads((repo/'contracts/schema/v1.schema.json').read_text())['$defs']
validated_responses=0

def local_refs(value):
    if isinstance(value,dict): return {k:(v.replace('../schema/v1.schema.json#/','#/') if k=='$ref' else local_refs(v)) for k,v in value.items()}
    if isinstance(value,list): return [local_refs(v) for v in value]
    return value

def validate_response(method,path,status,body):
    global validated_responses
    for template,methods in openapi['paths'].items():
        if re.fullmatch(re.sub(r'\{[^}]+\}',r'[^/]+',template),path) and method.lower() in methods:
            responses=methods[method.lower()]['responses']
            assert str(status) in responses, 'undocumented response status'
            schema=local_refs(responses[str(status)]['content']['application/json']['schema']);schema['$defs']=defs
            Draft202012Validator(schema).validate(body)
            validated_responses+=1
            return
    raise AssertionError('uncontracted test request')

bootstrap_token=secrets.token_urlsafe(32)
master_key=secrets.token_hex(32)
old_credential=str(uuid.uuid4()); new_credential=str(uuid.uuid4())
assert old_credential != new_credential

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]
port=free_port(); listen_port=free_port()
host=f'127.0.0.1:{port}'; origin=f'http://{host}'

def request(method,path,payload=None,auth=None,extra=None):
    headers={'Host':host,'Origin':origin,'Content-Type':'application/json'}
    if auth: headers.update({'Cookie':auth[0],'X-VP-CSRF':auth[1]})
    if extra: headers.update(extra)
    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=30)
    try:
        conn.request(method,path,None if payload is None else json.dumps(payload),headers)
        response=conn.getresponse(); data=json.loads(response.read(1024*1024))
        assert response.getheader('Cache-Control')=='no-store'
        validate_response(method,path,response.status,data)
        return response.status,dict(response.getheaders()),data
    finally: conn.close()

def command(method,key,revision,payload):
    return {'schemaVersion':1,'requestId':'actual-runtime-test','idempotencyKey':key,'expectedRevision':revision,'method':method,'payload':payload}

def start(root,initialize=False,key=None,selected_worker=None,digest=None):
    cmd=[str(daemon),'--state-root',str(root/'control'),'--bind',host,'--origin',origin,
         '--runtime-profile','loopback-vless-v1','--runtime-root',str(root/'runtime'),
         '--worker',str(selected_worker or worker),'--worker-sha256',digest or worker_hash,
         '--vault-root',str(root/'vault'),'--vault-namespace','runtime-http-test',
         '--vault-action','initialize' if initialize else 'open','--probe-bind','127.0.0.1:0']
    supplied={'username':'synthetic-runtime-admin','token':bootstrap_token,'vault':{
        'masterKeyHex':key or master_key,'credentials':[
            {'reference':'secret:synthetic-old-v1','version':1,'value':old_credential},
            {'reference':'secret:synthetic-new-v2','version':2,'value':new_credential},
        ] if initialize else []}}
    p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p.stdin.write(json.dumps(supplied).encode()); p.stdin.close();p.stdin=None
    return p

def ready(p):
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        if p.poll() is not None:
            out,err=p.communicate(); assert_no_credentials(out+err)
            raise AssertionError('real daemon startup failed: '+err.decode(errors='replace'))
        try:
            result=request('GET','/api/v1/build')
            if result[0]==401: return
        except (OSError,ValueError): pass
        time.sleep(.03)
    raise AssertionError('real daemon startup exceeded deadline')

def assert_no_credentials(data):
    for value in [bootstrap_token,master_key,old_credential,new_credential]: assert value.encode() not in data
    assert bytes.fromhex(master_key) not in data

def stop(p):
    if p.poll() is None: p.send_signal(signal.SIGTERM)
    try: out,err=p.communicate(timeout=35)
    except subprocess.TimeoutExpired:
        p.kill();p.communicate();raise AssertionError('daemon shutdown deadline exceeded')
    assert_no_credentials(out+err)
    assert p.returncode==0, 'daemon did not cleanly stop owned worker'

def login():
    status,headers,body=request('POST','/api/v1/auth/login',{'username':'synthetic-runtime-admin','password':bootstrap_token,'secondFactor':None})
    assert status==200
    return headers['set-cookie'].split(';')[0],body['result']['csrfToken']

def config(credential,bind_port=listen_port):
    fixture=json.loads((Path(__file__).parent/'fixtures/vless_loopback.json').read_text())
    fixture['listeners'][0]['bind']['port']=bind_port
    fixture['listeners'][0]['protocol']['users'][0]['credentialRef']=credential
    return fixture

def plan(auth,key,revision,configuration):
    status,_,result=request('POST','/api/v1/drafts',command('draft_create',key+'-draft',revision,configuration),auth)
    assert status==200,(status,result.get('error'))
    draft=result['result']
    status,_,valid=request('POST',f'/api/v1/drafts/{draft["id"]}/validate',command('validate',key+'-validate',draft['revision'],{}),auth)
    assert status==200 and valid['result']['valid'],(status,valid.get('error'))
    status,_,result=request('POST','/api/v1/plans',command('plan_create',key+'-plan',revision,{'draftId':draft['id']}),auth)
    assert status==200,(status,result.get('error'))
    return result['result']

def apply(auth,key,revision,prepared):
    payload=command('plan_apply',key+'-apply',revision,{'planHash':prepared['planHash'],'confirmed':True})
    route=f'/api/v1/plans/{prepared["id"]}/apply'
    status,_,accepted=request('POST',route,payload,auth); assert status==202,(status,accepted.get('error'))
    operation=accepted['operationId']; assert operation
    status,_,replayed=request('POST',route,payload,auth);assert status==202 and replayed['operationId']==operation
    deadline=time.monotonic()+40
    while time.monotonic()<deadline:
        status,_,result=request('GET',f'/api/v1/operations/{operation}',auth=auth); assert status==200
        state=result['result']['status']
        if state in ['succeeded','failed','rolled_back','recovery_required','canceled']:
            return result['result']
        time.sleep(.04)
    raise AssertionError('actual operation did not terminate within deadline')

def exact_read(stream,length):
    out=b''
    while len(out)<length:
        piece=stream.recv(length-len(out))
        if not piece: raise EOFError()
        out+=piece
    return out

def client_roundtrip(credential,listener_port,target_port,marker):
    with socket.create_connection(('127.0.0.1',listener_port),timeout=1) as s:
        s.settimeout(1)
        packet=b'\0'+uuid.UUID(credential).bytes+b'\0\1'+target_port.to_bytes(2,'big')+b'\1\x7f\0\0\1'+marker
        s.sendall(packet)
        try: return exact_read(s,2)==b'\0\0' and exact_read(s,len(marker))==marker
        except (OSError,EOFError): return False

def verify_wire(credential,expected=True):
    # Separate caller-owned target, distinct from daemon's health echo. Accept and
    # payload counters ensure wrong credentials do not reach this target either.
    import threading
    target=socket.socket(); target.bind(('127.0.0.1',0));target.listen();target.settimeout(.5)
    target_port=target.getsockname()[1]; marker=secrets.token_bytes(32); accepted=[]
    def echo():
        try:
            conn,_=target.accept();accepted.append(True)
            with conn: conn.settimeout(.5);data=exact_read(conn,32);conn.sendall(data)
        except (OSError,EOFError): pass
    thread=threading.Thread(target=echo);thread.start()
    try: result=client_roundtrip(credential,listen_port,target_port,marker)
    finally: thread.join(timeout=2);target.close()
    assert not thread.is_alive()
    assert result==expected and bool(accepted)==expected

def snapshot(auth,revision):
    status,_,body=request('GET','/api/v1/snapshot',auth=auth);assert status==200
    result=body['result'];assert result['desiredRevision']==revision and result['observedRevision']==revision
    listener=result['listeners'][0]
    assert listener['status']=='ready' and listener['bound'] and listener['authenticationLoaded']
    assert listener['forwarding']['status']=='passed' and listener['forwarding']['observedAt'] and listener['forwarding']['evidenceId']
    assert listener['generation']>0
    return listener['generation']

process=None
with tempfile.TemporaryDirectory(prefix='vp-management-runtime-') as temp:
    root=Path(temp);os.chmod(root,0o700)
    for child in ['control','runtime','vault']:(root/child).mkdir(mode=0o700)
    try:
        process=start(root,initialize=True);ready(process);auth=login()
        status,_,initial=request('GET','/api/v1/config',auth=auth);assert status==200 and initial['result']['revision']==0
        first=apply(auth,'first',0,plan(auth,'first',0,config('secret:synthetic-old-v1')))
        assert first['status']=='succeeded',first
        first_generation=snapshot(auth,1);verify_wire(old_credential)
        prepared=plan(auth,'rotate',1,config('secret:synthetic-new-v2'))
        concurrent_results=[]
        def concurrent_observation():
            try:
                for _ in range(3):
                    status,_,body=request('GET','/api/v1/snapshot',auth=auth)
                    assert status==200
                    assert body['result']['observedRevision'] in (1,2)
                    concurrent_results.append(True)
            except Exception as error: concurrent_results.append(type(error).__name__)
        observer=threading.Thread(target=concurrent_observation);observer.start()
        try: rotate=apply(auth,'rotate',1,prepared)
        finally: observer.join(timeout=30)
        assert not observer.is_alive() and concurrent_results==[True,True,True],concurrent_results
        assert rotate['status']=='succeeded',rotate
        second_generation=snapshot(auth,2);assert second_generation>first_generation
        verify_wire(new_credential);verify_wire(old_credential,False)
        # A real external bind conflict fails candidate startup after stopping old;
        # shared control must restore/verify the committed generation without mocks.
        occupied=socket.socket();occupied.bind(('127.0.0.1',0));occupied.listen()
        try:
            failed=apply(auth,'conflict',2,plan(auth,'conflict',2,config('secret:synthetic-new-v2',occupied.getsockname()[1])))
            # A foreign port owner prevents proving candidate absence: do not
            # turn that missing evidence into a successful rollback.
            assert failed['status']=='recovery_required',failed
            status,_,blocked=request('GET','/api/v1/snapshot',auth=auth)
            assert status==200 and blocked['result']['observedRevision'] is None
        finally: occupied.close()
        stop(process);process=None
        # Once the external conflict is gone, real shared startup recovery can
        # finish candidate-release verification and restore committed service.
        process=start(root);ready(process);auth=login()
        status,_,recovered=request('GET',f'/api/v1/operations/{failed["id"]}',auth=auth)
        assert status==200 and recovered['result']['status']=='rolled_back'
        rollback_generation=snapshot(auth,2);assert rollback_generation>second_generation
        verify_wire(new_credential);verify_wire(old_credential,False)
        stop(process);process=None
        try:
            with socket.create_connection(('127.0.0.1',listen_port),timeout=.5):
                raise AssertionError('listener still accepts after graceful shutdown')
        except ConnectionRefusedError: pass
        # Match Rust/worker TCP listener reuse policy: established test flows may
        # leave TIME_WAIT after real process exit; that is not an active listener.
        with socket.socket() as released:
            released.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            released.bind(('127.0.0.1',listen_port))
        # The encrypted vault is reopened, not repopulated; committed config is
        # explicitly reconciled and actively verified before HTTP is served.
        process=start(root);ready(process)
        assert request('GET','/api/v1/config',auth=auth)[0]==401
        auth=login();restart_generation=snapshot(auth,2);assert restart_generation>rollback_generation
        verify_wire(new_credential);verify_wire(old_credential,False)
        status,_,found=request('GET','/api/v1/operations/by-idempotency/rotate-apply',auth=auth)
        assert status==200 and found['result']['id']==rotate['id']
        # Unsupported/nonloopback configuration never silently becomes enabled.
        bad=config('secret:synthetic-new-v2');bad['listeners'][0]['bind']['address']='0.0.0.0'
        status,_,draft=request('POST','/api/v1/drafts',command('draft_create','public-draft',2,bad),auth);assert status==200
        status,_,rejected=request('POST','/api/v1/plans',command('plan_create','public-plan',2,{'draftId':draft['result']['id']}),auth)
        assert status==400 and rejected['error']['code']=='CONFIG_INVALID'
        stop(process);process=None
        for path in root.rglob('*'):
            if path.is_file(): assert_no_credentials(path.read_bytes())
        # Wrong master key fails closed; never initialize/reset an existing vault.
        wrong=start(root,key=secrets.token_hex(32));out,err=wrong.communicate(timeout=15)
        assert wrong.returncode!=0;assert_no_credentials(out+err)
        # Wrong worker digest also fails without starting listeners.
        wrong=start(root,digest='0'*64);out,err=wrong.communicate(timeout=15)
        assert wrong.returncode!=0;assert_no_credentials(out+err)
    finally:
        if process is not None: stop(process)
result={'status':'passed','profile':'loopback-vless-v1-uncertified','daemonSha256':hashlib.sha256(daemon.read_bytes()).hexdigest(),'workerSha256':worker_hash,
        'validatedHttpResponses':validated_responses,'checks':['authenticated-http-apply','encrypted-vault-reopen','fresh-generation-observation','concurrent-observation-apply-serialization','credential-rotation-old-rejection','actual-bind-failure-recovery-required','restart-finishes-real-rollback','graceful-port-release','restart-reconcile','durable-idempotency','nonloopback-denial','wrong-master-key-denial','worker-digest-denial','no-plaintext-credentials-on-disk-or-logs'],
        'independentProtocolCertification':False,'externalConnectivity':'not_checked','productionDeployment':False}
if args.evidence: args.evidence.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
