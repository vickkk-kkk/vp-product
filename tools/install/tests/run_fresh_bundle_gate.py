#!/usr/bin/env python3
"""Real approved bundle -> private first install -> supported API -> VLESS wire.

Explicit invocation only. Synthetic fixed bootstrap in a new retained evidence
root. No vault decryption, host changes, systemd or production credentials.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
from urllib.parse import urlsplit, unquote, parse_qsl
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vp_install import canonical, digest, require, InstallError
from vp_fresh_bundle import FreshBundle, MAINTENANCE
from vp_fresh_local import FreshLocal, UNINSTALLED
from vp_bootstrap import Bootstrap
from vp_api import Api
from vp_owned_runtime import identity as process_identity

USER='synthetic';TOKEN='S'*43;MASTER='12'*32

def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def exact_read(stream,n):
    value=b''
    while len(value)<n:
        chunk=stream.recv(n-len(value))
        if not chunk:raise EOFError()
        value+=chunk
    return value

def wire(credential,listener,expected):
    target=socket.socket();target.bind(('127.0.0.1',0));target.listen();target.settimeout(.7)
    port=target.getsockname()[1];received=[];marker=b'VP synthetic installer forwarding gate'
    def echo():
        try:
            stream,_=target.accept()
            with stream:
                stream.settimeout(1);value=exact_read(stream,len(marker));received.append(value==marker);stream.sendall(value)
        except (OSError,EOFError):pass
    thread=threading.Thread(target=echo);thread.start();forwarded=False
    try:
        with socket.create_connection(('127.0.0.1',listener),timeout=2) as s:
            s.settimeout(2);s.sendall(b'\0'+uuid.UUID(credential).bytes+b'\0\1'+port.to_bytes(2,'big')+b'\1\x7f\0\0\1'+marker)
            try:forwarded=exact_read(s,2)==b'\0\0' and exact_read(s,len(marker))==marker
            except (OSError,EOFError):pass
    finally:thread.join(3);target.close()
    require(not thread.is_alive() and forwarded==expected and bool(received)==expected,'wire acceptance mismatch')
    return {'forwarded':forwarded,'targetAccepted':bool(received),'payloadMatched':received==[True]}

def files(root):
    return {str(p.relative_to(root)):digest(p.read_bytes()) for p in root.rglob('*') if p.is_file()}

def apply(api,config):
    draft=api.command('/api/v1/drafts','draft_create','installer-draft',0,config)
    valid=api.command('/api/v1/drafts/'+draft['id']+'/validate','validate','installer-validate',draft['revision'],{})
    require(valid['valid'],'draft invalid')
    plan=api.command('/api/v1/plans','plan_create','installer-plan',0,{'draftId':draft['id']})
    op=api.command('/api/v1/plans/'+plan['id']+'/apply','plan_apply','installer-apply',0,{'planHash':plan['planHash'],'confirmed':True})
    deadline=time.monotonic()+45
    while op['status'] not in ('succeeded','failed','rolled_back','recovery_required','canceled'):
        require(time.monotonic()<deadline,'apply timeout')
        time.sleep(.1);op=api.request('GET','/api/v1/operations/'+op['id'])
    require(op['status']=='succeeded','apply did not succeed')

def fetch_publication(api,config,listener,sensitive):
    node=config['listeners'][0]
    publication=api.command('/api/v1/publications','publication_create','installer-publication',1,
        {'name':'Synthetic installer gate','enabled':True,'format':'uri_list','sources':[{'listenerId':node['id'],
         'userId':node['protocol']['users'][0]['id'],'endpoint':{'host':'127.0.0.1','port':listener},
         'clientSecurity':{'kind':'none'}}],'confirmPublishConnectionSecrets':True},etag=True)
    route='/api/v1/publications/'+publication['id']+'/token'
    issued=api.command(route,'publication_token_issue','installer-token',publication['revision'],
                       {'expiresInSeconds':600,'confirmIssueSecretUrl':True},etag=True,sensitive=True)
    require(issued['displayOnce'] is True,'secret URL was not one-time')
    parsed=urlsplit(issued['subscriptionUrl']);require(parsed.scheme=='http' and 'http://'+parsed.netloc==api.origin,'foreign publication origin')
    sensitive.append(issued['subscriptionUrl'].encode());sensitive.append(parsed.path.rsplit('/',1)[1].encode())
    conn=http.client.HTTPConnection('127.0.0.1',parsed.port,timeout=5)
    try:
        conn.request('GET',parsed.path);response=conn.getresponse();body=response.read(65537)
        require(response.status==200 and len(body)<=65536,'public subscription fetch failed')
    finally:conn.close()
    sensitive.append(body);lines=body.decode().splitlines();require(len(lines)==1,'unexpected subscription lines')
    uri=urlsplit(lines[0]);value=unquote(uri.username or '')
    require(uri.scheme=='vless' and uri.hostname=='127.0.0.1' and uri.port==listener and uuid.UUID(value).version==4 and
            dict(parse_qsl(uri.query))=={'encryption':'none','type':'tcp','security':'none'},'published connection mismatch')
    sensitive.append(value.encode());return value

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',required=True);parser.add_argument('--sha256',required=True);parser.add_argument('--out',required=True)
    args=parser.parse_args();out=Path(args.out).resolve();out.mkdir(mode=0o700)
    result={'scope':'synthetic private loopback only','productionCertified':False,'allProtocolsCertified':False,
            'status':'failed','checks':[], 'pidNamespace':os.readlink('/proc/self/ns/pid')};sensitive=[TOKEN.encode(),MASTER.encode()]
    def check(name):result['checks'].append(name)
    try:
        with FreshBundle(Path(args.bundle),args.sha256) as bundle:
            engine=FreshLocal(out/'installation',out/'materials')
            plan=engine.plan('install',bundle=bundle);engine.apply_install(plan,plan['planHash'],bundle);check('verified_bundle_install')
            source=out/'synthetic-import.json';source.write_bytes(canonical({'username':USER,'token':TOKEN,
                         'vault':{'masterKeyHex':MASTER,'credentials':[]}}));source.chmod(0o600)
            bootstrap=Bootstrap(engine.materials);opts={'username':USER,'namespace':'synthetic','requestKey':'installer-prepare',
                'generate':False,'importFile':str(source)}
            plan=engine.plan_bootstrap('prepare',opts);engine.apply_bootstrap(plan,plan['planHash'],opts);check('explicit_imported_material_preparation')
            opts={'maintenanceArtifact':str(engine.root/'release'/MAINTENANCE),
                  'maintenanceSha256':engine.hash_for(bundle.manifest,MAINTENANCE),'requestKey':'installer-vault-init'}
            plan=engine.plan_bootstrap('offline-vault-init',opts);engine.apply_bootstrap(plan,plan['planHash'],opts);check('sealed_bound_offline_init')
            port=free_port();origin='http://127.0.0.1:'+str(port);bind='127.0.0.1:'+str(port)
            plan=engine.plan('serve-fresh',bind=bind,origin=origin)
            with engine.run(plan,plan['planHash']) as (owned,ready):
                check('fresh_ready_empty_credentials');api=Api(origin);api.login(USER,TOKEN);check('administrator_login')
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
                try:
                    conn.request('GET','/');response=conn.getresponse();body=response.read(65537)
                    require(response.status==200 and digest(body)==engine.hash_for(bundle.manifest,'web/index.html'),'served actual panel index mismatch')
                finally:conn.close()
                check('same_origin_actual_panel_index')
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
                try:
                    conn.request('HEAD','/');response=conn.getresponse();empty=response.read(65537)
                    index_size=next(x['size'] for x in bundle.manifest['files'] if x['path']=='web/index.html')
                    require(response.status==200 and empty==b'' and response.getheader('Content-Length')==str(index_size),
                            'panel HEAD representation length mismatch')
                    conn.request('GET','/api');response=conn.getresponse();reserved=response.read(65537)
                    require(response.status==404 and b'<html' not in reserved.lower() and b'<!doctype' not in reserved.lower(),
                            'reserved API path fell through to panel')
                finally:conn.close()
                check('panel_head_length_and_reserved_api_refusal')
                inventory=api.request('GET','/api/v1/credentials');require(inventory['credentials']==[],'not empty initial credentials')
                payload={'kind':{'kind':'uuid'},'confirmGenerate':True}
                credential=api.command('/api/v1/credentials','credential_create','installer-credential',0,payload)
                replay=api.command('/api/v1/credentials','credential_create','installer-credential',0,payload)
                require(credential==replay and credential['state']=='available','credential idempotency failed');check('confirmed_api_uuid_generation')
                config=json.loads((Path(__file__).parent/'fixtures/fresh-vless-loopback.json').read_text());listener=free_port()
                config['listeners'][0]['bind']['port']=listener
                config['listeners'][0]['protocol']['users'][0]['credentialRef']=credential['secretRef']
                apply(api,config);owned.capture_workers();require(len(owned.workers)>0,'actual owned worker not observed');check('confirmed_plan_real_runtime_apply')
                value=fetch_publication(api,config,listener,sensitive);check('supported_subscription_delivery_no_vault_decryption')
                result['wireChecks']=[wire(value,listener,True),wire('11111111-1111-4111-8111-111111111111',listener,False)]
                check('real_vless_forwarding_and_wrong_credential_refusal');api.logout()
                result['firstOwnedWorkerCount']=len(owned.workers)
                first_workers=[dict(rec['identity']) for rec in owned.workers.values()]
                result['firstServicePid']=owned.process.pid
                result['firstServiceIdentity']=process_identity(owned.process.pid)
                result['firstWorkerIdentities']=first_workers
            require(owned.process.returncode==0,'owned service did not gracefully stop')
            for rec in first_workers:
                now=process_identity(rec['pid']);require(now is None or now['start']!=rec['start'] or now['state']=='Z','first owned worker remained live')
            result['firstServiceReapedExit']=owned.process.returncode
            result['firstWorkersNotLiveAfterOwnedStop']=True
            check('owned_stop')
            plan=engine.plan('serve-paired',bind=bind,origin=origin)
            with engine.run(plan,plan['planHash']) as (owned,ready):
                api=Api(origin);api.login(USER,TOKEN)
                result['wireChecks'].append(wire(value,listener,True));owned.capture_workers()
                require(len(owned.workers)>0,'paired worker not observed');api.logout();check('paired_login_and_actual_forwarding')
                paired_workers=[dict(rec['identity']) for rec in owned.workers.values()]
                result['pairedServicePid']=owned.process.pid;result['pairedWorkerIdentities']=paired_workers
                result['pairedServiceIdentity']=process_identity(owned.process.pid)
            require(owned.process.returncode==0,'paired stop failed')
            for rec in paired_workers:
                now=process_identity(rec['pid']);require(now is None or now['start']!=rec['start'] or now['state']=='Z','paired owned worker remained live')
            result['pairedServiceReapedExit']=owned.process.returncode
            result['pairedWorkersNotLiveAfterOwnedStop']=True
            # Snapshot every prior installation/release/material/import file;
            # deactivation may add only its explicit marker, never alter/delete bytes.
            before=files(out);retained_bytes=sum((out/name).stat().st_size for name in before)
            plan=engine.plan('uninstall');deactivated=engine.uninstall(plan,plan['planHash'])
            after=files(out)
            require(all(after.get(name)==sha for name,sha in before.items()),'deactivation changed a pre-existing file')
            require(set(after)-set(before)=={'installation/'+UNINSTALLED},'unexpected deactivation file mutation')
            require(deactivated['status']=='profile_disabled_all_files_retained' and
                    deactivated['allFilesRetained'] is True and deactivated['removesProgramFiles'] is False and
                    deactivated['deletedFiles']==0,'deactivation disclosure mismatch')
            result['retention']={'everyPreExistingFileByteIdentical':True,'fileCount':len(before),
                                 'byteCount':retained_bytes,'onlyAddedFile':'installation/'+UNINSTALLED,
                                 'scope':'release, installation metadata, materials and synthetic import',
                                 'removesProgramFiles':False,'deletedFiles':0}
            check('profile_deactivated_all_files_retained_no_program_files_removed_by_action')
            result['bundleSha256']=args.sha256;result['artifactSetDigest']=bundle.manifest['compatibilityDescriptor']['artifactSetDigest']
            result['status']='passed'
    except Exception as exc:
        # Never serialize arbitrary exception messages or process/HTTP bodies.
        result['errorType']=type(exc).__name__
        result['failedAfterChecks']=len(result['checks'])
        raise
    finally:
        raw=canonical(result)
        require(not any(secret in raw for secret in sensitive),'sensitive receipt rejected')
        (out/'RESULT.json').write_bytes(raw+b'\n');(out/'RESULT.json').chmod(0o600)
        print(json.dumps({'status':result['status'],'checks':len(result['checks']),'result':str(out/'RESULT.json')}))

if __name__=='__main__':main()
