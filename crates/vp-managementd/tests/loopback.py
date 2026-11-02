#!/usr/bin/env python3
"""Real loopback daemon, ephemeral synthetic credential and private temp DB only.
No TLS/browser or proxy-protocol acceptance claim. No keys/cookies printed/saved.
"""
import http.client
import json
import os
import re
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from jsonschema import Draft202012Validator

binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/vp-product-managementd').resolve()
assert binary.is_file()
repo = Path(__file__).resolve().parents[3]
openapi = json.loads((repo/'contracts/openapi/v1.yaml').read_text())
defs = json.loads((repo/'contracts/schema/v1.schema.json').read_text())['$defs']
validated_responses = 0

def local_refs(value):
    if isinstance(value, dict):
        return {k: (v.replace('../schema/v1.schema.json#/', '#/') if k == '$ref' else local_refs(v)) for k,v in value.items()}
    if isinstance(value, list): return [local_refs(v) for v in value]
    return value

def validate_response(method, path, status, body):
    global validated_responses
    path=path.split('?')[0]
    for template, methods in openapi['paths'].items():
        pattern=re.sub(r'\{[^}]+\}',r'[^/]+',template)
        if re.fullmatch(pattern,path) and method.lower() in methods:
            responses=methods[method.lower()]['responses']
            assert str(status) in responses, f'undocumented status {status} for {method} {template}'
            schema=local_refs(responses[str(status)]['content']['application/json']['schema'])
            schema['$defs']=defs
            Draft202012Validator(schema).validate(body)
            validated_responses += 1
            return
    raise AssertionError('uncontracted test request')

token = secrets.token_urlsafe(32)
with socket.socket() as socket_:
    socket_.bind(('127.0.0.1', 0))
    port = socket_.getsockname()[1]
origin = f'http://127.0.0.1:{port}'
host = f'127.0.0.1:{port}'

def request(method, path, body=None, cookie=None, csrf=None, headers=None):
    h = {'Host': host, 'Origin': origin, 'Content-Type': 'application/json'}
    if cookie: h['Cookie'] = cookie
    if csrf: h['X-VP-CSRF'] = csrf
    if headers: h.update(headers)
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    try:
        conn.request(method, path, None if body is None else json.dumps(body), h)
        r = conn.getresponse()
        data = json.loads(r.read(1024*1024))
        assert r.getheader('Cache-Control') == 'no-store'
        validate_response(method,path,r.status,data)
        return r.status, dict(r.getheaders()), data
    finally:
        conn.close()

def start(root):
    process = subprocess.Popen([str(binary), '--state-root', root, '--bind', host, '--origin', origin, '--web-root', str(Path(root)/'web')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.stdin.write(json.dumps({'username':'synthetic-admin','token':token}).encode())
    process.stdin.close(); process.stdin = None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None: raise AssertionError('daemon terminated before readiness')
        try:
            assert request('GET', '/api/v1/build')[0] == 401
            return process
        except (ConnectionRefusedError, ConnectionResetError): time.sleep(.05)
    raise AssertionError('daemon failed to listen before bounded deadline')

def stop(process):
    if process.poll() is None: process.send_signal(signal.SIGINT)
    try: out, err = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill(); process.communicate(); raise AssertionError('daemon graceful shutdown timeout')
    assert process.returncode == 0
    assert token.encode() not in out + err

def login():
    status, headers, body = request('POST','/api/v1/auth/login',{'username':'synthetic-admin','password':token,'secondFactor':None})
    assert status == 200
    cookie = headers['set-cookie']
    for flag in ['Secure','HttpOnly','SameSite=Strict']: assert flag in cookie
    return cookie.split(';')[0], body['result']['csrfToken']

def command(method, key, revision, payload):
    return {'schemaVersion':1,'requestId':'loopback-request','idempotencyKey':key,'expectedRevision':revision,'method':method,'payload':payload}

with tempfile.TemporaryDirectory(prefix='vp-api-loopback-') as root:
    os.chmod(root, 0o700)
    assets = Path(root)/'web'; assets.mkdir(mode=0o700)
    (assets/'index.html').write_text('<!doctype html><title>VP synthetic static boundary test</title>')
    (Path(root)/'outside.json').write_text('{"private":"synthetic-nonsecret"}')
    (assets/'escape.json').symlink_to(Path(root)/'outside.json')
    process = start(root)
    try:
        conn = http.client.HTTPConnection('127.0.0.1',port,timeout=3)
        conn.request('GET','/',headers={'Host':host}); response=conn.getresponse(); assert response.status==200 and b'VP synthetic' in response.read(); conn.close()
        for path in ['/escape.json','/%2e%2e/outside.json']:
            conn = http.client.HTTPConnection('127.0.0.1',port,timeout=3)
            conn.request('GET',path,headers={'Host':host}); response=conn.getresponse(); assert response.status==404; response.read();conn.close()

        cookie, csrf = login()
        capabilities = request('GET','/api/v1/capabilities',cookie=cookie)
        assert capabilities[0] == 200 and capabilities[2]['result']
        assert all(c['status']=='blocked' for c in capabilities[2]['result'])
        assert request('GET','/api/v1/auth/session',cookie=cookie)[2]['result']['csrfToken'] == csrf
        assert request('GET','/api/v1/build',cookie=cookie,headers={'Host':'evil.invalid'})[0] == 403
        assert request('GET','/api/v1/build?session=forbidden',cookie=cookie)[0] == 400
        assert request('POST','/api/v1/auth/logout',cookie=cookie,csrf=csrf,headers={'Origin':'https://evil.invalid'})[0] == 403
        assert request('POST','/api/v1/auth/logout',cookie=cookie,csrf='wrong')[0] == 403
        config = {'schemaVersion':1,'minimumReaderVersion':1,'nodes':[],'listeners':[],'subscriptions':[]}
        create = command('draft_create','persistent-retry',0,config)
        created = request('POST','/api/v1/drafts',create,cookie,csrf)
        assert created[0] == 200 and created[1]['etag'] == '"1"'
        draft = created[2]['result']
        assert request('POST','/api/v1/drafts',create,cookie,csrf)[2]['result'] == draft
        assert request('POST',f'/api/v1/drafts/{draft["id"]}/validate',command('validate','validate',1,{}),cookie,csrf)[0] == 503
        assert request('POST','/api/v1/plans',command('plan_create','plan',0,{'draftId':draft['id']}),cookie,csrf)[0] == 503
        assert request('GET','/api/v1/config',cookie=cookie)[2]['result'] == {'revision':0,'config':None}
        assert request('GET','/api/v1/operations/missing-operation',cookie=cookie)[0] == 404
        assert request('GET','/api/v1/drafts/%FF',cookie=cookie)[0] == 400
        assert request('GET','/api/v1/build',cookie=cookie,headers={'Origin':'null'})[0] == 403
        oversized=command('draft_create','oversized',0,{'untrusted':'x'*(600*1024)})
        assert request('POST','/api/v1/drafts',oversized,cookie,csrf)[0] == 413
        # Actual HTTP slow-body rejection, not a fabricated timeout result.
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
        conn.putrequest('POST','/api/v1/drafts',skip_host=True)
        for name,value in {'Host':host,'Origin':origin,'Content-Type':'application/json','Content-Length':'999','Cookie':cookie,'X-VP-CSRF':csrf}.items(): conn.putheader(name,value)
        conn.endheaders(b'{')
        response=conn.getresponse(); body=json.loads(response.read(65536))
        assert response.status==408 and response.getheader('Cache-Control')=='no-store'
        validate_response('POST','/api/v1/drafts',response.status,body);conn.close()
        # A repeated Cookie header must not be accepted as a second credential.
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
        conn.putrequest('GET','/api/v1/build',skip_host=True)
        conn.putheader('Host',host);conn.putheader('Cookie',cookie);conn.putheader('Cookie',cookie);conn.endheaders()
        response=conn.getresponse();body=json.loads(response.read(65536));assert response.status==403
        validate_response('GET','/api/v1/build',response.status,body);conn.close()

        stop(process)
        process = start(root)
        assert request('GET','/api/v1/build',cookie=cookie)[0] == 401  # ephemeral sessions revoked on restart
        cookie, csrf = login()
        assert request('POST','/api/v1/drafts',create,cookie,csrf)[2]['result'] == draft  # durable retry
        replace = command('draft_replace','replace',1,config)
        assert request('PUT',f'/api/v1/drafts/{draft["id"]}',replace,cookie,csrf)[0] == 412
        assert request('PUT',f'/api/v1/drafts/{draft["id"]}',replace,cookie,csrf,{'If-Match':'"1"'})[0] == 200
        assert request('POST','/api/v1/auth/logout',cookie=cookie,csrf=csrf)[0] == 200
        assert request('GET','/api/v1/build',cookie=cookie)[0] == 401
        for _ in range(11):
            status, _, _ = request('POST','/api/v1/auth/login',{'username':'synthetic-admin','password':'wrong','secondFactor':None})
            if status==429: break
            assert status==401
        else: raise AssertionError('login limiter did not engage')
    finally:
        if process.poll() is None: stop(process)
    public = subprocess.run([str(binary),'--state-root',root,'--bind','0.0.0.0:9876','--origin','https://admin.example.invalid'],input=b'',capture_output=True,timeout=5)
    assert public.returncode != 0 and b'loopback' in public.stderr
print(f'Validated {validated_responses} actual HTTP responses against canonical OpenAPI/domain schemas')
print('PASS: real HTTP authentication, Host/Origin/CSRF, session rotation/revocation, draft CAS, durable retry across restart, fail-closed runtime, public-bind refusal, same-origin static assets/traversal rejection; ephemeral local-only data removed')
