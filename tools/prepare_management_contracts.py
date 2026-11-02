#!/usr/bin/env python3
"""Apply reviewed candidate OpenAPI/refinement additions (no Rust execution).
The generated v1.schema.json is deliberately NOT edited: regenerate with the
real export_schema binary in the authorized build lane, then check drift/tests.
"""
from pathlib import Path
import copy,json
ROOT=Path(__file__).resolve().parents[1]
p=ROOT/'contracts/openapi/v1.yaml'; api=json.loads(p.read_text())
REF='../schema/v1.schema.json#/$defs/'
def ref(name):return {'$ref':REF+name}
def obj(props):return {'type':'object','additionalProperties':False,'properties':props,'required':list(props)}
def result(body):return obj({'schemaVersion':{'const':1},'requestId':ref('OpaqueId'),'operationId':{'anyOf':[ref('OpaqueId'),{'type':'null'}]},'result':body})
def response(body,description='Successful versioned result'):
 return {'description':description,'content':{'application/json':{'schema':body}}}
def parameter(name,where,schema,description=None):
 value={'name':name,'in':where,'required':True,'schema':schema}
 if description:value['description']=description
 return value
ID=parameter('id','path',ref('OpaqueId'))
IF=parameter('If-Match','header',{'type':'string','pattern':'^"[0-9]+"$'},'Quoted current record revision; must equal expectedRevision. Missing or mismatch is 412.')
FAIL={str(code):response(ref('FailureEnvelope'),'Structured failure without secret, URL or attacker-controlled path material') for code in [400,401,403,404,408,409,412,413,429,500,503]}
SECURITY_HEADERS={name:{'schema':{'type':'string','const':value}} for name,value in [('Cache-Control','no-store'),('Pragma','no-cache'),('Referrer-Policy','no-referrer')]}
def operation(oid,summary,body,method=None,payload=None,record=False,etag=False):
 responses=copy.deepcopy(FAIL);responses['200']=response(result(body))
 responses['200']['headers']=copy.deepcopy(SECURITY_HEADERS)
 if etag:responses['200']['headers']['ETag']={'schema':{'type':'string','pattern':'^"[0-9]+"$'}}
 op={'operationId':oid,'summary':summary,'x-implementation-status':'loopback-vless-v1-integration-verified-not-public-certified','security':[{'sessionCookie':[],**({'csrfToken':[]} if method else {})}],'responses':responses}
 if record:op['parameters']=[copy.deepcopy(ID)]+([copy.deepcopy(IF)] if method else [])
 if method:
  request=obj({'schemaVersion':{'const':1},'requestId':ref('OpaqueId'),'idempotencyKey':ref('OpaqueId'),'expectedRevision':ref('Revision'),'method':{'const':method},'payload':ref(payload)})
  op['requestBody']={'required':True,'content':{'application/json':{'schema':request}}}
 return op
paths={
 '/api/v1/credentials':{
  'get':operation('getCredentialInventory','Bounded safe metadata plus actual generator kinds; not protocol certification',ref('CredentialInventory')),
  'post':operation('createCredential','Explicit operator generation into encrypted vault; returns reference metadata only',ref('CredentialSummary'),'credential_create','CredentialCreatePayload',etag=True)},
 '/api/v1/credentials/{id}/retire':{
  'post':operation('retireCredential','Retire only unreferenced immutable vault object; preserve rollback/recovery history',ref('CredentialSummary'),'credential_retire','CredentialRetirePayload',record=True,etag=True)},
 '/api/v1/publications':{
  'get':operation('listPublications','At most 16 safe metadata records; never secret URLs/tokens',{'type':'array','maxItems':16,'items':ref('PublicationSummary')}),
  'post':operation('createPublication','Authorize exact currently observed active listener/user mappings',ref('PublicationSummary'),'publication_create','PublicationCreatePayload',etag=True)},
 '/api/v1/publications/{id}':{
  'get':operation('getPublication','Safe publication metadata and explicit pinned source revision',ref('PublicationSummary'),record=True,etag=True),
  'put':operation('replacePublication','Explicit republish to verified current active config; no silent follow',ref('PublicationSummary'),'publication_replace','PublicationReplacePayload',record=True,etag=True)},
 '/api/v1/publications/{id}/token':{
  'post':operation('issuePublicationToken','Explicit independent token issue/rotation; URL shown once only',ref('PublicationIssuedSecret'),'publication_token_issue','PublicationIssuePayload',record=True,etag=True),
  'delete':operation('revokePublicationToken','Revoke subscription access, not cached node credentials or live VPN sessions',ref('PublicationSummary'),'publication_token_revoke','PublicationRevokePayload',record=True,etag=True)},
}
paths['/api/v1/credentials']['post']['description']='expectedRevision is current active config revision. Payload requires confirmGenerate:true. Unsupported kind fails without substituting another kind. UUID is the only actual v1 generator capability. Credential writes use durable intent and the shared writer; uncertain outcomes recover without regenerating.'
paths['/api/v1/publications']['post']['description']='expectedRevision pins the exact committed and freshly verified runtime revision. Every source must resolve enabled listener/user and export losslessly; full-list atomic output only. Maximum 16 publications, 32 sources each; metadata response <=1 MiB.'
paths['/api/v1/publications/{id}']['put']['description']='CAS uses publication revision; payload sourceRevision must be current freshly observed active config. Any runtime commit makes old publication stale until this explicit republish. Disabling atomically revokes access; re-enabling never restores the old token.'
paths['/api/v1/publications/{id}/token']['post']['description']='Operator-configured trusted HTTPS origin required, never inferred from Host. Separate explicit development-loopback policy is local-test-only. The action key is durably consumed before entropy; only a domain-separated verifier and safe receipt are persisted. Same-key retry returns 409 SECRET_RESULT_UNAVAILABLE, never another token or a replay of raw URL. On response loss, read safe metadata and explicitly rotate with a new key/revision. Raw response must not enter diagnostics/storage/logs/screenshots or implicit clipboard. Token rotation does not revoke downloaded node credentials.'
public_responses=copy.deepcopy(FAIL)
public_responses['405']=response(ref('FailureEnvelope'),'Only GET is supported; structured response except HTTP HEAD body suppression')
public_responses['200']={'description':'Complete lossless UTF-8 URI list; contains deliberate connection secrets, never ordinary metadata','headers':{**copy.deepcopy(SECURITY_HEADERS),'X-VP-Config-Revision':{'schema':{'type':'string','pattern':'^[0-9]+$'}}},'content':{'text/plain':{'schema':{'type':'string','minLength':1,'maxLength':262144,'x-sensitive':True}}}}
paths['/subscriptions/v1/{id}/{token}']={'get':{
 'operationId':'fetchPublication','summary':'Independent bearer-path subscription retrieval; no management authority',
 'x-implementation-status':'loopback-vless-v1-integration-verified-not-public-certified','security':[],
 'x-independent-authorization':'Only the bounded token path parameter authenticates publication access. Session cookies confer no authority; Authorization header/query fallback is rejected.',
 'description':'Explicit trusted Host only; no CORS/redirect/query/body. Never log the URL/path or token. Invalid/revoked/expired/unknown tokens share generic 401. Fixed bounded rate and one outstanding probe/export; exact live runtime/config validation before <=256KiB full response. Unsupported/lossy/stale content fails atomically; clients retain prior list and require preview/diff confirmation on refresh. Successful audit commit precedes body release.',
 'parameters':[copy.deepcopy(ID),parameter('token','path',{'type':'string','pattern':'^vps1_[a-f0-9]{64}$','x-sensitive':True},'Independent random bearer secret; never a management token.')],
 'responses':public_responses}}
api['paths'].update(paths)
# Existing inherited prose contradicted actual structured 412 handling.
for path in api['paths'].values():
 for op in path.values():
  if isinstance(op,dict):
   for param in op.get('parameters',[]):
    if param.get('name')=='If-Match':param['description']=param.get('description','').replace('Missing is 428; mismatch is 412.','Missing or mismatch is 412.')
p.write_text(json.dumps(api,indent=2)+'\n')
r=ROOT/'contracts/schema/v1.refinements.json';review=json.loads(r.read_text());defs=review['$defs']
TIME={'type':'integer','minimum':0,'maximum':9007199254740991}
POSITIVE={'type':'integer','minimum':1,'maximum':9007199254740991}
defs.update({
 'ExplicitConfirmation':{'type':'boolean','const':True},
 'CredentialSummary':{'properties':{'schemaVersion':{'const':1},'revision':POSITIVE,'createdAt':TIME}},
 'CredentialInventory':{'properties':{'schemaVersion':{'const':1},'supportedKinds':{'type':'array','maxItems':11,'uniqueItems':True},'credentials':{'type':'array','maxItems':128}}},
 'PublicationSummary':{'properties':{'schemaVersion':{'const':1},'revision':POSITIVE,'sourceRevision':POSITIVE,'createdAt':TIME,'updatedAt':TIME,'lastSuccessfulReadAt':{'anyOf':[TIME,{'type':'null'}]}},'required':['lastSuccessfulReadAt']},
 'PublicationTokenStatus':{'properties':{'issuedAt':{'anyOf':[TIME,{'type':'null'}]},'expiresAt':{'anyOf':[TIME,{'type':'null'}]}},'required':['issuedAt','expiresAt']},
})
# check_contracts.py intentionally compares complete property sets, so use
# nested allOf refinement members for partial cross-cutting constraints.
for name in ['CredentialSummary','CredentialInventory','PublicationSummary','PublicationTokenStatus']:
 defs[name]={'allOf':[defs[name]]}
codes=defs['ProductError']['properties']['code']['enum']
if 'SECRET_RESULT_UNAVAILABLE' not in codes: codes.insert(codes.index('SECRET_NOT_FOUND')+1,'SECRET_RESULT_UNAVAILABLE')
r.write_text(json.dumps(review,indent=2)+'\n')
print('prepared 10 operations across 6 candidate paths; generated schema untouched')
