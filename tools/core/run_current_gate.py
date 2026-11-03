#!/usr/bin/env python3
"""Explicit serialized current-pin regression; never invoke on an unreviewed upstream."""
import argparse,hashlib,json,os,pathlib,re,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[2]
CORE=ROOT/'integration/vp_core'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--pin',required=True)
parser.add_argument('--evidence-dir',required=True,type=pathlib.Path)
options=parser.parse_args()
OUT=options.evidence_dir.resolve()
assert OUT.is_relative_to(ROOT/'tools/core/evidence') and not OUT.exists(), 'new dedicated evidence directory required'
OUT.mkdir(parents=True)
lock=json.loads((ROOT/'core-lock.json').read_text())
assert lock['upstream']['commit']=='a1abce2b515b199fe1120061b54654c60f4dd59c'
assert lock['integration']['commit']==options.pin and re.fullmatch('[0-9a-f]{40}',options.pin)
def git(*args):return subprocess.check_output(['git','-C',str(CORE),*args],text=True).strip()
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
assert git('rev-parse','HEAD')==lock['integration']['commit'] and not git('status','--porcelain')
def manifest():
 names=git('ls-files').splitlines()
 return {n:digest(CORE/n) for n in names if (CORE/n).is_file()}
source=manifest();(OUT/'source-before.json').write_text(json.dumps(source,sort_keys=True,indent=2)+'\n')
env=os.environ.copy();env.update(PATH=str(ROOT/'.toolchains/cargo/bin')+':'+env.get('PATH',''),RUSTUP_HOME=str(ROOT/'.toolchains/rustup'),CARGO_HOME=str(ROOT/'.toolchains/cargo'),CARGO_TARGET_DIR=str(ROOT/'.local-cache/product-core-target'),CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0')
local=['vp-common','vp-core','vp-config','vp-rule','vp-dns','vp-transport','vp-plugin-sdk','vp-plugin','vp-crypto','vp-router','vp-protocol','vp-tun','vp-app']
args=['cargo','clean','--manifest-path',str(CORE/'Cargo.toml')]
for name in local:args+=['-p',name]
with (OUT/'clean-local-packages.log').open('w') as log:subprocess.run(args,cwd=CORE,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
args=['cargo','test','--offline','--locked','--tests','--no-run','--message-format=json']
for name in ['vp-core','vp-crypto','vp-config','vp-router','vp-protocol','vp-tun','vp-dns','vp-app']:args+=['-p',name]
with (OUT/'build.jsonl').open('w') as stdout,(OUT/'build.log').open('w') as stderr:
 result=subprocess.run(args,cwd=CORE,env=env,stdout=stdout,stderr=stderr)
if result.returncode:sys.exit(result.returncode)
artifacts={}
for line in (OUT/'build.jsonl').read_text().splitlines():
 row=json.loads(line)
 if row.get('reason')=='compiler-artifact' and row.get('executable') and row['profile']['test']:
  assert str(CORE) in row['manifest_path'],row
  artifacts[row['target']['name']]=row
suites={
 'vp_config':(12,0), 'vp_core':(25,0), 'vp_router':(14,0), 'vp_protocol':(136,2),
 'vp_dns':(25,4), 'vp_tun':(7,0), 'vp_app':(26,0),
 'server_routing':(6,0),'quic_auth_negative':(19,0),'ss_standard':(10,0),
 'ss_managed':(3,0),'stream_udp':(4,0),'ss_library_interop':(2,0),
 'quic_library_interop':(19,0),'stream_library_interop':(2,0),'proxy_dns':(1,0),
}
# Crypto's full historical fixture inventory is recorded by --list; only the two
# specifically reviewed UUID tests are selected here, never a guessed full count.
suites['vp_crypto']=(2,0)
required={
 'vp_config':['udp_over_tcp_kebab_and_underscore_are_not_silently_ignored'],
 'server_routing':['authenticated_ss_uot_routes_each_target_and_selection_without_magic_dns','ss_uot_wrong_credentials_v2_and_nested_magic_never_reach_router'],
 'vp_core':['host_network::dns_policy_tests::explicit_policy_denies_direct_user_dns_and_unlisted_bootstrap_before_platform_hook'],
 'vp_protocol':['raw_uot_control_name_is_explicitly_unsupported','full_socket_budget_allows_ordered_route_replacement','stop_cancels_pending_open_started_by_retained_sender_outside_scope','udp_reply_domain_cannot_use_endpoint_bootstrap_dns'],
 'vp_router':['prepared_nested_fallback_has_aggregate_attempt_budget'],
 'vp_crypto':['uuid_parse_ascii_forms_and_unicode_are_bounded_and_redacted'],
 'vp_tun':['unsupported_invalid_and_auth_failures_never_fallback'],
 'proxy_dns':['authenticated_proxy_dns_a_aaaa_udp_tcp_ipv6_tun_negative_and_cancel'],
}
records={}
for name,counts in suites.items():
 a=artifacts[name];assert not a['fresh'],f'{name} was unexpectedly reused after invalidation'
 binary=pathlib.Path(a['executable']);assert binary.is_relative_to(ROOT/'.local-cache/product-core-target')
 listing=subprocess.check_output([str(binary),'--list'],cwd=CORE,env=env,text=True)
 (OUT/f'list-{name}.txt').write_text(listing)
 for test in required.get(name,[]):assert test in listing,(name,test)
 records[name]={'path':str(binary),'sha256':digest(binary),'artifact':a,'expected_passed':counts[0],'expected_ignored':counts[1]}
(OUT/'binaries-before.json').write_text(json.dumps(records,indent=2)+'\n')
for var,rel,expected in [
 ('VP_SS_REFERENCE','.toolchains/reference-ss','105434f5f86f4688c8092dff6e7f9d318978fd8e687b1430eebff9a1f5cd1753'),
 ('VP_STREAM_REFERENCE','.toolchains/reference-stream','eca989fc22cc8d1918e7fb3e0187e24a6207de31b138574ce8b5660053b55631'),
 ('VP_QUIC_REFERENCE','.local-cache/reference-quic','ddd444f6d9c52d86ee8ecc3b606822895bad7a484899915741b8e9d6a278b345')]:
 path=ROOT/rel;assert digest(path)==expected,(var,digest(path));env[var]=str(path)
failed=[];results={}
for name,record in records.items():
 args=[record['path'],'--nocapture','--test-threads=1']
 if name.endswith('library_interop') or name=='proxy_dns':args+=['--include-ignored']
 if name=='vp_crypto':args+=['uuid_parse']
 print('RUN',name,flush=True)
 with (OUT/f'test-{name}.log').open('w') as log:
  result=subprocess.run(args,cwd=CORE,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=360)
 text=(OUT/f'test-{name}.log').read_text();summary=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
 good=bool(summary and result.returncode==0 and summary[-1]==('ok',str(record['expected_passed']),'0',str(record['expected_ignored'])))
 print(name,'PASS' if good else 'FAIL',summary,flush=True)
 results[name]={'status':'passed' if good else 'failed','exit':result.returncode,'summary':summary,'args':args,'log_sha256':digest(OUT/f'test-{name}.log')}
 if not good:failed.append(name)
assert manifest()==source,'source changed during validation'
assert all(digest(pathlib.Path(v['path']))==v['sha256'] for v in records.values()),'binary changed during validation'
(OUT/'binaries-after.json').write_text(json.dumps(records,indent=2)+'\n')
(OUT/'source-after.json').write_text(json.dumps(manifest(),sort_keys=True,indent=2)+'\n')
(OUT/'result.json').write_text(json.dumps({'pin':lock['integration'],'core_lock_sha256':digest(ROOT/'core-lock.json'),'source_before_after_sha256':digest(OUT/'source-before.json'),'results':results,'failed':failed,'release_eligible':False},indent=2)+'\n')
print('FAILED',failed,flush=True);sys.exit(bool(failed))
