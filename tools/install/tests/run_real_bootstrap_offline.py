"""Real explicit bootstrap→offline vault-init journey, fixed synthetic input only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[3]
SCRIPT=ROOT/'tools/install/vp_bootstrap.py'
if len(sys.argv) != 3:
    raise SystemExit('usage: run_real_bootstrap_offline.py ABS_ARTIFACT SHA256')
ARTIFACT=Path(sys.argv[1])
SHA=sys.argv[2]
if not ARTIFACT.is_absolute() or len(SHA) != 64 or any(c not in '0123456789abcdef' for c in SHA):
    raise SystemExit('explicit absolute artifact and lowercase SHA256 required')
assert hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()==SHA
calls=0
value={'username':'synthetic','token':'S'*43,'vault':{'masterKeyHex':'12'*32,'credentials':[]}}
def run(args, code=0):
    global calls
    calls+=1
    result=subprocess.run([sys.executable,str(SCRIPT),*args],input=b'',capture_output=True,timeout=25)
    assert result.returncode==code, 'unexpected process result'
    assert value['token'].encode() not in result.stdout+result.stderr
    assert value['vault']['masterKeyHex'].encode() not in result.stdout+result.stderr
    assert b'Traceback' not in result.stderr
    return result
with tempfile.TemporaryDirectory(prefix='vp-bootstrap-real-offline-synthetic-') as tmp:
    base=Path(tmp); root=base/'materials'; source=base/'input'
    source.write_text(json.dumps(value));source.chmod(0o600)
    prepare=['prepare','--root',str(root),'--username','synthetic','--namespace','synthetic',
             '--request-key','prepare_one','--import-bootstrap-file',str(source)]
    plan=json.loads(run([*prepare,'--dry-run']).stdout)
    assert not root.exists()
    run([*prepare,'--confirm-plan-sha256',plan['planHash']])
    init=['offline-vault-init','--root',str(root),'--maintenance-artifact',str(ARTIFACT),
          '--maintenance-sha256',SHA,'--request-key','init_one']
    plan=json.loads(run([*init,'--dry-run']).stdout)
    assert not (root/'offline-init-intent.json').exists() and list((root/'vault').iterdir())==[]
    result=run([*init,'--confirm-plan-sha256',plan['planHash']])
    receipt=json.loads((root/'offline-init-result.json').read_bytes())
    assert receipt['vaultInitialized'] is True and receipt['recoveryEligible'] is False
    assert receipt['targetBindingValidated'] is True
    assert receipt['targetMutation']=='vault_manifest_created'
    assert (root/'offline-init-intent.json').exists()
    assert list((root/'control').iterdir())==[] and list((root/'runtime').iterdir())==[]
    vault_before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'vault').iterdir() if p.is_file()}
    run([*init,'--dry-run'],2)
    status=json.loads(run(['status','--root',str(root)]).stdout)
    assert status['serviceStartedByThisTool'] is False and status['recoveryEligible'] is False
    assert {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'vault').iterdir() if p.is_file()}==vault_before
print(json.dumps({'maintenanceSha256':SHA,'actualCliCalls':calls,
 'results':['prepare_plan_no_write','prepare_exact_confirmation','offline_init_plan_no_write',
 'explicit_sealed_offline_vault_init','durable_intent_and_safe_receipt','repeat_refused',
 'status_nonexecuting','no_control_database_or_runtime_created','ordinary_output_no_token_or_master'],
 'wholeSuiteReady':False,'positiveInspect':False,'kernelSyscallTrace':False},indent=2))
