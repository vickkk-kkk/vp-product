"""Real bound-init acceptance, including path swap-and-restore negative gate."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import vp_bootstrap as bootstrap
import vp_maintenance_bridge as bridge
from vp_install import InstallError, canonical

artifact=Path(sys.argv[1]); digest=sys.argv[2]
assert hashlib.sha256(artifact.read_bytes()).hexdigest()==digest

def setup(base):
    root=base/'materials'; source=base/'input'
    source.write_bytes(canonical({'username':'synthetic','token':'S'*43,'vault':{'masterKeyHex':'12'*32,'credentials':[]}}))
    source.chmod(0o600); engine=bootstrap.Bootstrap(root)
    opts=dict(username='synthetic',namespace='synthetic',requestKey='prepare_one',generate=False,importFile=str(source))
    plan=engine.plan('prepare',opts);engine.apply(plan,plan['planHash'],opts)
    opts=dict(maintenanceArtifact=str(artifact),maintenanceSha256=digest,requestKey='bound_one')
    return root,engine,opts

results=[]
with tempfile.TemporaryDirectory(prefix='vp-bound-init-synthetic-') as tmp:
    base=Path(tmp)
    positive=base/'positive';positive.mkdir(mode=0o700)
    root,engine,opts=setup(positive);plan=engine.plan('offline-vault-init',opts)
    result=engine.apply(plan,plan['planHash'],opts)
    assert result['vaultInitialized'] and not result['recoveryEligible']
    assert list((root/'vault').iterdir())
    assert list((root/'control').iterdir())==[] and list((root/'runtime').iterdir())==[]
    results.append('bound_actual_opened_vault_initialized')
    negative=base/'negative';negative.mkdir(mode=0o700)
    root,engine,opts=setup(negative);plan=engine.plan('offline-vault-init',opts)
    real=bridge.execute
    def swap(*args,**kwargs):
        (root/'vault').rename(negative/'original-vault');(root/'vault').mkdir(mode=0o700)
        try:
            return real(*args,**kwargs)
        finally:
            (root/'vault').rename(negative/'diverted-vault');(negative/'original-vault').rename(root/'vault')
    with mock.patch.object(bridge,'execute',side_effect=swap):
        try: engine.apply(plan,plan['planHash'],opts)
        except bridge.MaintenanceUncertain: pass
        else: raise AssertionError('swapped target must fail closed')
    assert list((root/'vault').iterdir())==[]
    assert list((negative/'diverted-vault').iterdir())==[]
    assert (root/bootstrap.OFFLINE_INTENT).exists() and not (root/bootstrap.OFFLINE_RESULT).exists()
    try:engine.plan('offline-vault-init',opts)
    except InstallError:pass
    else:raise AssertionError('uncertain initialization must not retry')
    results.append('swap_restore_rejected_before_writes_to_either_vault')
    results.append('consumed_intent_retained_and_repeat_refused')
print(json.dumps({'maintenanceSha256':digest,'results':results,'targetBindingRaceGate':'passed',
                  'syntheticOnly':True,'positiveInspect':False,'wholeSuiteReady':False},indent=2))
