#!/usr/bin/env python3
"""Private local fresh-runtime stages, exact confirmation, foreground only.

The uninstall action ONLY disables this local profile and retains ALL files.
Archive-bound deactivate works without runtime host eligibility.
Separate remove-program-files requires prior deactivation and exact bundle confirmation.
"""
import argparse
import json
import signal
import sys
from pathlib import Path
import vp_bootstrap as b
from vp_fresh_bundle import FreshBundle, MAINTENANCE
from vp_fresh_local import FreshLocal, observe, UNINSTALLED
from vp_host_preflight import check_sealed_runtime_host
from vp_fresh_removal import ProgramRemoval, RemovalBundle, removal_status
from vp_install import require, InstallError


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', help='uninstall retains ALL files; remove-program-files is separate, disabled-profile-only, no resume', choices=('install','prepare','init-vault','start','restart','uninstall','deactivate','remove-program-files','status'))
    p.add_argument('--root',required=True); p.add_argument('--materials',required=True)
    p.add_argument('--bundle'); p.add_argument('--bundle-sha256'); p.add_argument('--confirm-plan')
    p.add_argument('--username'); p.add_argument('--namespace'); p.add_argument('--request-key')
    p.add_argument('--generate',action='store_true'); p.add_argument('--import-file')
    p.add_argument('--bind'); p.add_argument('--origin')
    args = p.parse_args(argv)
    bundle = None
    try:
        engine = FreshLocal(Path(args.root),Path(args.materials))
        if args.action == 'status':
            print(json.dumps({'installation':observe(engine.root),'host':check_sealed_runtime_host(),
                              'serviceRunning':'not_inferred_from_files','programFileRemovalImplemented':True,
                              'programRemoval':removal_status(engine),
                              'uninstallAction':'disable_profile_retain_all_files','recoveryEligible':False},sort_keys=True));return 0
        if args.action in ('install','deactivate','remove-program-files'):
            require(args.bundle and args.bundle_sha256,'local bundle and trusted digest required')
            bundle = (FreshBundle if args.action == 'install' else RemovalBundle)(Path(args.bundle),args.bundle_sha256)
            if args.action in ('deactivate','remove-program-files'):
                removal = ProgramRemoval(engine,bundle); plan = removal.plan(args.action)
            else: plan = engine.plan('install',bundle=bundle)
        elif args.action in ('prepare','init-vault'):
            if args.action == 'prepare':
                action = 'prepare'; options = {'username':args.username,'namespace':args.namespace,
                    'requestKey':args.request_key,'generate':args.generate,'importFile':args.import_file}
            else:
                action = 'offline-vault-init'; options = {'requestKey':args.request_key}
            plan = engine.plan_bootstrap(action,options)
        else:
            action = {'start':'serve-fresh','restart':'serve-paired','uninstall':'uninstall'}[args.action]
            plan = engine.plan(action,bind=args.bind,origin=args.origin)
        if not args.confirm_plan:
            print(json.dumps(plan,sort_keys=True));return 0
        require(args.confirm_plan == plan['planHash'],'exact current --confirm-plan required')
        if args.action == 'install':result = engine.apply_install(plan,args.confirm_plan,bundle)
        elif args.action in ('prepare','init-vault'):result = engine.apply_bootstrap(plan,args.confirm_plan,options)
        elif args.action == 'deactivate':result = removal.deactivate(plan,args.confirm_plan)
        elif args.action == 'remove-program-files':result = removal.apply(plan,args.confirm_plan)
        elif args.action == 'uninstall':result = engine.uninstall(plan,args.confirm_plan)
        else:
            stopped = False
            def stop(_signum,_frame):
                nonlocal stopped
                stopped = True
            old = {sig:signal.signal(sig,stop) for sig in (signal.SIGINT,signal.SIGTERM)}
            try:
                with engine.run(plan,args.confirm_plan,cancelled=lambda:stopped) as (process,ready):
                    print(json.dumps(ready,sort_keys=True),flush=True)
                    while not stopped:
                        require(process.pump() is None,'runtime exited; inspect retained state before paired restart')
                result = {'status':'foreground_owned_service_stopped','stateRetained':True,'productionCertified':False}
            finally:
                for sig,handler in old.items():signal.signal(sig,handler)
        print(json.dumps(result,sort_keys=True));return 0
    except KeyboardInterrupt:
        print('fresh-local: canceled; retained state must be inspected before retry',file=sys.stderr)
        return 130
    except (InstallError,OSError,ValueError,KeyError,TypeError):
        # No arbitrary subprocess or OS text, secret-containing input, tracebacks.
        print('fresh-local: action refused or outcome uncertain; retain state, inspect privately; no automatic retry',file=sys.stderr)
        return 2
    finally:
        if bundle is not None:bundle.close()

if __name__=='__main__':sys.exit(main())
