"""Synthetic filesystem lifecycle tests. FakeRuntime never executes fixture ELFs."""
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import test_fresh_bundle
import vp_fresh_bundle as f
import vp_fresh_local as l
import vp_bootstrap as b
import vp_install as v


class FakeRuntime:
    requests=[]
    def __init__(self,daemon,daemon_sha,worker_sha,arguments,request):
        self.requests.append(copy.deepcopy(request));self.stopped=False
    def await_ready(self,genesis,**kwargs):return {'status':'http_ready','genesisId':genesis}
    def stop(self):self.stopped=True;return {'stopped':True}


class FreshLocalTests(unittest.TestCase):
    def setUp(self):
        self.fixture=test_fresh_bundle.FreshBundleTests();self.fixture.setUp()
        self.base=self.fixture.base;self.root=self.base/'installation';self.materials=self.base/'materials'
        self.engine=l.FreshLocal(self.root,self.materials)
        self.bundle=f.FreshBundle(*self.fixture.archive())
    def tearDown(self):self.bundle.close();self.fixture.tearDown()
    def install(self):
        plan=self.engine.plan('install',bundle=self.bundle)
        return self.engine.apply_install(plan,plan['planHash'],self.bundle)
    def prepare(self):
        source=self.base/'import.json';source.write_bytes(v.canonical({'username':'admin','token':'t'*64,
                      'vault':{'masterKeyHex':'a'*64,'credentials':[]}}));source.chmod(0o600)
        engine=b.Bootstrap(self.materials)
        opts={'username':'admin','namespace':'synthetic','requestKey':'synthetic-key','importFile':str(source),'generate':False}
        plan=engine.plan('prepare',opts);engine.apply(plan,plan['planHash'],opts)
        # Explicit fake receipt for filesystem composition tests ONLY; never
        # calls maintenance and never claims the synthetic vault is initialized.
        with b.owned_directory(self.materials) as fd:b.new_file(fd,b.OFFLINE_RESULT,b'{"testOnly":true}')
    def start_plan(self):return self.engine.plan('serve-fresh',bind='127.0.0.1:18081',origin='http://127.0.0.1:18081')
    def test_install_only_creates_separate_root(self):
        self.install();self.assertFalse(self.materials.exists());self.engine.verify_release()
    def test_bad_confirmation_no_writes(self):
        plan=self.engine.plan('install',bundle=self.bundle)
        with self.assertRaises(v.InstallError):self.engine.apply_install(plan,'0'*64,self.bundle)
        self.assertFalse(self.root.exists())
    def test_preflight_blocks_before_write(self):
        with mock.patch.object(l,'check_sealed_runtime_host',return_value={'prerequisitesAvailable':False}):
            with self.assertRaises(v.InstallError):self.engine.plan('install',bundle=self.bundle)
        self.assertFalse(self.root.exists())
    def test_no_existing_root_adoption(self):
        self.root.mkdir(mode=0o700)
        with self.assertRaises(v.InstallError):self.engine.plan('install',bundle=self.bundle)
    def test_changed_bundle_member_refused(self):
        self.install();(self.root/'release'/f.DAEMON).write_bytes(b'changed')
        with self.assertRaises(v.InstallError):self.engine.plan('uninstall')
    def test_unknown_root_refused(self):
        self.install();(self.root/'unknown').write_text('x')
        with self.assertRaises(v.InstallError):self.engine.plan('uninstall')
    def test_no_upgrade_or_rollback(self):
        for action in ('upgrade','rollback','restore','adopt'):
            with self.assertRaises(v.InstallError):self.engine.plan(action)
    def test_no_start_before_preparation(self):
        self.install()
        with self.assertRaises((v.InstallError,OSError)):self.start_plan()
    def test_explicit_fresh_then_paired_mock(self):
        self.install();self.prepare();plan=self.start_plan()
        with mock.patch.object(l,'OwnedRuntime',FakeRuntime):
            with self.engine.run(plan,plan['planHash']) as (process,_):self.assertFalse(process.stopped)
            self.assertTrue(process.stopped)
            second=self.engine.plan('serve-paired',bind=plan['bind'],origin=plan['origin'])
            with self.engine.run(second,second['planHash']):pass
        self.assertEqual(FakeRuntime.requests[-1]['credentials'],[])
        self.assertEqual(FakeRuntime.requests[-1]['artifactSetDigest'],self.fixture.m['compatibilityDescriptor']['artifactSetDigest'])
        with self.assertRaises(v.InstallError):self.start_plan()
        b.verified_material(self.materials)  # No unknown lifecycle files inside bootstrap root.
    def test_failed_start_consumes_intent_no_retry(self):
        self.install();self.prepare();plan=self.start_plan()
        with mock.patch.object(l,'OwnedRuntime',side_effect=v.InstallError('synthetic failure')):
            with self.assertRaises(v.InstallError):
                with self.engine.run(plan,plan['planHash']):pass
        self.assertTrue((self.root/l.ACTIVATION).exists())
        self.assertFalse((self.root/l.READY).exists())
        with self.assertRaises(v.InstallError):self.start_plan()
        with self.assertRaises(v.InstallError):self.engine.plan('serve-paired',bind=plan['bind'],origin=plan['origin'])
    def test_material_change_invalidates_plan(self):
        self.install();self.prepare();plan=self.start_plan()
        path=self.materials/b.MATERIAL;path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(v.InstallError):
            with self.engine.run(plan,plan['planHash']):pass
        self.assertFalse((self.root/l.ACTIVATION).exists())
    def test_uninstall_retains_every_prior_byte(self):
        self.install();self.prepare()
        before={p:p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
        plan=self.engine.plan('uninstall');result=self.engine.uninstall(plan,plan['planHash'])
        self.assertEqual(result['deletedFiles'],0)
        self.assertEqual(result['status'],'profile_disabled_all_files_retained')
        self.assertTrue(result['allFilesRetained'])
        self.assertFalse(result['removesProgramFiles'])
        self.assertEqual(l.UNINSTALLED,'profile-disabled-all-files-retained.json')
        for path,data in before.items():self.assertEqual(path.read_bytes(),data)
        with self.assertRaises(v.InstallError):self.start_plan()
    def test_historical_disable_receipt_still_blocks_adoption(self):
        self.install();self.prepare()
        with b.owned_directory(self.root) as fd:b.new_file(fd,l.LEGACY_UNINSTALLED,b'{"historical":true}')
        with self.assertRaises(v.InstallError):self.start_plan()
        self.assertIn(l.LEGACY_UNINSTALLED,l.observe(self.root)['entries'])
    def test_deactivation_plan_discloses_no_program_removal(self):
        self.install();plan=self.engine.plan('uninstall')
        self.assertEqual(plan['operation'],'disable_local_profile_retain_all_files')
        self.assertTrue(plan['allFilesRetained']);self.assertFalse(plan['removesProgramFiles'])
    def test_no_external_bind(self):
        self.install();self.prepare()
        with self.assertRaises(v.InstallError):self.engine.plan('serve-fresh',bind='0.0.0.0:18081',origin='http://0.0.0.0:18081')
    def test_web_writable_mode_refused_before_intent(self):
        self.install();self.prepare();(self.root/'release/web/index.html').chmod(0o666)
        with self.assertRaises(v.InstallError):self.start_plan()
        self.assertFalse((self.root/l.ACTIVATION).exists())
    def test_web_hardlink_refused_before_intent(self):
        self.install();self.prepare();os.link(self.root/'release/web/index.html',self.base/'alias')
        with self.assertRaises(v.InstallError):self.start_plan()
        self.assertFalse((self.root/l.ACTIVATION).exists())
    def test_installation_bound_preparation(self):
        self.install()
        opts={'username':'admin','namespace':'synthetic','requestKey':'prepare-key','generate':True,'importFile':None}
        plan=self.engine.plan_bootstrap('prepare',opts)
        self.assertIn('installationBefore',plan)
        self.engine.apply_bootstrap(plan,plan['planHash'],opts)
        b.verified_material(self.materials)
    def test_uninstall_invalidates_preparation_confirmation(self):
        self.install()
        opts={'username':'admin','namespace':'synthetic','requestKey':'prepare-key','generate':True,'importFile':None}
        plan=self.engine.plan_bootstrap('prepare',opts)
        remove=self.engine.plan('uninstall');self.engine.uninstall(remove,remove['planHash'])
        with self.assertRaises(v.InstallError):self.engine.apply_bootstrap(plan,plan['planHash'],opts)
        self.assertFalse(self.materials.exists())
    def test_preparation_holds_installation_lock(self):
        self.install()
        opts={'username':'admin','namespace':'synthetic','requestKey':'prepare-key','generate':True,'importFile':None}
        plan=self.engine.plan_bootstrap('prepare',opts)
        with b.owned_directory(self.root):
            with self.assertRaises(OSError):self.engine.apply_bootstrap(plan,plan['planHash'],opts)
        self.assertFalse(self.materials.exists())
    def test_distinct_sibling_roots(self):
        for materials in (self.root,self.root/'nested',self.base.parent/'elsewhere'):
            with self.assertRaises(v.InstallError):l.FreshLocal(self.root,materials)

if __name__=='__main__':unittest.main()
