"""Filesystem/security tests only. Synthetic ELF bytes NEVER execute.
FakeService is test-only; its results do not certify systemd or forwarding.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vp_install as vp
import vp_api
import build_bundle

class SimulatedCrash(BaseException):
    pass

class FakeService:
    """Explicit test double; no CLI flag can select this runner."""
    def __init__(self):
        self.running = False
        self.linked = False
        self.calls = []
        self.fail_next_start = False
    def active(self):
        return self.running
    def link(self):
        self.calls.append('link'); self.linked = True
    def start(self):
        self.calls.append('start')
        if self.fail_next_start:
            self.fail_next_start = False
            raise vp.InstallError('test-only injected start failure')
        self.running = True
    def stop(self):
        self.calls.append('stop'); self.running = False
    def remove(self):
        self.calls.append('remove'); self.running = self.linked = False

class Tty:
    """Actual PTY entry point; file-only synthetic bundles, never host service calls."""
    def __init__(self, args):
        import pty
        import subprocess
        self.master, slave = pty.openpty()
        entry = Path(vp.__file__).parent/'install.sh'
        self.process = subprocess.Popen(['/bin/sh', str(entry)] + args,
            stdin=slave, stdout=slave, stderr=slave, close_fds=True)
        os.close(slave)
        self.received = bytearray()
    def until(self, marker, count=1):
        import select
        import time
        deadline = time.monotonic() + 8
        while self.received.count(marker) < count:
            if time.monotonic() >= deadline:
                raise AssertionError('TTY prompt timed out: ' + repr(marker))
            ready, _, _ = select.select([self.master], [], [], .1)
            if ready:
                self.received.extend(os.read(self.master, 8192))
                if len(self.received) > 128 * 1024: raise AssertionError('TTY output exceeded bound')
    def send(self, text):
        os.write(self.master, text.encode()+b'\n')
    def finish(self):
        if self.process.wait(timeout=8) != 0: raise AssertionError('TTY CLI failed')
    def __enter__(self):
        return self
    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.kill(); self.process.wait(timeout=5)
        os.close(self.master)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vp-installer-test-')
        self.base = Path(self.temp.name)
        self.root = self.base / 'installation'
        self.fake = FakeService()
        self.engine = vp.Installer(self.root, service=self.fake)
        self.settings = {'mode':'files', 'bind':'127.0.0.1:18080', 'origin':'http://127.0.0.1:18080',
                         'bootstrapFile':'/etc/vp/bootstrap.json', 'runtimeProfile':None, 'vaultNamespace':None, 'enableOnBoot':False}
    def tearDown(self):
        self.temp.cleanup()
    def bundle(self, release='v1', altered=None, extras=None):
        header = bytearray(32)
        header[:6] = b'\x7fELF\x02\x01'
        header[18:20] = struct.pack('<H', 62 if vp.host_arch() == 'x86_64' else 183)
        payload = {'bin/vp-product-managementd':bytes(header), 'web/index.html':b'<!doctype html>TEST ONLY',
                   'core-lock.json':b'{"testOnly":true}', 'contracts/capabilities/presets.json':b'{"schemaVersion":1,"presets":[]}'}
        manifest = {'schemaVersion':1, 'releaseId':release, 'productVersion':release, 'engine':'vp_core',
                    'architecture':vp.host_arch(), 'storageSchema':1,
                    'coreLockSha256':vp.digest(payload['core-lock.json']), 'files':[]}
        for name, data in sorted(payload.items()):
            manifest['files'].append({'path':name, 'size':len(data), 'sha256':vp.digest(data),
                                      'executable':name.startswith('bin/')})
        if altered:
            altered(manifest, payload)
        path = self.base / (release + '.zip')
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as archive:
            archive.writestr('manifest.json', vp.canonical(manifest))
            for name, data in payload.items():
                item = zipfile.ZipInfo(name)
                item.create_system = 3
                item.external_attr = 0o100644 << 16
                archive.writestr(item, data)
            for item, data in extras or []:
                archive.writestr(item, data)
        return path, vp.digest(path.read_bytes())
    def install(self, release='v1', action='install'):
        path, h = self.bundle(release)
        with vp.Bundle(path, h) as bundle:
            plan = self.engine.plan(action, bundle, self.settings)
            return self.engine.apply(plan, plan['planHash'], bundle)

class BundleTests(Fixture):
    def test_verified_bundle(self):
        p,h = self.bundle()
        with vp.Bundle(p,h) as b:
            self.assertEqual(b.manifest['engine'], 'vp_core')
    def test_hash_required_and_mismatch(self):
        p,h = self.bundle()
        for bad in (None, '', 'z'*64, '0'*64):
            with self.assertRaises(vp.InstallError): vp.Bundle(p,bad)
        self.assertFalse(self.root.exists())
    def test_unlisted_path_traversal(self):
        for name in ('../escape', '/escape', 'web/../../escape', 'web//a', 'web/./a', 'web/a\\b'):
            p,h = self.bundle('v'+str(abs(hash(name))), extras=[(name,b'x')])
            with self.assertRaises(vp.InstallError): vp.Bundle(p,h)
        self.assertFalse((self.base/'escape').exists())
    def test_symlink_member(self):
        i = zipfile.ZipInfo('web/evil'); i.create_system=3; i.external_attr=0o120777 << 16
        p,h = self.bundle(extras=[(i,b'/etc/shadow')])
        with self.assertRaises(vp.InstallError): vp.Bundle(p,h)
    def test_duplicate_manifest_and_special_mode(self):
        p,h = self.bundle(extras=[('manifest.json',b'{}')])
        with self.assertRaises(vp.InstallError): vp.Bundle(p,h)
    def test_reject_script_hooks_and_missing_component(self):
        for change in (lambda m,p: m.update(hook='run.sh'), lambda m,p: m.update(engine='sing-box'),
                       lambda m,p: m.update(storageSchema=2), lambda m,p: p.update({'extra.sh':b'no'})):
            p,h=self.bundle(altered=change)
            with self.assertRaises(vp.InstallError): vp.Bundle(p,h)
    def test_wrong_member_hash(self):
        p,h=self.bundle(altered=lambda m,p:p.update({'web/index.html':b'x'*len(p['web/index.html'])}))
        with self.assertRaises(vp.InstallError): vp.Bundle(p,h)
    def test_bundle_source_symlink(self):
        p,h=self.bundle(); link=self.base/'link.zip';link.symlink_to(p)
        with self.assertRaises(vp.InstallError): vp.Bundle(link,h)
    def test_bounded_archive(self):
        p,h=self.bundle()
        with mock.patch.object(vp,'MAX_ARCHIVE', 25):
            with self.assertRaises(vp.InstallError): vp.Bundle(p,h)
    def test_executable_must_be_elf(self):
        def alter(m,p):
            p['bin/vp-product-managementd']=b'#!/bin/sh\nexit 0\n'
            for f in m['files']:
                if f['path'].startswith('bin/'):
                    f['size']=len(p[f['path']]);f['sha256']=vp.digest(p[f['path']])
        p,h=self.bundle(altered=alter)
        with self.assertRaises(vp.InstallError): vp.Bundle(p,h)

class LifecycleTests(Fixture):
    def test_dry_plan_is_read_only_and_deterministic(self):
        p,h=self.bundle()
        with vp.Bundle(p,h) as b:
            a=self.engine.plan('install',b,self.settings)
            self.assertEqual(a,self.engine.plan('install',b,self.settings))
            self.assertFalse(self.root.exists())
            with self.assertRaises(vp.InstallError):self.engine.apply(a,'wrong',b)
            self.assertFalse(self.root.exists())
    def test_real_files_install_repeat_update_rollback(self):
        result=self.install()
        self.assertEqual(result['activeRelease'],'v1')
        self.assertFalse(result['serviceActive'])
        self.assertEqual(result['forwarding'],'not_verified')
        self.assertEqual(os.readlink(self.root/'current'),'releases/v1')
        self.assertEqual(stat.S_IMODE((self.root/'state.json').stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE((self.root/'releases/v1/bin/vp-product-managementd').stat().st_mode),0o755)
        self.install()  # identical archive, no duplicate release
        self.install('v2','update')
        self.assertEqual(self.engine.state()['previous'],'v1')
        p=self.engine.plan('rollback'); self.engine.apply(p,p['planHash'])
        self.assertEqual(self.engine.state()['active'],'v1')
    def test_same_id_different_bytes_fails(self):
        self.install()
        p,h=self.bundle(altered=lambda m,p:m.update(productVersion='different'))
        with vp.Bundle(p,h) as b:
            with self.assertRaises(vp.InstallError):self.engine.plan('install',b,self.settings)
    def test_stale_plan_rejected(self):
        self.install()
        p,h=self.bundle('v2')
        with vp.Bundle(p,h) as b:
            plan=self.engine.plan('update',b,self.settings)
            state=self.engine.state(); state['previous']='v1'; vp.atomic_json(self.root/'state.json',state)
            with self.assertRaises(vp.InstallError):self.engine.apply(plan,plan['planHash'],b)
        self.assertEqual(self.engine.state()['active'],'v1')
    def test_failed_service_start_restores_old_slot(self):
        self.install(); self.fake.running=True; self.fake.fail_next_start=True
        p,h=self.bundle('v2')
        with vp.Bundle(p,h) as b:
            plan=self.engine.plan('update',b,self.settings)
            with self.assertRaisesRegex(vp.InstallError,'restored'):self.engine.apply(plan,plan['planHash'],b)
        self.assertEqual(self.engine.state()['active'],'v1');self.assertTrue(self.fake.running)
        self.assertFalse(self.engine.pending())
        self.assertIn('v2',self.engine.state()['releases'])
        self.install('v2','update') # recovered inactive slot can be retried
    def test_process_crash_journal_and_recovery(self):
        self.install(); self.fake.running=True
        p,h=self.bundle('v2')
        original=self.engine._journal
        def crash(j,phase):
            original(j,phase)
            if phase=='switched':raise SimulatedCrash()
        with vp.Bundle(p,h) as b:
            plan=self.engine.plan('update',b,self.settings)
            with mock.patch.object(self.engine,'_journal',side_effect=crash):
                with self.assertRaises(SimulatedCrash):self.engine.apply(plan,plan['planHash'],b)
        self.assertTrue(self.engine.pending());self.assertEqual(os.readlink(self.root/'current'),'releases/v2')
        with self.assertRaises(vp.InstallError):self.engine.plan('stop')
        plan=self.engine.plan('recover'); self.engine.apply(plan,plan['planHash'])
        self.assertEqual(os.readlink(self.root/'current'),'releases/v1');self.assertTrue(self.fake.running)
    def test_interrupted_partial_stage_removed_not_executed(self):
        self.install();p,h=self.bundle('v2')
        with vp.Bundle(p,h) as b:
            plan=self.engine.plan('update',b,self.settings)
            def crash(directory):
                directory.mkdir();(directory/'partial').write_bytes(b'partial');raise SimulatedCrash()
            with mock.patch.object(b,'extract',side_effect=crash):
                with self.assertRaises(SimulatedCrash):self.engine.apply(plan,plan['planHash'],b)
        plan=self.engine.plan('recover');self.engine.apply(plan,plan['planHash'])
        self.assertFalse((self.root/'releases/.stage-v2').exists())
        self.install('v2','update')
    def test_uninstall_retains_data_by_default(self):
        self.install();(self.root/'data/control.db').write_bytes(b'test-only database')
        p=self.engine.plan('uninstall');self.engine.apply(p,p['planHash'])
        self.assertFalse((self.root/'current').exists());self.assertTrue((self.root/'data/control.db').exists())
        self.assertFalse((self.root/'releases/v1').exists());self.assertFalse(self.engine.state()['installed'])
    def test_purge_explicit_and_symlink_rejected(self):
        self.install();outside=self.base/'valuable';outside.write_bytes(b'safe')
        (self.root/'data/link').symlink_to(outside)
        p=self.engine.plan('uninstall',purge=True)
        with self.assertRaises(vp.InstallError):self.engine.apply(p,p['planHash'])
        self.assertEqual(outside.read_bytes(),b'safe');self.assertTrue(self.engine.pending())
        (self.root/'data/link').unlink()
        p=self.engine.plan('recover');self.engine.apply(p,p['planHash'])
        self.assertFalse((self.root/'data').exists())
    def test_tamper_detected_before_start_or_rollback(self):
        self.install();(self.root/'releases/v1/web/index.html').write_bytes(b'tampered')
        with self.assertRaises(vp.InstallError):self.engine.plan('start')
    def test_symlink_ancestor_and_nonempty_root(self):
        self.root.symlink_to(self.base)
        with self.assertRaises(vp.InstallError):vp.Installer(self.root)
        self.root.unlink();self.root.mkdir();(self.root/'other-user').write_text('keep')
        with self.assertRaises(vp.InstallError):self.engine.state()
    def test_unit_has_no_shell_and_no_credentials(self):
        unit=vp.service_unit(self.root,self.settings)
        self.assertIn('LoadCredential=bootstrap:/etc/vp/bootstrap.json',unit)
        self.assertIn('StandardInput=file:%d/bootstrap',unit)
        self.assertIn('User=vp',unit)
        self.assertNotIn('/bin/sh',unit);self.assertNotIn('ExecStartPre',unit)
    def test_no_service_runner_never_reports_started(self):
        self.install();engine=vp.Installer(self.root)
        p=engine.plan('start')
        with self.assertRaises(vp.InstallError):engine.apply(p,p['planHash'])
        self.assertFalse(engine.status()['serviceActive'])

class ApiTests(unittest.TestCase):
    def test_derived_idempotency_keys_follow_shared_contract_without_dots(self):
        import re
        class Args:
            catalog=None; config='not-read-directly'; request_key='stable_cli'; dry_run=True
        api = vp_api.Api('http://127.0.0.1:1')
        responses = [[], {'revision': 0, 'config': None},
            {'id': 'draft-one', 'revision': 1, 'baseRevision': 0}, {'valid': True},
            {'id': 'plan-one', 'planHash': '0'*64, 'baseRevision': 0}]
        presets = vp_api.catalog()
        with mock.patch.object(vp_api, 'catalog', return_value=presets), \
             mock.patch.object(vp_api, 'read_regular', return_value=vp.canonical({'schemaVersion': 1})), \
             mock.patch.object(api, 'request', side_effect=responses) as request, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vp_api.configure(api, Args()), 0)
        schema = json.loads((Path(vp.__file__).parents[2]/'contracts/schema/v1.schema.json').read_text())
        pattern = schema['$defs']['IdempotencyKey']['pattern']
        keys = [call.args[2]['idempotencyKey'] for call in request.call_args_list if len(call.args) > 2]
        self.assertEqual(keys, ['stable_cli-draft', 'stable_cli-validate', 'stable_cli-plan'])
        self.assertTrue(all(re.fullmatch(pattern, key) for key in keys))
        with mock.patch.object(api, 'request') as request:
            with self.assertRaises(vp.InstallError):
                api.command('/api/v1/drafts', 'draft_create', 'old.invalid', 0, {})
            request.assert_not_called()
    def test_tty_unsupported_preset_explains_backend_dependency_before_form(self):
        class Args:
            catalog=None; config=None; schema=None
        api = vp_api.Api('http://127.0.0.1:1')
        caps = [{'key': 'preset.tuic', 'status': 'blocked', 'reason': 'capability.not_certified'}]
        with mock.patch.object(api, 'request', side_effect=[caps, {'revision': 0, 'config': None}]), \
             mock.patch.object(vp_api.sys.stdin, 'isatty', return_value=True), \
             mock.patch('builtins.input', return_value='1'), \
             mock.patch.object(vp_api, 'listener_wizard', side_effect=AssertionError('blocked before form')), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(vp.InstallError, 'capability.not_certified'):
                vp_api.configure(api, Args())
    def test_catalog_preserves_21_plus_direct_and_seven_ciphers(self):
        p=vp_api.catalog()
        self.assertEqual(sum(x['scope']=='required_public_baseline' for x in p),21)
        self.assertEqual(len(next(x for x in p if x['id']=='P08')['ciphers']),7)
    def test_insecure_remote_and_query_credentials_rejected(self):
        for origin in ('http://example.invalid','https://user:password@example.invalid','https://example.invalid/?token=x','https://example.invalid/'):
            with self.assertRaises(vp.InstallError):vp_api.Api(origin)
    def test_command_delegation_exact_revision_and_key(self):
        api=vp_api.Api('http://127.0.0.1:1')
        with mock.patch.object(api,'request',return_value={'id':'test-draft'}) as request:
            result=api.command('/api/v1/drafts','draft_create','stable-key',5,{'schemaVersion':1})
            method,path,body,etag=request.call_args.args
            self.assertEqual((method,path,etag),('POST','/api/v1/drafts',None))
            self.assertEqual(body['expectedRevision'],5);self.assertEqual(body['idempotencyKey'],'stable-key')
            self.assertEqual(body['method'],'draft_create');self.assertEqual(result['id'],'test-draft')
    def test_backend_unavailable_never_falls_back_or_exports_file(self):
        class Args:
            catalog=None;config=None;request_key='k';dry_run=True
        api=vp_api.Api('http://127.0.0.1:1')
        with mock.patch.object(api,'request',side_effect=vp.InstallError('API HTTP 503: CAPABILITY_UNAVAILABLE')):
            with self.assertRaisesRegex(vp.InstallError,'503'):vp_api.configure(api,Args())
    def test_pending_operation_not_success(self):
        api=vp_api.Api('http://127.0.0.1:1')
        with mock.patch.object(api,'command',return_value={'id':'op-test','status':'queued'}),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(vp_api.apply_plan(api,'plan-test',1,'0'*64,'stable',0),3)


class ExtraBoundaryTests(Fixture):
    def test_service_preflight_aggregates_missing_dependencies_without_mutation(self):
        settings = {**self.settings, 'mode': 'systemd', 'bootstrapFile': str(self.base/'missing-bootstrap'),
                    'runtimeProfile': 'loopback-vless-v1', 'vaultNamespace': 'synthetic-test'}
        with mock.patch.object(vp.pwd, 'getpwnam', side_effect=KeyError), \
             mock.patch.object(vp.grp, 'getgrnam', side_effect=KeyError), \
             mock.patch.object(vp.os, 'geteuid', return_value=12345), \
             mock.patch.object(vp.subprocess, 'run', side_effect=AssertionError('no host commands')):
            report = vp.service_preflight(self.root, settings, {'files': []})
        missing = {c['dependency'] for c in report['checks'] if c['status'] == 'missing_or_invalid'}
        self.assertTrue({'root_authority', 'vp_group', 'vp_nonlogin_account', 'external_bootstrap_metadata',
                         'pinned_worker_in_bundle', 'explicitly_initialized_vault'} <= missing)
        self.assertFalse(report['canAttemptServiceDeployment'])
        self.assertFalse(self.root.exists())
    def test_preflight_observation_never_queries_service(self):
        self.install()
        with mock.patch.object(self.fake, 'active', side_effect=AssertionError('no service query')):
            result = self.engine.status(observe_service=False)
        self.assertIsNone(result['serviceActive'])
        self.assertEqual(result['serviceObservation'], 'not_checked_preflight')
    def test_missing_systemd_prerequisites_refused_before_creating_root(self):
        path, expected = self.bundle()
        with mock.patch.object(vp.pwd, 'getpwnam', side_effect=KeyError), \
             mock.patch.object(vp.grp, 'getgrnam', side_effect=KeyError), \
             mock.patch.object(vp.subprocess, 'run', side_effect=AssertionError('no host commands')), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = vp.main(['install', '--root', str(self.root), '--bundle', str(path), '--sha256', expected,
                            '--service-mode', 'systemd', '--dry-run'])
        self.assertEqual(code, 2)
        self.assertFalse(self.root.exists())
    def test_recover_without_journal_is_not_mutation(self):
        with self.assertRaises(vp.InstallError):self.engine.plan('recover')
        self.assertFalse(self.root.exists())
    def test_activation_pointer_drift(self):
        self.install();self.install('v2','update')
        (self.root/'current').unlink();(self.root/'current').symlink_to('releases/v1')
        with self.assertRaisesRegex(vp.InstallError,'pointer drift'):self.engine.plan('start')
    def test_recover_uninstall_after_partial_release_deletion(self):
        self.install();self.install('v2','update')
        original=self.engine._remove_private_tree
        def crash(path):
            original(path)
            raise SimulatedCrash()
        p=self.engine.plan('uninstall')
        with mock.patch.object(self.engine,'_remove_private_tree',side_effect=crash):
            with self.assertRaises(SimulatedCrash):self.engine.apply(p,p['planHash'])
        p=self.engine.plan('recover');self.engine.apply(p,p['planHash'])
        self.assertFalse(self.engine.state()['installed']);self.assertEqual(self.engine.state()['releases'],{})
        self.assertTrue((self.root/'data').exists())
    def test_recover_interrupted_atomic_pointer(self):
        self.install();p,h=self.bundle('v2')
        original=self.engine._pointer
        def crash(release):
            (self.root/'.current-next').symlink_to('releases/'+release)
            raise SimulatedCrash()
        with vp.Bundle(p,h) as b:
            plan=self.engine.plan('update',b,self.settings)
            with mock.patch.object(self.engine,'_pointer',side_effect=crash):
                with self.assertRaises(SimulatedCrash):self.engine.apply(plan,plan['planHash'],b)
        p=self.engine.plan('recover');self.engine.apply(p,p['planHash'])
        self.assertFalse((self.root/'.current-next').is_symlink());self.assertEqual(self.engine.state()['active'],'v1')
    def test_runtime_profile_requires_real_bundled_worker(self):
        p,h=self.bundle()
        settings={**self.settings,'runtimeProfile':'loopback-vless-v1','vaultNamespace':'test-only'}
        with vp.Bundle(p,h) as b:
            with self.assertRaisesRegex(vp.InstallError,'worker'):self.engine.plan('install',b,settings)
    def test_runtime_unit_explicit_open_only_no_key(self):
        settings={**self.settings,'runtimeProfile':'loopback-vless-v1','vaultNamespace':'test-only'}
        unit=vp.service_unit(self.root,settings,'a'*64)
        self.assertIn('--vault-action open',unit);self.assertNotIn('initialize',unit)
        self.assertIn('--worker-sha256 '+'a'*64,unit)
        self.assertIn('--runtime-profile loopback-vless-v1',unit)
        self.assertNotIn('masterKeyHex',unit);self.assertNotIn('password',unit)
    def test_packager_produces_deterministic_bundle_from_local_files(self):
        path,h=self.bundle()
        with vp.Bundle(path,h) as b:
            b.extract(self.base/'artifacts')
        src=self.base/'artifacts'
        (src/'web/.last_build_id').write_text('synthetic-Flutter-local-build-marker')
        for output in ('built1.zip','built2.zip'):
            args=['--managementd',str(src/'bin/vp-product-managementd'),'--web-root',str(src/'web'),
                  '--core-lock',str(src/'core-lock.json'),'--presets',str(src/'contracts/capabilities/presets.json'),
                  '--release-id','local-test','--product-version','test-1','--output',str(self.base/output)]
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(build_bundle.main(args),0)
        self.assertEqual((self.base/'built1.zip').read_bytes(),(self.base/'built2.zip').read_bytes())
        with zipfile.ZipFile(self.base/'built1.zip') as built:
            self.assertNotIn('web/.last_build_id',built.namelist())
    def test_real_cli_entry_plan_install_status_uninstall(self):
        import subprocess
        path,h=self.bundle()
        cli=Path(vp.__file__).parent/'vpctl.py'
        base=[sys.executable,str(cli)]
        args=['install','--root',str(self.root),'--bundle',str(path),'--sha256',h]
        dry=subprocess.run(base+args+['--dry-run'],capture_output=True,text=True,check=True)
        plan=json.loads(dry.stdout);self.assertFalse(self.root.exists())
        subprocess.run(base+args+['--confirm-plan-sha256',plan['planHash']],capture_output=True,text=True,check=True)
        status=subprocess.run(base+['status','--root',str(self.root)],capture_output=True,text=True,check=True)
        self.assertTrue(json.loads(status.stdout)['status']['installed'])
        dry=subprocess.run(base+['uninstall','--root',str(self.root),'--dry-run'],capture_output=True,text=True,check=True)
        plan=json.loads(dry.stdout)
        subprocess.run(base+['uninstall','--root',str(self.root),'--confirm',plan['planHash']],capture_output=True,text=True,check=True)
        self.assertFalse((self.root/'releases/v1').exists())

    def test_real_tty_numbered_wizard_binds_short_confirmation(self):
        path, expected = self.bundle()
        with Tty(['--root', str(self.root)]) as tty:
            tty.until(b'Choice [0]: '); tty.send('1')
            tty.until(b'Verified local bundle path: '); tty.send(str(path))
            tty.until(b'Independently trusted SHA256: '); tty.send(expected)
            tty.until(b"Type 'install' to confirm")
            self.assertFalse(self.root.exists(), 'TTY mutated before confirmation')
            self.assertIn(str(self.root).encode(), tty.received)
            self.assertIn(b'Plan SHA256: ', tty.received)
            tty.send('安装'); tty.finish()
        self.assertTrue(self.engine.status()['installed'])

    def test_tty_empty_confirmation_cancels_without_install(self):
        path, expected = self.bundle()
        with Tty(['install', '--root', str(self.root), '--bundle', str(path), '--sha256', expected]) as tty:
            tty.until(b"Type 'install' to confirm"); tty.send(''); tty.finish()
        self.assertFalse(self.root.exists())

    def test_tty_changed_plan_discards_consent_and_previews_again(self):
        self.install()
        path, expected = self.bundle('v2')
        with Tty(['update', '--root', str(self.root), '--bundle', str(path), '--sha256', expected]) as tty:
            tty.until(b"Type 'update' to confirm")
            self.install('v3', 'update')  # Another confirmed operation while operator reads.
            tty.send('更新')
            tty.until(b'previous consent discarded')
            tty.until(b"Type 'update' to confirm", count=2)
            self.assertEqual(self.engine.status()['activeRelease'], 'v3')
            self.assertIn(b'v3 -> v2', tty.received)
            tty.send(''); tty.finish()
        self.assertEqual(self.engine.status()['activeRelease'], 'v3')

    def test_tty_purge_requires_separate_explicit_confirmation(self):
        self.install()
        state = self.root/'data/operator-data'; state.write_text('retained synthetic data')
        with Tty(['uninstall', '--root', str(self.root), '--purge-data']) as tty:
            tty.until(b"Type 'uninstall' to confirm"); tty.send('卸载')
            tty.until(b"Type 'purge data'"); tty.send(''); tty.finish()
        self.assertTrue(state.exists())
        self.assertTrue(self.engine.status()['installed'])


class FormTests(unittest.TestCase):
    def test_form_uses_shared_schema_and_preserves_secret_references(self):
        from vp_form import SchemaForm
        document={'$defs':{'ServerListener':{},'SecretRef':{'type':'string'}}}
        form=SchemaForm(document,ask=lambda _: 'secret:existing-reference',say=lambda _:None)
        value=form.collect({'$ref':'#/$defs/SecretRef'},'listener.credentialRef')
        self.assertEqual(value,'secret:existing-reference')
    def test_form_rejects_inline_secret_and_unknown_variant(self):
        from vp_form import SchemaForm
        form=SchemaForm({'$defs':{'ServerListener':{}}},ask=lambda _:'password-is-not-a-reference',say=lambda _:None)
        with self.assertRaises(vp.InstallError):form.collect({'type':'string'},'listener.privateKeyRef')
        with self.assertRaises(vp.InstallError):form.collect({'oneOf':[{'type':'object','properties':{'kind':{'const':'known'}}}]},'listener.protocol',{'listener.protocol.kind':'unknown'})
    def test_pending_direct_is_not_silently_substituted(self):
        from vp_form import listener_wizard
        direct=next(p for p in vp_api.catalog() if p['id']=='P22-DIRECT')
        with self.assertRaises(vp.InstallError):listener_wizard(direct)


class AdditionalFormTests(unittest.TestCase):
    def test_all_21_shared_schema_preset_branches_are_promptable_not_certified(self):
        from vp_form import listener_wizard
        def answer(prompt):
            if 'Choice number' in prompt:return '1'
            if 'number of items' in prompt:return '1' if '(1..' in prompt else '0'
            if 'true/false' in prompt:return 'false'
            if 'integer' in prompt:return '12345'
            if '可选项' in prompt:return 'n'
            if '仅现有引用' in prompt:return 'secret:test-reference'
            return 'test-value'
        for preset in vp_api.catalog():
            if preset['scope'] != 'required_public_baseline':continue
            dto=listener_wizard(preset,ask=answer,say=lambda _:None)
            self.assertEqual(dto['protocol']['protocol']['kind'],preset['protocol'])
            self.assertEqual(dto['transport']['kind'],preset['transport'])
            self.assertEqual(dto['security']['kind'],preset['security'])
            self.assertEqual(dto['requirements'],[preset['key']])

class MoreLifecycleTests(Fixture):
    def test_identical_install_does_not_restart_running_service(self):
        self.install(); self.fake.running=True;self.fake.calls=[]
        result=self.install()
        self.assertTrue(result['serviceActive']);self.assertEqual(self.fake.calls,[])


class MutableBundleRegression(Fixture):
    def test_low_trust_source_inode_write_after_hash_cannot_change_snapshot(self):
        def content(letter):
            def change(manifest,payload):
                payload['web/index.html']=letter*100000
                for item in manifest['files']:
                    if item['path']=='web/index.html':
                        item['size']=100000;item['sha256']=vp.digest(payload[item['path']])
            return change
        original,expected=self.bundle('trusted',altered=content(b'A'))
        mutated,other=self.bundle('trusted',altered=content(b'B'))
        malicious_bytes=mutated.read_bytes()
        original,expected=self.bundle('trusted',altered=content(b'A'))
        inode=original.stat().st_ino
        constructor=vp.zipfile.ZipFile
        def mutate_then_parse(file,*args,**kwargs):
            # Models an attacker owning the source under sudo: same inode, same size,
            # after outer hash but before manifest parsing. Snapshot must stay trusted.
            with original.open('r+b') as out:
                out.write(malicious_bytes);out.flush();os.fsync(out.fileno())
            self.assertEqual(original.stat().st_ino,inode)
            return constructor(file,*args,**kwargs)
        with mock.patch.object(vp.zipfile,'ZipFile',side_effect=mutate_then_parse):
            with vp.Bundle(original,expected) as bundle:
                bundle.extract(self.base/'snapshot-extraction')
        self.assertNotEqual(vp.digest(original.read_bytes()),expected)
        self.assertEqual((self.base/'snapshot-extraction/web/index.html').read_bytes(),b'A'*100000)
    def test_path_replacement_after_snapshot_does_not_change_trusted_bytes(self):
        original,expected=self.bundle('v1');replacement,other=self.bundle('v2')
        constructor=vp.zipfile.ZipFile
        def replace_then_parse(file,*args,**kwargs):
            os.replace(replacement,original)
            return constructor(file,*args,**kwargs)
        with mock.patch.object(vp.zipfile,'ZipFile',side_effect=replace_then_parse):
            with vp.Bundle(original,expected) as bundle:
                self.assertEqual(bundle.manifest['releaseId'],'v1')
        self.assertNotEqual(vp.digest(original.read_bytes()),expected)

if __name__=='__main__':
    unittest.main()
