"""Offline plan/transaction tests with mocked maintenance; no binary executed."""
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vp_bootstrap as bootstrap
import vp_maintenance_bridge as bridge
from vp_install import InstallError, canonical

class OfflineBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vp-bootstrap-offline-synthetic-')
        self.base = Path(self.temp.name); self.root = self.base/'materials'
        self.engine = bootstrap.Bootstrap(self.root)
        self.source = self.base/'input'
        self.value = {'username':'synthetic', 'token':'S'*43, 'vault':{'masterKeyHex':'12'*32,'credentials':[]}}
        self.source.write_bytes(canonical(self.value)); self.source.chmod(0o600)
        self.prepare_options = dict(username='synthetic', namespace='synthetic', requestKey='prepare_one', generate=False, importFile=str(self.source))
        plan = self.engine.plan('prepare', self.prepare_options)
        self.engine.apply(plan, plan['planHash'], self.prepare_options)
        raw = bytearray(128); raw[:7]=b'\x7fELF\x02\x01\x01'; raw[16:18]=(3).to_bytes(2,'little')
        raw[18:20]={'x86_64':62,'aarch64':183}[platform.machine()].to_bytes(2,'little')
        self.artifact = self.base/'synthetic-elf-never-run'; self.artifact.write_bytes(raw); self.artifact.chmod(0o500)
        self.options = dict(maintenanceArtifact=str(self.artifact), maintenanceSha256=hashlib.sha256(raw).hexdigest(), requestKey='init_one')
        self.response = dict(status='offline_observation_received', command='vault-init-bound', operationId='init_one', vaultInitialized=True,
            targetMutation='vault_manifest_created', recoveryEligible=False, authorityBinding=None, serviceStartedByThisTool=False,
            receiptValidated=True, leaseScope='observation_only_released_before_exit')
    def tearDown(self): self.temp.cleanup()
    def plan(self): return self.engine.plan('offline-vault-init', self.options)
    def test_plan_is_read_only_and_redacted(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*'))
        with mock.patch.object(bridge, 'execute') as run:
            plan = self.plan()
        run.assert_not_called()
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*')))
        self.assertNotIn(self.value['token'], json.dumps(plan)); self.assertNotIn(self.value['vault']['masterKeyHex'], json.dumps(plan))
    def test_wrong_confirmation_no_intent_or_process(self):
        plan = self.plan()
        with mock.patch.object(bridge, 'execute') as run, self.assertRaises(InstallError):
            self.engine.apply(plan, '0'*64, self.options)
        run.assert_not_called(); self.assertFalse((self.root/bootstrap.OFFLINE_INTENT).exists())
    def test_success_consumes_intent_before_execution_and_never_repeats(self):
        def run(*args, **kwargs):
            self.assertEqual(kwargs['expected_vault_directory'], {'device': (self.root/'vault').stat().st_dev, 'inode': (self.root/'vault').stat().st_ino})
            self.assertTrue((self.root/bootstrap.OFFLINE_INTENT).is_file())
            self.assertFalse((self.root/bootstrap.OFFLINE_PENDING).exists())
            self.assertFalse((self.root/bootstrap.OFFLINE_RESULT).exists())
            return self.response
        plan = self.plan()
        with mock.patch.object(bridge, 'execute', side_effect=run) as execute:
            result = self.engine.apply(plan, plan['planHash'], self.options)
        self.assertEqual(execute.call_count, 1); self.assertFalse(result['serviceReady'])
        self.assertTrue((self.root/bootstrap.OFFLINE_RESULT).is_file())
        with self.assertRaises(InstallError): self.plan()
    def test_spawn_uncertainty_retains_intent_and_no_retry(self):
        plan = self.plan()
        with mock.patch.object(bridge, 'execute', side_effect=bridge.MaintenanceUncertain('synthetic')), self.assertRaises(InstallError):
            self.engine.apply(plan, plan['planHash'], self.options)
        self.assertTrue((self.root/bootstrap.OFFLINE_INTENT).is_file())
        self.assertFalse((self.root/bootstrap.OFFLINE_RESULT).exists())
        with self.assertRaises(InstallError): self.plan()
    def test_result_write_failure_retains_consumed_intent(self):
        original = bootstrap.new_file
        def write(fd, name, data):
            if name == bootstrap.OFFLINE_RESULT: raise OSError('injected result failure')
            return original(fd,name,data)
        plan = self.plan()
        with mock.patch.object(bridge, 'execute', return_value=self.response), mock.patch.object(bootstrap,'new_file',side_effect=write), self.assertRaises(OSError):
            self.engine.apply(plan, plan['planHash'], self.options)
        self.assertTrue((self.root/bootstrap.OFFLINE_INTENT).exists())
        with self.assertRaises(InstallError): self.plan()
    def test_intent_durability_failure_never_launches(self):
        plan = self.plan()
        with mock.patch.object(bootstrap,'publish_pending',side_effect=OSError('injected fsync failure')), \
             mock.patch.object(bridge,'execute') as run, self.assertRaises(OSError):
            self.engine.apply(plan, plan['planHash'], self.options)
        run.assert_not_called(); self.assertTrue((self.root/bootstrap.OFFLINE_PENDING).exists())
        with self.assertRaises(InstallError): self.plan()
    def test_changed_vault_or_artifact_rejects_old_plan(self):
        plan = self.plan(); (self.root/'vault'/'unknown').write_bytes(b'unknown')
        with mock.patch.object(bridge,'execute') as run, self.assertRaises(InstallError):
            self.engine.apply(plan, plan['planHash'], self.options)
        run.assert_not_called(); self.assertFalse((self.root/bootstrap.OFFLINE_INTENT).exists())
    def mutate_after_fresh_plan(self, filename, field, value):
        original_plan = self.engine.plan
        def changed(action, options):
            fresh = original_plan(action, options)
            target = self.root/filename
            data = json.loads(target.read_bytes()); data[field] = value
            target.write_bytes(canonical(data) + b'\n')
            return fresh
        return changed
    def test_offline_confirmation_rejects_namespace_or_intent_change_before_lock(self):
        for filename, field, value in ((bootstrap.MANIFEST,'namespace','changed_namespace'),
                                       (bootstrap.INTENT,'requestKey','changed_request')):
            with self.subTest(field=field):
                target=self.root/filename; saved=target.read_bytes(); plan=self.plan()
                try:
                    with mock.patch.object(self.engine,'plan',side_effect=self.mutate_after_fresh_plan(filename,field,value)), \
                         mock.patch.object(bridge,'execute') as run, self.assertRaises(InstallError):
                        self.engine.apply(plan,plan['planHash'],self.options)
                    run.assert_not_called()
                    self.assertFalse((self.root/bootstrap.OFFLINE_INTENT).exists())
                    self.assertFalse((self.root/bootstrap.OFFLINE_PENDING).exists())
                    self.assertEqual(list((self.root/'vault').iterdir()),[])
                finally: target.write_bytes(saved)
    def test_backup_confirmation_rejects_manifest_namespace_change_before_lock(self):
        backup=self.base/'backup'; backup.mkdir(mode=0o700)
        options={'backupFile':str(backup/'key'),'acknowledgePlaintext':True}
        plan=self.engine.plan('backup-key',options)
        with mock.patch.object(self.engine,'plan',side_effect=self.mutate_after_fresh_plan(bootstrap.MANIFEST,'namespace','changed_namespace')), \
             self.assertRaises(InstallError):
            self.engine.apply(plan,plan['planHash'],options)
        self.assertEqual(list(backup.iterdir()),[])
    def test_token_confirmation_rejects_manifest_namespace_change_before_lock(self):
        plan=self.engine.plan('show-admin-token',{})
        output=io.StringIO(); output.isatty=lambda:True
        with mock.patch.object(self.engine,'plan',side_effect=self.mutate_after_fresh_plan(bootstrap.MANIFEST,'namespace','changed_namespace')), \
             mock.patch.object(sys.stdin,'isatty',return_value=True), contextlib.redirect_stdout(output), \
             self.assertRaises(InstallError):
            self.engine.show_admin_token(plan,plan['planHash'])
        self.assertEqual(output.getvalue(),'')
    def test_status_after_attempt_remains_nonexecuting_and_no_recovery_authority(self):
        plan=self.plan()
        with mock.patch.object(bridge,'execute',return_value=self.response):
            self.engine.apply(plan,plan['planHash'],self.options)
        with mock.patch.object(bridge,'execute') as run:
            status=bootstrap.status(self.root)
        run.assert_not_called(); self.assertFalse(status['recoveryEligible']); self.assertIsNone(status['vaultInitialized'])
        self.assertTrue(status['offlineInitializationAttemptRecorded']); self.assertTrue(status['offlineInitializationReceiptPresent'])
        self.assertFalse(status['offlineInitializationLiveStateVerified'])

if __name__ == '__main__': unittest.main()
