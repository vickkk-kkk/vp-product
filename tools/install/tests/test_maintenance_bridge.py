"""Pure bridge and sealed-data tests; no executable/maintenance process starts."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vp_maintenance_bridge as bridge
from vp_install import InstallError

class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vp-maintenance-bridge-synthetic-')
        self.base = Path(self.temp.name)
        header = bytearray(128); header[:7] = b'\x7fELF\x02\x01\x01'
        header[16:18] = (3).to_bytes(2, 'little')
        header[18:20] = {'x86_64':62, 'aarch64':183}[platform.machine()].to_bytes(2, 'little')
        self.raw = bytes(header)
        self.artifact = self.base / 'synthetic-ELF-never-execute'
        self.artifact.write_bytes(self.raw); self.artifact.chmod(0o500)
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.key = '12' * 32
    def tearDown(self):
        self.temp.cleanup()
    def kwargs(self, action='vault-init-bound'):
        return dict(action=action, artifact=self.artifact, artifact_sha256=self.digest,
                    vault_root=self.base / 'vault', namespace='synthetic', operation_id='test_one', master_hex=self.key,
                    state_root=self.base / 'control' if action == 'inspect' else None,
                    expected_vault_directory={'device':1,'inode':2} if action == 'vault-init-bound' else None)
    def receipt(self, action='vault-init-bound'):
        return dict(protocolVersion=1, receiptVersion=1, command=action, operationId='test_one',
                    operationIdRole='correlation_only_not_persisted', targetMutation='vault_manifest_created' if action=='vault-init-bound' else 'none',
                    authorityBinding=None, controlAuthorityId=None, retirementWatermark=None,
                    publicationRevocationWatermark=None, authorityStatus='unavailable', watermarkStatus='unavailable',
                    leaseScope='observation_only_released_before_exit', recoveryEligible=False, vault={'keyAuthenticated':True}, targetBindingValidated=True)
    def test_sealed_copy_survives_source_rewrite_and_closes(self):
        with bridge.sealed_artifact(self.artifact, self.digest) as fd:
            self.assertEqual(fcntl.fcntl(fd, bridge.F_GET_SEALS) & bridge.SEALS, bridge.SEALS)
            self.assertFalse(os.get_inheritable(fd))
            self.artifact.chmod(0o600); self.artifact.write_bytes(b'changed source bytes')
            self.assertEqual(os.read(fd, 256), self.raw)
            with self.assertRaises(OSError): os.write(fd, b'X')
            with self.assertRaises(OSError): os.ftruncate(fd, 0)
        with self.assertRaises(OSError): os.fstat(fd)
    def test_hash_mismatch_and_unsupported_memfd_never_fallback(self):
        with self.assertRaises(InstallError):
            with bridge.sealed_artifact(self.artifact, '0' * 64): self.fail('must not yield')
        with mock.patch.object(bridge.os, 'memfd_create', side_effect=OSError('policy')), self.assertRaises(InstallError):
            with bridge.sealed_artifact(self.artifact, self.digest): self.fail('must not yield')
    def test_symlink_public_writable_and_wrong_arch_refused(self):
        alias = self.base / 'alias'; alias.symlink_to(self.artifact)
        for path in (alias,):
            with self.assertRaises(InstallError):
                with bridge.sealed_artifact(path, self.digest): self.fail('must not yield')
        self.artifact.chmod(0o666)
        with self.assertRaises(InstallError):
            with bridge.sealed_artifact(self.artifact, self.digest): self.fail('must not yield')
        self.artifact.chmod(0o500)
        with mock.patch.object(bridge.platform, 'machine', return_value='unknown'), self.assertRaises(InstallError):
            with bridge.sealed_artifact(self.artifact, self.digest): self.fail('must not yield')
    def test_fixed_input_only_key_in_stdin(self):
        args, secret = bridge.fixed_request('vault-init-bound', self.base/'vault', None, 'synthetic', 'test_one', self.key, {'device':1,'inode':2})
        self.assertNotIn(self.key, ' '.join(args)); self.assertEqual(json.loads(secret)['masterKeyHex'], self.key)
        self.assertNotIn(b'\\', secret); self.assertLessEqual(len(secret), 4096)
        with self.assertRaises(InstallError):
            bridge.fixed_request('shell', self.base/'vault', None, 'synthetic', 'test_one', self.key)
    def test_spawn_contract_one_code_fd_empty_environment_and_redacted_result(self):
        with mock.patch.object(bridge.subprocess, 'Popen') as spawn, \
             mock.patch.object(bridge, 'bounded_exchange', return_value=(0, json.dumps(self.receipt()).encode())):
            result = bridge.execute(**self.kwargs())
        args, opts = spawn.call_args
        self.assertTrue(args[0][0].startswith('/proc/self/fd/'))
        self.assertEqual(opts['env'], {}); self.assertTrue(opts['close_fds']); self.assertEqual(len(opts['pass_fds']), 1)
        with self.assertRaises(OSError): os.fstat(opts['pass_fds'][0])
        self.assertNotIn(self.key, repr(spawn.call_args)); self.assertNotIn(self.key, json.dumps(result))
        self.assertFalse(result['recoveryEligible']); self.assertTrue(result['vaultInitialized'])
    def test_lost_failed_or_authority_claiming_init_receipt_always_uncertain_no_retry(self):
        for response in ((1, b'{}'), (0, b''), (0, json.dumps({**self.receipt(), 'recoveryEligible':True}).encode()),
                         (0, json.dumps({**self.receipt(), 'targetMutation':self.key}).encode())):
            with self.subTest(response=response[0]), mock.patch.object(bridge.subprocess, 'Popen') as spawn, \
                 mock.patch.object(bridge, 'bounded_exchange', return_value=response), self.assertRaises(bridge.MaintenanceUncertain):
                bridge.execute(**self.kwargs())
            self.assertEqual(spawn.call_count, 1)
    def test_bound_init_requires_exact_identity_and_explicit_receipt(self):
        for identity in (None, {'device':True,'inode':2}, {'device':1,'inode':-1}, {'device':1,'inode':2,'extra':3}):
            with mock.patch.object(bridge.subprocess,'Popen') as run, self.assertRaises(InstallError):
                bridge.execute(**{**self.kwargs(), 'expected_vault_directory':identity})
            run.assert_not_called()
        receipt=self.receipt(); receipt.pop('targetBindingValidated')
        with mock.patch.object(bridge.subprocess,'Popen'), \
             mock.patch.object(bridge,'bounded_exchange',return_value=(0,json.dumps(receipt).encode())), \
             self.assertRaises(bridge.MaintenanceUncertain):
            bridge.execute(**self.kwargs())
        with self.assertRaises(InstallError):
            bridge.fixed_request('vault-init', self.base/'vault', None, 'synthetic', 'test_one', self.key)
    def test_interrupt_after_spawn_is_uncertain_and_owned_child_reaped(self):
        process = mock.Mock(); process.poll.return_value = None
        with mock.patch.object(bridge.subprocess, 'Popen', return_value=process), \
             mock.patch.object(bridge, 'bounded_exchange', side_effect=KeyboardInterrupt), \
             self.assertRaises(bridge.MaintenanceUncertain):
            bridge.execute(**self.kwargs())
        process.kill.assert_called_once(); process.wait.assert_called_once_with(timeout=3)
    def test_prespawn_failure_is_not_uncertain_and_does_not_spawn(self):
        with mock.patch.object(bridge.subprocess, 'Popen') as spawn, \
             mock.patch.object(bridge.os, 'memfd_create', side_effect=OSError('policy')):
            with self.assertRaises(InstallError) as caught: bridge.execute(**self.kwargs())
        self.assertNotIsInstance(caught.exception, bridge.MaintenanceUncertain); spawn.assert_not_called()
    def test_inspect_receipt_never_implies_initialization_or_recovery(self):
        with mock.patch.object(bridge.subprocess, 'Popen'), \
             mock.patch.object(bridge, 'bounded_exchange', return_value=(0, json.dumps(self.receipt('inspect')).encode())):
            result = bridge.execute(**self.kwargs('inspect'))
        self.assertFalse(result['vaultInitialized']); self.assertFalse(result['recoveryEligible'])

if __name__ == '__main__': unittest.main()
