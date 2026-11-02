"""No probe executable launches. Installation gate tests use synthetic plans only."""
import errno
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vp_host_preflight as host
import vp_install as vp
from test_installer import Fixture, SimulatedCrash


class HostPreflightTests(unittest.TestCase):
    def test_old_kernel_refused_before_descriptor_creation(self):
        with mock.patch.object(host.platform, 'release', return_value='6.2.99-custom'), mock.patch.object(host.os, 'memfd_create') as create:
            result = host.check_sealed_runtime_host()
        self.assertFalse(result['prerequisitesAvailable'])
        self.assertEqual(result['reason'], 'linux_6_3_or_newer_required')
        create.assert_not_called()

    def test_unknown_kernel_fails_closed(self):
        with mock.patch.object(host.platform, 'release', return_value='unparseable'):
            self.assertFalse(host.check_sealed_runtime_host()['prerequisitesAvailable'])

    def test_non_native_arch_fails_closed(self):
        with mock.patch.object(host.platform, 'machine', return_value='riscv64'):
            self.assertEqual(host.check_sealed_runtime_host()['reason'], 'unsupported_os_or_architecture')

    def test_non_linux_fails_closed(self):
        with mock.patch.object(host.platform, 'system', return_value='Darwin'):
            self.assertFalse(host.check_sealed_runtime_host()['prerequisitesAvailable'])

    def test_exec_memfd_denied_is_explicit(self):
        with mock.patch.object(host.os, 'memfd_create', side_effect=PermissionError(errno.EPERM, 'denied')):
            result = host.check_sealed_runtime_host()
        self.assertFalse(result['prerequisitesAvailable'])
        self.assertEqual(result['finalExecPolicy'], 'not_checked_no_process_execution')

    def test_real_anonymous_capabilities_no_child_no_descriptor_leak(self):
        before = set(os.listdir('/proc/self/fd'))
        with mock.patch.object(vp.subprocess, 'run', side_effect=AssertionError('no child exec')):
            result = host.check_sealed_runtime_host()
        self.assertTrue(result['prerequisitesAvailable'], result)
        self.assertEqual(result['status'], 'prerequisites_present_not_execution_certified')
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_missing_seals_fails_and_closes_descriptor(self):
        original = host.fcntl.fcntl
        def control(fd, command, *args):
            return 0 if command == host.F_GET_SEALS else original(fd, command, *args)
        before = set(os.listdir('/proc/self/fd'))
        with mock.patch.object(host.fcntl, 'fcntl', side_effect=control):
            self.assertFalse(host.check_sealed_runtime_host()['prerequisitesAvailable'])
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_proc_unavailable_fails_and_closes_descriptor(self):
        before = set(os.listdir('/proc/self/fd'))
        with mock.patch.object(host.os, 'open', side_effect=PermissionError(errno.EACCES, 'no proc')):
            self.assertFalse(host.check_sealed_runtime_host()['prerequisitesAvailable'])
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_runtime_actions_refused_before_lock_or_root_mutation(self):
        with tempfile.TemporaryDirectory(prefix='vp-preflight-test-') as directory:
            root = Path(directory) / 'not-created'
            engine = vp.Installer(root)
            for action in ('install', 'update', 'rollback', 'start', 'recover'):
                plan = {'action': action, 'settings': {'runtimeProfile': 'loopback-vless-v1'}, 'planHash': '0'*64}
                with self.subTest(action=action), mock.patch.object(host.platform, 'release', return_value='5.15.0'), mock.patch.object(engine, 'locked', side_effect=AssertionError('mutation lock entered')):
                    with self.assertRaisesRegex(vp.InstallError, 'linux_6_3_or_newer_required'):
                        engine.apply(plan, '0'*64)
                self.assertFalse(root.exists())
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_existing_runtime_cannot_be_hidden_by_plan_settings(self):
        with tempfile.TemporaryDirectory(prefix='vp-preflight-test-') as directory:
            engine = vp.Installer(Path(directory)/'absent')
            plan = {'action':'update', 'settings':{'runtimeProfile':None}, 'planHash':'0'*64}
            with mock.patch.object(host.platform, 'release', return_value='5.15.0'), mock.patch.object(engine, 'state', return_value={'settings':{'runtimeProfile':'loopback-vless-v1'}}), mock.patch.object(engine, 'locked', side_effect=AssertionError('mutation')):
                with self.assertRaisesRegex(vp.InstallError, 'unsupported'):
                    engine.apply(plan, '0'*64)

    def test_recovery_checks_original_and_pending_runtime(self):
        with tempfile.TemporaryDirectory(prefix='vp-preflight-test-') as directory:
            engine = vp.Installer(Path(directory)/'absent')
            plan = {'action':'recover', 'settings':None, 'planHash':'0'*64}
            for journal in ({'settings':{'runtimeProfile':'loopback-vless-v1'}}, {'before':{'settings':{'runtimeProfile':'loopback-vless-v1'}}}):
                with mock.patch.object(host.platform, 'release', return_value='5.15.0'), mock.patch.object(engine, 'pending', return_value=journal), mock.patch.object(engine, 'locked', side_effect=AssertionError('mutation')):
                    with self.assertRaisesRegex(vp.InstallError, 'unsupported'):
                        engine.apply(plan, '0'*64)

    def test_file_only_preflight_reports_runtime_failure(self):
        with mock.patch.object(host.platform, 'release', return_value='5.15.0'):
            report = vp.service_preflight('/tmp/not-created', {'mode':'files', 'runtimeProfile':'loopback-vless-v1'})
        self.assertEqual(report['checks'][0]['status'], 'missing_or_invalid')
        self.assertFalse(report['canAttemptServiceDeployment'])

    def test_cli_preflight_returns_nonzero_without_creating_root_on_old_kernel(self):
        with tempfile.TemporaryDirectory(prefix='vp-preflight-cli-') as directory:
            root = Path(directory)/'absent'
            output = io.StringIO()
            with mock.patch.object(host.platform, 'release', return_value='5.15.0'), contextlib.redirect_stdout(output):
                status = vp.main(['preflight', '--root', str(root), '--runtime-profile', 'loopback-vless-v1', '--vault-namespace', 'fixture', '--json'])
            self.assertEqual(status, 2)
            self.assertEqual(json.loads(output.getvalue())['servicePreflight']['checks'][0]['status'], 'missing_or_invalid')
            self.assertFalse(root.exists())

    def test_non_runtime_preflight_does_not_request_capabilities(self):
        with mock.patch.object(vp, 'check_sealed_runtime_host', side_effect=AssertionError('not a runtime install')):
            report = vp.service_preflight('/tmp/not-created', {'mode':'files', 'runtimeProfile':None})
        self.assertEqual(report['checks'], [])

class UnsupportedHostCleanupTests(Fixture):
    def runtime_bundle(self, release):
        def add_worker(manifest, payload):
            data = payload['bin/vp-product-managementd']
            payload['bin/vp-core-managed-worker'] = data
            manifest['files'].append({'path':'bin/vp-core-managed-worker', 'size':len(data), 'sha256':vp.digest(data), 'executable':True})
        return self.bundle(release, altered=add_worker)

    def install_runtime(self):
        self.settings.update(runtimeProfile='loopback-vless-v1', vaultNamespace='test-only')
        path, expected = self.runtime_bundle('v1')
        with vp.Bundle(path, expected) as bundle:
            plan = self.engine.plan('install', bundle, self.settings)
            self.engine.apply(plan, plan['planHash'], bundle)

    def test_old_kernel_finishes_interrupted_runtime_uninstall(self):
        self.install_runtime()
        original = self.engine._journal
        def crash(journal, phase):
            original(journal, phase)
            if phase == 'uninstall_stopped':
                raise SimulatedCrash()
        plan = self.engine.plan('uninstall')
        with mock.patch.object(self.engine, '_journal', side_effect=crash):
            with self.assertRaises(SimulatedCrash):
                self.engine.apply(plan, plan['planHash'])
        self.assertEqual(self.engine.pending()['action'], 'uninstall')
        plan = self.engine.plan('recover')
        with mock.patch.object(host.platform, 'release', return_value='5.15.0'), mock.patch.object(self.fake, 'start', side_effect=AssertionError('cleanup cannot start service')):
            result = self.engine.apply(plan, plan['planHash'])
        self.assertFalse(result['installed'])
        self.assertIsNone(self.engine.pending())

    def test_old_kernel_clears_committed_runtime_update_journal(self):
        self.install_runtime()
        path, expected = self.runtime_bundle('v2')
        original = self.engine._journal
        def crash(journal, phase):
            original(journal, phase)
            if phase == 'committed':
                raise SimulatedCrash()
        with vp.Bundle(path, expected) as bundle:
            plan = self.engine.plan('update', bundle, self.settings)
            with mock.patch.object(self.engine, '_journal', side_effect=crash):
                with self.assertRaises(SimulatedCrash):
                    self.engine.apply(plan, plan['planHash'], bundle)
        self.assertEqual(self.engine.pending()['phase'], 'committed')
        before = (self.root/'state.json').read_bytes()
        plan = self.engine.plan('recover')
        with mock.patch.object(host.platform, 'release', return_value='5.15.0'), mock.patch.object(self.fake, 'start', side_effect=AssertionError('cleanup cannot start service')):
            self.engine.apply(plan, plan['planHash'])
        self.assertEqual((self.root/'state.json').read_bytes(), before)
        self.assertIsNone(self.engine.pending())

if __name__ == '__main__':
    unittest.main()
