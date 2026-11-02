"""Actual CLI/PTY gates on fixed synthetic credentials and temporary roots only."""
import errno
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'vp_bootstrap.py'
# Fail the subprocess if CLI code attempts service/process/network operations.
# This is a Python audit boundary, not a kernel syscall trace or native proof.
LAUNCHER = '''import runpy, sys
sys.path.insert(0, sys.argv[1])
def forbid(event, args):
    if event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.spawn')) or event in ('os.system', 'os.fork', 'os.forkpty'):
        raise RuntimeError('forbidden process/network action')
sys.addaudithook(forbid)
sys.argv = sys.argv[2:]
runpy.run_path(sys.argv[0], run_name='__main__')
'''

class BootstrapProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vp-bootstrap-process-synthetic-')
        self.base = Path(self.temp.name)
        self.root = self.base / 'materials'
        self.source = self.base / 'synthetic.json'
        self.value = {'username': 'synthetic_admin', 'token': 'S' * 43,
                      'vault': {'masterKeyHex': '12' * 32, 'credentials': []}}
        self.source.write_text(json.dumps(self.value))
        self.source.chmod(0o600)
        self.prepare_args = ['prepare', '--root', str(self.root), '--username', 'synthetic_admin',
            '--namespace', 'synthetic_vault', '--request-key', 'process_one',
            '--import-bootstrap-file', str(self.source)]
    def tearDown(self):
        self.temp.cleanup()
    def command(self, args):
        return [sys.executable, '-c', LAUNCHER, str(SCRIPT.parent), str(SCRIPT), *args]
    def run_cli(self, args):
        return subprocess.run(self.command(args), input=b'', capture_output=True, timeout=5)
    def assert_redacted(self, output):
        self.assertNotIn(self.value['token'].encode(), output)
        self.assertNotIn(self.value['vault']['masterKeyHex'].encode(), output)
        self.assertNotIn(b'Traceback', output)
    def prepare(self):
        planned = self.run_cli([*self.prepare_args, '--dry-run'])
        self.assertEqual(planned.returncode, 0)
        plan = json.loads(planned.stdout)
        result = self.run_cli([*self.prepare_args, '--confirm-plan-sha256', plan['planHash']])
        self.assertEqual(result.returncode, 0)
        self.assert_redacted(planned.stdout + planned.stderr + result.stdout + result.stderr)
        return result
    def tty(self, args, response):
        master, slave = os.openpty()
        process = subprocess.Popen(self.command(args), stdin=slave, stdout=slave, stderr=slave, close_fds=True)
        os.close(slave)
        output = bytearray(); sent = False
        deadline = time.monotonic() + 5
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], .05)
                if ready:
                    try:
                        block = os.read(master, 65536)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not block:
                        break
                    output.extend(block)
                    if not sent and '确认当前完整计划'.encode() in output:
                        os.write(master, response.encode() + b'\n'); sent = True
                elif process.poll() is not None:
                    break
            self.assertTrue(sent, 'actual interactive confirmation must be observed')
            return process.wait(timeout=1), bytes(output)
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=2)
            os.close(master)
    def test_actual_cli_plan_apply_and_status_without_service(self):
        planned = self.run_cli([*self.prepare_args, '--dry-run'])
        self.assertEqual(planned.returncode, 0); self.assertFalse(self.root.exists())
        self.prepare()
        result = self.run_cli(['status', '--root', str(self.root)])
        self.assertEqual(result.returncode, 0)
        observed = json.loads(result.stdout)
        self.assertTrue(observed['materialsPrepared'])
        self.assertFalse(observed['serviceStartedByThisTool'])
        self.assertIsNone(observed['vaultInitialized'])
        self.assert_redacted(result.stdout + result.stderr)
        for name in ('control', 'runtime', 'vault'):
            self.assertEqual(list((self.root / name).iterdir()), [])
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / 'bootstrap.json').stat().st_mode), 0o600)
    def test_actual_tty_cancel_has_no_material_side_effect(self):
        code, output = self.tty(self.prepare_args, '')
        self.assertEqual(code, 0); self.assertFalse(self.root.exists()); self.assert_redacted(output)
    def test_actual_tty_confirm_and_token_display_never_master(self):
        code, output = self.tty(self.prepare_args, '准备敏感材料')
        self.assertEqual(code, 0); self.assertTrue(self.root.exists()); self.assert_redacted(output)
        code, output = self.tty(['show-admin-token', '--root', str(self.root)], '显示管理员令牌')
        self.assertEqual(code, 0)
        self.assertIn(self.value['token'].encode(), output)
        self.assertNotIn(self.value['vault']['masterKeyHex'].encode(), output)
    def test_actual_pipe_token_display_and_recovery_fail_closed(self):
        self.prepare()
        display = self.run_cli(['show-admin-token', '--root', str(self.root)])
        self.assertEqual(display.returncode, 2); self.assert_redacted(display.stdout + display.stderr)
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        for action in ('resume', 'restore-key'):
            result = self.run_cli([action, '--root', str(self.root)])
            self.assertEqual(result.returncode, 3); self.assert_redacted(result.stdout + result.stderr)
            self.assertFalse(json.loads(result.stdout)['blocking']['recoveryEligible'])
        after = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertTrue(before == after, 'recovery refusal must preserve private bytes')
    def test_actual_cli_stale_confirmation_rejects_changed_import(self):
        plan = json.loads(self.run_cli([*self.prepare_args, '--dry-run']).stdout)
        changed = {**self.value, 'token': 'X' * 43}
        self.source.write_text(json.dumps(changed))
        result = self.run_cli([*self.prepare_args, '--confirm-plan-sha256', plan['planHash']])
        self.assertEqual(result.returncode, 2); self.assertFalse(self.root.exists())
        self.assert_redacted(result.stdout + result.stderr)
        self.assertNotIn(changed['token'].encode(), result.stdout + result.stderr)

if __name__ == '__main__':
    unittest.main()
