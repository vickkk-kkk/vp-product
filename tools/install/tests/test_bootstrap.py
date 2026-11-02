"""SOURCE-ONLY synthetic private-root tests. No daemon, service, host or network.
Generator tests inject fixed nonproduction bytes; only temporary roots are mutated.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vp_bootstrap as bootstrap
from vp_install import InstallError, canonical, digest


class Terminal(io.StringIO):
    def isatty(self):
        return True


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vp-bootstrap-synthetic-')
        self.base = Path(self.temp.name); self.base.chmod(0o700)
        self.root = self.base / 'materials'
        self.engine = bootstrap.Bootstrap(self.root)
        self.value = {'username': 'synthetic_admin', 'token': 'S' * 43,
                      'vault': {'masterKeyHex': '12' * 32, 'credentials': []}}
        self.raw = canonical(self.value) + b'\n'
        self.source = self.base / 'provided.json'
        self.source.write_bytes(self.raw); self.source.chmod(0o600)
        self.options = {'username': 'synthetic_admin', 'namespace': 'synthetic_vault', 'requestKey': 'prepare_one',
                        'generate': False, 'importFile': str(self.source)}
    def tearDown(self):
        self.temp.cleanup()
    def prepare(self):
        plan = self.engine.plan('prepare', self.options)
        return self.engine.apply(plan, plan['planHash'], self.options)
    def assert_safe(self, value):
        text = json.dumps(value)
        self.assertTrue(self.value['token'] not in text, 'no token in ordinary output')
        self.assertTrue(self.value['vault']['masterKeyHex'] not in text, 'no master in ordinary output')
        self.assertTrue(digest(self.raw) not in text, 'material fingerprint is private, not ordinary output')
    def test_plan_does_not_write_lock_directory_or_generate_entropy(self):
        before = sorted(p.name for p in self.base.iterdir())
        with mock.patch.object(bootstrap.secrets, 'token_urlsafe', side_effect=AssertionError('no entropy')), \
             mock.patch.object(bootstrap.secrets, 'token_hex', side_effect=AssertionError('no entropy')):
            plan = self.engine.plan('prepare', self.options)
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), before)
        self.assertFalse(self.root.exists()); self.assert_safe(plan)
    def test_no_default_credentials_or_ambiguous_generation(self):
        for options in ({**self.options, 'importFile': None}, {**self.options, 'generate': True},
                        {**self.options, 'username': None}, {**self.options, 'requestKey': None}):
            with self.assertRaises(InstallError):
                self.engine.plan('prepare', options)
        self.assertFalse(self.root.exists())
    def test_confirmation_mismatch_does_not_write(self):
        plan = self.engine.plan('prepare', self.options)
        with self.assertRaises(InstallError):
            self.engine.apply(plan, '0' * 64, self.options)
        self.assertFalse(self.root.exists())
    def test_long_root_rejected_before_filesystem_or_entropy(self):
        root = self.base.joinpath(*(['x' * 100] * 35), 'materials')
        before = sorted(p.name for p in self.base.iterdir())
        with mock.patch.object(bootstrap.secrets, 'token_urlsafe') as token, \
             mock.patch.object(bootstrap.secrets, 'token_hex') as key, \
             self.assertRaisesRegex(InstallError, 'local metadata bound'):
            bootstrap.Bootstrap(root)
        token.assert_not_called(); key.assert_not_called()
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), before)
    def test_long_supported_root_keeps_all_private_files_readable(self):
        parent = self.base
        while len(str(parent)) + 101 + len('/materials') <= bootstrap.MAX_ROOT_BYTES:
            parent = parent / ('x' * 100); parent.mkdir(mode=0o700)
        root = parent / 'materials'; engine = bootstrap.Bootstrap(root)
        value = {'username': 'a' * 64, 'token': 'S' * 256,
                 'vault': {'masterKeyHex': '12' * 32, 'credentials': []}}
        source = self.base / 'long-input.json'; source.write_bytes(canonical(value)); source.chmod(0o600)
        options = {**self.options, 'username': value['username'], 'namespace': 'n' * 64,
                   'requestKey': 'r' * 64, 'importFile': str(source)}
        plan = engine.plan('prepare', options)
        self.assertTrue(engine.apply(plan, plan['planHash'], options)['materialsPrepared'])
        self.assertTrue(bootstrap.status(root)['materialsPrepared'])
        for name in (bootstrap.INTENT, bootstrap.MANIFEST, bootstrap.MATERIAL):
            self.assertLessEqual((root / name).stat().st_size, bootstrap.MAX_MATERIAL)
            bootstrap.private_bytes(root / name)
    def test_private_writer_rejects_unreadable_size_before_open(self):
        with mock.patch.object(bootstrap.os, 'open', side_effect=AssertionError('must reject before create')), \
             self.assertRaises(InstallError):
            bootstrap.new_file(-1, 'not-created', b'x' * (bootstrap.MAX_MATERIAL + 1))
    def test_import_prepares_exact_real_daemon_shape_and_private_modes(self):
        with mock.patch.object(bootstrap.secrets, 'token_urlsafe', side_effect=AssertionError('no generation')):
            result = self.prepare()
        self.assertTrue(result['materialsPrepared'])
        self.assertIsNone(result['vaultInitialized']); self.assertFalse(result['serviceStartedByThisTool'])
        self.assertFalse(result['recoveryEligible']); self.assert_safe(result)
        self.assertTrue((self.root / bootstrap.MATERIAL).read_bytes() == self.raw, 'exact imported material')
        for name in bootstrap.DIRECTORIES:
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o700)
            self.assertEqual(list((self.root / name).iterdir()), [])
        for name in (bootstrap.MATERIAL, bootstrap.MANIFEST, bootstrap.INTENT):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600)
        self.assertEqual(json.loads((self.root / bootstrap.MANIFEST).read_bytes())['authorityBinding'], None)
    def test_generate_requires_durable_atomic_consumed_intent_before_entropy(self):
        options = {**self.options, 'generate': True, 'importFile': None}
        plan = self.engine.plan('prepare', options)
        calls = []
        def token(size):
            intent = json.loads((self.root / bootstrap.INTENT).read_bytes())
            self.assertEqual(intent['generationReservation'], 'consumed')
            self.assertFalse((self.root / bootstrap.INTENT_PENDING).exists())
            calls.append('token'); return self.value['token']
        def key(size):
            self.assertTrue((self.root / bootstrap.INTENT).is_file())
            calls.append('master'); return self.value['vault']['masterKeyHex']
        with mock.patch.object(bootstrap.secrets, 'token_urlsafe', side_effect=token), \
             mock.patch.object(bootstrap.secrets, 'token_hex', side_effect=key):
            result = self.engine.apply(plan, plan['planHash'], options)
        self.assertEqual(calls, ['token', 'master']); self.assert_safe(result)
    def test_existing_empty_root_parent_fsync_precedes_entropy(self):
        self.root.mkdir(mode=0o700)
        options = {**self.options, 'generate': True, 'importFile': None}
        plan = self.engine.plan('prepare', options)
        parent = self.base.stat(); events = []
        original_fsync = bootstrap.os.fsync
        def synced(fd):
            observed = os.fstat(fd)
            original_fsync(fd)
            if (observed.st_dev, observed.st_ino) == (parent.st_dev, parent.st_ino):
                events.append('parent_barrier_complete')
        def token(size):
            self.assertEqual(events, ['parent_barrier_complete'])
            self.assertTrue((self.root / bootstrap.INTENT).is_file())
            events.append('token'); return self.value['token']
        def key(size):
            self.assertEqual(events, ['parent_barrier_complete', 'token'])
            events.append('master'); return self.value['vault']['masterKeyHex']
        with mock.patch.object(bootstrap.os, 'fsync', side_effect=synced), \
             mock.patch.object(bootstrap.secrets, 'token_urlsafe', side_effect=token), \
             mock.patch.object(bootstrap.secrets, 'token_hex', side_effect=key):
            result = self.engine.apply(plan, plan['planHash'], options)
        self.assertEqual(events, ['parent_barrier_complete', 'token', 'master'])
        self.assertFalse(plan['durabilityBoundary']['absenceProvesNoPriorIdentity'])
        self.assertFalse(plan['durabilityBoundary']['parentAncestryDurabilityVerified'])
        self.assert_safe(result)
    def test_parent_fsync_failure_preserves_empty_root_without_generation(self):
        parent = self.base.stat(); original_fsync = bootstrap.os.fsync
        def fail_parent(fd):
            observed = os.fstat(fd)
            if (observed.st_dev, observed.st_ino) == (parent.st_dev, parent.st_ino):
                raise OSError('synthetic parent durability failure')
            original_fsync(fd)
        for existing in (False, True):
            with self.subTest(existing_empty_root=existing):
                root = self.base / ('existing-root' if existing else 'new-root')
                if existing:
                    root.mkdir(mode=0o700)
                engine = bootstrap.Bootstrap(root)
                options = {**self.options, 'generate': True, 'importFile': None}
                plan = engine.plan('prepare', options)
                with mock.patch.object(bootstrap.os, 'fsync', side_effect=fail_parent), \
                     mock.patch.object(bootstrap.secrets, 'token_urlsafe') as token, \
                     mock.patch.object(bootstrap.secrets, 'token_hex') as key, \
                     self.assertRaises(OSError):
                    engine.apply(plan, plan['planHash'], options)
                token.assert_not_called(); key.assert_not_called()
                self.assertTrue(root.is_dir())
                self.assertEqual(list(root.iterdir()), [])
    def test_consumed_root_refuses_second_prepare(self):
        self.prepare()
        with mock.patch.object(bootstrap.secrets, 'token_urlsafe', side_effect=AssertionError('no regeneration')), \
             self.assertRaises(InstallError):
            self.engine.plan('prepare', {**self.options, 'generate': True, 'importFile': None})
        self.assertTrue((self.root / bootstrap.MATERIAL).read_bytes() == self.raw, 'material unchanged')
    def test_prepare_rejects_replaced_confirmed_empty_root_before_entropy(self):
        self.root.mkdir(mode=0o700)
        options = {**self.options, 'generate': True, 'importFile': None}
        plan = self.engine.plan('prepare', options)
        original_fsync = bootstrap.os.fsync; parent = self.base.stat()
        moved = self.base / 'original-root'; swapped = []
        def replace_at_parent_barrier(fd):
            observed = os.fstat(fd)
            if not swapped and (observed.st_dev, observed.st_ino) == (parent.st_dev, parent.st_ino):
                self.root.rename(moved); self.root.mkdir(mode=0o700); swapped.append(True)
            original_fsync(fd)
        with mock.patch.object(bootstrap.os, 'fsync', side_effect=replace_at_parent_barrier), \
             mock.patch.object(bootstrap.secrets, 'token_urlsafe') as token, \
             mock.patch.object(bootstrap.secrets, 'token_hex') as key, self.assertRaises(InstallError):
            self.engine.apply(plan, plan['planHash'], options)
        token.assert_not_called(); key.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), []); self.assertEqual(list(moved.iterdir()), [])
    def test_generation_failure_preserves_intent_and_blocks_new_generation(self):
        options = {**self.options, 'generate': True, 'importFile': None}
        plan = self.engine.plan('prepare', options)
        with mock.patch.object(bootstrap.secrets, 'token_urlsafe', side_effect=OSError('synthetic generator unavailable')), \
             self.assertRaises(OSError):
            self.engine.apply(plan, plan['planHash'], options)
        self.assertTrue((self.root / bootstrap.INTENT).is_file())
        self.assertFalse((self.root / bootstrap.MATERIAL).exists())
        with self.assertRaises(InstallError):
            self.engine.plan('prepare', options)
        result = bootstrap.status(self.root)
        self.assertEqual(result['status'], 'RecoveryNeedsVerification')
        self.assertFalse(result['recoveryEligible'])
    def test_interrupted_pending_material_is_preserved_not_adopted(self):
        plan = self.engine.plan('prepare', self.options)
        original = bootstrap.publish_pending
        def interrupt(fd, pending, target):
            if target == bootstrap.MATERIAL:
                raise OSError('synthetic interruption')
            return original(fd, pending, target)
        with mock.patch.object(bootstrap, 'publish_pending', side_effect=interrupt), self.assertRaises(OSError):
            self.engine.apply(plan, plan['planHash'], self.options)
        self.assertTrue((self.root / bootstrap.PENDING).read_bytes() == self.raw, 'pending material retained')
        recovery = self.engine.plan('resume', {})
        self.assertFalse(recovery['blocking']['recoveryEligible']); self.assert_safe(recovery)
        with self.assertRaises(InstallError):
            self.engine.apply(recovery, recovery['planHash'], {})
        self.assertTrue((self.root / bootstrap.PENDING).is_file())
    def test_source_change_invalidates_confirmation(self):
        plan = self.engine.plan('prepare', self.options)
        changed = {**self.value, 'token': 'D' * 43}
        self.source.write_bytes(canonical(changed) + b'\n')
        with self.assertRaises(InstallError):
            self.engine.apply(plan, plan['planHash'], self.options)
        self.assertFalse(self.root.exists())
    def test_unmanaged_nonempty_root_is_not_deleted_or_adopted(self):
        self.root.mkdir(mode=0o700); (self.root / 'unknown').write_text('synthetic')
        with self.assertRaises(InstallError):
            self.engine.plan('prepare', self.options)
        self.assertTrue((self.root / 'unknown').exists())
    def test_empty_private_root_can_be_exclusively_prepared(self):
        self.root.mkdir(mode=0o700)
        self.assertTrue(self.prepare()['materialsPrepared'])
    def test_private_import_rejects_public_permissions_symlink_and_hardlink(self):
        self.source.chmod(0o644)
        with self.assertRaises(InstallError):
            self.engine.plan('prepare', self.options)
        self.source.chmod(0o600)
        link = self.base / 'input-link'; link.symlink_to(self.source)
        with self.assertRaises(InstallError):
            self.engine.plan('prepare', {**self.options, 'importFile': str(link)})
        link.unlink(); os.link(self.source, link)
        with self.assertRaises(InstallError):
            self.engine.plan('prepare', self.options)
    def test_private_reader_rechecks_single_link_on_opened_descriptor(self):
        alias = self.base / 'raced-link'; original_open = bootstrap.os.open
        def link_before_open(path, flags, *args, **kwargs):
            if Path(path) == self.source and not alias.exists():
                os.link(self.source, alias)
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(bootstrap.os, 'open', side_effect=link_before_open), self.assertRaises(InstallError):
            bootstrap.private_bytes(self.source)
        self.assertEqual(self.source.stat().st_nlink, 2)
    def test_private_reader_rejects_fifo_without_blocking(self):
        fifo = self.base / 'synthetic-fifo'; os.mkfifo(fifo, 0o600)
        with self.assertRaises(InstallError):
            bootstrap.private_bytes(fifo)
    def test_private_reader_open_errors_are_generic_and_do_not_write(self):
        before = sorted(p.name for p in self.base.iterdir())
        with mock.patch.object(bootstrap.os, 'open', side_effect=OSError('synthetic private diagnostic')), \
             self.assertRaises(InstallError) as caught:
            bootstrap.private_bytes(self.source)
        self.assertEqual(str(caught.exception), 'private material could not be opened safely')
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), before)
    def test_engine_import_read_os_errors_are_generic(self):
        original_fstat = bootstrap.os.fstat
        for failure_stage in ('fstat', 'read', 'post-fstat'):
            with self.subTest(stage=failure_stage):
                count = [0]
                def fstat(fd):
                    count[0] += 1
                    if (failure_stage == 'fstat' and count[0] == 1) or (failure_stage == 'post-fstat' and count[0] == 2):
                        raise OSError('synthetic private diagnostic')
                    return original_fstat(fd)
                original_fdopen = bootstrap.os.fdopen
                def fdopen(fd, *args, **kwargs):
                    stream = original_fdopen(fd, *args, **kwargs)
                    if failure_stage == 'read':
                        stream.read = mock.Mock(side_effect=OSError('synthetic private diagnostic'))
                    return stream
                with mock.patch.object(bootstrap.os, 'fstat', side_effect=fstat), \
                     mock.patch.object(bootstrap.os, 'fdopen', side_effect=fdopen), \
                     self.assertRaises(InstallError) as caught:
                    self.engine.plan('prepare', self.options)
                self.assertEqual(str(caught.exception), 'private material could not be read safely')
                self.assertFalse(self.root.exists())
    def test_unknown_root_scan_stops_at_first_unknown_entry(self):
        self.root.mkdir(mode=0o700); consumed = []
        def entries():
            consumed.append(True)
            yield type('Entry', (), {'name': 'unknown'})()
            raise AssertionError('must not scan an unbounded unknown directory')
        with mock.patch.object(bootstrap.os, 'scandir', return_value=contextlib.nullcontext(entries())), \
             self.assertRaises(InstallError):
            bootstrap.root_observation(self.root)
        self.assertEqual(consumed, [True])
    def test_unknown_inline_node_credentials_are_never_persisted(self):
        for value in ({**self.value, 'unknown': True},
                      {**self.value, 'vault': {'masterKeyHex': '12' * 32, 'credentials': [{'value': 'synthetic'}]}}):
            self.source.write_bytes(canonical(value))
            with self.assertRaises(InstallError):
                self.engine.plan('prepare', self.options)
        self.assertFalse(self.root.exists())
    def test_backup_requires_explicit_plaintext_risk_and_private_external_parent(self):
        self.prepare()
        backup_parent = self.base / 'offline-backup'; backup_parent.mkdir(mode=0o700)
        options = {'backupFile': str(backup_parent / 'key.json'), 'acknowledgePlaintext': False}
        with self.assertRaises(InstallError):
            self.engine.plan('backup-key', options)
        options['acknowledgePlaintext'] = True
        backup_parent.chmod(0o755)
        with self.assertRaises(InstallError):
            self.engine.plan('backup-key', options)
        with self.assertRaises(InstallError):
            self.engine.plan('backup-key', {**options, 'backupFile': str(self.root / 'vault/key.json')})
    def test_backup_is_exact_new_private_file_not_snapshot_or_restore_authority(self):
        self.prepare()
        directory = self.base / 'backup'; directory.mkdir(mode=0o700)
        options = {'backupFile': str(directory / 'key.json'), 'acknowledgePlaintext': True}
        plan = self.engine.plan('backup-key', options); self.assert_safe(plan)
        result = self.engine.apply(plan, plan['planHash'], options)
        self.assertFalse(result['encrypted']); self.assertFalse(result['restoreEligible'])
        self.assertFalse(result['databaseOrVaultSnapshot']); self.assert_safe(result)
        target = Path(options['backupFile'])
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertTrue(target.read_bytes() == self.raw, 'exact private key backup')
        with self.assertRaises(InstallError):
            self.engine.plan('backup-key', options)
    def test_missing_bootstrap_never_authorizes_old_material_restore(self):
        self.prepare(); (self.root / bootstrap.MATERIAL).unlink()
        plan = self.engine.plan('restore-key', {})
        self.assertFalse(plan['writesSecrets']); self.assertFalse(plan['blocking']['recoveryEligible'])
        self.assertEqual(plan['blocking']['status'], 'RecoveryNeedsVerification')
        with self.assertRaises(InstallError):
            self.engine.apply(plan, plan['planHash'], {})
        self.assertFalse((self.root / bootstrap.MATERIAL).exists())
    def test_backup_reads_locked_root_descriptor_and_refuses_renamed_root(self):
        self.prepare()
        directory = self.base / 'backup'; directory.mkdir(mode=0o700)
        options = {'backupFile': str(directory / 'key.json'), 'acknowledgePlaintext': True}
        plan = self.engine.plan('backup-key', options)
        original = bootstrap.verified_material; moved = self.base / 'original-root'; checked = []
        def replace_after_lock(root, directory_fd=None, snapshots=None):
            self.assertIsNotNone(directory_fd, 'backup must retain and read its locked root descriptor')
            self.root.rename(moved); self.root.mkdir(mode=0o700)
            result = original(root, directory_fd, snapshots)
            self.assertTrue(result[1] == self.raw, 'read the locked original, not replacement pathname')
            checked.append(True); return result
        with mock.patch.object(bootstrap, 'verified_material', side_effect=replace_after_lock), self.assertRaises(InstallError):
            self.engine._backup(plan)
        self.assertEqual(checked, [True]); self.assertEqual(list(directory.iterdir()), [])
        self.assertEqual(list(self.root.iterdir()), []); self.assertTrue((moved / bootstrap.MATERIAL).is_file())
    def test_changed_existing_key_is_not_adopted_or_overwritten(self):
        self.prepare()
        changed = canonical({**self.value, 'token': 'X' * 43}) + b'\n'
        (self.root / bootstrap.MATERIAL).write_bytes(changed)
        with self.assertRaises(InstallError):
            bootstrap.status(self.root)
        self.assertTrue((self.root / bootstrap.MATERIAL).read_bytes() == changed, 'no silent restore')
    def test_admin_token_display_requires_fresh_real_tty_and_never_master(self):
        self.prepare(); plan = self.engine.plan('show-admin-token', {})
        with mock.patch.object(sys.stdin, 'isatty', return_value=False), self.assertRaises(InstallError):
            self.engine.show_admin_token(plan, plan['planHash'])
        terminal = Terminal()
        with mock.patch.object(sys.stdin, 'isatty', return_value=True), contextlib.redirect_stdout(terminal):
            self.engine.show_admin_token(plan, plan['planHash'])
        output = terminal.getvalue()
        self.assertTrue(output == self.value['token'] + '\n', 'explicit admin-only terminal display')
        self.assertTrue(self.value['vault']['masterKeyHex'] not in output, 'master never displayed')
    def test_normal_cli_plan_and_status_do_not_leak_material_or_digest(self):
        out = io.StringIO(); err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = bootstrap.main(['prepare', '--root', str(self.root), '--username', 'synthetic_admin',
                                   '--namespace', 'synthetic_vault', '--request-key', 'prepare_one',
                                   '--import-bootstrap-file', str(self.source), '--dry-run'])
        self.assertEqual(code, 0); self.assertFalse(self.root.exists())
        self.assert_safe({'out': out.getvalue(), 'err': err.getvalue()})
    def test_token_display_rejects_material_pair_changed_after_fresh_plan(self):
        self.prepare(); plan = self.engine.plan('show-admin-token', {})
        original_plan = self.engine.plan
        def replace_after_fresh_plan(action, options):
            fresh = original_plan(action, options)
            replacement = canonical({**self.value, 'token': 'Z' * 43}) + b'\n'
            metadata = json.loads((self.root / bootstrap.MANIFEST).read_bytes())
            metadata['materialSha256'] = digest(replacement)
            (self.root / bootstrap.MATERIAL).write_bytes(replacement)
            (self.root / bootstrap.MANIFEST).write_bytes(canonical(metadata))
            return fresh
        terminal = Terminal()
        with mock.patch.object(self.engine, 'plan', side_effect=replace_after_fresh_plan), \
             mock.patch.object(sys.stdin, 'isatty', return_value=True), \
             contextlib.redirect_stdout(terminal), self.assertRaises(InstallError):
            self.engine.show_admin_token(plan, plan['planHash'])
        self.assertEqual(terminal.getvalue(), '')
    def test_exception_diagnostics_never_print_external_secret_repr(self):
        for exception_type in (OSError, RuntimeError, RecursionError):
            with self.subTest(exception_type=exception_type.__name__):
                out = io.StringIO(); err = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                     mock.patch.object(bootstrap.Bootstrap, 'plan', side_effect=exception_type(self.value['token'])):
                    code = bootstrap.main(['prepare', '--root', str(self.root)])
                self.assertEqual(code, 2); self.assert_safe({'out': out.getvalue(), 'err': err.getvalue()})
                self.assertNotIn('Traceback', err.getvalue())
    def test_deeply_nested_json_is_rejected_without_traceback(self):
        self.source.write_bytes(b'[' * 1100 + b'0' + b']' * 1100)
        out = io.StringIO(); err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = bootstrap.main(['prepare', '--root', str(self.root), '--username', 'synthetic_admin',
                '--namespace', 'synthetic_vault', '--request-key', 'prepare_one',
                '--import-bootstrap-file', str(self.source), '--dry-run'])
        self.assertEqual(code, 2); self.assertNotIn('Traceback', err.getvalue()); self.assertFalse(self.root.exists())
    def test_unknown_cli_secret_argument_is_never_echoed(self):
        out = io.StringIO(); err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = bootstrap.main(['prepare', '--root', str(self.root), '--unsupported-secret', self.value['token']])
        self.assertEqual(code, 2); self.assert_safe({'out': out.getvalue(), 'err': err.getvalue()})
        self.assertFalse(self.root.exists())
    def test_launch_plan_only_uses_real_flags_no_offline_or_public_readiness_claim(self):
        self.prepare()
        daemon = self.base / 'synthetic-never-executed-daemon'; daemon.write_bytes(b'synthetic daemon fixture')
        worker = self.base / 'synthetic-never-executed-worker'; worker.write_bytes(b'synthetic worker fixture')
        options = bootstrap.parser().parse_args(['launch-plan', '--root', str(self.root),
            '--daemon', str(daemon), '--daemon-sha256', digest(daemon.read_bytes()),
            '--worker', str(worker), '--worker-sha256', digest(worker.read_bytes()),
            '--bind', '127.0.0.1:18080', '--origin', 'https://admin.example.invalid', '--vault-action', 'initialize',
            '--subscription-public-base', 'https://subscription.example.invalid', '--subscription-network-profile', 'https'])
        value = bootstrap.launch_plan(self.engine, options)
        self.assertEqual(value['status'], 'launch_arguments_only_not_executed')
        self.assertFalse(value['serviceReady']); self.assertFalse(value['artifactCompatibility']['bundleV2Accepted'])
        self.assertEqual(value['externalHttps'], 'not_configured_or_verified'); self.assert_safe(value)
        flags = value['commandArgv'][1::2]
        self.assertTrue(all(flag in ('--state-root', '--bind', '--origin', '--runtime-profile', '--runtime-root',
            '--worker', '--worker-sha256', '--vault-root', '--vault-namespace', '--vault-action', '--probe-bind',
            '--subscription-public-base', '--subscription-network-profile') for flag in flags))
    def test_recovery_port_is_always_unavailable_without_authority(self):
        value = bootstrap.recovery_status()
        self.assertIsNone(value['authorityBinding']); self.assertIsNone(value['controlAuthorityId'])
        self.assertEqual(value['revocationWatermarks'], 'unsupported'); self.assertFalse(value['recoveryEligible'])

if __name__ == '__main__':
    unittest.main()
