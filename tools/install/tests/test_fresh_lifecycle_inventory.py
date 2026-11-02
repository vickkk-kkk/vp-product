"""Tiny synthetic fixtures only; no fixture ELF, network or repair execution."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_fresh_local
import vp_bootstrap as b
import vp_fresh_local as l
import vp_fresh_lifecycle_inventory as inv
import vp_install as v


class InventoryTests(unittest.TestCase):
    setUp = test_fresh_local.FreshLocalTests.setUp
    tearDown = test_fresh_local.FreshLocalTests.tearDown
    install = test_fresh_local.FreshLocalTests.install
    prepare = test_fresh_local.FreshLocalTests.prepare

    def setup_disabled(self):
        self.install(); self.prepare()
        plan = self.engine.plan('uninstall')
        self.engine.uninstall(plan, plan['planHash'])

    def assess(self, action='review-same-artifact-repair'):
        return inv.LifecycleInventory(self.engine, self.bundle).plan(action)

    def snapshot(self):
        return {str(p.relative_to(self.base)): (p.read_bytes(), p.stat().st_ino,
                    p.stat().st_mode, p.stat().st_mtime_ns, p.stat().st_ctime_ns)
                for p in self.base.rglob('*') if p.is_file()}

    def test_exact_disabled_is_nonexecuting_and_no_mutation(self):
        self.setup_disabled(); before = self.snapshot()
        with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('process')), \
             mock.patch.object(socket, 'socket', side_effect=AssertionError('network')), \
             mock.patch.object(os, 'system', side_effect=AssertionError('shell')), \
             mock.patch.object(os, 'unlink', side_effect=AssertionError('delete')), \
             mock.patch.object(os, 'mkdir', side_effect=AssertionError('create')):
            result = self.assess()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(result['programClassification'], 'exact_program_files')
        self.assertEqual(result['privateState'], 'structurally_intact_authority_unverified')
        self.assertFalse(result['executable']); self.assertFalse(result['writesFiles'])
        self.assertFalse(result['repairSupported']); self.assertFalse(result['reactivationSupported'])
        self.assertIn('control_vault_runtime_authority_not_verified', result['blockers'])
        self.assertEqual(self.assess(), result)
        # Existing execution refusal remains unchanged.
        with self.assertRaises(v.InstallError): self.engine.plan_bootstrap('prepare', {})
        with self.assertRaises(v.InstallError): self.engine.plan('serve-paired', bind='127.0.0.1:18081', origin='http://127.0.0.1:18081')

    def test_missing_expected_program_is_distinct_from_unknown(self):
        self.setup_disabled(); (self.root/'release/web/index.html').unlink()
        result = self.assess('review-reactivation')
        self.assertEqual(result['missingProgramFiles'], ['web/index.html'])
        self.assertEqual(result['programClassification'], 'missing_program_files')
        self.assertEqual(result['unknownTargets'], [])
        self.assertIn('program_repair_required', result['blockers'])

    def test_missing_directory_classifies_expected_descendants(self):
        self.setup_disabled(); p=self.root/'release/web'; (p/'index.html').unlink(); p.rmdir()
        result=self.assess()
        self.assertEqual(result['missingDirectories'], ['web'])
        self.assertEqual(result['missingProgramFiles'], ['web/index.html'])

    def test_unknown_file_and_empty_directory_not_traversed(self):
        self.setup_disabled(); (self.root/'release/extra').mkdir()
        (self.root/'release/extra/sensitive').write_text('not inspected')
        (self.root/'release/unknown').write_text('not inspected')
        result=self.assess()
        self.assertEqual(result['unknownTargets'], ['extra', 'unknown'])
        self.assertEqual(result['programClassification'], 'refused_targets')
        self.assertNotIn('sensitive', v.canonical(result).decode())

    def test_changed_known_file_refused(self):
        self.setup_disabled(); (self.root/'release/web/index.html').write_bytes(b'changed')
        result=self.assess()
        self.assertEqual(result['changedOrUnsafeFiles'], ['web/index.html'])
        self.assertEqual(result['programClassification'], 'refused_targets')

    def test_hardlink_refused(self):
        self.setup_disabled(); os.link(self.root/'release/web/index.html',self.base/'alias')
        self.assertEqual(self.assess()['changedOrUnsafeFiles'], ['web/index.html'])

    def test_symlink_file_refused_without_following(self):
        self.setup_disabled(); p=self.root/'release/web/index.html'; p.unlink(); p.symlink_to(self.materials/b.MATERIAL)
        self.assertEqual(self.assess()['changedOrUnsafeFiles'], ['web/index.html'])

    def test_symlink_directory_is_not_missing_or_followed(self):
        self.setup_disabled(); p=self.root/'release/web'; (p/'index.html').unlink(); p.rmdir(); p.symlink_to(self.materials)
        result=self.assess()
        self.assertEqual(result['unsafeDirectories'], ['web'])
        self.assertEqual(result['missingProgramFiles'], [])
        self.assertEqual(result['changedOrUnsafeFiles'], ['web/index.html'])

    def test_writable_program_refused(self):
        self.setup_disabled(); (self.root/'release/web/index.html').chmod(0o666)
        self.assertEqual(self.assess()['changedOrUnsafeFiles'], ['web/index.html'])

    def test_manifest_is_not_repairable(self):
        self.setup_disabled(); (self.root/'release/manifest.json').unlink()
        with self.assertRaises((OSError,v.InstallError)): self.assess()

    def test_wrong_archive_refused(self):
        self.setup_disabled(); self.bundle.sha256='0'*64
        with self.assertRaises(v.InstallError): self.assess()

    def test_unknown_installation_metadata_refused(self):
        self.setup_disabled(); (self.root/'surprise').write_text('x')
        with self.assertRaises(v.InstallError): self.assess()

    def test_missing_materials_distinct(self):
        self.install()
        self.assertEqual(self.assess()['privateState'], 'missing')

    def test_private_material_change_is_damage_not_recovery(self):
        self.setup_disabled(); p=self.materials/b.MATERIAL; p.write_bytes(p.read_bytes()+b' ')
        result=self.assess()
        self.assertEqual(result['privateState'], 'damaged_or_unrecognized')
        self.assertIn('private_materials_unavailable_or_damaged',result['blockers'])

    def test_missing_private_directory_is_damage(self):
        self.setup_disabled(); (self.materials/'runtime').rmdir()
        self.assertEqual(self.assess()['privateState'], 'damaged_or_unrecognized')

    def test_secret_material_not_exposed(self):
        self.setup_disabled(); result=v.canonical(self.assess()).decode()
        raw=(self.materials/b.MATERIAL).read_bytes()
        for forbidden in ('t'*64,'a'*64,v.digest(raw),'fingerprints','token','masterKeyHex'):
            self.assertNotIn(forbidden,result)

    def test_removal_intent_always_requires_review_even_with_receipt(self):
        self.setup_disabled()
        with b.owned_directory(self.root) as fd:
            b.new_file(fd,l.REMOVAL_INTENT,b'{"synthetic":true}')
            b.new_file(fd,l.REMOVAL_RECEIPT,b'{"synthetic":true}')
        result=self.assess()
        self.assertIn('removal_attempt_requires_separate_recovery_review', result['priorTransitions'])
        self.assertEqual(result['priorDurability'],'not_inferred')

    def test_receipt_without_intent_inconsistent(self):
        self.setup_disabled()
        with b.owned_directory(self.root) as fd: b.new_file(fd,l.REMOVAL_RECEIPT,b'{}')
        self.assertIn('removal_provenance_inconsistent',self.assess()['priorTransitions'])

    def test_activation_intent_without_ready_unresolved(self):
        self.setup_disabled()
        with b.owned_directory(self.root) as fd: b.new_file(fd,l.ACTIVATION,b'{}')
        self.assertIn('activation_unresolved', self.assess()['priorTransitions'])

    def test_ready_without_activation_inconsistent(self):
        self.setup_disabled()
        with b.owned_directory(self.root) as fd: b.new_file(fd,l.READY,b'{}')
        self.assertIn('activation_provenance_inconsistent', self.assess()['priorTransitions'])

    def test_private_pending_file_blocks(self):
        self.setup_disabled()
        with b.owned_directory(self.materials) as fd: b.new_file(fd,b.OFFLINE_PENDING,b'{}')
        self.assertIn('private_pending_file',self.assess()['priorTransitions'])

    def test_live_private_lease_refuses(self):
        self.setup_disabled()
        with b.owned_directory(self.materials/'control'):
            with self.assertRaises(BlockingIOError): self.assess()

    def test_live_installation_lease_refuses(self):
        self.setup_disabled()
        with b.owned_directory(self.root):
            with self.assertRaises(BlockingIOError): self.assess()

    def test_arbitrary_execution_action_refused(self):
        self.setup_disabled()
        for action in ('repair','reactivate','install','upgrade'):
            with self.assertRaises(v.InstallError): self.assess(action)
        self.assertFalse(hasattr(inv.LifecycleInventory,'apply'))

    def test_changed_survivor_during_scan_invalidates_entire_observation(self):
        self.setup_disabled(); original=inv.file_observation; calls=0
        def changing(fd,name,item):
            nonlocal calls
            value=original(fd,name,item); calls+=1
            if calls == len(self.fixture.blobs)+2:
                (self.root/'release/web/index.html').write_bytes(b'changed')
            return value
        with mock.patch.object(inv,'file_observation',side_effect=changing):
            with self.assertRaises(v.InstallError): self.assess()

    def test_changed_observation_hash_for_missing_file(self):
        self.setup_disabled(); before=self.assess()['observationHash']
        (self.root/'release/web/index.html').unlink()
        self.assertNotEqual(self.assess()['observationHash'],before)

    def test_removed_executable_bit_not_exact_survivor(self):
        self.setup_disabled(); name=next(n for n in self.fixture.blobs if n.startswith('bin/'))
        (self.root/'release'/name).chmod(0o644)
        self.assertIn(name,self.assess()['changedOrUnsafeFiles'])

    def test_manifest_mode_changed_refuses_provenance(self):
        self.setup_disabled(); (self.root/'release/manifest.json').chmod(0o600)
        with self.assertRaises(v.InstallError): self.assess()

    def test_public_fields_exclude_internal_file_fingerprints(self):
        self.setup_disabled(); value=self.assess()
        self.assertNotIn('inventory',value); self.assertNotIn('private_guard',value)
        self.assertEqual(len(value['observationHash']),64)

    def test_receipt_is_not_authenticated_state(self):
        self.setup_disabled()
        # The shared fixture deliberately has a fake offline-init receipt and
        # empty private data directories: it cannot yield authority or readiness.
        result=self.assess('review-reactivation')
        self.assertEqual(result['privateState'],'structurally_intact_authority_unverified')
        self.assertIn('control_vault_runtime_authority_not_verified',result['blockers'])
        self.assertFalse(result['executable'])

    def test_legacy_disabled_marker_preserved_and_recognized(self):
        self.install(); self.prepare()
        with b.owned_directory(self.root) as fd: b.new_file(fd,l.LEGACY_UNINSTALLED,b'{}')
        before=self.snapshot()
        self.assertTrue(self.assess()['profileDisabledObserved'])
        self.assertEqual(self.snapshot(),before)

    def test_corrupt_material_does_not_skip_live_vault_lease(self):
        self.setup_disabled(); p=self.materials/b.MATERIAL; p.write_bytes(p.read_bytes()+b' ')
        with b.owned_directory(self.materials/'vault'):
            with self.assertRaises(BlockingIOError): self.assess()

    def test_missing_early_private_child_does_not_skip_later_lease(self):
        self.setup_disabled(); (self.materials/'control').rmdir()
        with b.owned_directory(self.materials/'vault'):
            with self.assertRaises(BlockingIOError): self.assess()

    def test_unsafe_early_child_does_not_skip_later_lease(self):
        self.setup_disabled(); (self.materials/'control').rmdir()
        (self.materials/'control').symlink_to(self.base)
        with b.owned_directory(self.materials/'runtime'):
            with self.assertRaises(BlockingIOError): self.assess()

    def test_corrupt_manifest_does_not_skip_live_runtime_lease(self):
        self.setup_disabled(); (self.materials/b.MANIFEST).write_bytes(b'{}')
        with b.owned_directory(self.materials/'runtime'):
            with self.assertRaises(BlockingIOError): self.assess()

    def test_unknown_private_metadata_does_not_skip_live_vault_lease(self):
        self.setup_disabled(); (self.materials/'unknown').write_bytes(b'x')
        with b.owned_directory(self.materials/'vault'):
            with self.assertRaises(BlockingIOError): self.assess()

    def test_no_unbounded_listdir_in_any_assessment_pass(self):
        self.setup_disabled()
        with mock.patch.object(os,'listdir',side_effect=AssertionError('unbounded listing')):
            self.assertEqual(self.assess()['programClassification'],'exact_program_files')

    def test_initial_installation_enumeration_is_bounded(self):
        self.setup_disabled()
        self.check_bounded_scan(self.root, 1, len(l.NAMES))

    def test_final_installation_enumeration_is_bounded(self):
        self.setup_disabled()
        self.check_bounded_scan(self.root, 2, len(l.NAMES))

    def test_final_release_enumeration_is_bounded(self):
        self.setup_disabled()
        self.check_bounded_scan(self.root/'release', 2, 8192)

    def check_bounded_scan(self, target, ordinal, bound):
        import contextlib
        from types import SimpleNamespace
        original=os.scandir; inode=target.stat().st_ino; seen=0; yielded=0
        @contextlib.contextmanager
        def scan(fd):
            nonlocal seen,yielded
            match=isinstance(fd,int) and os.fstat(fd).st_ino==inode
            if match: seen+=1
            if match and seen==ordinal:
                def unlimited():
                    nonlocal yielded
                    while True:
                        yielded+=1
                        if yielded>bound+1: raise AssertionError('scan did not stop at bound')
                        yield SimpleNamespace(name='synthetic-entry-'+str(yielded))
                yield unlimited()
            else:
                with original(fd) as entries: yield entries
        with mock.patch.object(os,'scandir',side_effect=scan):
            with self.assertRaisesRegex(v.InstallError,'directory inventory bound exceeded'):
                self.assess()
        self.assertEqual(yielded,bound+1)
