"""All removals target newly created tiny synthetic files, never real artifacts."""
import os
import contextlib
import io
import json
import platform
import multiprocessing
from pathlib import Path
import subprocess
import socket
import sys
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_fresh_local
import vp_bootstrap as b
import vp_fresh_bundle as f
import vp_fresh_local as l
import vp_fresh_removal as r
import vp_install as v
import vp_fresh_cli as cli


def hold_data_lock(path, connection):
    with b.owned_directory(path):
        connection.send('locked')
        connection.recv()
    connection.close()


class RemovalTests(unittest.TestCase):
    setUp = test_fresh_local.FreshLocalTests.setUp
    tearDown = test_fresh_local.FreshLocalTests.tearDown
    install = test_fresh_local.FreshLocalTests.install
    prepare = test_fresh_local.FreshLocalTests.prepare

    def disabled(self, materials=True):
        self.install()
        if materials: self.prepare()
        plan = self.engine.plan('uninstall'); self.engine.uninstall(plan, plan['planHash'])
        self.removal = r.ProgramRemoval(self.engine, self.bundle)
        return self.removal.plan()

    def apply(self, plan, **kw): return self.removal.apply(plan, plan['planHash'], **kw)
    def untouched(self): self.assertFalse((self.root/l.REMOVAL_INTENT).exists())

    def test_exact_removal_preserves_all_nonprogram_bytes_and_inodes(self):
        self.disabled()
        for name in b.DIRECTORIES:
            nested=self.materials/name/'nested-synthetic-data'; nested.mkdir(mode=0o700)
            sentinel=nested/'retained.bin'; sentinel.write_bytes(('synthetic retained '+name).encode())
            sentinel.chmod(0o600)
        plan = self.removal.plan()
        program = {self.root/'release'/name for name in self.fixture.blobs}
        retained = {p:(p.read_bytes(), p.stat().st_ino) for p in self.base.rglob('*')
                    if p.is_file() and p not in program}
        result = self.apply(plan)
        self.assertEqual(result['deletedFiles'], len(program))
        self.assertTrue(result['durabilityBarriersReturned'])
        self.assertEqual(list((self.root/'release').iterdir()), [self.root/'release/manifest.json'])
        for p, expected in retained.items(): self.assertEqual((p.read_bytes(),p.stat().st_ino), expected)
        self.assertEqual(r.removal_status(self.engine)['state'], 'program_files_absent_observed')
        with self.assertRaises(v.InstallError): self.removal.plan()
        with self.assertRaises(v.InstallError): self.engine.plan_bootstrap('prepare', {})

    def test_no_materials_and_no_runtime_host_process_or_network_dependency(self):
        self.disabled(False)
        with mock.patch.object(f, 'host_arch', side_effect=AssertionError('host dependency')), \
             mock.patch.object(l, 'check_sealed_runtime_host', side_effect=AssertionError('host probe')), \
             mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('process')), \
             mock.patch.object(socket, 'socket', side_effect=AssertionError('network')), \
             mock.patch.object(os, 'system', side_effect=AssertionError('shell')):
            with r.RemovalBundle(self.bundle.path, self.bundle.sha256) as bundle:
                removal = r.ProgramRemoval(self.engine, bundle)
                plan = removal.plan(); removal.apply(plan, plan['planHash'])
        self.assertFalse(self.materials.exists())

    def test_must_be_disabled(self):
        self.install()
        with self.assertRaises(v.InstallError): r.ProgramRemoval(self.engine,self.bundle).plan()
        self.untouched()

    def test_legacy_marker_supported(self):
        self.install()
        with b.owned_directory(self.root) as fd: b.new_file(fd,l.LEGACY_UNINSTALLED,b'{"historical":true}')
        self.removal=r.ProgramRemoval(self.engine,self.bundle)
        self.apply(self.removal.plan())
        self.assertTrue((self.root/l.LEGACY_UNINSTALLED).exists())

    def test_wrong_confirmation(self):
        plan=self.disabled()
        with self.assertRaises(v.InstallError): self.removal.apply(plan,'0'*64)
        self.untouched()

    def test_archive_mismatch(self):
        self.disabled()
        self.fixture.m['releaseId']='different-archive'
        with f.FreshBundle(*self.fixture.archive()) as other:
            with self.assertRaises(v.InstallError): r.ProgramRemoval(self.engine,other).plan()
        self.untouched()

    def test_manifest_mismatch(self):
        plan=self.disabled(); p=self.root/'release/manifest.json'; p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(v.InstallError): self.apply(plan)
        self.untouched()

    def test_changed_member(self):
        plan=self.disabled(); (self.root/'release'/f.DAEMON).write_bytes(b'changed')
        with self.assertRaises(v.InstallError): self.apply(plan)
        self.untouched()

    def test_missing_member(self):
        plan=self.disabled(); (self.root/'release/web/index.html').unlink()
        with self.assertRaises(v.InstallError): self.apply(plan)
        self.untouched()

    def test_unknown_file(self):
        plan=self.disabled(); (self.root/'release/unknown').write_bytes(b'x')
        with self.assertRaises(v.InstallError): self.apply(plan)
        self.untouched()

    def test_unknown_empty_directory(self):
        plan=self.disabled(); (self.root/'release/empty').mkdir()
        with self.assertRaises(v.InstallError): self.apply(plan)
        self.untouched()

    def test_hardlink_executable(self):
        plan=self.disabled(); os.link(self.root/'release'/f.DAEMON, self.base/'alias')
        with self.assertRaises(v.InstallError): self.apply(plan)
        self.untouched()

    def test_symlink_member(self):
        plan=self.disabled(); p=self.root/'release/web/index.html'; p.rename(self.base/'held'); p.symlink_to(self.base/'held')
        with self.assertRaises((v.InstallError,OSError)): self.apply(plan)
        self.untouched()

    def test_active_installation_material_or_each_data_lock(self):
        plan=self.disabled()
        for path in [self.root,self.materials,*[self.materials/name for name in b.DIRECTORIES]]:
            with self.subTest(path=path), b.owned_directory(path):
                with self.assertRaises(OSError): self.apply(plan)
            self.untouched()

    def test_replaced_release_directory(self):
        plan=self.disabled(); release=self.root/'release'; release.rename(self.root/'held')
        # Only synthetic fixture files copied. Unknown retained root entry also
        # independently blocks adoption, not merely digest equality.
        release.mkdir(mode=0o755)
        with self.assertRaises(v.InstallError): self.apply(plan)
        self.untouched()

    def test_replaced_file_same_bytes(self):
        plan=self.disabled(); p=self.root/'release/web/index.html'; raw=p.read_bytes()
        p.rename(self.base/'old'); p.write_bytes(raw)
        with self.assertRaises(v.InstallError): self.apply(plan)
        self.untouched()

    def test_missing_data_root_refused(self):
        plan=self.disabled(); (self.materials/'runtime').rmdir()
        with self.assertRaises(OSError): self.apply(plan)
        self.untouched()

    def test_canceled_before_intent(self):
        plan=self.disabled()
        with self.assertRaises(v.InstallError): self.apply(plan,cancelled=lambda:True)
        self.untouched()

    def test_canceled_after_intent_no_resume(self):
        plan=self.disabled(); calls=iter([False,True])
        with self.assertRaises(v.InstallError): self.apply(plan,cancelled=lambda:next(calls))
        self.assertTrue((self.root/l.REMOVAL_INTENT).exists())
        self.assertFalse((self.root/l.REMOVAL_RECEIPT).exists())
        with self.assertRaises(v.InstallError): self.removal.plan()
        self.assertEqual(r.removal_status(self.engine)['state'],'incomplete_or_uncertain')

    def test_intent_fsync_failure_deletes_nothing(self):
        plan=self.disabled()
        with mock.patch.object(os,'fsync',side_effect=OSError('synthetic fsync failure')):
            with self.assertRaises(OSError): self.apply(plan)
        self.assertTrue(all((self.root/'release'/name).exists() for name in self.fixture.blobs))
        self.assertFalse((self.root/l.REMOVAL_RECEIPT).exists())

    def test_unlink_directory_fsync_failure_is_partial(self):
        plan=self.disabled(); original=os.fsync; count=0
        def fail(fd):
            nonlocal count
            count+=1
            if count==3: raise OSError('synthetic unlink barrier')
            return original(fd)
        with mock.patch.object(os,'fsync',side_effect=fail):
            with self.assertRaises(OSError): self.apply(plan)
        remaining=sum((self.root/'release'/name).exists() for name in self.fixture.blobs)
        self.assertEqual(remaining,len(self.fixture.blobs)-1)
        self.assertEqual(r.removal_status(self.engine)['state'],'incomplete_or_uncertain')
        self.assertFalse((self.root/l.REMOVAL_RECEIPT).exists())

    def test_path_swap_after_intent_no_unlink(self):
        plan=self.disabled(); original=b.new_file
        def swap(fd,name,data):
            original(fd,name,data)
            if name==l.REMOVAL_INTENT:
                (self.root/'release').rename(self.base/'held-release')
                (self.root/'release').mkdir(mode=0o755)
        with mock.patch.object(b,'new_file',side_effect=swap):
            with self.assertRaises(v.InstallError): self.apply(plan)
        self.assertTrue(all((self.base/'held-release'/name).exists() for name in self.fixture.blobs))
        self.assertFalse((self.root/l.REMOVAL_RECEIPT).exists())

    def test_receipt_fsync_failure_not_inferred_as_durable_success(self):
        plan=self.disabled(); original=b.new_file
        def fail(fd,name,data):
            if name==l.REMOVAL_RECEIPT:
                with mock.patch.object(os,'fsync',side_effect=OSError('synthetic final barrier')):
                    return original(fd,name,data)
            return original(fd,name,data)
        with mock.patch.object(b,'new_file',side_effect=fail):
            with self.assertRaises(OSError): self.apply(plan)
        status=r.removal_status(self.engine)
        self.assertEqual(status['state'],'program_files_absent_observed')
        self.assertEqual(status['priorDurability'],'not_inferred')
        self.assertTrue(status['completionReceiptPresent'])
        with self.assertRaises(v.InstallError): self.removal.plan()

    def test_removal_bundle_cannot_install(self):
        with r.RemovalBundle(self.bundle.path,self.bundle.sha256) as bundle:
            with self.assertRaises(v.InstallError): self.engine.plan('install',bundle=bundle)


    def test_cli_plan_confirmation_and_live_status(self):
        self.disabled(False)
        args=['remove-program-files','--root',str(self.root),'--materials',str(self.materials),
              '--bundle',str(self.bundle.path),'--bundle-sha256',self.bundle.sha256]
        output=io.StringIO()
        with contextlib.redirect_stdout(output): self.assertEqual(cli.main(args),0)
        plan=json.loads(output.getvalue()); self.untouched()
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(args+['--confirm-plan',plan['planHash']]),0)
        self.assertEqual(json.loads(output.getvalue())['status'],'program_files_removed_data_retained')
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(['status','--root',str(self.root),'--materials',str(self.materials)]),0)
        self.assertEqual(json.loads(output.getvalue())['programRemoval']['priorDurability'],'not_inferred')

    def test_read_only_foreign_host_and_no_process_network_audit(self):
        self.disabled(False)
        observed=[]; active=[True]
        def audit(event,args):
            if active[0] and (event.startswith('subprocess.') or event.startswith('socket.') or
                             event in ('os.exec','os.posix_spawn','os.system','os.fork','os.forkpty')):
                observed.append(event)
        sys.addaudithook(audit)
        try:
            with mock.patch.object(platform,'machine',return_value='unsupported-test-architecture'):
                with r.RemovalBundle(self.bundle.path,self.bundle.sha256) as bundle:
                    removal=r.ProgramRemoval(self.engine,bundle)
                    plan=removal.plan(); removal.apply(plan,plan['planHash'])
        finally: active[0]=False
        self.assertEqual(observed,[])

    def test_data_root_replacement_after_intent_preserves_programs(self):
        plan=self.disabled(); original=b.new_file
        def swap(fd,name,data):
            original(fd,name,data)
            if name==l.REMOVAL_INTENT:
                (self.materials/'runtime').rename(self.materials/'old-runtime')
                (self.materials/'runtime').mkdir(mode=0o700)
        with mock.patch.object(b,'new_file',side_effect=swap):
            with self.assertRaises(v.InstallError): self.apply(plan)
        self.assertTrue(all((self.root/'release'/name).exists() for name in self.fixture.blobs))

    def test_live_status_rejects_post_receipt_unknown_entry(self):
        self.apply(self.disabled())
        (self.root/'release/unexpected').write_bytes(b'new synthetic file')
        self.assertEqual(r.removal_status(self.engine)['state'],'incomplete_or_uncertain')

    def test_cancellation_after_one_unlink(self):
        plan=self.disabled(); calls=iter([False,False,True])
        with self.assertRaises(v.InstallError): self.apply(plan,cancelled=lambda:next(calls))
        self.assertEqual(sum((self.root/'release'/name).exists() for name in self.fixture.blobs),len(self.fixture.blobs)-1)
        self.assertFalse((self.root/l.REMOVAL_RECEIPT).exists())



    def test_intent_parent_fsync_failure_deletes_nothing(self):
        plan=self.disabled(); original=os.fsync; calls=0
        def fail(fd):
            nonlocal calls
            calls+=1
            if calls==2: raise OSError('synthetic intent directory barrier')
            return original(fd)
        with mock.patch.object(os,'fsync',side_effect=fail):
            with self.assertRaises(OSError): self.apply(plan)
        self.assertTrue(all((self.root/'release'/name).exists() for name in self.fixture.blobs))
        self.assertTrue((self.root/l.REMOVAL_INTENT).exists())
        with self.assertRaises(v.InstallError): self.removal.plan()

    def test_rmdir_parent_fsync_failure_never_claims_complete(self):
        plan=self.disabled(); original=os.fsync; rmdir=os.rmdir; removed=[False]
        def remove(*args,**kw):
            result=rmdir(*args,**kw); removed[0]=True; return result
        def fail(fd):
            if removed[0]: raise OSError('synthetic rmdir directory barrier')
            return original(fd)
        with mock.patch.object(os,'rmdir',side_effect=remove), mock.patch.object(os,'fsync',side_effect=fail):
            with self.assertRaises(OSError): self.apply(plan)
        self.assertTrue((self.root/l.REMOVAL_INTENT).exists())
        self.assertFalse((self.root/l.REMOVAL_RECEIPT).exists())
        self.assertEqual(r.removal_status(self.engine)['state'],'incomplete_or_uncertain')

    def test_receipt_parent_fsync_failure_is_not_durability_proof(self):
        plan=self.disabled(); original=b.new_file; fsync=os.fsync
        def fail(fd,name,data):
            if name!=l.REMOVAL_RECEIPT: return original(fd,name,data)
            calls=0
            def barrier(handle):
                nonlocal calls
                calls+=1
                if calls==2: raise OSError('synthetic receipt directory barrier')
                return fsync(handle)
            with mock.patch.object(os,'fsync',side_effect=barrier): return original(fd,name,data)
        with mock.patch.object(b,'new_file',side_effect=fail):
            with self.assertRaises(OSError): self.apply(plan)
        status=r.removal_status(self.engine)
        self.assertEqual(status['state'],'program_files_absent_observed')
        self.assertEqual(status['priorDurability'],'not_inferred')
        with self.assertRaises(v.InstallError): self.removal.plan()

    def test_independent_data_lease_without_supervisor_blocks_removal(self):
        plan=self.disabled(); ctx=multiprocessing.get_context('fork')
        for name in b.DIRECTORIES:
            parent,child=ctx.Pipe()
            process=ctx.Process(target=hold_data_lock,args=(self.materials/name,child))
            process.start(); child.close()
            try:
                self.assertTrue(parent.poll(5)); self.assertEqual(parent.recv(),'locked')
                # Installation/supervisor lease is demonstrably free, but the
                # independently owned actual data-root lease still blocks us.
                with b.owned_directory(self.root): pass
                with self.assertRaises(OSError): self.apply(plan)
                self.untouched()
            finally:
                parent.send('stop'); parent.close(); process.join(5)
                if process.is_alive(): process.terminate(); process.join(5)
            self.assertEqual(process.exitcode,0)

    def test_atime_change_is_not_identity_drift(self):
        self.disabled(False)
        for path in (self.root/'release').rglob('*'):
            if path.is_file(): os.utime(path,ns=(1,path.stat().st_mtime_ns))
        plan=self.removal.plan()
        self.apply(plan)
        self.assertEqual(r.removal_status(self.engine)['state'],'program_files_absent_observed')



    def test_unsupported_host_cli_deactivate_then_remove_without_execution(self):
        self.install(); self.prepare()
        before={p:(p.read_bytes(),p.stat().st_ino) for p in self.base.rglob('*') if p.is_file()}
        observed=[]; active=[True]
        def audit(event,args):
            if active[0] and (event.startswith('subprocess.') or event.startswith('socket.') or
                             event in ('os.exec','os.posix_spawn','os.system','os.fork','os.forkpty')):
                observed.append(event)
        sys.addaudithook(audit)
        common=['--root',str(self.root),'--materials',str(self.materials),
                '--bundle',str(self.bundle.path),'--bundle-sha256',self.bundle.sha256]
        try:
            with mock.patch.object(platform,'machine',return_value='unsupported-test-architecture'), \
                 mock.patch.object(l,'check_sealed_runtime_host',side_effect=AssertionError('runtime host probe')):
                for action in ('deactivate','remove-program-files'):
                    output=io.StringIO()
                    with contextlib.redirect_stdout(output): self.assertEqual(cli.main([action]+common),0)
                    plan=json.loads(output.getvalue())
                    output=io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(cli.main([action]+common+['--confirm-plan',plan['planHash']]),0)
                    if action=='deactivate':
                        result=json.loads(output.getvalue())
                        self.assertEqual(result['deletedFiles'],0); self.assertFalse(result['removesProgramFiles'])
                        for path,expected in before.items():
                            self.assertEqual((path.read_bytes(),path.stat().st_ino),expected)
                        self.assertFalse((self.root/l.REMOVAL_INTENT).exists())
        finally: active[0]=False
        self.assertEqual(observed,[])
        self.assertEqual(r.removal_status(self.engine)['state'],'program_files_absent_observed')

    def test_deactivate_all_lifetime_locks(self):
        self.install(); self.prepare(); removal=r.ProgramRemoval(self.engine,self.bundle)
        plan=removal.plan('deactivate')
        for path in [self.root,self.materials,*[self.materials/name for name in b.DIRECTORIES]]:
            with b.owned_directory(path):
                with self.assertRaises(OSError): removal.deactivate(plan,plan['planHash'])
            self.assertFalse((self.root/l.UNINSTALLED).exists())

    def test_deactivate_rechecks_unknown_entry_before_write(self):
        self.install(); removal=r.ProgramRemoval(self.engine,self.bundle); plan=removal.plan('deactivate')
        (self.root/'release/unknown').write_bytes(b'new synthetic unknown')
        with self.assertRaises(v.InstallError): removal.deactivate(plan,plan['planHash'])
        self.assertFalse((self.root/l.UNINSTALLED).exists())

    def test_deactivate_repeated_or_wrong_action_confirmation_refused(self):
        self.install(); removal=r.ProgramRemoval(self.engine,self.bundle); plan=removal.plan('deactivate')
        with self.assertRaises(v.InstallError): removal.deactivate(plan,'0'*64)
        with self.assertRaises(v.InstallError): removal.apply(plan,plan['planHash'])
        self.assertFalse((self.root/l.UNINSTALLED).exists()); self.untouched()
        removal.deactivate(plan,plan['planHash'])
        with self.assertRaises(v.InstallError): removal.deactivate(plan,plan['planHash'])
        remove=removal.plan()
        with self.assertRaises(v.InstallError): removal.deactivate(remove,remove['planHash'])
        self.untouched()


if __name__=='__main__': unittest.main()
