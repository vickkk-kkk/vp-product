"""Explicit manifest-owned program removal; never data purge or recovery.

Cooperative same-UID/stable trusted paths model, as for fresh-local. An intent
consumes this one-shot action, including on cancellation or uncertain fsync. No
resume, restore, repair or reactivation is implemented. Retained receipts are
observations, not proof that a previous process completed a durability barrier.
"""
import contextlib
import hashlib
import os
from pathlib import PurePosixPath
import stat
import time

import vp_bootstrap as b
from vp_fresh_bundle import FreshBundle
from vp_fresh_local import (OWNER, PROFILE, DISABLED_MARKERS, REMOVAL_INTENT,
                            REMOVAL_RECEIPT, UNINSTALLED, observe)
from vp_install import require, canonical, digest, MAX_FILE

ACTION = 'remove-program-files'
DEACTIVATE = 'deactivate'


class RemovalBundle(FreshBundle):
    """Read-only archive admission independent of the current execution host."""
    removal_only = True

    def validate_architecture(self, architecture):
        require(architecture in ('x86_64', 'aarch64'), 'unknown release architecture')

    def validate_elf(self, raw):
        require(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01' and
                int.from_bytes(raw[16:18], 'little') in (2, 3) and
                int.from_bytes(raw[18:20], 'little') ==
                {'x86_64': 62, 'aarch64': 183}[self.manifest['architecture']],
                'release ELF does not match declared architecture')


def file_metadata(value):
    # Reading may update atime on relatime/strictatime mounts; it is not identity.
    return {**b.stat_metadata(value), 'links': value.st_nlink,
            'mtimeNs': value.st_mtime_ns, 'ctimeNs': value.st_ctime_ns}


def file_observation(fd, name, item):
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(handle)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_uid == os.geteuid() and not before.st_mode & 0o022 and
                before.st_size == item['size'] and before.st_size <= MAX_FILE,
                'release file identity/type/size/mode refused')
        h = hashlib.sha256(); size = 0; deadline = time.monotonic() + 30
        while True:
            require(time.monotonic() < deadline, 'release read deadline exceeded')
            raw = os.read(handle, min(65536, before.st_size - size + 1))
            if not raw: break
            size += len(raw); require(size <= before.st_size, 'release file grew')
            h.update(raw)
        require(size == before.st_size and h.hexdigest() == item['sha256'] and
                file_metadata(os.fstat(handle)) == file_metadata(before), 'release file changed')
        require(b.entry_stat(name, fd) == b.stat_metadata(before), 'release file path changed')
        return {**file_metadata(before), 'sha256': h.hexdigest()}
    finally:
        os.close(handle)


@contextlib.contextmanager
def release_directory(name, parent):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        value = os.fstat(fd)
        require(value.st_uid == os.geteuid() and not value.st_mode & 0o022,
                'untrusted release directory')
        b.require_path_identity(name, fd, parent)
        yield fd
    finally:
        os.close(fd)


class ProgramRemoval:
    def __init__(self, engine, bundle):
        require(isinstance(bundle, FreshBundle), 'verified original bundle required')
        self.engine = engine; self.bundle = bundle
        self.items = {item['path']: item for item in bundle.manifest['files']}
        raw = canonical(bundle.manifest)
        self.items['manifest.json'] = {'size': len(raw), 'sha256': digest(raw)}
        self.directories = {''}
        for name in self.items:
            parts = name.split('/')
            self.directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
        require(len(self.items) + len(self.directories) <= 8192, 'removal inventory bound')

    @contextlib.contextmanager
    def admitted(self, action=ACTION):
        require(action in (ACTION, DEACTIVATE), 'unsupported cleanup action')
        e = self.engine
        with contextlib.ExitStack() as stack:
            parent = stack.enter_context(b.bound_parent(e.root.parent, b.entry_stat(e.root.parent)))
            root = stack.enter_context(b.owned_directory(e.root.name, directory_fd=parent))
            before = observe(e.root)
            disabled = bool(DISABLED_MARKERS.intersection(before['entries']))
            require(disabled if action == ACTION else not disabled,
                    'removal requires disabled profile; deactivation requires enabled profile')
            require(REMOVAL_INTENT not in before['entries'] and REMOVAL_RECEIPT not in before['entries'],
                    'removal already attempted; no retry/resume/recovery')
            record = e.record()
            require(record['bundleSha256'] == self.bundle.sha256 and
                    record['manifestDigest'] == digest(canonical(self.bundle.manifest)),
                    'original archive/manifest mismatch')
            materials_entry = b.entry_stat(e.materials.name, parent)
            leases = []
            if materials_entry is not None:
                material = stack.enter_context(b.owned_directory(e.materials.name, directory_fd=parent,
                                                                 expected=materials_entry))
                leases.append((e.materials.name, material, parent))
                for name in b.DIRECTORIES:
                    fd = stack.enter_context(b.owned_directory(name, directory_fd=material))
                    leases.append((name, fd, material))
            dirs = {}
            for name in sorted(self.directories, key=lambda p: (p.count('/'), p)):
                parts = PurePosixPath(name)
                parent_fd = root if not name else dirs[str(parts.parent) if str(parts.parent) != '.' else '']
                dirs[name] = stack.enter_context(release_directory(parts.name if name else 'release', parent_fd))
            def stable():
                b.require_path_identity(e.root.parent, parent)
                b.require_path_identity(e.root.name, root, parent)
                if materials_entry is None:
                    require(b.entry_stat(e.materials.name, parent) is None, 'material root appeared')
                for name, fd, parent_fd in leases: b.require_path_identity(name, fd, parent_fd)
                for name, fd in dirs.items():
                    parts = PurePosixPath(name)
                    parent_fd = root if not name else dirs[str(parts.parent) if str(parts.parent) != '.' else '']
                    b.require_path_identity(parts.name if name else 'release', fd, parent_fd)
            stable()
            private_ids = {(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in [root, *[fd for _,fd,_ in leases]]}
            release_ids = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in dirs.values()]
            require(len(set(release_ids)) == len(release_ids) and not private_ids.intersection(release_ids),
                    'aliased release/private directory')
            inventory = {}
            for name, fd in dirs.items():
                prefix = name + '/' if name else ''
                expected = {p[len(prefix):].split('/')[0] for p in self.items if p.startswith(prefix)}
                require(set(os.listdir(fd)) == expected, 'missing/unexpected release entry')
                inventory[name + '/'] = b.stat_metadata(os.fstat(fd))
            for name, item in sorted(self.items.items()):
                part = PurePosixPath(name)
                fd = dirs[str(part.parent) if str(part.parent) != '.' else '']
                inventory[name] = file_observation(fd, part.name, item)
            stable()
            value = {'schemaVersion': 1, 'owner': OWNER, 'profile': PROFILE, 'action': action,
                     'root': str(e.root), 'materials': str(e.materials), 'before': before,
                     'parentIdentity': {'device': os.fstat(parent).st_dev, 'inode': os.fstat(parent).st_ino},
                     'bundleSha256': self.bundle.sha256, 'manifestDigest': record['manifestDigest'],
                     'inventory': inventory, 'materialsIdentity': materials_entry,
                     'dataDirectoryIdentities': [b.stat_metadata(os.fstat(fd)) for _,fd,_ in leases],
                     'plannedFilesToRemove': len(self.items)-1 if action == ACTION else 0, 'dataDeletion': False,
                     'serviceChanges': False, 'executesPrograms': False, 'resumeSupported': False,
                     'retainedManifest': 'release/manifest.json'}
            value['planHash'] = digest(canonical(value))
            yield value, root, dirs, stable

    def plan(self, action=ACTION):
        with self.admitted(action) as (plan, *_): return plan

    def deactivate(self, plan, confirmation):
        require(confirmation == plan.get('planHash'), 'exact deactivation confirmation required')
        with self.admitted(DEACTIVATE) as (current, root, _, stable):
            require(current == plan, 'stale deactivation plan')
            stable()
            receipt = {'owner': OWNER, 'status': 'profile_disabled_all_files_retained',
                       'action': DEACTIVATE, 'planHash': confirmation, 'deletedFiles': 0,
                       'allFilesRetained': True, 'removesProgramFiles': False}
            b.new_file(root, UNINSTALLED, canonical(receipt))
            stable()
            return {**receipt, 'recoveryEligible': False}

    def apply(self, plan, confirmation, cancelled=lambda: False):
        require(confirmation == plan.get('planHash'), 'exact removal confirmation required')
        with self.admitted() as (current, root, dirs, stable):
            require(current == plan, 'stale removal plan')
            require(not cancelled(), 'removal canceled before intent')
            stable()
            intent = {'schemaVersion': 1, 'owner': OWNER, 'action': ACTION,
                      'planHash': confirmation, 'bundleSha256': self.bundle.sha256,
                      'manifestDigest': plan['manifestDigest'],
                      'inventoryDigest': digest(canonical(plan['inventory'])),
                      'expectedFiles': len(self.items)-1, 'status': 'consumed_outcome_not_inferred',
                      'resumeSupported': False, 'dataDeletion': False}
            b.new_file(root, REMOVAL_INTENT, canonical(intent))
            count = 0
            for name, item in sorted(self.items.items()):
                if name == 'manifest.json': continue
                require(not cancelled(), 'removal canceled; intent retained, no resume')
                stable(); part = PurePosixPath(name)
                fd = dirs[str(part.parent) if str(part.parent) != '.' else '']
                require(file_observation(fd, part.name, item) == plan['inventory'][name],
                        'release changed after removal intent')
                stable()
                leaf = os.stat(part.name, dir_fd=fd, follow_symlinks=False)
                expected = plan['inventory'][name]
                require(file_metadata(leaf) == {key: expected[key] for key in file_metadata(leaf)},
                        'release leaf replaced immediately before unlink')
                os.unlink(part.name, dir_fd=fd); os.fsync(fd); count += 1
            for name in sorted((p for p in dirs if p), key=lambda p: (p.count('/'), p), reverse=True):
                require(not cancelled(), 'removal canceled; intent retained, no resume')
                stable(); require(not os.listdir(dirs[name]), 'directory changed during removal')
                part = PurePosixPath(name); parent_fd = dirs[str(part.parent) if str(part.parent) != '.' else '']
                os.rmdir(part.name, dir_fd=parent_fd); os.fsync(parent_fd)
                del dirs[name]
            stable()
            require(set(os.listdir(dirs[''])) == {'manifest.json'}, 'unexpected final release inventory')
            require(file_observation(dirs[''], 'manifest.json', self.items['manifest.json']) ==
                    plan['inventory']['manifest.json'], 'retained manifest changed')
            require(not cancelled(), 'removal canceled before receipt; no resume')
            receipt = {'schemaVersion': 1, 'owner': OWNER, 'planHash': confirmation,
                       'status': 'program_files_absent_observed', 'deletedFiles': count,
                       'dataRetained': True, 'resumeSupported': False,
                       'durabilityNotInferredFromReceipt': True}
            b.new_file(root, REMOVAL_RECEIPT, canonical(receipt))
            stable()
            return {**receipt, 'status': 'program_files_removed_data_retained',
                    'durabilityBarriersReturned': True, 'productionCertified': False}


def removal_status(engine):
    """Live read-only inventory, not a receipt-derived success/durability claim."""
    state = observe(engine.root)
    if REMOVAL_INTENT not in state['entries']:
        return {'state': 'not_attempted', 'resumeSupported': False}
    # Only classify complete file absence when the original installed manifest
    # remains exact and the release contains precisely that one regular file.
    record = engine.record()
    with b.owned_directory(engine.root, lock=False) as root:
        with release_directory('release', root) as release:
            from vp_install import read_regular
            raw = read_regular(engine.root/'release/manifest.json', 128*1024)
            require(digest(raw) == record['manifestDigest'], 'retained manifest changed')
            file_observation(release, 'manifest.json', {'size':len(raw), 'sha256':digest(raw)})
            # Missing, partial or unknown trees never yield completed status.
            only_manifest = set(os.listdir(release)) == {'manifest.json'}
            b.require_path_identity(engine.root, root)
            b.require_path_identity('release', release, root)
    return {'state': 'program_files_absent_observed' if only_manifest else 'incomplete_or_uncertain',
            'completionReceiptPresent': REMOVAL_RECEIPT in state['entries'],
            'priorDurability': 'not_inferred', 'resumeSupported': False}
