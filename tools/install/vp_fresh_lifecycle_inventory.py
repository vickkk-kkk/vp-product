"""Read-only same-artifact lifecycle assessment, never recovery authority.

No CLI integration, persistence, repair execution or reactivation. Plans are
non-executable review proposals; private-state authentication is NOT performed.
Uses the existing stable trusted paths/cooperative same-UID model.
"""
import contextlib
import os
from pathlib import PurePosixPath

import vp_bootstrap as b
from vp_fresh_bundle import FreshBundle
from vp_fresh_local import (ACTIVATION, READY, DISABLED_MARKERS, REMOVAL_INTENT,
                            REMOVAL_RECEIPT, NAMES)
from vp_fresh_removal import file_observation, release_directory
from vp_install import InstallError, canonical, digest, require


def bounded_names(fd, limit):
    """Bound allocation while enumerating, including all revalidation passes."""
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            require(len(names) < limit, 'directory inventory bound exceeded')
            names.append(entry.name)
    return sorted(names)


def installation_observation(root):
    names = bounded_names(root, len(NAMES))
    require(set(names) <= NAMES, 'unknown installation state; no adoption')
    files = {name: digest(b.private_bytes(name, root)) for name in names if name != 'release'}
    return {'entry': b.stat_metadata(os.fstat(root)), 'files': files, 'entries': names}


class LifecycleInventory:
    def __init__(self, engine, bundle):
        require(isinstance(bundle, FreshBundle), 'verified original bundle required')
        self.engine = engine
        self.bundle = bundle
        self.items = {item['path']: item for item in bundle.manifest['files']}
        raw = canonical(bundle.manifest)
        self.items['manifest.json'] = {'size': len(raw), 'sha256': digest(raw)}
        self.directories = {''}
        for name in self.items:
            parts = name.split('/')
            self.directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
        require(len(self.items) + len(self.directories) <= 8192, 'inventory bound')

    def plan(self, action):
        require(action in ('review-same-artifact-repair', 'review-reactivation'),
                'only non-executable lifecycle review supported')
        e = self.engine
        with contextlib.ExitStack() as stack:
            parent = stack.enter_context(b.bound_parent(e.root.parent, b.entry_stat(e.root.parent)))
            root = stack.enter_context(b.owned_directory(e.root.name, directory_fd=parent))
            before = installation_observation(root)
            record = e.record()
            require(record['bundleSha256'] == self.bundle.sha256 and
                    record['manifestDigest'] == digest(canonical(self.bundle.manifest)),
                    'original archive/manifest mismatch')
            # Provenance cannot be repaired or inferred from archive membership.
            release = stack.enter_context(release_directory('release', root))
            manifest = file_observation(release, 'manifest.json', self.items['manifest.json'])
            opened = {'': release}
            inventory = {}
            missing_dirs = []
            refused_dirs = []
            unknown = []
            directory_snapshots = {}
            observed_entries = 0
            for name in sorted(self.directories, key=lambda p: (p.count('/'), p)):
                if name:
                    part = PurePosixPath(name)
                    parent_name = str(part.parent) if str(part.parent) != '.' else ''
                    if parent_name not in opened:
                        if any(name == p or name.startswith(p + '/') for p in refused_dirs):
                            continue
                        missing_dirs.append(name)
                        continue
                    pfd = opened[parent_name]
                    if b.entry_stat(part.name, pfd) is None:
                        missing_dirs.append(name)
                        continue
                    try:
                        opened[name] = stack.enter_context(release_directory(part.name, pfd))
                    except (OSError, InstallError):
                        refused_dirs.append(name)
                        continue
                fd = opened[name]
                # Bounded enumeration; do not follow or inspect unknown entries.
                names = bounded_names(fd, 8192 - observed_entries)
                observed_entries += len(names)
                directory_snapshots[name] = names
                prefix = name + '/' if name else ''
                expected = {p[len(prefix):].split('/')[0] for p in self.items if p.startswith(prefix)}
                unknown.extend(prefix + n for n in names if n not in expected)
            missing = []
            refused = []
            for name, item in sorted(self.items.items()):
                part = PurePosixPath(name)
                parent_name = str(part.parent) if str(part.parent) != '.' else ''
                if any(name.startswith(p + '/') for p in refused_dirs):
                    refused.append(name)
                    continue
                if parent_name not in opened or b.entry_stat(part.name, opened[parent_name]) is None:
                    missing.append(name)
                    continue
                try:
                    observed = file_observation(opened[parent_name], part.name, item)
                    require(observed['mode'] == (0o755 if item.get('executable', False) else 0o644),
                            'program file mode differs from original extraction')
                    inventory[name] = observed
                except (OSError, InstallError):
                    refused.append(name)
            require(inventory.get('manifest.json') == manifest, 'manifest changed during inventory')
            material_entry = b.entry_stat(e.materials.name, parent)
            private_guard = {}
            private_leases = []
            private_status = 'missing'
            private_transition = []
            private_names = None
            child_entries = {}
            if material_entry is not None:
                # An unsafe parent is a hard refusal: we cannot inspect or lock
                # its children through a trusted descriptor. Never call it idle.
                material = stack.enter_context(b.owned_directory(e.materials.name, directory_fd=parent,
                                                                 expected=material_entry))
                private_leases.append((e.materials.name, material, parent))
                damaged = False
                # Acquire EVERY present known child lease before metadata/material
                # validation. Missing/unsafe early children must not skip later
                # children that may be held by a live service.
                for name in b.DIRECTORIES:
                    child_entries[name] = b.entry_stat(name, material)
                    if child_entries[name] is None:
                        damaged = True
                        continue
                    try:
                        fd = stack.enter_context(b.owned_directory(name, directory_fd=material,
                                                                 expected=child_entries[name]))
                        private_leases.append((name, fd, material))
                    except BlockingIOError:
                        raise
                    except (OSError, InstallError):
                        damaged = True
                private_names = bounded_names(material, len(b.KNOWN_NAMES))
                try:
                    state, fingerprints = b.root_snapshot(e.materials)
                    b.verified_material(e.materials, material)
                    private_guard = {'state': state, 'fingerprints': fingerprints}
                    names = set(state['entries'])
                    if names.intersection((b.INTENT_PENDING, b.PENDING, b.OFFLINE_PENDING)):
                        private_transition.append('private_pending_file')
                    if b.OFFLINE_INTENT in names and b.OFFLINE_RESULT not in names:
                        private_transition.append('offline_initialization_unresolved')
                    if b.OFFLINE_RESULT not in names:
                        private_transition.append('offline_initialization_not_established')
                except BlockingIOError:
                    raise
                except (OSError, InstallError):
                    damaged = True
                private_status = ('damaged_or_unrecognized' if damaged else
                                  'structurally_intact_authority_unverified')
            private_ids = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                           for fd in [root, *[fd for _, fd, _ in private_leases]]]
            release_ids = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in opened.values()]
            require(len(set(private_ids + release_ids)) == len(private_ids + release_ids),
                    'aliased installation/private/release directories')
            # Revalidate every held path and namespace. These observations do not
            # claim defense against a hostile same-UID writer or physical rollback.
            b.require_path_identity(e.root.parent, parent)
            b.require_path_identity(e.root.name, root, parent)
            b.require_path_identity('release', release, root)
            require(installation_observation(root) == before, 'installation changed during inventory')
            require(b.entry_stat(e.materials.name, parent) == material_entry, 'private root changed')
            for name, fd, pfd in private_leases:
                b.require_path_identity(name, fd, pfd)
            if private_names is not None:
                require(bounded_names(material, len(b.KNOWN_NAMES)) == private_names,
                        'private namespace changed')
                require({name: b.entry_stat(name, material) for name in b.DIRECTORIES} == child_entries,
                        'private child changed')
            if private_guard:
                current, fingerprints = b.root_snapshot(e.materials)
                require(current == private_guard['state'] and fingerprints == private_guard['fingerprints'],
                        'private materials changed during inventory')
            rechecked_entries = 0
            for name, fd in opened.items():
                part = PurePosixPath(name)
                if name:
                    p = str(part.parent) if str(part.parent) != '.' else ''
                    b.require_path_identity(part.name, fd, opened[p])
                current_names = bounded_names(fd, 8192 - rechecked_entries)
                rechecked_entries += len(current_names)
                require(current_names == directory_snapshots[name], 'release namespace changed')
            for name, expected in inventory.items():
                part = PurePosixPath(name)
                p = str(part.parent) if str(part.parent) != '.' else ''
                require(file_observation(opened[p], part.name, self.items[name]) == expected,
                        'surviving program changed during inventory')
            transitions = list(private_transition)
            entries = set(before['entries'])
            if ACTIVATION in entries and READY not in entries:
                transitions.append('activation_unresolved')
            if READY in entries and ACTIVATION not in entries:
                transitions.append('activation_provenance_inconsistent')
            if REMOVAL_INTENT in entries:
                transitions.append('removal_attempt_requires_separate_recovery_review')
            if REMOVAL_RECEIPT in entries and REMOVAL_INTENT not in entries:
                transitions.append('removal_provenance_inconsistent')
            disabled = bool(entries.intersection(DISABLED_MARKERS))
            classification = ('refused_targets' if unknown or refused or refused_dirs else
                              'missing_program_files' if missing else 'exact_program_files')
            blockers = ['execution_not_implemented', 'control_vault_runtime_authority_not_verified']
            if private_status != 'structurally_intact_authority_unverified': blockers.append('private_materials_unavailable_or_damaged')
            if not disabled: blockers.append('profile_not_disabled')
            if classification == 'refused_targets': blockers.append('unknown_changed_or_unsafe_targets')
            if action == 'review-reactivation' and missing: blockers.append('program_repair_required')
            blockers.extend(transitions)
            value = {'action': action, 'assessmentOnly': True, 'executable': False,
                     'repairSupported': False, 'reactivationSupported': False,
                     'writesFiles': False, 'executesPrograms': False, 'usesNetwork': False,
                     'sameArtifactOnly': True, 'bundleSha256': self.bundle.sha256,
                     'manifestDigest': record['manifestDigest'], 'root': str(e.root),
                     'materials': str(e.materials), 'profileDisabledObserved': disabled,
                     'programClassification': classification,
                     'exactSurvivors': sorted(n for n in inventory if n != 'manifest.json'),
                     'missingProgramFiles': missing, 'missingDirectories': missing_dirs,
                     'unknownTargets': sorted(unknown), 'changedOrUnsafeFiles': refused,
                     'unsafeDirectories': refused_dirs, 'privateState': private_status,
                     'priorTransitions': transitions, 'priorDurability': 'not_inferred',
                     'blockers': blockers}
            # Secret fingerprints are only opaque hash input; never expose them.
            value['observationHash'] = digest(canonical({'public': value, 'installation': before,
                'inventory': inventory, 'private': private_guard, 'materialEntry': material_entry,
                'privateNames': private_names, 'privateChildren': child_entries}))
            return value
