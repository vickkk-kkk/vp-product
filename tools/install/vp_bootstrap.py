#!/usr/bin/env python3
"""Plan-first local bootstrap MATERIAL preparation; never a service installer.

Secret generation is explicit, after confirmed durable consumed intent. This tool
never runs a daemon, restores state, changes a host account,
uses secret argv/env, or treats a directory/key file as authoritative recovery.
Local crash ordering assumes an operator-chosen, already durable trusted parent
ancestry. It cannot detect external deletion, rollback or temporary-root cleanup;
an absent root does not prove that no previous identity existed.
"""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from urllib.parse import urlsplit

from vp_install import InstallError, require, safe_absolute, check_ancestors, canonical, digest, strict_json, read_regular

OWNER = 'vp-bootstrap-materials'
PROFILE = 'local-materials-v1'
MAX_MATERIAL = 4096
MAX_ROOT_BYTES = 1024  # leave bounded headroom for every private JSON metadata file
SAFE_ID = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
DIRECTORIES = ('control', 'runtime', 'vault')
INTENT = '.bootstrap-intent.json'
INTENT_PENDING = '.bootstrap-intent.pending'
MATERIAL = 'bootstrap.json'
PENDING = '.bootstrap.pending'
MANIFEST = 'bootstrap-materials.json'
OFFLINE_INTENT = 'offline-init-intent.json'
OFFLINE_PENDING = '.offline-init-intent.pending'
OFFLINE_RESULT = 'offline-init-result.json'
KNOWN_NAMES = set(DIRECTORIES) | {INTENT, INTENT_PENDING, MATERIAL, PENDING, MANIFEST, OFFLINE_INTENT, OFFLINE_PENDING, OFFLINE_RESULT}
RECOVERY_BLOCKERS = ('offline_inspect_not_implemented', 'control_authority_unavailable',
                     'revocation_watermarks_unavailable', 'external_trusted_checkpoint_required')


def exact(value, fields):
    require(isinstance(value, dict) and set(value) == set(fields), 'unsupported/missing local material fields')


def safe_id(value):
    require(isinstance(value, str) and SAFE_ID.fullmatch(value), 'explicit 1..64 letter/digit/underscore/hyphen identity required')
    return value


def stat_metadata(value):
    return {'device': value.st_dev, 'inode': value.st_ino, 'uid': value.st_uid,
            'mode': stat.S_IMODE(value.st_mode), 'type': stat.S_IFMT(value.st_mode), 'size': value.st_size}


def entry_stat(path, directory_fd=None):
    try:
        value = os.stat(path, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return stat_metadata(value)


def require_identity(observed, expected):
    require(expected is not None and (observed.st_dev, observed.st_ino) ==
            (expected['device'], expected['inode']), 'confirmed filesystem identity changed')


def private_directory(path):
    path = check_ancestors(path)
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
            value.st_uid == os.geteuid() and not value.st_mode & 0o077, 'existing same-owner 0700 private directory required')
    return path


def private_snapshot(path, directory_fd=None, expected=None):
    if directory_fd is None:
        check_ancestors(Path(path).parent)
    # Every validation applies to the exact descriptor read below, not a prior
    # lstat object. NONBLOCK also prevents a raced FIFO from hanging the process.
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except OSError:
        # Preserve the fail-closed descriptor open while keeping OS paths and
        # diagnostics out of the engine's public error contract.
        raise InstallError('private material could not be opened safely') from None
    try:
        with os.fdopen(descriptor, 'rb') as stream:
            value = os.fstat(stream.fileno())
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and
                    value.st_uid == os.geteuid() and not value.st_mode & 0o077 and
                    0 <= value.st_size <= MAX_MATERIAL, 'private single-link bounded regular file required')
            if expected is not None:
                require_identity(value, expected)
            raw = stream.read(MAX_MATERIAL + 1)
            require(len(raw) <= MAX_MATERIAL, 'private material exceeds size bound')
            after = os.fstat(stream.fileno())
            require((after.st_nlink, after.st_mode, after.st_uid, after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                    (value.st_nlink, value.st_mode, value.st_uid, value.st_size, value.st_mtime_ns, value.st_ctime_ns),
                    'private material changed during read')
            return raw, stat_metadata(value)
    except OSError:
        raise InstallError('private material could not be read safely') from None



def private_bytes(path, directory_fd=None, expected=None):
    return private_snapshot(path, directory_fd, expected)[0]


def material(raw):
    value = strict_json(raw)
    exact(value, ('username', 'token', 'vault'))
    safe_id(value['username'])
    require(isinstance(value['token'], str) and re.fullmatch(r'[A-Za-z0-9_-]{43,256}', value['token']),
            'administrator token must satisfy real high-entropy bootstrap encoding')
    exact(value['vault'], ('masterKeyHex', 'credentials'))
    require(isinstance(value['vault']['masterKeyHex'], str) and
            re.fullmatch(r'[0-9A-Fa-f]{64}', value['vault']['masterKeyHex']), 'vault master key must be explicit 32-byte hex')
    require(value['vault']['credentials'] == [], 'persistent bootstrap accepts no plaintext node credentials; use authenticated UUID API later')
    return value


def recovery_status():
    # Explicit unavailable port. Do not call SqliteStore::open or vault::open:
    # both can write/clean state and are NOT read-only inspection contracts.
    return {'status': 'RecoveryNeedsVerification', 'authorityBinding': None,
            'controlAuthorityId': None, 'revocationWatermarks': 'unsupported',
            'recoveryEligible': False, 'blockingReasons': list(RECOVERY_BLOCKERS),
            'restored': False, 'vaultInitialized': None, 'vaultInspection': 'unavailable'}


def root_snapshot(root):
    value = entry_stat(root)
    if value is None:
        return {'entry': None, 'entries': [], 'fileMetadata': {}}, {}
    with owned_directory(root, expected=value, lock=False) as directory:
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                require(entry.name in KNOWN_NAMES and len(names) < len(KNOWN_NAMES),
                        'unknown/nonempty root requires authority verification; no adoption')
                names.append(entry.name)
        names.sort()
        metadata = {}; fingerprints = {}
        for name in (INTENT, INTENT_PENDING, MATERIAL, PENDING, MANIFEST, OFFLINE_INTENT, OFFLINE_PENDING, OFFLINE_RESULT):
            if name in names:
                raw, metadata[name] = private_snapshot(name, directory)
                fingerprints[name] = digest(raw)
        for name in DIRECTORIES:
            if name in names:
                with owned_directory(name, directory_fd=directory, lock=False):
                    pass
        require_path_identity(root, directory)
    return {'entry': value, 'entries': names, 'fileMetadata': metadata}, fingerprints


def root_observation(root):
    return root_snapshot(root)[0]


def manifest(root, directory_fd, snapshots=None):
    value = strict_json(private_bytes(MANIFEST, directory_fd) if snapshots is None else snapshots[MANIFEST])
    exact(value, ('schemaVersion', 'owner', 'profile', 'uid', 'root', 'username', 'namespace',
                  'materialSha256', 'journalId', 'authorityBinding', 'vaultProvisioning'))
    require(value['schemaVersion'] == 1 and value['owner'] == OWNER and value['profile'] == PROFILE,
            'unknown local material manifest')
    require(value['uid'] == os.geteuid() and value['root'] == str(root), 'material owner/root changed; authority verification required')
    safe_id(value['username']); safe_id(value['namespace'])
    require(HEX.fullmatch(value['materialSha256']) and HEX.fullmatch(value['journalId']) and
            value['authorityBinding'] is None and value['vaultProvisioning'] == 'not_performed',
            'invalid material metadata; no recovery authority inferred')
    return value


def verified_material(root, directory_fd=None, snapshots=None):
    if directory_fd is None:
        with owned_directory(root, lock=False) as directory:
            result = verified_material(root, directory)
            require_path_identity(root, directory)
            return result
    value = manifest(root, directory_fd, snapshots)
    raw = private_bytes(MATERIAL, directory_fd) if snapshots is None else snapshots[MATERIAL]
    require(digest(raw) == value['materialSha256'], 'bootstrap changed; no overwrite, adoption or fallback generation')
    decoded = material(raw)
    require(decoded['username'] == value['username'], 'bootstrap username does not match preparation')
    return value, raw, decoded


def confirmed_material(root, directory_fd, plan, guard):
    """Bind every confirmed immutable file under the held root lock.

    Decode and consume these captured bytes, never re-read a pathname after its
    digest was checked. This protects the confirmation-to-lock gap as well as
    manifest fields (e.g. namespace), not merely the key-file fingerprint.
    """
    with os.scandir(directory_fd) as entries:
        names = []
        for entry in entries:
            require(entry.name in KNOWN_NAMES and len(names) < len(KNOWN_NAMES),
                    'private root entries changed after confirmation')
            names.append(entry.name)
    require(sorted(names) == plan['before']['entries'], 'private root entries changed after confirmation')
    expected = guard['rootFileDigests']
    require(set(expected) == set(plan['before']['fileMetadata']), 'confirmed private file inventory invalid')
    snapshots = {}
    for name, expected_digest in expected.items():
        raw = private_bytes(name, directory_fd, expected=plan['before']['fileMetadata'][name])
        require(digest(raw) == expected_digest, 'private file changed after confirmation')
        snapshots[name] = raw
    require(MANIFEST in snapshots and MATERIAL in snapshots, 'confirmed material missing')
    return verified_material(root, directory_fd, snapshots)


def status(root):
    observation = root_observation(root)
    if observation['entry'] is None:
        return {**recovery_status(), 'status': 'not_prepared', 'materialsPrepared': False}
    if MANIFEST not in observation['entries'] or MATERIAL not in observation['entries']:
        return {**recovery_status(), 'materialsPrepared': False, 'interruptedOrMissingMaterial': True,
                'durableIntentPresent': INTENT in observation['entries'], 'rawMaterialDisplayed': False}
    value, _, _ = verified_material(root)
    return {**prepared_status(root, value),
            'offlineInitializationAttemptRecorded': any(name in observation['entries'] for name in (OFFLINE_INTENT, OFFLINE_PENDING)),
            'offlineInitializationReceiptPresent': OFFLINE_RESULT in observation['entries'],
            'offlineInitializationLiveStateVerified': False}


def prepared_status(root, value):
    return {'status': 'materials_prepared_only', 'materialsPrepared': True, 'root': str(root),
            'profile': PROFILE, 'username': value['username'], 'namespace': value['namespace'],
            'materialMatchesPrivateManifest': True, 'authorityBinding': None,
            'vaultInitialized': None, 'vaultInspection': 'unavailable', 'serviceStartedByThisTool': False,
            'serviceObservation': 'not_performed', 'publicHttpsVerified': False,
            'recoveryEligible': False, 'backupEncryption': 'not_provided'}


def new_file(directory_fd, name, data):
    require(len(data) <= MAX_MATERIAL, 'private file exceeds readable metadata/material bound')
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    with os.fdopen(descriptor, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)  # only this newly created owned file
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.fsync(directory_fd)


def publish_pending(directory_fd, pending, target):
    # link() provides atomic no-replace publication; rename() could replace an
    # unexpected empty destination. Both names are fixed/validated private files.
    os.link(pending, target, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
    os.fsync(directory_fd)
    os.unlink(pending, dir_fd=directory_fd)
    os.fsync(directory_fd)


def require_path_identity(path, descriptor, directory_fd=None):
    require_identity(os.fstat(descriptor), entry_stat(path, directory_fd))


@contextlib.contextmanager
def bound_parent(path, expected):
    check_ancestors(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require_identity(os.fstat(descriptor), expected)
        yield descriptor
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def owned_directory(path, directory_fd=None, expected=None, lock=True):
    if directory_fd is None:
        check_ancestors(Path(path).parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        current = os.fstat(descriptor)
        require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.geteuid() and
                not current.st_mode & 0o077, 'private directory changed')
        if expected is not None:
            require_identity(current, expected)
        if lock:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield descriptor
    finally:
        os.close(descriptor)


class Bootstrap:
    def __init__(self, root):
        self.root = safe_absolute(root)
        # The root is embedded in intent/manifest. Reject before filesystem
        # mutation or entropy rather than produce files our reader cannot open.
        require(len(str(self.root).encode('utf-8')) <= MAX_ROOT_BYTES, 'bootstrap root exceeds local metadata bound')
        check_ancestors(self.root.parent)
        require(self.root.parent.is_dir(), 'parent must already exist; no recursive parent creation')

    def plan(self, action, options):
        before, fingerprints = root_snapshot(self.root)
        # Content fingerprints stay in process memory / private manifest only.
        # The opaque confirmation hash binds these guards without putting a raw
        # material digest (or any token/key bytes) in the public plan/receipt.
        guard = {'rootFileDigests': fingerprints}
        value = {'schemaVersion': 1, 'owner': OWNER, 'profile': PROFILE, 'action': action,
                 'root': str(self.root), 'uid': os.geteuid(), 'parentObservation': entry_stat(self.root.parent),
                 'before': before, 'writesSecrets': action in ('prepare', 'backup-key', 'offline-vault-init'),
                 'serviceChanges': False, 'hostChanges': False, 'authorityBinding': None,
                 'recoveryEligible': False, 'options': {}, 'changes': []}
        if action == 'prepare':
            require(not before['entries'], 'prepare requires absent/fully empty root; consumed intent or unknown state cannot regenerate')
            username = safe_id(options.get('username')); namespace = safe_id(options.get('namespace'))
            request_key = safe_id(options.get('requestKey'))
            generate = options.get('generate') is True
            source = options.get('importFile')
            require(generate != bool(source), 'select explicit generate OR private import; no default credentials')
            source_meta = None
            if source:
                source = safe_absolute(source)
                raw, source_entry = private_snapshot(source); decoded = material(raw)
                require(decoded['username'] == username, 'import username mismatch')
                source_meta = {'path': str(source), 'entry': source_entry}
                guard['importDigest'] = digest(raw)
            value['options'] = {'username': username, 'namespace': namespace, 'requestKey': request_key,
                                'generate': generate, 'importFile': str(source) if source else None, 'source': source_meta}
            value['durabilityBoundary'] = {'trustedPersistentParentRequired': True,
                                           'parentAncestryDurabilityVerified': False,
                                           'externalDeletionOrRollbackProtected': False,
                                           'absenceProvesNoPriorIdentity': False}
            value['changes'] = ['explicit fresh preparation only; absent root is not recovery authorization',
                                'fsync bound parent for either new or existing empty root before entropy',
                                'create consumed non-secret intent before any entropy',
                                'create separate private 0700 control/runtime/vault directories',
                                'write private 0600 plaintext admin-token/vault-master bootstrap material',
                                'record safe material digest only; do not initialize vault or start service']
        elif action == 'offline-vault-init':
            prepared, _, _ = verified_material(self.root)
            require(not any(name in before['entries'] for name in (OFFLINE_INTENT, OFFLINE_PENDING, OFFLINE_RESULT)),
                    'offline initialization already attempted; no retry/adoption')
            artifact = safe_absolute(options.get('maintenanceArtifact') or '')
            expected = options.get('maintenanceSha256')
            require(HEX.fullmatch(expected or ''), 'explicit trusted maintenance digest required')
            request_key = safe_id(options.get('requestKey'))
            # Pure bounded source validation only: no memfd or subprocess while planning.
            from vp_maintenance_bridge import source_chunks
            import hashlib, time
            artifact_hash = hashlib.sha256()
            for block in source_chunks(artifact, time.monotonic() + 10):
                artifact_hash.update(block)
            require(artifact_hash.hexdigest() == expected, 'maintenance artifact mismatch')
            vault = self.root / 'vault'
            with owned_directory(vault, lock=False) as directory:
                with os.scandir(directory) as entries:
                    require(next(entries, None) is None, 'offline initialize requires empty vault; never reopen/reset')
                vault_identity = stat_metadata(os.fstat(directory))
                require_path_identity(vault, directory)
            guard['materialDigest'] = prepared['materialSha256']
            value['options'] = {'maintenanceArtifact': str(artifact), 'maintenanceSha256': expected,
                                'requestKey': request_key, 'vaultIdentity': vault_identity}
            value['changes'] = ['consume durable one-time offline initialization intent before process start',
                                'send existing imported/generated master only over stdin to pinned sealed maintenance ELF',
                                'create encrypted vault manifest only; no control DB, administrator session or service',
                                'retain uncertain outcome without retry, restore, adoption or key regeneration']
        elif action == 'backup-key':
            prepared, _, _ = verified_material(self.root)
            require(options.get('acknowledgePlaintext') is True, 'explicit plaintext key-backup risk acknowledgement required')
            target = safe_absolute(options.get('backupFile') or '')
            require(self.root not in target.parents and target != self.root, 'backup must be outside this root, never in runtime/vault')
            private_directory(target.parent)
            require(entry_stat(target) is None and entry_stat(target.parent / ('.' + target.name + '.pending')) is None,
                    'backup destination or pending material already exists; never overwrite')
            value['options'] = {'backupFile': str(target), 'acknowledgePlaintext': True,
                                'backupParent': entry_stat(target.parent)}
            guard['materialDigest'] = prepared['materialSha256']
            value['changes'] = ['copy exact bootstrap bytes into one new private 0600 external file',
                                'backup contains plaintext admin token AND vault master; no encryption or off-host guarantee',
                                'do not snapshot, modify or restore control/vault state']
        elif action in ('restore-key', 'resume'):
            value['writesSecrets'] = False
            value['blocking'] = recovery_status()
            value['changes'] = ['no changes: authoritative vault/control identity and watermarks are unavailable',
                                'retain all current material; never restore/adopt an old backup or mint replacement keys']
        elif action == 'show-admin-token':
            prepared, _, _ = verified_material(self.root)
            guard['materialDigest'] = prepared['materialSha256']
            value['changes'] = ['explicit terminal-only display of persistent administrator token; never display vault master']
        else:
            raise InstallError('unsupported bootstrap material action')
        value['planHash'] = digest(canonical({'publicPlan': value, 'privateGuard': guard}))
        self._private_guard = guard
        return value

    def apply(self, plan, confirmation, options):
        require(HEX.fullmatch(confirmation or '') and confirmation == plan['planHash'], 'exact displayed plan confirmation required')
        require(plan['action'] in ('prepare', 'backup-key', 'offline-vault-init'), 'RecoveryNeedsVerification: no restore/resume mutation implementation')
        fresh = self.plan(plan['action'], options)
        require(fresh == plan, 'plan changed; discard old confirmation and inspect again')
        previous_mask = os.umask(0o077)
        try:
            if plan['action'] == 'prepare':
                return self._prepare(plan)
            if plan['action'] == 'offline-vault-init':
                return self._offline_initialize(plan)
            return self._backup(plan)
        finally:
            os.umask(previous_mask)

    def _prepare(self, plan):
        # mkdir is exclusive; root may only be an already observed empty private
        # directory. No foreign path is adopted, chmodded, chowned or removed.
        with bound_parent(self.root.parent, plan['parentObservation']) as parent:
            root_entry = plan['before']['entry']
            if root_entry is None:
                os.mkdir(self.root.name, 0o700, dir_fd=parent)
                root_entry = entry_stat(self.root.name, parent)
                require(root_entry is not None, 'new root disappeared; no material generation')
            # An operator may have just created the observed empty root without
            # syncing its parent. Sync the bound parent in BOTH branches before
            # intent/entropy; root fsync alone cannot persist its parent entry.
            # This does not establish durability of the parent's own ancestry or
            # protect against external deletion, rollback or temporary cleanup.
            os.fsync(parent)
            with owned_directory(self.root.name, directory_fd=parent, expected=root_entry) as directory:
                require_path_identity(self.root.name, directory, parent)
                with os.scandir(directory) as entries:
                    require(next(entries, None) is None, 'nonempty root refuses initialization')
                opts = plan['options']
                intent = {'schemaVersion': 1, 'owner': OWNER, 'profile': PROFILE, 'planHash': plan['planHash'],
                          'requestKey': opts['requestKey'], 'uid': os.geteuid(), 'root': str(self.root),
                          'generationReservation': 'consumed', 'sourceMode': 'generate' if opts['generate'] else 'import'}
                new_file(directory, INTENT_PENDING, canonical(intent) + b'\n')
                publish_pending(directory, INTENT_PENDING, INTENT)
                for name in DIRECTORIES:
                    os.mkdir(name, 0o700, dir_fd=directory)
                os.fsync(directory)
                require_path_identity(self.root.parent, parent)
                require_path_identity(self.root.name, directory, parent)
                # All failures after intent preserve the consumed root. There is
                # intentionally no catch-and-regenerate or destructive rollback.
                if opts['generate']:
                    decoded = {'username': opts['username'], 'token': secrets.token_urlsafe(32),
                               'vault': {'masterKeyHex': secrets.token_hex(32), 'credentials': []}}
                else:
                    raw = private_bytes(opts['importFile'], expected=opts['source']['entry'])
                    require(digest(raw) == self._private_guard['importDigest'], 'private import changed after confirmation')
                    decoded = material(raw)
                raw = canonical(decoded) + b'\n'
                material(raw)
                new_file(directory, PENDING, raw)
                publish_pending(directory, PENDING, MATERIAL)
                prepared = {'schemaVersion': 1, 'owner': OWNER, 'profile': PROFILE, 'uid': os.geteuid(),
                            'root': str(self.root), 'username': opts['username'], 'namespace': opts['namespace'],
                            'materialSha256': digest(raw), 'journalId': plan['planHash'],
                            'authorityBinding': None, 'vaultProvisioning': 'not_performed'}
                new_file(directory, MANIFEST, canonical(prepared) + b'\n')
                decoded = raw = None
                require_path_identity(self.root.parent, parent)
                require_path_identity(self.root.name, directory, parent)
                return prepared_status(self.root, prepared)

    def _offline_initialize(self, plan):
        from vp_maintenance_bridge import execute, MaintenanceUncertain
        with bound_parent(self.root.parent, plan['parentObservation']) as parent:
            with owned_directory(self.root.name, directory_fd=parent, expected=plan['before']['entry']) as directory:
                prepared, _, decoded = confirmed_material(self.root, directory, plan, self._private_guard)
                require(prepared['materialSha256'] == self._private_guard['materialDigest'], 'material changed; offline init refused')
                require_path_identity(self.root.parent, parent)
                require_path_identity(self.root.name, directory, parent)
                for name in (OFFLINE_INTENT, OFFLINE_PENDING, OFFLINE_RESULT):
                    require(entry_stat(name, directory) is None, 'offline initialization already attempted; no retry')
                with owned_directory('vault', directory_fd=directory, expected=plan['options']['vaultIdentity'], lock=False) as vault:
                    with os.scandir(vault) as entries:
                        require(next(entries, None) is None, 'nonempty vault refuses initialization')
                    require_path_identity('vault', vault, directory)
                    intent = {'schemaVersion': 1, 'operationId': plan['options']['requestKey'],
                              'planHash': plan['planHash'], 'maintenanceSha256': plan['options']['maintenanceSha256'],
                              'status': 'consumed_do_not_retry', 'recoveryEligible': False}
                    new_file(directory, OFFLINE_PENDING, canonical(intent) + b'\n')
                    publish_pending(directory, OFFLINE_PENDING, OFFLINE_INTENT)
                    # The root lock prevents another cooperating bootstrap operator;
                    # maintenance obtains its own vault lifetime lock. No vault lock
                    # is held here, otherwise the child would correctly return BUSY.
                    require_path_identity(self.root.name, directory, parent)
                    require_path_identity('vault', vault, directory)
                    result = execute('vault-init-bound', plan['options']['maintenanceArtifact'],
                                     plan['options']['maintenanceSha256'], self.root / 'vault',
                                     prepared['namespace'], plan['options']['requestKey'],
                                     decoded['vault']['masterKeyHex'],
                                     expected_vault_directory={k: plan['options']['vaultIdentity'][k] for k in ('device', 'inode')})
                    decoded = None
                    require_path_identity(self.root.name, directory, parent)
                    require_path_identity('vault', vault, directory)
                    new_file(directory, OFFLINE_RESULT, canonical(result) + b'\n')
                    return {**result, 'status': 'offline_vault_initialized_only',
                            'administratorSessionCreated': False, 'controlDatabaseInitialized': False,
                            'serviceReady': False, 'publicHttpsVerified': False}

    def _backup(self, plan):
        with bound_parent(self.root.parent, plan['parentObservation']) as parent:
            with owned_directory(self.root.name, directory_fd=parent, expected=plan['before']['entry']) as root_directory:
                prepared, raw, _ = confirmed_material(self.root, root_directory, plan, self._private_guard)
                require(prepared['materialSha256'] == self._private_guard['materialDigest'], 'material changed; backup refused')
                require_path_identity(self.root.parent, parent)
                require_path_identity(self.root.name, root_directory, parent)
                target = Path(plan['options']['backupFile'])
                with owned_directory(target.parent, expected=plan['options']['backupParent']) as directory:
                    current = os.fstat(directory); root_identity = os.fstat(root_directory)
                    require((current.st_dev, current.st_ino) != (root_identity.st_dev, root_identity.st_ino),
                            'backup parent aliases the material root')
                    require_path_identity(target.parent, directory)
                    pending = '.' + target.name + '.pending'
                    new_file(directory, pending, raw)
                    publish_pending(directory, pending, target.name)
                    require_path_identity(target.parent, directory)
                    require_path_identity(self.root.name, root_directory, parent)
                raw = None
        return {'status': 'private_plaintext_key_backup_created', 'backupFile': str(target),
                'materialMatchesPrivateManifest': True, 'encrypted': False,
                'databaseOrVaultSnapshot': False, 'restoreEligible': False, 'authorityBinding': None}

    def show_admin_token(self, plan, confirmation):
        require(sys.stdin.isatty() and sys.stdout.isatty(), 'administrator token display requires explicit real terminal input/output')
        require(plan['action'] == 'show-admin-token' and confirmation == plan['planHash'], 'exact token-display confirmation required')
        require(self.plan('show-admin-token', {}) == plan, 'material changed since display confirmation')
        with bound_parent(self.root.parent, plan['parentObservation']) as parent:
            with owned_directory(self.root.name, directory_fd=parent, expected=plan['before']['entry']) as directory:
                prepared, _, decoded = confirmed_material(self.root, directory, plan, self._private_guard)
                require(prepared['materialSha256'] == self._private_guard['materialDigest'], 'material changed; display refused')
                require_path_identity(self.root.parent, parent)
                require_path_identity(self.root.name, directory, parent)
                require(sys.stdout.isatty(), 'terminal changed; no file/pipe fallback')
                sys.stdout.write(decoded['token'] + '\n'); sys.stdout.flush()
                decoded = None


def launch_plan(engine, args):
    prepared, _, _ = verified_material(engine.root)
    require(args.vault_action in ('initialize', 'open'), 'explicit --vault-action initialize|open required; never fallback from open')
    if args.vault_action == 'open' or any(any((engine.root / name).iterdir()) for name in DIRECTORIES):
        return {**recovery_status(), 'status': 'launch_requires_authoritative_inspection',
                'commandArgv': None, 'executionAllowed': False, 'serviceReady': False}
    require(args.daemon and args.worker and HEX.fullmatch(args.daemon_sha256 or '') and HEX.fullmatch(args.worker_sha256 or ''),
            'explicit local artifact paths and independently trusted expected digests required')
    daemon = safe_absolute(args.daemon); worker = safe_absolute(args.worker)
    for path, expected in ((daemon, args.daemon_sha256), (worker, args.worker_sha256)):
        require(digest(read_regular(path, 128 * 1024 * 1024)) == expected, 'local artifact digest mismatch')
    require(isinstance(args.bind, str) and re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', args.bind), 'explicit IPv4 loopback bind required')
    require(1 <= int(args.bind.split(':')[1]) <= 65535, 'invalid loopback port')
    parsed = urlsplit(args.origin or '')
    require(parsed.scheme in ('http', 'https') and parsed.hostname and not parsed.path and not parsed.query and
            not parsed.fragment and not parsed.username and not parsed.password, 'explicit canonical Origin required')
    require(parsed.scheme == 'https' or args.origin == 'http://' + args.bind, 'local HTTP Origin must exactly match loopback bind')
    command = [str(daemon), '--state-root', str(engine.root / 'control'), '--bind', args.bind, '--origin', args.origin,
               '--runtime-profile', 'loopback-vless-v1', '--runtime-root', str(engine.root / 'runtime'),
               '--worker', str(worker), '--worker-sha256', args.worker_sha256,
               '--vault-root', str(engine.root / 'vault'), '--vault-namespace', prepared['namespace'],
               '--vault-action', args.vault_action, '--probe-bind', '127.0.0.1:0']
    require(bool(args.subscription_public_base) == bool(args.subscription_network_profile), 'subscription base/profile must be explicit together')
    if args.subscription_public_base:
        base = urlsplit(args.subscription_public_base)
        require(base.hostname and not base.path and not base.query and not base.fragment and not base.username and not base.password,
                'canonical trusted subscription base required')
        require((args.subscription_network_profile == 'https' and base.scheme == 'https') or
                (args.subscription_network_profile == 'development-loopback' and args.subscription_public_base == args.origin
                 and parsed.scheme == 'http'), 'subscription network policy mismatch; no inferred public URL')
        command.extend(['--subscription-public-base', args.subscription_public_base,
                        '--subscription-network-profile', args.subscription_network_profile])
    return {'status': 'launch_arguments_only_not_executed', 'commandArgv': command,
            'stdinFile': str(engine.root / MATERIAL), 'secretEnv': {}, 'secretsInArgv': False,
            'runtimeProfile': 'loopback-vless-v1', 'vaultInitializationPerformed': False,
            'artifactCompatibility': {'status': 'unavailable', 'sqlLayout': None, 'payload': None, 'bundleV2Accepted': False},
            'externalHttps': 'not_configured_or_verified', 'localhostPhoneReachable': False,
            'executionAllowed': False, 'serviceReady': False, 'allPresetCertification': False,
            'warnings': ['foreground daemon initialize binds HTTP/runtime; it is NOT offline vault initialization',
                         'HTTPS Origin/base does not install TLS termination, certificate, proxy or DNS',
                         'never package payload2 under bundle-v1 storageSchema=1 compatibility',
                         'lost/old keys and existing state require authoritative inspection; no restore or adoption']}


class RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error includes arbitrary argv text. Even accidental
        # unsupported secret arguments must not be echoed to stderr.
        raise InstallError('invalid bootstrap arguments')


# Explicit offline init uses only the validated bound-directory Rust contract.
def parser():
    value = RedactedArgumentParser(description=__doc__)
    value.add_argument('action', choices=('prepare', 'status', 'backup-key', 'restore-key', 'resume', 'show-admin-token', 'launch-plan', 'offline-vault-init'))
    value.add_argument('--root', required=True)
    value.add_argument('--username'); value.add_argument('--namespace'); value.add_argument('--request-key')
    value.add_argument('--generate-bootstrap', action='store_true')
    value.add_argument('--import-bootstrap-file'); value.add_argument('--backup-file')
    value.add_argument('--acknowledge-plaintext-key-backup', action='store_true')
    value.add_argument('--dry-run', action='store_true'); value.add_argument('--confirm-plan-sha256')
    value.add_argument('--maintenance-artifact'); value.add_argument('--maintenance-sha256')
    value.add_argument('--daemon'); value.add_argument('--daemon-sha256'); value.add_argument('--worker'); value.add_argument('--worker-sha256')
    value.add_argument('--bind'); value.add_argument('--origin'); value.add_argument('--vault-action', choices=('initialize', 'open'))
    value.add_argument('--subscription-public-base')
    value.add_argument('--subscription-network-profile', choices=('https', 'development-loopback'))
    return value


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        engine = Bootstrap(args.root)
        if args.action == 'status':
            print(json.dumps(status(engine.root), indent=2)); return 0
        if args.action == 'launch-plan':
            print(json.dumps(launch_plan(engine, args), indent=2)); return 0
        options = {'username': args.username, 'namespace': args.namespace, 'requestKey': args.request_key,
                   'generate': args.generate_bootstrap, 'importFile': args.import_bootstrap_file,
                   'backupFile': args.backup_file, 'acknowledgePlaintext': args.acknowledge_plaintext_key_backup,
                   'maintenanceArtifact': args.maintenance_artifact, 'maintenanceSha256': args.maintenance_sha256}
        plan = engine.plan(args.action, options)
        print(json.dumps(plan, indent=2))
        if args.action in ('restore-key', 'resume'):
            print('RecoveryNeedsVerification: no restore, adoption, regeneration or service action performed.', file=sys.stderr)
            return 3
        if args.dry_run:
            return 0
        confirmation = args.confirm_plan_sha256
        if args.action == 'show-admin-token':
            require(sys.stdin.isatty() and sys.stdout.isatty() and not confirmation,
                    'show-admin-token always requires a fresh interactive TTY confirmation; no automated display')
        if sys.stdin.isatty():
            require(confirmation is None or confirmation == plan['planHash'], 'TTY plan confirmation hash mismatch')
            words = {'prepare': '准备敏感材料', 'backup-key': '备份明文密钥', 'show-admin-token': '显示管理员令牌', 'offline-vault-init': '初始化离线密钥库'}
            print('风险：bootstrap文件包含管理员令牌和vault主密钥，0600并非加密；备份泄漏会暴露权限。', file=sys.stderr)
            print('不会建立主机账号、启动服务、配置TLS或证明隧道可用；master key不会打印。', file=sys.stderr)
            if args.action == 'prepare':
                print('仅限已有可信持久父根中的全新材料准备；目录缺失不证明没有历史身份。外部删除/回滚、未持久祖先或临时目录清理不受本地intent保护；恢复请停止。', file=sys.stderr)
            word = words[args.action]
            if input('输入“' + word + '”确认当前完整计划，回车取消: ').strip() != word:
                print('已取消，未写入或生成材料。'); return 0
            confirmation = plan['planHash']
        if not confirmation:
            print('Plan only; no material generated or file written. Exact hash confirmation is required.')
            return 0
        if args.action == 'show-admin-token':
            engine.show_admin_token(plan, confirmation); return 0
        result = engine.apply(plan, confirmation, options)
        print(json.dumps(result, indent=2)); return 0
    except (Exception, KeyboardInterrupt):
        # Third-party/parser/programming exception text can contain input bytes.
        # The CLI boundary must never emit exception repr or a traceback.
        print('vp-bootstrap: operation refused/interrupted; inspect private state. No recovery or key regeneration inferred.', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
