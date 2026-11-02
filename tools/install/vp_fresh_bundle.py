"""Strict private fresh-runtime bundle; intentionally not accepted by v1 installer.

Reading never executes members. Descriptor production executes only explicitly
operator-pinned authored artifacts through the existing sealed execution bridge.
"""
import subprocess
import os
import stat
from pathlib import Path
from vp_install import (Bundle, require, exact_keys, IDENT, HEX, host_arch,
                        MAX_FILES, MAX_FILE, safe_relative, strict_json, canonical, digest, check_ancestors)
from vp_host_preflight import check_sealed_runtime_host
from vp_maintenance_bridge import sealed_artifact, bounded_exchange, elf_header

PROFILE = 'fresh-runtime-v1'
DAEMON = 'bin/vp-product-fresh-runtime'
WORKER = 'bin/vp-core-managed-worker'
MAINTENANCE = 'bin/vp-product-maintenance'
REQUIRED = {DAEMON, WORKER, MAINTENANCE, 'core-lock.json',
            'contracts/capabilities/presets.json', 'web/index.html'}
MAINTENANCE_CAPABILITY = {'action': 'vault-init-bound', 'protocolVersion': 1,
                          'controlInspectionSupported': False}
HOST = {'os': 'Linux', 'minimumKernel': '6.3', 'sealedExecutableRequired': True,
        'pathExecutionFallback': False}
CONTROL = {'sqlLayout': {'readVersions': [1], 'writeVersion': 1},
           'payload': {'readVersions': [3], 'writeVersion': 3}}


WEB_FILE = 32 * 1024 * 1024
WEB_TOTAL = 256 * 1024 * 1024


def validate_web_records(records):
    names = set(records)
    for name in names:
        parts = name.split('/')
        require(not any('/'.join(parts[:i]) in names for i in range(1, len(parts))),
                'file/directory prefix collision')
    web = {name: item for name, item in records.items() if name.startswith('web/')}
    dirs = set(); total = 0
    for name, item in web.items():
        parts = name.split('/')[1:]
        require(len(parts) - 1 <= 32 and item['size'] <= WEB_FILE, 'web file/depth limit')
        dirs.update('/'.join(parts[:i]) for i in range(1, len(parts)))
        total += item['size']
    require(len(dirs) + len(web) <= 4096 and total <= WEB_TOTAL, 'web tree limit')


def validate_web_tree(root, private_roots=()):
    root = Path(root)
    require(root.is_absolute() and root.resolve() == root and root.is_dir(), 'canonical web root required')
    check_ancestors(root)
    private_ids = set()
    for private in private_roots:
        private = Path(private)
        require(root != private and root not in private.parents and private not in root.parents,
                'web/private root overlap')
        value = private.stat(); private_ids.add((value.st_dev, value.st_ino))
    count = total = 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        directory = Path(parent); value = directory.lstat()
        require(stat.S_ISDIR(value.st_mode) and value.st_uid in (0, os.geteuid()) and
                not value.st_mode & 0o022 and (value.st_dev, value.st_ino) not in private_ids and
                len(directory.relative_to(root).parts) <= 32, 'untrusted/deep web directory')
        for name in dirs + files:
            value = (directory/name).lstat(); count += 1
            require(count <= 4096 and value.st_uid in (0, os.geteuid()) and not value.st_mode & 0o022,
                    'untrusted/oversized web tree')
            if stat.S_ISDIR(value.st_mode): continue
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_size <= WEB_FILE,
                    'untrusted/oversized web file')
            total += value.st_size
            require(total <= WEB_TOTAL, 'web total size limit')

def exact_value(actual, expected, message):
    # Canonical bytes preserve bool/int distinction, unlike Python dict equality.
    require(canonical(actual) == canonical(expected), message)


def validate_descriptor(value, daemon_sha, worker_sha):
    exact_keys(value, ('descriptorVersion', 'metadata', 'artifactSetDigest', 'createsState', 'startsService'))
    exact_value([value['descriptorVersion'], value['createsState'], value['startsService']],
                [2, False, False], 'unsupported stateful descriptor')
    m = value['metadata']
    exact_keys(m, ('artifactBindingVersion', 'coreAbiMajor', 'coreAbiMinor', 'coreCommit',
                   'executableSha256', 'payloadRead', 'payloadWrite', 'profile',
                   'runtimeAvailable', 'runtimeJournalPayload', 'sqlLayout',
                   'vaultBindingKind', 'workerSha256', 'publicationDelivery',
                   'publicationNetworkPolicy', 'explicitWebRoot', 'managementApiVersion'))
    expected = {'artifactBindingVersion': 1, 'coreAbiMajor': 1, 'coreAbiMinor': 1,
                'coreCommit': 'e96584fb8c7a38aa2c24beb89dcf969e70c24c93',
                'executableSha256': daemon_sha, 'payloadRead': 3, 'payloadWrite': 3,
                'profile': PROFILE, 'runtimeAvailable': True, 'runtimeJournalPayload': 2,
                'sqlLayout': 1, 'vaultBindingKind': 5, 'workerSha256': worker_sha,
                'publicationDelivery': True, 'publicationNetworkPolicy': 'explicit_same_origin_loopback',
                'explicitWebRoot': True, 'managementApiVersion': 1}
    exact_value(m, expected, 'unsupported or artifact-mismatched runtime descriptor')
    require(isinstance(daemon_sha, str) and HEX.fullmatch(daemon_sha) and
            isinstance(worker_sha, str) and HEX.fullmatch(worker_sha), 'artifact digest required')
    require(value['artifactSetDigest'] == digest(b'vp.fresh-artifact-set.v1\0' + canonical(m)),
            'artifact-set digest mismatch')
    return value


def describe(daemon, daemon_sha, worker, worker_sha):
    require(check_sealed_runtime_host()['prerequisitesAvailable'], 'sealed runtime host prerequisites unavailable')
    require(Path(worker).is_absolute(), 'absolute pinned worker required')
    # VerifiedWorker itself captures and seals the exact worker bytes. Do not pass
    # /proc/self/fd as its user path: its source opener intentionally uses NOFOLLOW.
    with sealed_artifact(Path(daemon), daemon_sha) as fd:
        process = subprocess.Popen([f'/proc/self/fd/{fd}', 'describe', '--worker', str(worker),
                                    '--worker-sha256', worker_sha], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={}, close_fds=True, pass_fds=(fd,))
        code, raw = bounded_exchange(process, bytearray(b'\n'))
    require(code == 0, 'runtime descriptor refused')
    return validate_descriptor(strict_json(raw), daemon_sha, worker_sha)


class FreshBundle(Bundle):
    removal_only = False

    def validate_architecture(self, architecture):
        require(architecture == host_arch(), 'bundle architecture mismatch')

    def validate_elf(self, raw):
        elf_header(raw)

    def _validate_manifest(self):
        m = self.manifest
        exact_keys(m, ('schemaVersion', 'profile', 'releaseId', 'productVersion', 'engine',
                       'architecture', 'files', 'coreLockSha256', 'controlState',
                       'runtimeJournalPayload', 'vaultBindingKind', 'compatibilityDescriptor',
                       'maintenance', 'hostRequirements'))
        exact_value([m['schemaVersion'], m['profile'], m['engine']], [2, PROFILE, 'vp_core'],
                    'unsupported fresh bundle profile')
        for field in ('releaseId', 'productVersion'):
            require(isinstance(m[field], str) and IDENT.fullmatch(m[field]), 'invalid release identity')
        self.validate_architecture(m['architecture'])
        exact_value(m['controlState'], CONTROL, 'unsupported control compatibility')
        exact_value([m['runtimeJournalPayload'], m['vaultBindingKind']], [2, 5], 'unsupported runtime/vault format')
        exact_value(m['maintenance'], MAINTENANCE_CAPABILITY, 'unsupported maintenance capability')
        exact_value(m['hostRequirements'], HOST, 'unsupported execution requirements')
        require(isinstance(m['files'], list) and 1 <= len(m['files']) < MAX_FILES, 'invalid files')
        records = {}
        for f in m['files']:
            exact_keys(f, ('path', 'size', 'sha256', 'executable'))
            name = safe_relative(f['path'])
            require(name not in records and (name in REQUIRED or name.startswith('web/')), 'unapproved/duplicate member')
            require(type(f['size']) is int and 0 <= f['size'] <= MAX_FILE and
                    isinstance(f['sha256'], str) and HEX.fullmatch(f['sha256']) and
                    type(f['executable']) is bool and f['executable'] == name.startswith('bin/'), 'invalid member metadata')
            records[name] = f
        require(REQUIRED <= records.keys(), 'required fresh product component missing')
        validate_web_records(records)
        for name in (DAEMON, WORKER, MAINTENANCE):
            require(records[name]['size'] >= 64, 'native executable header required')
            with self.zip.open(name) as stream:
                self.validate_elf(stream.read(64))
        require(m['coreLockSha256'] == records['core-lock.json']['sha256'], 'core lock digest mismatch')
        descriptor = validate_descriptor(m['compatibilityDescriptor'], records[DAEMON]['sha256'], records[WORKER]['sha256'])
        require(self.zip.getinfo('core-lock.json').file_size <= 128 * 1024, 'core lock too large')
        core = strict_json(self.zip.read('core-lock.json'))
        require(isinstance(core, dict) and isinstance(core.get('integration'), dict) and
                core['integration'].get('commit') == descriptor['metadata']['coreCommit'], 'core integration identity mismatch')
