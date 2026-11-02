"""Explicit private fresh installation stages. No service registration or upgrades.

Installation metadata and bootstrap material roots must be separate siblings.
Cooperative same-UID tools and stable trusted paths are required; this does not
claim protection against hostile same-UID mutation or physical rollback.
"""
import contextlib
import hashlib
import os
from pathlib import Path
import signal
import time
from urllib.parse import urlsplit
from vp_install import (require, InstallError, safe_absolute, check_ancestors,
                        canonical, digest, strict_json, read_regular, MAX_FILE, exact_keys, HEX)
import vp_bootstrap as b
from vp_fresh_bundle import (FreshBundle, PROFILE, DAEMON, WORKER, MAINTENANCE,
                             validate_descriptor, describe, validate_web_tree)
from vp_host_preflight import check_sealed_runtime_host
from vp_maintenance_bridge import source_chunks
from vp_owned_runtime import OwnedRuntime

OWNER = 'vp-fresh-local-installer'
RECORD = 'installation.json'
ACTIVATION = 'activation-intent.json'
READY = 'activation-ready.json'
UNINSTALLED = 'profile-disabled-all-files-retained.json'
LEGACY_UNINSTALLED = 'uninstalled-retained.json'
DISABLED_MARKERS = {UNINSTALLED, LEGACY_UNINSTALLED}
REMOVAL_INTENT = 'program-removal-intent.json'
REMOVAL_RECEIPT = 'program-removal-receipt.json'
NAMES = {REMOVAL_INTENT, REMOVAL_RECEIPT, RECORD, 'install-intent.json', 'release', ACTIVATION, READY, *DISABLED_MARKERS}


def identity(path):
    with b.owned_directory(path, lock=False) as fd:
        st = os.fstat(fd)
        return {'device': st.st_dev, 'inode': st.st_ino}


def observe(root):
    entry = b.entry_stat(root)
    if entry is None: return {'entry': None, 'files': {}, 'entries': []}
    with b.owned_directory(root, expected=entry, lock=False) as fd:
        names = sorted(os.listdir(fd)); require(set(names) <= NAMES, 'unknown installation state; no adoption')
        files = {name: digest(b.private_bytes(name, fd)) for name in names if name != 'release'}
        b.require_path_identity(root, fd)
    return {'entry': entry, 'files': files, 'entries': names}


def validate_endpoint(bind, origin):
    parsed = urlsplit(origin)
    require(parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and
            parsed.port is not None and 0 < parsed.port < 65536 and not parsed.path and
            not parsed.query and not parsed.fragment and not parsed.username and not parsed.password and
            origin == 'http://' + bind and bind == '127.0.0.1:' + str(parsed.port),
            'this private profile requires explicit canonical IPv4 loopback origin')


class FreshLocal:
    def __init__(self, root, materials):
        self.root = safe_absolute(root); self.materials = safe_absolute(materials)
        require(self.root.parent == self.materials.parent and self.root != self.materials,
                'installation and materials must be distinct sibling roots')
        check_ancestors(self.root.parent)
        require(self.root.parent.is_dir(), 'existing trusted parent required')

    def record(self):
        value = strict_json(b.private_bytes(self.root / RECORD))
        exact_keys(value, ('schemaVersion','owner','profile','root','materials','bundleSha256','manifestDigest'))
        require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1 and
                all(isinstance(value[k],str) and HEX.fullmatch(value[k]) for k in ('bundleSha256','manifestDigest')),
                'invalid installation record')
        require(isinstance(value, dict) and value.get('owner') == OWNER and
                value.get('profile') == PROFILE and value.get('root') == str(self.root) and
                value.get('materials') == str(self.materials), 'foreign installation record')
        return value

    def verify_release(self):
        record = self.record()
        release = self.root / 'release'
        raw = read_regular(release / 'manifest.json', 128 * 1024)
        require(digest(raw) == record['manifestDigest'], 'release manifest changed')
        manifest = strict_json(raw)
        names = {'manifest.json'}
        for item in manifest['files']:
            path = release / item['path']; names.add(item['path'])
            h = hashlib.sha256(); length = 0
            for block in source_chunks(path, time.monotonic() + 10) if item['executable'] else [read_regular(path, MAX_FILE)]:
                h.update(block); length += len(block)
            require(h.hexdigest() == item['sha256'] and length == item['size'], 'release artifact changed')
        validate_web_tree(release/'web')
        actual = set()
        for parent, dirs, files in os.walk(release, followlinks=False):
            require(not any((Path(parent)/name).is_symlink() for name in dirs + files), 'release symlink refused')
            actual.update((Path(parent)/name).relative_to(release).as_posix() for name in files)
        require(actual == names, 'release inventory changed')
        validate_descriptor(manifest['compatibilityDescriptor'], self.hash_for(manifest, DAEMON), self.hash_for(manifest, WORKER))
        return manifest

    @staticmethod
    def hash_for(manifest, path):
        return next(item['sha256'] for item in manifest['files'] if item['path'] == path)

    def plan(self, action, bundle=None, bind=None, origin=None):
        require(action in ('install', 'serve-fresh', 'serve-paired', 'uninstall'),
                'upgrade, rollback, recovery and adoption unavailable')
        host = check_sealed_runtime_host()
        require(host['prerequisitesAvailable'], 'sealed runtime host prerequisites unavailable; no writes')
        before = observe(self.root)
        value = {'schemaVersion': 1, 'owner': OWNER, 'profile': PROFILE, 'action': action,
                 'root': str(self.root), 'materials': str(self.materials), 'parent': b.entry_stat(self.root.parent),
                 'before': before, 'host': host, 'serviceRegistration': False, 'hostChanges': False,
                 'recoveryEligible': False, 'upgradeAvailable': False, 'rollbackAvailable': False}
        guard = {}
        if action == 'install':
            require(isinstance(bundle, FreshBundle) and not bundle.removal_only, 'verified native fresh bundle required')
            require(before['entry'] is None, 'install requires absent root; no adoption/retry')
            value['bundleSha256'] = bundle.sha256
            value['manifestDigest'] = digest(canonical(bundle.manifest))
            value['changes'] = ['consume install intent', 'extract exact verified local release; start no service']
        else:
            require(not DISABLED_MARKERS.intersection(before['entries']), 'profile disabled; all files retained, no adoption')
            manifest = self.verify_release()
            value['artifactSetDigest'] = manifest['compatibilityDescriptor']['artifactSetDigest']
            if action == 'uninstall':
                value['operation'] = 'disable_local_profile_retain_all_files'
                value['removesProgramFiles'] = False
                value['allFilesRetained'] = True
                value['changes'] = ['disable this local profile under exclusive lifetime lock; NOT program-file removal',
                                    'retain release, bootstrap, vault, control and runtime; delete nothing']
            else:
                validate_endpoint(bind, origin)
                state, fingerprints = b.root_snapshot(self.materials)
                prepared, _, _ = b.verified_material(self.materials)
                require(b.OFFLINE_RESULT in state['entries'], 'explicit bound offline initialization required')
                value.update(bind=bind, origin=origin, materialBefore=state,
                             directoryIdentities={name: identity(self.materials/name) for name in b.DIRECTORIES})
                validate_web_tree(self.root/'release'/'web', [self.materials/name for name in b.DIRECTORIES])
                guard = {'rootFileDigests': fingerprints}
                if action == 'serve-fresh':
                    require(ACTIVATION not in before['entries'] and READY not in before['entries'],
                            'activation already attempted; no fresh retry/adoption')
                    for name in ('control', 'runtime'):
                        with b.owned_directory(self.materials/name, lock=False) as fd:
                            require(not os.listdir(fd), 'fresh activation requires empty control/runtime')
                    value['preparationDigest'] = digest(canonical(prepared))
                else:
                    require(ACTIVATION in before['entries'] and READY in before['entries'],
                            'paired startup requires prior observed ready; no partial-state recovery')
                value['changes'] = ['consume explicit activation intent before first start' if action == 'serve-fresh' else 'open exact previously paired artifact set',
                                    'send existing materials only over stdin', 'supervise owned foreground child; SIGINT/TERM stop owned service']
        value['planHash'] = digest(canonical({'public': value, 'guard': guard}))
        self.guard = guard
        return value

    def plan_bootstrap(self, action, options):
        require(action in ('prepare', 'offline-vault-init'), 'unsupported preparation stage')
        require(check_sealed_runtime_host()['prerequisitesAvailable'], 'sealed host prerequisites unavailable')
        before = observe(self.root)
        require(not DISABLED_MARKERS.intersection(before['entries']), 'disabled profile cannot prepare or initialize')
        manifest = self.verify_release()
        opts = dict(options)
        if action == 'offline-vault-init':
            opts = {'requestKey': options.get('requestKey'),
                    'maintenanceArtifact': str(self.root/'release'/MAINTENANCE),
                    'maintenanceSha256': self.hash_for(manifest, MAINTENANCE)}
        bootstrap = b.Bootstrap(self.materials)
        inner = bootstrap.plan(action, opts)
        value = {'schemaVersion': 1, 'owner': OWNER, 'profile': PROFILE,
                 'action': action, 'root': str(self.root), 'materials': str(self.materials),
                 'installationBefore': before, 'manifestDigest': digest(canonical(manifest)),
                 'bootstrapPlan': inner, 'serviceChanges': False, 'hostChanges': False}
        value['planHash'] = digest(canonical(value))
        self._bootstrap = bootstrap; self._bootstrap_options = opts
        return value

    def apply_bootstrap(self, plan, confirmation, options):
        require(confirmation == plan['planHash'] and self.plan_bootstrap(plan['action'], options) == plan,
                'stale/unconfirmed installation-bound bootstrap plan')
        with b.owned_directory(self.root, expected=plan['installationBefore']['entry']) as fd:
            require(observe(self.root) == plan['installationBefore'], 'installation changed after confirmation')
            require(digest(canonical(self.verify_release())) == plan['manifestDigest'], 'release changed after confirmation')
            b.require_path_identity(self.root, fd)
            inner = plan['bootstrapPlan']
            return self._bootstrap.apply(inner, inner['planHash'], self._bootstrap_options)

    def apply_install(self, plan, confirmation, bundle):
        require(confirmation == plan['planHash'] and self.plan('install', bundle=bundle) == plan, 'stale/unconfirmed install plan')
        with b.bound_parent(self.root.parent, plan['parent']) as parent:
            os.mkdir(self.root.name, 0o700, dir_fd=parent); os.fsync(parent)
            with b.owned_directory(self.root.name, directory_fd=parent) as fd:
                b.new_file(fd, 'install-intent.json', canonical({'owner':OWNER,'planHash':confirmation,'status':'consumed_no_retry'}))
                b.require_path_identity(self.root.name, fd, parent)
                bundle.extract(self.root/'release')
                b.require_path_identity(self.root.name, fd, parent)
                record = {'schemaVersion':1,'owner':OWNER,'profile':PROFILE,'root':str(self.root),
                          'materials':str(self.materials),'bundleSha256':bundle.sha256,
                          'manifestDigest':digest(canonical(bundle.manifest))}
                b.new_file(fd, RECORD, canonical(record))
        return {'status':'private_release_installed_not_started','productionCertified':False}

    @contextlib.contextmanager
    def run(self, plan, confirmation, cancelled=lambda: False):
        action = plan['action']; require(action in ('serve-fresh','serve-paired'), 'not a foreground start plan')
        require(confirmation == plan['planHash'] and self.plan(action, bind=plan['bind'], origin=plan['origin']) == plan,
                'stale/unconfirmed activation plan')
        process = None
        with b.bound_parent(self.root.parent, plan['parent']) as parent:
            with b.owned_directory(self.root.name, directory_fd=parent, expected=plan['before']['entry']) as fd:
                require(observe(self.root) == plan['before'], 'installation changed after confirmation')
                manifest = self.verify_release()
                with b.owned_directory(self.materials, expected=plan['materialBefore']['entry']) as material_fd:
                    prepared, _, material = b.confirmed_material(self.materials, material_fd,
                        {'before':plan['materialBefore']}, self.guard)
                    validate_web_tree(self.root/'release'/'web', [self.materials/name for name in b.DIRECTORIES])
                    require({name:identity(self.materials/name) for name in b.DIRECTORIES} == plan['directoryIdentities'],
                            'data directory identity changed')
                    if action == 'serve-fresh':
                        intent = {'schemaVersion':1,'profile':PROFILE,'planHash':confirmation,
                                  'genesisId':digest(('vp-fresh-genesis:'+confirmation).encode())[:32],
                                  'artifactSetDigest':plan['artifactSetDigest'],
                                  'preparationDigest':plan['preparationDigest'],
                                  'directoryIdentities':plan['directoryIdentities']}
                        b.new_file(fd, ACTIVATION, canonical(intent))
                    else:
                        intent = strict_json(b.private_bytes(ACTIVATION, fd))
                        require(intent['artifactSetDigest'] == plan['artifactSetDigest'] and
                                intent['directoryIdentities'] == plan['directoryIdentities'] and
                                intent['preparationDigest'] == digest(canonical(prepared)), 'paired identity mismatch; no migration')
                    request = {'schemaVersion':1,'username':material['username'],'token':material['token'],
                               'masterKeyHex':material['vault']['masterKeyHex'],'namespace':prepared['namespace'],
                               'genesisId':intent['genesisId'],'preparationDigest':intent['preparationDigest'],
                               'activationIntentDigest':digest(canonical(intent)),
                               'artifactSetDigest':intent['artifactSetDigest'],'credentials':[]}
                    for name in b.DIRECTORIES:
                        request['expected'+name.title()+'Directory'] = plan['directoryIdentities'][name]
                    release = self.root/'release'
                    args = [action,'--control-root',str(self.materials/'control'),'--vault-root',str(self.materials/'vault'),
                            '--runtime-root',str(self.materials/'runtime'),'--bind',plan['bind'],'--origin',plan['origin'],
                            '--worker',str(release/WORKER),'--worker-sha256',self.hash_for(manifest,WORKER),
                            '--probe-bind','127.0.0.1:0','--publication-base',plan['origin'],
                            '--web-root',str(release/'web')]
                    b.require_path_identity(self.root.name, fd, parent)
                    b.require_path_identity(self.materials, material_fd)
                    try:
                        require(not cancelled(), 'startup canceled; retained intent, no retry')
                        process = OwnedRuntime(release/DAEMON, self.hash_for(manifest,DAEMON),self.hash_for(manifest,WORKER),args,request)
                        request = material = None
                        ready = process.await_ready(intent['genesisId'], cancelled=cancelled)
                        if action == 'serve-fresh':
                            b.new_file(fd, READY, canonical({'status':'http_ready_observed','activationIntentDigest':digest(canonical(intent)),
                                                           'productionCertified':False,'forwardingCertified':False}))
                        yield process, ready
                    finally:
                        request = material = None
                        if process is not None: process.stop()

    def uninstall(self, plan, confirmation):
        require(plan['action'] == 'uninstall' and confirmation == plan['planHash'] and self.plan('uninstall') == plan,
                'stale/unconfirmed uninstall plan')
        # The running foreground supervisor holds this same exclusive lock. We
        # never attempt to kill an alleged PID from disk. Stop its owner first.
        with b.owned_directory(self.root, expected=plan['before']['entry']) as fd:
            require(observe(self.root) == plan['before'], 'installation changed after confirmation')
            b.new_file(fd, UNINSTALLED, canonical({'owner':OWNER,'status':'profile_disabled_all_files_retained',
                                                 'planHash':confirmation,'deletedFiles':0,
                                                 'allFilesRetained':True,'removesProgramFiles':False}))
        return {'status':'profile_disabled_all_files_retained','deletedFiles':0,'allFilesRetained':True,
                'removesProgramFiles':False,'recoveryEligible':False}
