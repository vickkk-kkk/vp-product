#!/usr/bin/env python3
"""Package real local artifacts. No builds, downloads, signing or credential creation.
The resulting hash is NOT an independent trust anchor; distribute it securely.
"""
import argparse
import hashlib
import os
from pathlib import Path
import sys
import zipfile
from vp_install import ( InstallError, require, IDENT, host_arch, canonical,
                        MAX_ARCHIVE, MAX_FILES, MAX_FILE, MAX_TOTAL, safe_relative, read_regular)
from vp_fresh_bundle import (FreshBundle, describe, DAEMON, WORKER, MAINTENANCE, PROFILE,
                             CONTROL, HOST, MAINTENANCE_CAPABILITY, validate_web_tree)

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--managementd', required=True)
    p.add_argument('--worker', required=True)
    p.add_argument('--managementd-sha256', required=True)
    p.add_argument('--worker-sha256', required=True)
    p.add_argument('--maintenance', required=True)
    p.add_argument('--maintenance-sha256', required=True)
    p.add_argument('--web-root', required=True)
    p.add_argument('--core-lock', required=True)
    p.add_argument('--presets', required=True)
    p.add_argument('--release-id', required=True)
    p.add_argument('--product-version', required=True)
    p.add_argument('--output', required=True)
    args = p.parse_args(argv)
    output = Path(args.output)
    created = False
    try:
        require(IDENT.fullmatch(args.release_id) and IDENT.fullmatch(args.product_version), 'invalid release identity')
        files = {DAEMON: Path(args.managementd), MAINTENANCE: Path(args.maintenance), 'core-lock.json': Path(args.core_lock),
                 'contracts/capabilities/presets.json': Path(args.presets)}
        if args.worker:
            files[WORKER] = Path(args.worker)
        web = Path(args.web_root)
        validate_web_tree(web)
        require(web.is_dir() and not web.is_symlink(), 'real built Flutter web directory required')
        for parent, dirs, names in os.walk(web, followlinks=False):
            for name in dirs + names:
                require(not (Path(parent) / name).is_symlink(), 'symlink build artifact rejected')
            for name in names:
                path = Path(parent) / name
                # Flutter's local build fingerprint is not a served asset. Do not
                # broaden this exception to hidden files or arbitrary metadata.
                if path == web / '.last_build_id':
                    continue
                relative = 'web/' + path.relative_to(web).as_posix()
                safe_relative(relative)
                files[relative] = path
                require(len(files) < MAX_FILES, 'too many build artifacts')
        descriptor = describe(Path(args.managementd), args.managementd_sha256,
                              Path(args.worker), args.worker_sha256)
        manifest = {'schemaVersion': 2, 'profile': PROFILE, 'releaseId': args.release_id,
                    'productVersion': args.product_version, 'engine': 'vp_core',
                    'architecture': host_arch(), 'files': [], 'controlState': CONTROL,
                    'runtimeJournalPayload': 2, 'vaultBindingKind': 5, 'hostRequirements': HOST,
                    'maintenance': MAINTENANCE_CAPABILITY, 'compatibilityDescriptor': descriptor}
        total = 0
        blobs = {}
        for name, path in sorted(files.items()):
            data = read_regular(path, MAX_FILE)
            total += len(data)
            require(total <= MAX_TOTAL, 'build artifacts too large')
            blobs[name] = data
            manifest['files'].append({'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                                      'executable': name.startswith('bin/')})
        manifest['coreLockSha256'] = hashlib.sha256(blobs['core-lock.json']).hexdigest()
        for name, expected in ((DAEMON, args.managementd_sha256), (WORKER, args.worker_sha256),
                               (MAINTENANCE, args.maintenance_sha256)):
            require(hashlib.sha256(blobs[name]).hexdigest() == expected, 'pinned build artifact changed')
        blobs['manifest.json'] = canonical(manifest)
        # Deterministic metadata and stored ZIP: avoids bombs and hidden timestamps.
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        with os.fdopen(fd, 'wb') as stream:
            with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
                for name, data in sorted(blobs.items()):
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = (0o100755 if name.startswith('bin/') else 0o100644) << 16
                    archive.writestr(info, data)
            stream.flush()
            os.fsync(stream.fileno())
        require(output.stat().st_size <= MAX_ARCHIVE, 'bundle too large')
        h = hashlib.sha256(output.read_bytes()).hexdigest()
        with FreshBundle(output, h):
            pass
        print(h + '  ' + output.name)
        print('Unsigned private fresh-runtime bundle only; web build provenance must be reviewed separately. No production/all-protocol certification.', file=sys.stderr)
        return 0
    except (InstallError, OSError) as exc:
        if created:
            print('Rejected output retained; do not install or reuse it.', file=sys.stderr)
        print('build-fresh-bundle: ' + (str(exc) if isinstance(exc, InstallError) else 'artifact unavailable'), file=sys.stderr)
        return 2
if __name__ == '__main__':
    sys.exit(main())
