#!/usr/bin/env python3
"""Opt-in exact-binary CLI/daemon integration; private temp FS and loopback only.
Not discovered by unit tests. No systemd, public sockets, default production keys,
protocol certification or publication. Caller supplies already built artifact hashes.
"""
import argparse
import datetime
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parents[1]
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
from vp_install import Bundle


def objects(text):
    decoder = json.JSONDecoder()
    results = []
    lines = text.splitlines(keepends=True)
    position = 0
    joined = ''.join(lines)
    for line in lines:
        if line.startswith('{'):
            try:
                value, _ = decoder.raw_decode(joined[position:])
                results.append(value)
            except json.JSONDecodeError:
                pass
        position += len(line)
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--daemon', required=True, type=Path)
    p.add_argument('--daemon-sha256', required=True)
    p.add_argument('--worker', required=True, type=Path)
    p.add_argument('--worker-sha256', required=True)
    p.add_argument('--web-root', required=True, type=Path)
    p.add_argument('--evidence', required=True, type=Path)
    args = p.parse_args()
    token = secrets.token_urlsafe(32)
    key = secrets.token_hex(32)
    credential = str(uuid.uuid4())
    sensitive = [token.encode(), key.encode(), bytes.fromhex(key), credential.encode()]
    bootstrap = {'username': 'synthetic-cli-admin', 'token': token}

    def no_secret(data):
        assert all(value not in data for value in sensitive), 'secret leaked to output/state'

    def run(arguments, auth=False):
        result = subprocess.run([sys.executable, str(HERE/'vpctl.py')] + arguments,
                                input=json.dumps(bootstrap).encode() if auth else b'',
                                capture_output=True, timeout=90)
        no_secret(result.stdout + result.stderr)
        return result

    def good(arguments, auth=False):
        result = run(arguments, auth)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        return objects(result.stdout.decode())

    def port():
        with socket.socket() as owned:
            owned.bind(('127.0.0.1', 0))
            return owned.getsockname()[1]

    process = None
    worker_processes = {}
    with tempfile.TemporaryDirectory(prefix='vp-live-cli-') as directory:
        base = Path(directory); os.chmod(base, 0o700)
        archive = base/'local.zip'; root = base/'installation'
        packed = subprocess.run([sys.executable, str(HERE/'build_bundle.py'),
            '--managementd', str(args.daemon.resolve()), '--worker', str(args.worker.resolve()),
            '--web-root', str(args.web_root.resolve()), '--core-lock', str(REPO/'core-lock.json'),
            '--presets', str(REPO/'contracts/capabilities/presets.json'),
            '--release-id', 'local-cli-integration', '--product-version', '0.1.0-local',
            '--output', str(archive)], capture_output=True, timeout=90)
        assert packed.returncode == 0, packed.stderr.decode(errors='replace')
        bundle_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        with Bundle(archive, bundle_hash) as verified:
            manifest = verified.manifest
            hashes = {f['path']: f['sha256'] for f in manifest['files']}
            assert hashes['bin/vp-product-managementd'] == args.daemon_sha256
            assert hashes['bin/vp-core-managed-worker'] == args.worker_sha256
        common = ['--root', str(root)]
        install = ['install'] + common + ['--bundle', str(archive), '--sha256', bundle_hash,
            '--runtime-profile', 'loopback-vless-v1', '--vault-namespace', 'synthetic-cli-test']
        planned = good(install + ['--dry-run'])[0]
        assert not root.exists(), 'dry-run wrote installation root'
        installed = good(install + ['--confirm-plan-sha256', planned['planHash']])[-1]
        assert installed['installed'] and installed['forwarding'] == 'not_verified'
        status = good(['status'] + common)[0]['status']
        assert status['releaseIntegrity'] == 'verified_files_only'
        bind = f'127.0.0.1:{port()}'; origin = 'http://' + bind; listener_port = port()
        daemon = root/'current/bin/vp-product-managementd'
        worker = root/'current/bin/vp-core-managed-worker'
        inherited = dict(bootstrap, vault={'masterKeyHex': key, 'credentials': [
            {'reference': 'secret:synthetic-old-v1', 'version': 1, 'value': credential}]})
        process = subprocess.Popen([str(daemon), '--state-root', str(root/'data'),
            '--bind', bind, '--origin', origin, '--web-root', str(root/'current/web'),
            '--runtime-profile', 'loopback-vless-v1', '--runtime-root', str(root/'runtime'),
            '--worker', str(worker), '--worker-sha256', args.worker_sha256,
            '--vault-root', str(root/'vault'), '--vault-namespace', 'synthetic-cli-test',
            '--vault-action', 'initialize', '--probe-bind', '127.0.0.1:0'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stdin.write(json.dumps(inherited).encode()); process.stdin.close(); process.stdin = None
        try:
            deadline = time.monotonic() + 30
            while True:
                if process.poll() is not None:
                    out, err = process.communicate(); no_secret(out + err)
                    raise AssertionError('installed daemon failed startup: ' + err.decode(errors='replace'))
                try:
                    connection = http.client.HTTPConnection(bind, timeout=1)
                    connection.request('GET', '/api/v1/build', headers={'Host': bind, 'Origin': origin})
                    response = connection.getresponse(); response.read(); connection.close()
                    assert response.status == 401
                    break
                except OSError:
                    assert time.monotonic() < deadline, 'daemon readiness deadline'
                    time.sleep(.04)
            api = ['--origin', origin, '--credential-stdin']
            observed_build = good(['build'] + api, auth=True)[0]
            core_lock = json.loads((root/'current/core-lock.json').read_text())
            assert observed_build['release']['coreCommit'] == core_lock['upstream']['commit']
            assert observed_build['release']['patchsetHash'] == core_lock['patchset']['sha256']
            listed = run(['protocols'] + api, auth=True)
            assert listed.returncode == 0
            assert listed.stdout.count(b'required_public_baseline') == 21
            fixture = REPO/'crates/vp-managementd/tests/fixtures/vless_loopback.json'
            configuration = json.loads(fixture.read_text())
            configuration['listeners'][0]['bind']['port'] = listener_port
            dto = base/'config.json'; dto.write_text(json.dumps(configuration)); dto.chmod(0o600)
            configured = good(['configure'] + api + ['--config', str(dto), '--request-key', 'cli-live', '--dry-run'], auth=True)
            plan = next(item for item in configured if 'planHash' in item)
            before = good(['snapshot'] + api, auth=True)[0]
            assert before['desiredRevision'] == 0
            applied = good(['apply-plan'] + api + ['--plan-id', plan['id'], '--revision', str(plan['baseRevision']),
                '--confirm-plan-sha256', plan['planHash'], '--request-key', 'cli-live-apply', '--wait-seconds', '40'], auth=True)[-1]
            assert applied['status'] == 'succeeded'
            observed = good(['snapshot'] + api, auth=True)[0]
            assert observed['desiredRevision'] == observed['observedRevision'] == 1
            assert observed['listeners'][0]['forwarding']['status'] == 'passed'
            # Frozen e965/v1 test-only observation of our private runtime journal.
            # Do not depend on the optional /proc/task/*/children interface, and
            # never infer a process identity from a listening port.
            with (root/'runtime/runtime.journal.json').open('rb') as state:
                raw = state.read(8 * 1024 * 1024 + 1)
            assert len(raw) <= 8 * 1024 * 1024
            journal = json.loads(raw)['journal']
            assert journal['schemaVersion'] == 1 and journal['workerDigest'] == args.worker_sha256
            active = journal['active']
            assert active['generation'] == observed['listeners'][0]['generation']
            identity = active['process']; child = identity['pid']
            assert identity['bootId'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            fields = Path(f'/proc/{child}/stat').read_text().rsplit(')', 1)[1].split()
            assert int(fields[1]) == process.pid and fields[19] == identity['startTicks']
            worker_processes[child] = (fields[19], identity['bootId'])
            request = base/'export.json'; request.write_text('{}')
            destination = base/'must-not-exist.json'
            exported = run(['export'] + api + ['--request-file', str(request), '--output', str(destination)], auth=True)
            assert exported.returncode == 2 and b'503' in exported.stderr
            assert not destination.exists(), 'unimplemented export created a fabricated output'
        finally:
            if process.poll() is None: process.send_signal(signal.SIGTERM)
            try: out, err = process.communicate(timeout=40)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate(); raise AssertionError('daemon graceful stop timeout')
            no_secret(out + err)
            assert process.returncode == 0, 'daemon shutdown failed'
            process = None
        for child, (starttime, boot_id) in worker_processes.items():
            assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot_id
            try:
                fields = Path(f'/proc/{child}/stat').read_text().rsplit(')', 1)[1].split()
            except FileNotFoundError:
                continue
            assert fields[19] != starttime, 'owned worker process survived daemon shutdown'
        stopped = json.loads((root/'runtime/runtime.journal.json').read_text())['journal']
        assert stopped['active'] is None and stopped['launching'] is None, 'runtime stop not durable'
        with socket.socket() as closed:
            closed.settimeout(1)
            assert closed.connect_ex(('127.0.0.1', listener_port)) == errno.ECONNREFUSED, 'listener still accepts after shutdown'
        with socket.socket() as released:
            # Completed TCP connections may remain in TIME_WAIT. A new active
            # listener must still be exclusive: never use SO_REUSEPORT here.
            released.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            released.bind(('127.0.0.1', listener_port))
            released.listen(1)
        remove = good(['uninstall'] + common + ['--dry-run'])[0]
        removed = good(['uninstall'] + common + ['--confirm-plan-sha256', remove['planHash']])[-1]
        assert not removed['installed'] and (root/'data').is_dir() and (root/'vault').is_dir()
        for path in root.rglob('*'):
            if path.is_file(): no_secret(path.read_bytes())
        evidence = {'schemaVersion': 1, 'status': 'passed',
            'recordedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'installerSources': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(HERE.glob('*.py'))},
            'harnessSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'scope': 'temporary-filesystem + real installed loopback daemon/worker + CLI',
            'daemonSha256': args.daemon_sha256, 'workerSha256': args.worker_sha256, 'bundleSha256': bundle_hash,
            'coreLockSha256': manifest['coreLockSha256'], 'webIndexSha256': hashes['web/index.html'],
            'sharedConfigFixtureSha256': hashlib.sha256(fixture.read_bytes()).hexdigest(),
            'observedBuildIdentity': observed_build['release'],
            'checks': ['real-local-artifacts-packaged', 'readonly-install-plan', 'confirmed-files-only-install',
                'installed-binary-launch', 'observed-build-core-and-patch-match-bundle', 'all-21-presets-preserved', 'shared-api-draft-validate-plan',
                'dryrun-does-not-apply', 'confirmed-api-apply', 'observed-loopback-forwarding-probe',
                'unimplemented-export-rejected-without-output', 'daemon-and-owned-worker-processes-exited',
                'post-stop-connect-refused-and-exclusive-rebind-listen', 'retaining-uninstall',
                'no-plaintext-test-credentials-in-retained-state-or-output'],
            'systemd': 'not_run', 'independentProtocolCertification': False, 'publicDeployment': False,
            'browserMobileSubscriptionJourney': 'not_run'}
    args.evidence.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(evidence, indent=2))

if __name__ == '__main__':
    main()
