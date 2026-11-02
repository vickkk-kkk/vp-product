#!/usr/bin/env python3
"""Authorized direct HTTP integration, not a browser/network-policy workaround.
Daemon and Dart test share one isolated command process tree. Temporary auth and
SQLite state are synthetic, loopback-only and removed on exit. No routes change.
"""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
PORT = 18081
with tempfile.TemporaryDirectory(prefix='vp-dart-api-test-') as state:
    os.chmod(state, 0o700)
    process = subprocess.Popen([
        str(ROOT / 'target/debug/vp-product-managementd'),
        '--state-root', state, '--bind', f'127.0.0.1:{PORT}',
        '--origin', f'http://localhost:{PORT}',
    ], stdin=subprocess.PIPE)
    try:
        process.stdin.write(json.dumps({
            'username': 'synthetic-admin',
            'token': 'synthetic-browser-qa-only-not-for-production-0123456789',
        }).encode())
        process.stdin.close()
        deadline = time.monotonic() + 10
        while True:
            if process.poll() is not None:
                raise RuntimeError('Fixture daemon exited before listening.')
            try:
                with socket.create_connection(('localhost', PORT), timeout=1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Loopback fixture not reachable within this command.')
                time.sleep(.1)
        result = subprocess.run([
            str(ROOT / 'flutter/tools/sdk.sh'), 'test', '--no-pub',
            '--reporter', 'expanded',
            f'--dart-define=VP_LIVE_MANAGEMENT_ORIGIN=http://localhost:{PORT}',
            'test/live_management_api_test.dart',
        ], cwd=ROOT / 'flutter/packages/vp_api_client')
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RuntimeError('Fixture required forced shutdown; graceful cleanup unverified.')
    if process.returncode != 0:
        raise RuntimeError(f'Fixture daemon shutdown returned {process.returncode}.')
    print('Fixture daemon stopped; ephemeral state will be removed. No browser was exercised.', flush=True)
    raise SystemExit(result.returncode)
