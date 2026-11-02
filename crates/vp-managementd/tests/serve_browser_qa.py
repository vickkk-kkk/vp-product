#!/usr/bin/env python3
"""Tracked browser QA only. Public synthetic test fixture is NOT a deployment credential.
Run in foreground, stop with Ctrl-C; temporary database removed after daemon exit.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile

# Deliberately synthetic; never provision this value into a real installation.
SYNTHETIC_TOKEN = 'synthetic-browser-qa-only-not-for-production-0123456789'
parser=argparse.ArgumentParser()
parser.add_argument('--web-root',required=True,type=Path)
parser.add_argument('--binary',type=Path,default=Path('target/debug/vp-product-managementd'))
parser.add_argument('--port',type=int,default=18080)
args=parser.parse_args()
assert 1024 <= args.port <= 65535
web=args.web_root.resolve(); assert (web/'index.html').is_file()
with tempfile.TemporaryDirectory(prefix='vp-browser-qa-') as root:
    os.chmod(root,0o700)
    process=subprocess.Popen([str(args.binary.resolve()),'--state-root',root,'--bind',f'127.0.0.1:{args.port}','--origin',f'http://localhost:{args.port}','--web-root',str(web)],stdin=subprocess.PIPE)
    process.stdin.write(json.dumps({'username':'synthetic-admin','token':SYNTHETIC_TOKEN}).encode());process.stdin.close();process.stdin=None
    print(f'QA only: http://localhost:{args.port} (synthetic-admin). Stop this foreground harness with Ctrl-C.',flush=True)
    try:
        process.wait()
    except KeyboardInterrupt:
        if process.poll() is None: process.send_signal(signal.SIGINT)
    finally:
        if process.poll() is None:
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill();process.wait()
                raise RuntimeError('daemon shutdown exceeded deadline; temp state removed, recovery unverified')
    assert process.returncode==0, 'daemon failed; no browser QA acceptance'
