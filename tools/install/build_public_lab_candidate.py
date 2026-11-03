#!/usr/bin/env python3
"""Build a local-only experimental lab archive, not a distributable release."""
import argparse, hashlib, io, json, os, pathlib, stat, subprocess, tarfile, tempfile
from vp_elf_abi import inspect_reviewed_elf

p = argparse.ArgumentParser()
p.add_argument('--lab', required=True, type=pathlib.Path)
p.add_argument('--worker', required=True, type=pathlib.Path)
p.add_argument('--output', required=True, type=pathlib.Path)
a = p.parse_args()

def capture(path):
    metadata = inspect_reviewed_elf(path)
    if metadata['status'] != 'glibc_floor_detected_not_execution_certified':
        raise ValueError('unknown ELF compatibility')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 128 * 1024 * 1024:
            raise ValueError('invalid binary')
        with os.fdopen(fd, 'rb', closefd=False) as f: data = f.read(128 * 1024 * 1024 + 1)
    finally: os.close(fd)
    if data[:6] != b'\x7fELF\x02\x01' or data[18:20] != b'\x3e\x00':
        raise ValueError('expected little-endian x86_64 ELF')
    if len(data) != st.st_size or hashlib.sha256(data).hexdigest() != metadata['sha256']:
        raise ValueError('binary changed during capture')
    return data, metadata

lab, lm = capture(a.lab)
worker, wm = capture(a.worker)
# Execute only the captured, reviewed local artifacts in a private staging area.
# The host check does not open listeners or create product state.
with tempfile.TemporaryDirectory(prefix='vp-bundle-identity-') as tmp:
    stage = pathlib.Path(tmp); lp = stage/'lab'; wp = stage/'worker'
    lp.write_bytes(lab); wp.write_bytes(worker); lp.chmod(0o700); wp.chmod(0o700)
    check = subprocess.run([str(lp),'--check-host','--worker',str(wp),'--worker-sha256',wm['sha256']],
                           capture_output=True, text=True, timeout=30, check=True)
    if len(check.stdout)>65536 or len(check.stderr)>65536: raise ValueError('identity output exceeds limit')
    identity = json.loads(check.stdout)
    if identity.get('testFixture') is not False or identity.get('workerSha256') != wm['sha256'] or identity.get('architecture') != 'x86_64':
        raise ValueError('test fixture or incompatible artifact identity')
version = lambda v: tuple(map(int, v.split('.')))
floor = max([lm['minimum'], wm['minimum']], key=version)
launcher = '''#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
D=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
[ ! -L "$D/vp-public-lab" ] && [ ! -L "$D/vp-core-server-worker-v2" ] || exit 1
[ "$(uname -m)" = x86_64 ] || { echo 'unsupported architecture' >&2; exit 1; }
# Refuse package directories or ancestors writable by untrusted users.
P=$D
ME=$(id -u)
while :; do
  OWNER=$(stat -c %u -- "$P") || exit 1
  MODE=$(stat -c %a -- "$P") || exit 1
  [ "$OWNER" = 0 ] || [ "$OWNER" = "$ME" ] || { echo 'untrusted directory owner' >&2; exit 1; }
  BITS=$((0$MODE))
  if [ "$P" = "$D" ]; then
    [ "$OWNER" = "$ME" ] && [ $((BITS & 18)) -eq 0 ] || { echo 'package directory is not private' >&2; exit 1; }
  fi
  if [ $((BITS & 18)) -ne 0 ]; then
    [ "$OWNER" = 0 ] && [ $((BITS & 512)) -ne 0 ] || { echo 'unsafe writable directory' >&2; exit 1; }
  fi
  [ "$P" = / ] && break
  P=$(dirname -- "$P")
done
for F in "$D/vp-public-lab" "$D/vp-core-server-worker-v2"; do
  OWNER=$(stat -c %u -- "$F") || exit 1
  MODE=$(stat -c %a -- "$F") || exit 1
  [ "$OWNER" = "$ME" ] || [ "$OWNER" = 0 ] || { echo 'untrusted binary owner' >&2; exit 1; }
  [ $((0$MODE & 18)) -eq 0 ] || { echo 'unsafe binary permissions' >&2; exit 1; }
done
GLIBC=$(getconf GNU_LIBC_VERSION 2>/dev/null) || { echo 'glibc unavailable' >&2; exit 1; }
printf '%s\n' "$GLIBC" | awk -v min='@FLOOR@' '
  /^glibc [0-9]+\\.[0-9]+(\\.[0-9]+)?$/ { found=1; split($2,a,"."); split(min,b,"."); for(i=1;i<=3;i++){if((a[i]+0)>(b[i]+0)){rc=0;exit};if((a[i]+0)<(b[i]+0)){rc=1;exit}} }
  END {if(!found)exit 1; exit rc}' || { echo 'glibc version insufficient or unknown' >&2; exit 1; }
printf '%s  %s\\n' '@LAB_HASH@' "$D/vp-public-lab" '@WORKER_HASH@' "$D/vp-core-server-worker-v2" | sha256sum -c --status || { echo 'artifact checksum mismatch' >&2; exit 1; }
[ "${1:-}" = check ] || [ "${1:-}" = run ] || { echo 'usage: ./vp-lab check | run <arguments>' >&2; exit 2; }
MODE=$1
shift
if [ "$MODE" = check ]; then
  [ "$#" -eq 0 ] || exit 2
  exec "$D/vp-public-lab" --check-host --worker "$D/vp-core-server-worker-v2" --worker-sha256 '@WORKER_HASH@'
fi
exec "$D/vp-public-lab" --worker "$D/vp-core-server-worker-v2" --worker-sha256 '@WORKER_HASH@' "$@"
'''.replace('@LAB_HASH@', lm['sha256']).replace('@WORKER_HASH@', wm['sha256']).replace('@FLOOR@', floor).encode()
manifest = json.dumps({'kind':'LOCAL_ONLY_NOT_A_RELEASE','architecture':'x86_64','minimum_glibc':floor,'binaries':{'vp-public-lab':lm,'vp-core-server-worker-v2':wm},'warning':'Development builds; no VPS validation; license inventory incomplete.'}, indent=2).encode()+b'\n'
notice = b'LOCAL EXPERIMENT ONLY. NOT A RELEASE. DO NOT DISTRIBUTE. License inventory and upstream license evidence are incomplete. No VPS validation has been performed.\n'
files = [('vp-lab',launcher,0o700),('vp-public-lab',lab,0o700),('vp-core-server-worker-v2',worker,0o700),('manifest.json',manifest,0o600),('NOT_FOR_DISTRIBUTION.txt',notice,0o600)]
fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(fd, 'wb') as out, tarfile.open(fileobj=out, mode='w:gz') as tar:
        for name, data, mode in files:
            info = tarfile.TarInfo(name); info.size=len(data); info.mode=mode; info.uid=info.gid=0; info.mtime=0
            tar.addfile(info, io.BytesIO(data))
except BaseException:
    a.output.unlink(missing_ok=True)
    raise
print(json.dumps({'output':str(a.output),'minimum_glibc':floor,'status':'LOCAL_ONLY_NOT_A_RELEASE'}))
