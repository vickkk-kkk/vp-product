"""Foreground-only owned runtime supervision. Never accepts a PID to kill.

Direct child ownership is the live Popen handle. Worker ownership additionally
requires PPid, start ticks, exact loaded ELF hash and a retained pidfd. No process
name matching, stale PID files, host service commands or process-group kills.
"""
import hashlib
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
from vp_install import require, InstallError, canonical, strict_json, exact_keys
from vp_maintenance_bridge import sealed_artifact


def identity(pid):
    try:
        suffix = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return {'pid': pid, 'parent': int(suffix[1]), 'start': suffix[19], 'state': suffix[0]}
    except FileNotFoundError:
        return None


def loaded_digest(pid):
    h = hashlib.sha256(); length = 0
    with open(f'/proc/{pid}/exe', 'rb') as stream:
        while block := stream.read(65536):
            length += len(block); require(length <= 128 * 1024 * 1024, 'owned child ELF too large')
            h.update(block)
    return h.hexdigest()


class OwnedRuntime:
    def __init__(self, daemon, daemon_sha, worker_sha, arguments, request):
        require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd supervision unavailable')
        self.process = None; self.workers = {}; self.selector = selectors.DefaultSelector()
        self.buffers = {'stdout': bytearray(), 'stderr': bytearray()}; self.ready = None
        self.worker_sha = worker_sha; self.request = request
        raw = bytearray(canonical(request) + b'\n')
        require(len(raw) <= 8192, 'fresh startup request exceeds bound')
        try:
            with sealed_artifact(daemon, daemon_sha) as fd:
                self.process = subprocess.Popen([f'/proc/self/fd/{fd}', *arguments],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={}, close_fds=True, pass_fds=(fd,), start_new_session=True)
            # A bounded request is below PIPE_BUF on supported targets after this
            # explicit check. No secret bytes enter argv, environment or receipts.
            require(len(raw) <= os.fpathconf(self.process.stdin.fileno(), 'PC_PIPE_BUF'), 'startup request exceeds atomic pipe bound')
            os.set_blocking(self.process.stdin.fileno(), False)
            require(os.write(self.process.stdin.fileno(), raw) == len(raw), 'startup input incomplete')
            self.process.stdin.close()
            for name in ('stdout', 'stderr'):
                stream = getattr(self.process, name); os.set_blocking(stream.fileno(), False)
                self.selector.register(stream, selectors.EVENT_READ, name)
        except BaseException:
            self.stop()
            raise
        finally:
            raw[:] = b'\0' * len(raw)
            self.request = None

    def capture_workers(self):
        if self.process is None or self.process.poll() is not None:
            return
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit(): continue
            try:
                if entry.stat().st_uid != os.geteuid(): continue
            except FileNotFoundError: continue
            rec = identity(int(entry.name))
            if rec is None or rec['parent'] != self.process.pid or rec['state'] == 'Z': continue
            key = (rec['pid'], rec['start'])
            if key in self.workers: continue
            try:
                require(loaded_digest(rec['pid']) == self.worker_sha, 'unexpected direct runtime child')
                fd = os.pidfd_open(rec['pid'])
            except (FileNotFoundError, ProcessLookupError):
                continue
            now = identity(rec['pid'])
            if now is None or now['start'] != rec['start'] or now['parent'] != self.process.pid:
                os.close(fd); continue
            self.workers[key] = {'identity': rec, 'fd': fd}

    def pump(self, timeout=.1):
        self.capture_workers()
        for key, _ in self.selector.select(timeout):
            block = os.read(key.fileobj.fileno(), 4096)
            if not block:
                self.selector.unregister(key.fileobj); key.fileobj.close(); continue
            buffer = self.buffers[key.data]; buffer.extend(block)
            require(len(buffer) <= 8192, 'runtime output limit; retained state requires inspection')
        # Never render untrusted child diagnostics (which could contain secrets).
        raw = self.buffers['stdout']
        if self.ready is None and b'\n' in raw:
            line, remainder = raw.split(b'\n', 1)
            value = strict_json(line)
            exact_keys(value, ('protocolVersion','status','genesisId','profile','endpoint','runtimeAvailable',
                               'productionCertified','recoveryEligible','webAvailable','publicationAvailable'))
            require(isinstance(value, dict) and value.get('protocolVersion') == 1 and
                    value.get('status') == 'http_ready' and value.get('runtimeAvailable') is True and
                    value.get('productionCertified') is False and value.get('recoveryEligible') is False and
                    value.get('webAvailable') is True and value.get('publicationAvailable') is True,
                    'runtime readiness refused')
            self.ready = value; self.buffers['stdout'] = bytearray(remainder)
        return self.process.poll()

    def await_ready(self, genesis, timeout=30, cancelled=lambda: False):
        deadline = time.monotonic() + timeout
        while self.ready is None:
            require(not cancelled(), 'startup canceled; retain activation intent')
            require(time.monotonic() < deadline, 'runtime readiness timeout; no retry')
            code = self.pump()
            require(code is None, 'runtime exited before readiness; inspect retained state')
        require(self.ready.get('genesisId') == genesis and self.ready.get('profile') == 'fresh-runtime-v1',
                'runtime readiness identity mismatch')
        return dict(self.ready)

    @staticmethod
    def _worker_gone(rec):
        now = identity(rec['pid'])
        return now is None or now['start'] != rec['start'] or now['state'] == 'Z'

    def _stop_worker(self, record):
        rec = record['identity']; fd = record['fd']
        if self._worker_gone(rec): return
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try: signal.pidfd_send_signal(fd, sig)
            except ProcessLookupError: return  # Exact pidfd target exited normally.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if self._worker_gone(rec): return
                time.sleep(.05)
        raise InstallError('observed owned worker cleanup uncertain')

    def stop(self):
        if self.process is None: return {'stopped': True, 'ownedWorkers': 0}
        errors = []; count = len(self.workers)
        try:
            # Capture while the direct parent is alive. Receipts are not authority.
            try: self.capture_workers()
            except (OSError, InstallError): errors.append('capture')
            count = len(self.workers)
            try:
                if self.process.poll() is None:
                    self.process.terminate()
                    try: self.process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        self.process.kill(); self.process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired): errors.append('direct-child')
            # Every retained handle is processed even if another child exits or
            # becomes unobservable. Never let ESRCH skip remaining cleanup.
            for record in self.workers.values():
                try: self._stop_worker(record)
                except (OSError, InstallError): errors.append('worker')
                finally:
                    try: os.close(record['fd'])
                    except OSError: errors.append('pidfd-close')
        finally:
            self.workers.clear()
            self.selector.close()
            for name in ('stdin', 'stdout', 'stderr'):
                stream = getattr(self.process, name)
                if stream is not None and not stream.closed:
                    try: stream.close()
                    except OSError: errors.append('stream-close')
        require(not errors, 'owned-child cleanup or observation uncertain; inspect retained state')
        return {'stopped': True, 'ownedWorkers': count, 'directExitCode': self.process.returncode,
                'scope': 'observed-owned-processes', 'unobservedDescendantsCertified': False}
