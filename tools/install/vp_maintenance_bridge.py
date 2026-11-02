"""Private source candidate: explicit offline maintenance execution primitive.

Explicit offline primitive used by the candidate Engine. Bound initialization
requires Rust to verify the opened target directory identity before writes.
No arbitrary argv, environment, shell or fallback.
A successful receipt never grants recovery/restore authority. The one inherited
nonstdio descriptor contains only sealed executable ELF bytes, never key material.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import stat
import subprocess
import time

from vp_install import InstallError, require, check_ancestors, safe_absolute, strict_json

MAX_ELF = 256 * 1024 * 1024
MAX_OUTPUT = 65536
MFD_EXEC = 0x10
F_SEAL_EXEC = 0x20
# Stable Linux UAPI values; some Python builds omit these symbolic constants.
F_ADD_SEALS = 1033
F_GET_SEALS = 1034
SEALS = 0x01 | 0x02 | 0x04 | 0x08 | F_SEAL_EXEC
HEX = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')


class MaintenanceUncertain(InstallError):
    """A spawned initializer did not yield a complete validated receipt."""


def elf_header(raw):
    require(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01', 'native ELF64 artifact required')
    require(int.from_bytes(raw[16:18], 'little') in (2, 3), 'executable/PIE ELF required')
    arch = {'x86_64': 62, 'aarch64': 183}.get(platform.machine())
    require(arch is not None and int.from_bytes(raw[18:20], 'little') == arch, 'native ELF architecture required')


def source_chunks(path, deadline):
    path = safe_absolute(path)
    check_ancestors(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid in (0, os.geteuid())
                and not before.st_mode & 0o022 and 64 <= before.st_size <= MAX_ELF,
                'bounded trusted-owner nonwritable ELF required')
        total = 0
        while True:
            require(time.monotonic() < deadline, 'artifact read deadline exceeded')
            raw = os.read(descriptor, min(65536, before.st_size - total + 1))
            if not raw:
                break
            if total == 0:
                elf_header(raw)
            total += len(raw)
            require(total <= before.st_size, 'artifact length changed')
            yield raw
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        require(total == before.st_size and all(getattr(before, x) == getattr(after, x) for x in fields),
                'artifact changed during bounded read')
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def sealed_artifact(path, expected_sha256):
    require(platform.system() == 'Linux' and HEX.fullmatch(expected_sha256 or ''), 'pinned Linux ELF required')
    descriptor = None
    try:
        # MFD_EXEC requires Linux >=6.3 and an executable-memfd policy. No fallback.
        descriptor = os.memfd_create('vp-offline-maintenance', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MFD_EXEC)
        digest = hashlib.sha256(); length = 0
        for raw in source_chunks(path, time.monotonic() + 10):
            digest.update(raw); length += len(raw)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                require(count > 0, 'artifact copy unavailable'); view = view[count:]
        require(digest.hexdigest() == expected_sha256, 'artifact digest mismatch')
        os.fchmod(descriptor, 0o555)
        fcntl.fcntl(descriptor, F_ADD_SEALS, SEALS)
        bound = os.fstat(descriptor)
        require(fcntl.fcntl(descriptor, F_GET_SEALS) & SEALS == SEALS
                and stat.S_IMODE(bound.st_mode) == 0o555 and bound.st_size == length,
                'sealed executable identity unavailable')
        os.lseek(descriptor, 0, os.SEEK_SET)
        yield descriptor
    except OSError:
        raise InstallError('sealed execution unavailable; no pathname fallback') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def fixed_request(action, vault_root, state_root, namespace, operation_id, master_hex, expected_vault_directory=None):
    require(action in ('vault-init-bound', 'inspect'), 'unsupported offline action')
    require(ID.fullmatch(namespace or '') and ID.fullmatch(operation_id or ''), 'bounded explicit identities required')
    require(isinstance(master_hex, str) and re.fullmatch(r'[0-9a-fA-F]{64}', master_hex), 'explicit key input required')
    vault_root = safe_absolute(vault_root)
    arguments = [action, '--vault-root', str(vault_root), '--vault-namespace', namespace]
    if action == 'inspect':
        state_root = safe_absolute(state_root)
        require(state_root != vault_root, 'distinct state/vault roots required')
        arguments.extend(['--state-root', str(state_root)])
    else:
        require(state_root is None, 'vault initialization has no control-state argument')
    envelope = {'schemaVersion': 1, 'operationId': operation_id, 'masterKeyHex': master_hex}
    if action == 'vault-init-bound':
        require(isinstance(expected_vault_directory, dict) and set(expected_vault_directory) == {'device', 'inode'}
                and all(type(v) is int and 0 <= v <= 2**64 - 1 for v in expected_vault_directory.values()),
                'exact expected opened-vault identity required')
        envelope['expectedVaultDirectory'] = expected_vault_directory
    else:
        require(expected_vault_directory is None, 'unexpected vault identity on inspect')
    sensitive = bytearray(json.dumps(envelope, separators=(',', ':')).encode())
    require(len(sensitive) <= 4096 and b'\\' not in sensitive, 'maintenance input unsupported')
    return arguments, sensitive


def bounded_exchange(process, sensitive):
    selector = selectors.DefaultSelector()
    output = bytearray(); errors = bytearray(); offset = 0
    deadline = time.monotonic() + 17
    try:
        for stream, event in ((process.stdin, selectors.EVENT_WRITE), (process.stdout, selectors.EVENT_READ),
                              (process.stderr, selectors.EVENT_READ)):
            os.set_blocking(stream.fileno(), False); selector.register(stream, event)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'maintenance deadline exceeded')
            for key, _ in selector.select(min(remaining, .1)):
                stream = key.fileobj
                if stream is process.stdin:
                    try:
                        offset += os.write(stream.fileno(), memoryview(sensitive)[offset:])
                    except BrokenPipeError:
                        offset = len(sensitive)
                    if offset == len(sensitive):
                        selector.unregister(stream); stream.close()
                else:
                    block = os.read(stream.fileno(), 4096)
                    if not block:
                        selector.unregister(stream); stream.close(); continue
                    target = output if stream is process.stdout else errors
                    target.extend(block)
                    require(len(target) <= (MAX_OUTPUT if stream is process.stdout else 4096), 'maintenance output bound exceeded')
        result = process.wait(timeout=max(.01, deadline - time.monotonic()))
        require(not errors, 'maintenance diagnostic output refused')
        return result, bytes(output)
    finally:
        sensitive[:] = b'\0' * len(sensitive)
        selector.close()
        if process.poll() is None:
            process.kill(); process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()


def execute(action, artifact, artifact_sha256, vault_root, namespace, operation_id, master_hex, state_root=None, expected_vault_directory=None):
    """Call only after external plan/confirmation and retained material-root lock.

    No automatic retries. A partial/lost/invalid init response is always uncertain.
    The caller must journal consumed initialization intent before calling this.
    """
    arguments, sensitive = fixed_request(action, vault_root, state_root, namespace, operation_id, master_hex, expected_vault_directory)
    process = None
    try:
        with sealed_artifact(artifact, artifact_sha256) as descriptor:
            process = subprocess.Popen(['/proc/self/fd/' + str(descriptor), *arguments],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, pass_fds=(descriptor,), env={}, start_new_session=True)
            code, raw = bounded_exchange(process, sensitive)
        value = strict_json(raw)
        require(isinstance(value, dict) and value.get('protocolVersion') == 1 and value.get('recoveryEligible') is False,
                'maintenance receipt invalid')
        if code != 0:
            # Never surface arbitrary child text. Even an explicit pre-write failure
            # does not authorize this bridge to automatically retry initialization.
            raise InstallError('maintenance refused; retained evidence requires review')
        require(value.get('receiptVersion') == 1 and value.get('command') == action and value.get('operationId') == operation_id
                and value.get('authorityBinding') is None and value.get('controlAuthorityId') is None
                and value.get('retirementWatermark') is None and value.get('publicationRevocationWatermark') is None
                and value.get('authorityStatus') == 'unavailable' and value.get('watermarkStatus') == 'unavailable'
                and value.get('leaseScope') == 'observation_only_released_before_exit', 'maintenance authority receipt invalid')
        if action == 'vault-init-bound':
            require(value.get('targetBindingValidated') is True, 'opened-vault identity binding not proven')
        mutation = 'vault_manifest_created' if action == 'vault-init-bound' else 'none'
        require(value.get('targetMutation') == mutation and value.get('operationIdRole') == 'correlation_only_not_persisted'
                and isinstance(value.get('vault'), dict) and value['vault'].get('keyAuthenticated') is True,
                'maintenance observation invalid')
        # Do not return child-controlled diagnostic fields, unknown data or secrets.
        return {'status': 'offline_observation_received', 'command': action,
                'operationId': operation_id, 'vaultInitialized': action == 'vault-init-bound',
                'targetMutation': mutation, 'recoveryEligible': False,
                'authorityBinding': None, 'serviceStartedByThisTool': False,
                'receiptValidated': True, 'targetBindingValidated': action == 'vault-init-bound', 'leaseScope': 'observation_only_released_before_exit'}
    except (Exception, KeyboardInterrupt):
        if process is not None and action == 'vault-init-bound':
            raise MaintenanceUncertain('uncertain_do_not_retry_initialize') from None
        raise InstallError('offline maintenance unavailable/refused; no recovery inferred') from None
    finally:
        sensitive[:] = b'\0' * len(sensitive)
        if process is not None:
            if process.poll() is None:
                process.kill(); process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
