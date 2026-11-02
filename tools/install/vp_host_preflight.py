"""No-service/no-exec sealed-runtime prerequisite probe.

Only anonymous, non-secret memory descriptors are created and closed. No files,
credentials, processes, network, host settings or installation state are changed.
Success is not final exec-policy or production-runtime certification.
"""
from __future__ import annotations
import errno
import fcntl
import os
import platform
import re
import stat

MFD_EXEC = 0x0010
F_SEAL_EXEC = 0x0020
# Stable Linux UAPI numbers; Python builds may omit these symbolic names.
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
REQUIRED_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008 | F_SEAL_EXEC
REMEDY = ("需要原生 Linux >=6.3 x86_64/aarch64、允许 MFD_EXEC、完整文件封印及 /proc/self/fd；"
          "此检查不启动进程，最终 MAC/exec 策略仍须实际启动验证。不会自动修改系统策略或退回路径执行。")


def check_sealed_runtime_host():
    result = {"status": "unsupported", "prerequisitesAvailable": False,
              "finalExecPolicy": "not_checked_no_process_execution", "reason": "unknown",
              "nextStep": REMEDY}
    kernel = re.match(r"^(\d+)\.(\d+)(?:[.\-+]|$)", platform.release())
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64"):
        result["reason"] = "unsupported_os_or_architecture"
        return result
    if kernel is None or tuple(map(int, kernel.groups())) < (6, 3):
        result["reason"] = "linux_6_3_or_newer_required"
        return result
    if not hasattr(os, "memfd_create"):
        result["reason"] = "python_memfd_api_unavailable"
        return result
    fd = None
    try:
        fd = os.memfd_create("vp-preflight-not-executable-content", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MFD_EXEC)
        payload = b"VP non-secret capability probe. These bytes are never executed."
        if os.write(fd, payload) != len(payload):
            raise OSError(errno.EIO, "short anonymous probe write")
        os.fchmod(fd, 0o555)
        fcntl.fcntl(fd, F_ADD_SEALS, REQUIRED_SEALS)
        if fcntl.fcntl(fd, F_GET_SEALS) & REQUIRED_SEALS != REQUIRED_SEALS:
            raise OSError(errno.ENOTSUP, "missing executable seals")
        if not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            raise OSError(errno.ENOTSUP, "missing cloexec")
        original = os.fstat(fd)
        if not stat.S_ISREG(original.st_mode) or original.st_size != len(payload) or stat.S_IMODE(original.st_mode) != 0o555:
            raise OSError(errno.ENOTSUP, "unexpected anonymous descriptor")
        # Deliberate trusted proc-fd traversal, never an external supplied path.
        reopened = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            actual = os.fstat(reopened)
            if (actual.st_dev, actual.st_ino) != (original.st_dev, original.st_ino) or os.read(reopened, len(payload) + 1) != payload:
                raise OSError(errno.ENOTSUP, "proc descriptor mismatch")
        finally:
            os.close(reopened)
        result.update(status="prerequisites_present_not_execution_certified",
                      prerequisitesAvailable=True, reason="anonymous_exec_memfd_seals_and_proc_access_verified")
    except (OSError, ValueError, AttributeError):
        result["reason"] = "exec_memfd_sealing_or_proc_access_unavailable"
    finally:
        if fd is not None:
            os.close(fd)
    return result
