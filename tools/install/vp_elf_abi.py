"""Build-side ELF version inspection. No target execution or download.

The result is a conservative glibc floor, not full compatibility certification.
Call only for reviewed release artifacts and retain the exact artifact hash.
"""
from __future__ import annotations
import hashlib
import fcntl
import os
import selectors
import time
from pathlib import Path
import re
import stat
import subprocess

MAX_ELF = 128 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
VERSION = re.compile(r"^\s*0x[0-9a-fA-F]+:\s+.*?Name:\s+(GLIBC_[^\s]+)\s+Flags:")
NUMERIC = re.compile(r"GLIBC_([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?)\Z")


def parse_glibc_versions(output):
    """Parse only version-need names, refusing unknown GLIBC ABI tags."""
    versions = []
    unknown = []
    for line in output.splitlines():
        match = VERSION.match(line)
        if not match:
            continue
        name = match.group(1)
        numeric = NUMERIC.fullmatch(name)
        if numeric:
            versions.append(numeric.group(1))
        else:
            unknown.append(name)
    if unknown:
        return {"status": "unknown_glibc_abi", "minimum": None, "unknown": sorted(set(unknown))}
    if not versions:
        return {"status": "no_numeric_glibc_requirement_found", "minimum": None, "unknown": []}
    key = lambda v: tuple((list(map(int, v.split('.'))) + [0, 0])[:3])
    return {"status": "glibc_floor_detected_not_execution_certified", "minimum": max(versions, key=key), "unknown": []}


def _bounded_readelf(readelf, fd):
    proc = subprocess.Popen([readelf, "--version-info", f"/proc/self/fd/{fd}"],
                            pass_fds=(fd,), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    output = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + 10
    try:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("readelf deadline")
            ready = selector.select(remaining)
            if not ready:
                raise TimeoutError("readelf deadline")
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_OUTPUT:
                raise ValueError("readelf output exceeds limit")
        if proc.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise ValueError("readelf failed")
        return bytes(output)
    finally:
        selector.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()


def inspect_reviewed_elf(path, *, readelf="/usr/bin/readelf"):
    """Inspect a bounded immutable snapshot; never execute the artifact."""
    path = Path(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    snapshot = None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size < 64 or st.st_size > MAX_ELF:
            raise ValueError("invalid artifact type or size")
        if not hasattr(os, "memfd_create"):
            raise ValueError("immutable snapshot unavailable")
        snapshot = os.memfd_create("vp-elf-abi-snapshot", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        digest = hashlib.sha256()
        size = 0
        first = b""
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            if not first:
                first = chunk[:4]
            size += len(chunk)
            if size > MAX_ELF:
                raise ValueError("artifact exceeds limit")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                n = os.write(snapshot, view)
                if n <= 0:
                    raise ValueError("snapshot short write")
                view = view[n:]
        if size != st.st_size or first != b"\x7fELF":
            raise ValueError("invalid or changed ELF")
        # Linux UAPI values, for Python builds missing symbolic constants.
        seals = 0x0008 | 0x0004 | 0x0002 | 0x0001
        fcntl.fcntl(snapshot, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
        if fcntl.fcntl(snapshot, getattr(fcntl, "F_GET_SEALS", 1034)) & seals != seals:
            raise ValueError("snapshot sealing failed")
        output = _bounded_readelf(readelf, snapshot)
        report = parse_glibc_versions(output.decode("ascii", "strict"))
        report["sha256"] = digest.hexdigest()
        return report
    finally:
        if snapshot is not None:
            os.close(snapshot)
        os.close(fd)


def aggregate_artifact_glibc(reports):
    """Conservative bundle floor from immutable, hash-identified ELF reports.

    Unknown or static/musl binaries cannot silently become a glibc claim. This
    does not certify architecture, dynamic loader, kernel, or actual execution.
    """
    if not isinstance(reports, dict) or not reports or len(reports) > 32:
        raise ValueError("artifact reports required")
    floors = []
    artifact_hashes = {}
    for name, report in sorted(reports.items()):
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name):
            raise ValueError("invalid artifact name")
        if not isinstance(report, dict) or report.get("status") != "glibc_floor_detected_not_execution_certified":
            raise ValueError("unknown artifact glibc requirement")
        version = report.get("minimum")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?", version):
            raise ValueError("invalid artifact glibc requirement")
        sha = report.get("sha256")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError("invalid artifact digest")
        if report.get("unknown") != []:
            raise ValueError("unknown glibc ABI")
        floors.append((tuple((list(map(int, version.split('.'))) + [0, 0])[:3]), version))
        artifact_hashes[name] = sha
    return {"status": "declared_floor_not_execution_certified", "minimum": max(floors)[1],
            "artifactSha256": artifact_hashes}
