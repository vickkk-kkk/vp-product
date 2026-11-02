#!/usr/bin/env python3
"""Independent local-bundle Linux lifecycle tooling; no protocol templates or hooks.

All mutation requires an exact deterministic plan hash. No network download,
credential generation, package installation, firewall or route manipulation.
"""
from __future__ import annotations
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import grp
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from vp_host_preflight import check_sealed_runtime_host

OWNER = {"owner": "vp-product-local-installer", "schemaVersion": 1}
UNIT = "vp-managementd.service"
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_FILES = 4096
HEX = re.compile(r"[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")

class InstallError(Exception):
    pass

class StalePlan(InstallError):
    """The displayed plan is no longer current; prior consent cannot be reused."""
    pass

def require(value, message):
    if not value:
        raise InstallError(message)

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def digest(data):
    return hashlib.sha256(data).hexdigest()

def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InstallError("nonfinite JSON")))
    except (ValueError, UnicodeError) as exc:
        raise InstallError("invalid JSON") from exc

def exact_keys(obj, keys):
    require(isinstance(obj, dict) and set(obj) == set(keys), "unsupported/missing manifest fields")

def safe_relative(name):
    require(isinstance(name, str) and 0 < len(name) <= 240, "invalid bundle path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and
            all(part not in ("", ".", "..") and re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]*", part)
                for part in path.parts), "unsafe bundle path")
    return name

def safe_absolute(path):
    path = Path(path)
    require(path.is_absolute() and str(path) != "/" and
            re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)) and ".." not in path.parts,
            "absolute path must contain only safe path characters, no parent segments")
    require(str(path) == os.path.normpath(str(path)), "noncanonical path")
    return path

def check_ancestors(path):
    """Reject symlink/writable ancestors; private directories under sticky /tmp allowed."""
    path = safe_absolute(path)
    for part in list(reversed(path.parents)) + [path]:
        try:
            st = part.lstat()
        except FileNotFoundError:
            continue
        require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "symlink/non-directory ancestor")
        sticky_temp = str(part) in ("/tmp", "/var/tmp") and bool(st.st_mode & stat.S_ISVTX)
        require(st.st_uid in (0, os.geteuid()) and (not st.st_mode & 0o022 or sticky_temp),
                "untrusted writable ancestor")
    return path

def read_regular(path, limit, private=False):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            st = os.fstat(stream.fileno())
            require(stat.S_ISREG(st.st_mode) and st.st_size <= limit, "file type/size rejected")
            if private:
                require(st.st_uid == os.geteuid() and not st.st_mode & 0o077, "private file permissions required")
            data = stream.read(limit + 1)
            require(len(data) <= limit, "file too large")
            return data
    except OSError as exc:
        raise InstallError("required regular file unavailable") from exc

def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def atomic_write(path, data, mode=0o600):
    path = Path(path)
    require(not path.is_symlink(), "refusing symlink destination")
    fd, tmp = tempfile.mkstemp(prefix=".vp-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def atomic_json(path, obj):
    atomic_write(path, canonical(obj) + b"\n")

def host_arch():
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(platform.machine())
    require(platform.system() == "Linux" and arch is not None, "Linux x86_64/aarch64 required")
    return arch

class Bundle:
    """A verified, bounded private ZIP snapshot retained across plan and staging.

    No extractall, links, archives-in-archives, shell hooks or executable scripts.
    Local SHA256 must arrive through the operator's independently trusted channel.
    """
    def __init__(self, path, expected_sha256):
        require(HEX.fullmatch(expected_sha256 or ""), "trusted expected --sha256 is mandatory")
        self.path = Path(path)
        self.sha256 = expected_sha256
        self.stream = None
        self.zip = None
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            # A retained source FD does NOT freeze an inode writable by its owner.
            # Snapshot under installer ownership first; only these exact privately
            # held bytes may be parsed/extracted after external digest verification.
            with os.fdopen(fd, "rb") as source:
                st = os.fstat(source.fileno())
                require(stat.S_ISREG(st.st_mode) and 22 <= st.st_size <= MAX_ARCHIVE, "bundle type/size rejected")
                self.stream = tempfile.TemporaryFile(mode="w+b", prefix="vp-bundle-snapshot-")
                os.fchmod(self.stream.fileno(), 0o600)
                h = hashlib.sha256()
                copied = 0
                while data := source.read(1024 * 1024):
                    copied += len(data)
                    require(copied <= MAX_ARCHIVE, "bundle grew beyond snapshot bound")
                    self.stream.write(data)
                    h.update(data)
                require(copied == st.st_size and h.hexdigest() == expected_sha256, "bundle SHA256 mismatch")
                self.stream.flush()
            # Source descriptor is now closed. Snapshot is never exposed by pathname.
            # Bound central-directory allocation before ZipFile parses it; ZIP64 and comments rejected.
            self.stream.seek(-22, os.SEEK_END)
            tail = self.stream.read(22)
            signature, disk, start_disk, on_disk, count, cd_size, cd_offset, comment = struct.unpack("<4s4H2IH", tail)
            require(signature == b"PK\x05\x06" and disk == start_disk == comment == 0 and
                    count == on_disk and 1 <= count <= MAX_FILES and cd_size <= 2 * 1024 * 1024 and
                    cd_offset + cd_size == st.st_size - 22, "unsupported or oversized ZIP directory")
            self.stream.seek(0)
            self.zip = zipfile.ZipFile(self.stream)
            entries = self.zip.infolist()
            require(len(entries) == count, "ZIP entry count mismatch")
            names = set()
            total = 0
            for item in entries:
                safe_relative(item.filename)
                require(item.filename not in names and not item.is_dir(), "duplicate/directory ZIP member")
                names.add(item.filename)
                mode = item.external_attr >> 16
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG) and not mode & 0o7000, "links/special files not permitted")
                require(not item.flag_bits & 1 and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "unsupported ZIP encoding")
                require(item.file_size <= MAX_FILE and item.file_size <= max(1024, item.compress_size * 200), "oversized/compression-bomb member")
                total += item.file_size
                require(total <= MAX_TOTAL, "bundle unpacked size limit")
            require("manifest.json" in names, "manifest missing")
            require(self.zip.getinfo("manifest.json").file_size <= 128 * 1024, "manifest too large")
            self.manifest = strict_json(self.zip.read("manifest.json"))
            self._validate_manifest()
            require(names == {"manifest.json"} | {f["path"] for f in self.manifest["files"]}, "unlisted or missing bundle file")
            for item in self.manifest["files"]:
                require(self.zip.getinfo(item["path"]).file_size == item["size"], "manifest size mismatch")
                require(self._hash_member(item["path"]) == item["sha256"], "manifest member hash mismatch")
            for item in self.manifest["files"]:
                if not item["executable"]:
                    continue
                with self.zip.open(item["path"]) as binary:
                    header = binary.read(20)
                machine = {"x86_64": 62, "aarch64": 183}[self.manifest["architecture"]]
                require(len(header) == 20 and header[:6] == b"\x7fELF\x02\x01" and
                        struct.unpack("<H", header[18:20])[0] == machine, "binary must be matching Linux ELF64")
        except (OSError, zipfile.BadZipFile, RuntimeError, KeyError, TypeError, struct.error) as exc:
            self.close()
            raise InstallError("invalid/unreadable bundle") from exc
        except BaseException:
            self.close()
            raise

    def _validate_manifest(self):
        m = self.manifest
        exact_keys(m, ("schemaVersion", "releaseId", "productVersion", "engine", "architecture", "coreLockSha256", "storageSchema", "files"))
        require(m["schemaVersion"] == 1 and m["engine"] == "vp_core" and m["storageSchema"] == 1, "unsupported bundle/engine/storage schema")
        require(isinstance(m["releaseId"], str) and IDENT.fullmatch(m["releaseId"]), "invalid release ID")
        require(isinstance(m["productVersion"], str) and IDENT.fullmatch(m["productVersion"]), "invalid product version")
        require(m["architecture"] == host_arch(), "bundle architecture mismatch")
        require(isinstance(m["coreLockSha256"], str) and HEX.fullmatch(m["coreLockSha256"]), "core lock digest required")
        require(isinstance(m["files"], list) and 1 <= len(m["files"]) < MAX_FILES, "invalid file manifest")
        paths = set()
        for f in m["files"]:
            exact_keys(f, ("path", "size", "sha256", "executable"))
            path = safe_relative(f["path"])
            require(path not in paths and path != "manifest.json", "duplicate manifest path")
            paths.add(path)
            require(type(f["size"]) is int and 0 <= f["size"] <= MAX_FILE and
                    isinstance(f["sha256"], str) and HEX.fullmatch(f["sha256"]) and type(f["executable"]) is bool, "invalid file metadata")
            require(path in ("bin/vp-product-managementd", "bin/vp-core-managed-worker", "core-lock.json", "contracts/capabilities/presets.json") or path.startswith("web/"), "unapproved bundle component")
            require(f["executable"] == path.startswith("bin/"), "unapproved executable")
        require({"bin/vp-product-managementd", "web/index.html", "core-lock.json", "contracts/capabilities/presets.json"} <= paths, "required product component missing")
        core = next(f for f in m["files"] if f["path"] == "core-lock.json")
        require(core["sha256"] == m["coreLockSha256"], "core identity mismatch")

    def _hash_member(self, name, destination=None):
        h = hashlib.sha256()
        count = 0
        with self.zip.open(name) as src:
            while data := src.read(1024 * 1024):
                count += len(data)
                require(count <= MAX_FILE, "expanded member too large")
                h.update(data)
                if destination:
                    destination.write(data)
        return h.hexdigest()

    def extract(self, directory):
        directory.mkdir(mode=0o700)
        for f in self.manifest["files"]:
            dest = directory / f["path"]
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with dest.open("xb") as out:
                require(self._hash_member(f["path"], out) == f["sha256"], "bundle changed during extraction")
                out.flush()
                os.fchmod(out.fileno(), 0o755 if f["executable"] else 0o644)
                os.fsync(out.fileno())
        atomic_write(directory / "manifest.json", canonical(self.manifest), 0o644)
        # Directories are readable, not mutable, by the service account.
        for parent, dirs, _ in os.walk(directory, topdown=False):
            os.chmod(parent, 0o755)
            sync_dir(parent)

    def close(self):
        if self.zip:
            self.zip.close()
        if self.stream:
            self.stream.close()
    def __enter__(self):
        return self
    def __exit__(self, *_):
        self.close()

class Systemd:
    """Only fixed systemctl verbs; never shell=True, arbitrary commands or hooks."""
    def __init__(self, root, enable_on_boot=False):
        self.root = root
        self.enable_on_boot = enable_on_boot
    def call(self, *args, check=True):
        allowed = {("show", "--property=LoadState", "--property=FragmentPath", UNIT),
                   ("is-active", UNIT), ("link", str(self.root / "systemd" / UNIT)),
                   ("daemon-reload",), ("enable", UNIT), ("start", UNIT), ("stop", UNIT),
                   ("disable", "--now", UNIT)}
        require(args in allowed, "systemctl verb/target is not allowlisted")
        require(os.geteuid() == 0, "systemd actions require root")
        binary = "/usr/bin/systemctl"
        require(Path(binary).is_file(), "systemctl unavailable")
        try:
            p = subprocess.run([binary, *args], env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InstallError("systemctl action failed/uncertain; recover before retry") from exc
        require(not check or p.returncode == 0, "systemctl action failed; inspect service privately")
        return p
    def owned(self):
        p = self.call("show", "--property=LoadState", "--property=FragmentPath", UNIT, check=False)
        values = dict(line.split("=", 1) for line in p.stdout.decode("utf-8", "replace").splitlines() if "=" in line)
        require(p.returncode == 0 or values.get("LoadState") == "not-found", "systemd manager unavailable")
        require("LoadState" in values, "systemd unit state unavailable")
        value = values.get("FragmentPath", "")
        if value:
            require(Path(value).resolve() == (self.root / "systemd" / UNIT).resolve(), "another installation owns systemd unit")
        else:
            require(values["LoadState"] == "not-found", "ambiguous systemd unit ownership")
        return bool(value)
    def active(self):
        if not self.owned():
            return False
        p = self.call("is-active", UNIT, check=False)
        require(p.returncode in (0, 3, 4), "systemd state unavailable")
        return p.returncode == 0
    def link(self):
        self.owned()
        self.call("link", str(self.root / "systemd" / UNIT))
        self.call("daemon-reload")
        if self.enable_on_boot:
            self.call("enable", UNIT)
    def start(self):
        self.owned()
        self.call("start", UNIT)
        require(self.active(), "service did not become active; no forwarding claim")
    def stop(self):
        self.owned()
        self.call("stop", UNIT)
        require(not self.active(), "service remained active")
    def remove(self):
        if not self.owned():
            return
        self.call("disable", "--now", UNIT)
        self.call("daemon-reload")

class NoService:
    def active(self):
        return False
    def link(self):
        pass
    def remove(self):
        pass
    def start(self):
        raise InstallError("file-only installation: no system service configured")
    def stop(self):
        raise InstallError("file-only installation: no system service configured")

def empty_state():
    return {"schemaVersion": 1, "installed": False, "active": None, "previous": None, "releases": {}, "settings": None}

def worker_hash(manifest, settings):
    if not settings.get("runtimeProfile"):
        return None
    workers = [f for f in manifest["files"] if f["path"] == "bin/vp-core-managed-worker"]
    require(len(workers) == 1, "explicit runtime profile requires verified bundled vp-core-managed-worker")
    return workers[0]["sha256"]

def service_unit(root, settings, worker_sha256=None):
    # All interpolated strings validated below; no shell command lines or hooks.
    runtime = ""
    writable = str(root / "data")
    if settings.get("runtimeProfile"):
        require(HEX.fullmatch(worker_sha256 or ""), "runtime worker hash required")
        runtime = (f" --runtime-profile loopback-vless-v1 --runtime-root {root}/runtime"
                   f" --worker {root}/current/bin/vp-core-managed-worker --worker-sha256 {worker_sha256}"
                   f" --vault-root {root}/vault --vault-namespace {settings['vaultNamespace']}"
                   " --vault-action open --probe-bind 127.0.0.1:0")
        writable += f" {root}/runtime {root}/vault"
    return ("# Independently authored VP product unit; generated by tools/install\n"
        "[Unit]\nDescription=VP authenticated management service\nAfter=network.target\n\n"
        "[Service]\nType=simple\nUser=vp\nGroup=vp\nUMask=0077\n"
        f"LoadCredential=bootstrap:{settings['bootstrapFile']}\nStandardInput=file:%d/bootstrap\n"
        f"ExecStart={root}/current/bin/vp-product-managementd --state-root {root}/data "
        f"--bind {settings['bind']} --origin {settings['origin']} --web-root {root}/current/web{runtime}\n"
        "Restart=on-failure\nRestartSec=3\nTimeoutStopSec=30\nNoNewPrivileges=yes\n"
        "PrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\n"
        f"ReadWritePaths={writable}\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
        "[Install]\nWantedBy=multi-user.target\n")

def service_preflight(root, settings, manifest=None):
    """Aggregate read-only prerequisites; never invoke a host service command.

    File metadata presence is not credential/vault validity or runtime readiness.
    """
    checks = []
    def add(name, ok, remedy):
        checks.append({"dependency": name, "status": "present_not_certified" if ok else "missing_or_invalid",
                       "required": True, "nextStep": remedy})
    if settings.get("runtimeProfile"):
        host = check_sealed_runtime_host()
        checks.append({"dependency": "sealed_executable_host", "status": "present_not_certified" if host["prerequisitesAvailable"] else "missing_or_invalid",
                       "required": True, "nextStep": host["nextStep"], "detail": host})
    if settings["mode"] != "systemd":
        return {"mode": "files", "canAttemptServiceDeployment": False, "checks": checks,
                "note": "只安装文件；不会创建可用服务，不证明隧道可用。"}
    add("root_authority", os.geteuid() == 0, "真实目标主机需要管理员授权；当前工具不会自动提权。")
    add("systemctl", Path('/usr/bin/systemctl').is_file(), "在受支持的目标发行版提供 systemd；工具不会安装软件包。")
    add("systemd_manager", Path('/run/systemd/system').is_dir(), "在实际 systemd Linux 主机部署；容器的 file-only 成功不能替代服务验收。")
    account = group = None
    try: account = pwd.getpwnam('vp')
    except KeyError: pass
    try: group = grp.getgrnam('vp')
    except KeyError: pass
    add("vp_group", group is not None, "管理员需预建专用 vp 组；当前未实现首次 provision 子命令。")
    add("vp_nonlogin_account", account is not None and account.pw_uid != 0 and group is not None and
        account.pw_gid == group.gr_gid and account.pw_shell in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'),
        "管理员需预建非 root、不可登录且主组为 vp 的专用 vp 用户。")
    bootstrap_ok = False
    try:
        bootstrap = safe_absolute(settings['bootstrapFile'])
        check_ancestors(bootstrap.parent)
        st = bootstrap.lstat()
        bootstrap_ok = stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077 and 0 < st.st_size <= 4096
    except (InstallError, OSError):
        pass
    add("external_bootstrap_metadata", bootstrap_ok,
        "管理员通过安全渠道提供 root 所有的私密 JSON（最多 4096 字节）；用户名/高熵令牌和可选 vault master key 均不在 argv。仅检查元数据，不读取秘密。")
    if settings.get('runtimeProfile'):
        if manifest is None:
            checks.append({"dependency": "pinned_worker_in_bundle", "status": "not_checked", "required": False,
                           "nextStep": "未读取发布包；安装时必须验证实际 worker 清单、SHA256 与 daemon core/patch identity。"})
        else:
            add("pinned_worker_in_bundle", any(f['path'] == 'bin/vp-core-managed-worker' for f in manifest['files']),
                "提供与 daemon core/patch identity 匹配的真实 worker，并纳入发布包的逐文件 SHA256 清单。")
        vault = Path(root)/'vault'
        vault_present = False
        try:
            st = vault.lstat()
            vault_present = stat.S_ISDIR(st.st_mode) and not st.st_mode & 0o077 and any(vault.iterdir())
        except OSError:
            pass
        add("explicitly_initialized_vault", vault_present,
            "首次运行时服务 provision 流程尚未完成，当前为明确阻塞项；需统一安全初始化后才能服务部署。不要手工伪造安装标记或将 file-only 成功当作服务成功；启动只允许 open。")
    checks.append({"dependency": "systemd_version_and_runtime_acceptance", "status": "not_checked", "required": False,
                   "nextStep": "目标需 systemd 247+ 的 credential 支持；真实主机版本、MAC、权限、启动和转发须单独验收。"})
    return {"mode": "systemd", "canAttemptServiceDeployment": all(c['status'] != 'missing_or_invalid' for c in checks), "checks": checks}

def show_preflight(report):
    print("安装前依赖汇总（只读，不创建账号/凭据、不调用 systemd）：")
    if not report['checks']:
        print("  " + report['note'])
    for check in report['checks']:
        print(f"  - {check['dependency']}: {check['status']}\n    {check['nextStep']}")

def validate_settings(settings):
    exact_keys(settings, ("mode", "bind", "origin", "bootstrapFile", "runtimeProfile", "vaultNamespace", "enableOnBoot"))
    require(settings["mode"] in ("files", "systemd"), "invalid service mode")
    require(type(settings["enableOnBoot"]) is bool and (not settings["enableOnBoot"] or settings["mode"] == "systemd"), "boot enable requires explicit systemd mode")
    require(re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", settings["bind"] or ""), "explicit IPv4 loopback bind required")
    require(1 <= int(settings["bind"].split(":")[1]) <= 65535, "invalid service port")
    require(settings["origin"] == "http://" + settings["bind"], "local origin must exactly match bind; TLS edge requires separate deployment")
    safe_absolute(settings["bootstrapFile"])
    require(settings["runtimeProfile"] in (None, "loopback-vless-v1"), "unsupported runtime profile")
    if settings["runtimeProfile"]:
        require(isinstance(settings["vaultNamespace"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", settings["vaultNamespace"]), "explicit vault namespace required")
    else:
        require(settings["vaultNamespace"] is None, "vault namespace requires explicit runtime profile")

class Installer:
    def __init__(self, root, service=None):
        self.root = check_ancestors(root)
        self.injected_service = service  # Dependency injection only; CLI exposes no fake service option.

    def _owned_root(self):
        if not self.root.exists():
            return False
        st = self.root.stat()
        require(st.st_uid == os.geteuid() and not st.st_mode & 0o022, "installation root ownership/permissions rejected")
        marker = self.root / ".vp-owned.json"
        if not marker.exists():
            require(not list(self.root.iterdir()), "nonempty unmanaged installation root")
            return False
        require(strict_json(read_regular(marker, 4096, True)) == OWNER, "installation ownership marker mismatch")
        return True

    def state(self):
        if not self._owned_root():
            return empty_state()
        file = self.root / "state.json"
        if not file.exists():
            return empty_state()
        s = strict_json(read_regular(file, 1024 * 1024, True))
        exact_keys(s, ("schemaVersion", "installed", "active", "previous", "releases", "settings"))
        require(s["schemaVersion"] == 1 and type(s["installed"]) is bool and isinstance(s["releases"], dict), "invalid installer state")
        for key, record in s["releases"].items():
            require(IDENT.fullmatch(key), "invalid persisted release ID")
            exact_keys(record, ("bundleSha256", "manifestSha256"))
            require(all(isinstance(v, str) and HEX.fullmatch(v) for v in record.values()), "invalid stored digest")
        for key in ("active", "previous"):
            require(s[key] is None or s[key] in s["releases"], "invalid activation state")
        if s["settings"]:
            validate_settings(s["settings"])
        return s

    def runner(self, state):
        return self.injected_service or (Systemd(self.root, state["settings"]["enableOnBoot"]) if state["settings"] and state["settings"]["mode"] == "systemd" else NoService())

    def verify_slot(self, release, record):
        slot = self.root / "releases" / release
        check_ancestors(slot)
        manifest = read_regular(slot / "manifest.json", 128 * 1024)
        require(digest(manifest) == record["manifestSha256"], "installed release manifest drift")
        m = strict_json(manifest)
        require(m["releaseId"] == release and m["storageSchema"] == 1, "incompatible installed slot")
        expected = {f["path"] for f in m["files"]} | {"manifest.json"}
        found = set()
        for parent, dirs, files in os.walk(slot, followlinks=False):
            for child in dirs + files:
                require(not (Path(parent) / child).is_symlink(), "symlink in release slot")
            for file in files:
                found.add(str((Path(parent) / file).relative_to(slot)))
        require(found == expected, "untracked files in release slot")
        for f in m["files"]:
            safe_relative(f["path"])
            path = slot / f["path"]
            st = path.lstat()
            require(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == (0o755 if f["executable"] else 0o644), "installed release permission drift")
            data = read_regular(path, MAX_FILE)
            require(len(data) == f["size"] and digest(data) == f["sha256"], "installed release file drift")
        return m

    def pending(self):
        path = self.root / "journal.json"
        if not self._owned_root() or not path.exists():
            return None
        j = strict_json(read_regular(path, 2 * 1024 * 1024, True))
        require(j.get("owner") == OWNER["owner"] and j.get("action") in ("install", "update", "rollback", "uninstall", "start", "stop"), "invalid recovery journal")
        return j

    def plan(self, action, bundle=None, settings=None, target=None, purge=False):
        require(not self.pending() or action == "recover", "unfinished operation: run recover before any mutation")
        s = self.state()
        if action == "recover":
            require(self.pending(), "no pending operation to recover")
        if action in ("install", "update"):
            require(bundle is not None, "verified local --bundle and --sha256 required; no published source configured")
            require(action != "update" or s["installed"], "update requires installed release")
            if s["settings"]:
                require(settings is None or settings == s["settings"], "settings change requires a separately reviewed deployment")
                settings = s["settings"]
            require(settings is not None, "service settings required")
            validate_settings(settings)
            worker_hash(bundle.manifest, settings)
            target = bundle.manifest["releaseId"]
            if target in s["releases"]:
                require(s["releases"][target]["bundleSha256"] == bundle.sha256, "release ID already maps to different bundle")
                worker_hash(self.verify_slot(target, s["releases"][target]), settings)
        elif action == "rollback":
            target = target or s["previous"]
            require(s["installed"] and target in s["releases"] and target != s["active"], "no different verified rollback slot")
            worker_hash(self.verify_slot(target, s["releases"][target]), s["settings"])
        elif action in ("start", "stop", "uninstall"):
            require(s["installed"], "product not installed")
        elif action != "recover":
            raise InstallError("unsupported action")
        if action == "uninstall":
            for release, record in s["releases"].items():
                self.verify_slot(release, record)
        if action != "recover":
            current = self.root / "current"
            if s["active"]:
                self.verify_slot(s["active"], s["releases"][s["active"]])
                require(current.is_symlink() and os.readlink(current) == "releases/" + s["active"], "activation pointer drift")
            else:
                require(not current.exists() and not current.is_symlink(), "unowned activation pointer")
        if purge:
            require(action == "uninstall", "purge only supported for uninstall")
        result = {"schemaVersion": 1, "action": action, "root": str(self.root), "before": s,
                  "target": target, "bundleSha256": bundle.sha256 if bundle else None,
                  "settings": settings, "purgeData": bool(purge),
                  "recoveryDigest": digest(canonical(self.pending())) if action == "recover" else None,
                  "changes": ["owned release files/activation/installer journal only", "data retained unless purgeData=true", "no routes/firewall/system proxy changes"],
                  "runtimeAcceptance": "not_verified",
                  "noOp": action in ("install", "update") and s["installed"] and target == s["active"]}
        result["planHash"] = digest(canonical(result))
        return result

    @contextlib.contextmanager
    def locked(self):
        owned = self._owned_root()
        self.root.mkdir(mode=0o755, parents=False, exist_ok=True)
        if not owned:
            atomic_json(self.root / ".vp-owned.json", OWNER)
        fd = os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise InstallError("another installer operation owns the lock") from exc
            yield
        finally:
            os.close(fd)

    def _pointer(self, release):
        current = self.root / "current"
        if current.exists() or current.is_symlink():
            require(current.is_symlink() and re.fullmatch(r"releases/[A-Za-z0-9][A-Za-z0-9._-]{0,79}", os.readlink(current)), "unowned activation pointer")
        tmp = self.root / ".current-next"
        require(not tmp.exists() and not tmp.is_symlink(), "unexpected activation temporary file")
        if release:
            tmp.symlink_to("releases/" + release)
            os.replace(tmp, current)
        elif current.is_symlink():
            current.unlink()
        sync_dir(self.root)

    def _journal(self, record, phase):
        record["phase"] = phase
        atomic_json(self.root / "journal.json", record)

    def _clear_journal(self):
        (self.root / "journal.json").unlink(missing_ok=True)
        sync_dir(self.root)

    def _provision_files(self, settings, worker_sha256=None):
        names = ("releases", "systemd", "data", "runtime", "vault") if settings.get("runtimeProfile") else ("releases", "systemd", "data")
        for name in names:
            path = self.root / name
            if name in ("data", "runtime", "vault") and path.exists():
                st = path.lstat()
                require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and not st.st_mode & 0o077, "unsafe existing state directory")
            else:
                check_ancestors(path)
                path.mkdir(exist_ok=True, mode=0o700 if name in ("data", "runtime", "vault") else 0o755)
        atomic_write(self.root / "systemd" / UNIT, service_unit(self.root, settings, worker_sha256).encode(), 0o644)

    def _check_service_prerequisites(self, settings, worker_sha256=None):
        if settings["mode"] != "systemd" or self.injected_service:
            return
        require(os.geteuid() == 0, "systemd deployment requires root")
        try:
            account = pwd.getpwnam("vp")
            group = grp.getgrnam("vp")
        except KeyError as exc:
            raise InstallError("dedicated vp account/group must be provisioned externally") from exc
        require(account.pw_gid == group.gr_gid and account.pw_uid != 0 and account.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"), "vp account must be non-login/non-root")
        require(read_regular(self.root / "systemd" / UNIT, 16384) == service_unit(self.root, settings, worker_sha256).encode(), "systemd unit drift")
        credential = safe_absolute(settings["bootstrapFile"])
        check_ancestors(credential.parent)
        read_regular(credential, 4096, True)  # Never persist/copy/print/parse a real credential.
        # Only our private state directory; never chown an arbitrary caller path.
        for name in (("data", "runtime", "vault") if settings.get("runtimeProfile") else ("data",)):
            os.chown(self.root / name, account.pw_uid, account.pw_gid)
            os.chmod(self.root / name, 0o700)

    def apply(self, plan, confirmation, bundle=None):
        require(HEX.fullmatch(confirmation or "") and confirmation == plan["planHash"], "exact plan hash confirmation required")
        # Inspect real current/pending settings before locked() creates any root,
        # marker or lock. A fabricated plan cannot hide an existing runtime profile.
        needs_runtime_gate = plan["action"] in ("install", "update", "rollback", "start", "recover")
        journal = self.pending() or {} if plan["action"] == "recover" else {}
        if plan["action"] == "recover" and (journal.get("phase") == "committed" or journal.get("action") == "uninstall"):
            # These exact _recover branches cannot launch a worker. Keep cleanup
            # possible on unsupported hosts; fresh plan/digest is rechecked locked.
            needs_runtime_gate = False
        if needs_runtime_gate:
            candidates = [plan.get("settings"), self.state().get("settings")]
            if plan["action"] == "recover":
                candidates += [journal.get("settings"), journal.get("before", {}).get("settings")]
            if any(settings and settings.get("runtimeProfile") for settings in candidates):
                host = check_sealed_runtime_host()
                require(host["prerequisitesAvailable"], "sealed runtime host unsupported: " + host["reason"] + "; " + host["nextStep"])
        with self.locked():
            fresh = self.plan(plan["action"], bundle, plan["settings"], plan["target"], plan["purgeData"])
            if fresh != plan:
                raise StalePlan("state changed since plan; review a fresh plan")
            if plan["action"] == "recover":
                return self._recover()
            if plan["noOp"]:
                return self.status()
            before = plan["before"]
            runner = self.runner(before if before["settings"] else {**before, "settings": plan["settings"]})
            was_active = runner.active()
            journal = {"owner": OWNER["owner"], "action": plan["action"], "before": before,
                       "beforeActive": was_active, "target": plan["target"], "settings": plan["settings"],
                       "purgeData": plan["purgeData"], "planHash": plan["planHash"],
                       "targetRecord": {"bundleSha256": bundle.sha256, "manifestSha256": digest(canonical(bundle.manifest))} if bundle else None}
            self._journal(journal, "prepared")
            try:
                action = plan["action"]
                if action in ("start", "stop"):
                    if action == "start":
                        active_manifest = self.verify_slot(before["active"], before["releases"][before["active"]])
                        self._check_service_prerequisites(before["settings"], worker_hash(active_manifest, before["settings"]))
                        runner.start()
                    else:
                        runner.stop()
                    self._clear_journal()
                    return self.status()
                if action == "uninstall":
                    return self._finish_uninstall(journal, runner)
                settings = plan["settings"] or before["settings"]
                target_manifest = bundle.manifest if bundle else self.verify_slot(plan["target"], before["releases"][plan["target"]])
                worker_sha = worker_hash(target_manifest, settings)
                self._provision_files(settings, worker_sha)
                self._check_service_prerequisites(settings, worker_sha)
                after = strict_json(canonical(before))
                target = plan["target"]
                if bundle and target not in before["releases"]:
                    stage = self.root / "releases" / (".stage-" + target)
                    require(not stage.exists(), "staging residue requires recovery/inspection")
                    bundle.extract(stage)
                    self._journal(journal, "staged")
                    dest = self.root / "releases" / target
                    require(not dest.exists(), "untracked release destination")
                    os.rename(stage, dest)
                    sync_dir(dest.parent)
                    after["releases"][target] = {"bundleSha256": bundle.sha256,
                        "manifestSha256": digest(canonical(bundle.manifest))}
                if was_active:
                    runner.stop()
                self._journal(journal, "switch_intent")
                self._pointer(target)
                after.update(installed=True, active=target, settings=settings,
                             previous=before["active"] if before["active"] != target else before["previous"])
                self._journal(journal, "switched")
                runner.link()
                if was_active:
                    runner.start()
                self._journal(journal, "service_verified")
                atomic_json(self.root / "state.json", after)
                self._journal(journal, "committed")
                self._clear_journal()
                return self.status()
            except Exception as exc:
                # If recovery fails journal remains. Never retry uncertain actions silently.
                try:
                    self._recover()
                except Exception as recovery:
                    raise InstallError("operation failed; recovery required, journal retained") from recovery
                raise InstallError("operation failed; previous release/service state restored") from exc

    def _recover(self):
        journal = self.pending()
        if not journal:
            return self.status()
        before = journal["before"]
        runner = self.runner(before if before["settings"] else {**before, "settings": journal["settings"]})
        if journal["phase"] == "committed":
            self._clear_journal()
            return self.status()
        if journal["action"] == "uninstall":
            return self._finish_uninstall(journal, runner)
        if before["active"]:
            old_manifest = self.verify_slot(before["active"], before["releases"][before["active"]])
            self._provision_files(before["settings"], worker_hash(old_manifest, before["settings"]))
        if runner.active():
            runner.stop()
        temporary = self.root / ".current-next"
        if temporary.exists() or temporary.is_symlink():
            allowed = {"releases/" + r for r in (before["active"], journal.get("target")) if r}
            require(temporary.is_symlink() and os.readlink(temporary) in allowed, "unowned interrupted activation pointer")
            temporary.unlink()
        self._pointer(before["active"])
        if before["installed"]:
            runner.link()  # Restored unit must be reloaded before old process restarts.
        if not before["installed"]:
            runner.remove()
        if journal["beforeActive"]:
            runner.start()
        target = journal.get("target")
        record = journal.get("targetRecord")
        if target and record and target not in before["releases"]:
            require(IDENT.fullmatch(target), "invalid recovery release ID")
            slot = self.root / "releases" / target
            if slot.exists():
                self.verify_slot(target, record)
                before["releases"][target] = record  # Retained verified inactive release, safe to retry.
            stage = self.root / "releases" / (".stage-" + target)
            if stage.exists():
                self._remove_private_tree(stage)
        atomic_json(self.root / "state.json", before)
        # Unrecognized paths are never deleted by recovery.
        self._clear_journal()
        return self.status()

    def _finish_uninstall(self, journal, runner):
        # Forward-only idempotent cleanup. Configuration is NEVER automatically rolled
        # back/migrated; no assumption about database reversibility.
        runner.remove()
        self._journal(journal, "uninstall_stopped")
        self._pointer(None)
        if journal["purgeData"]:
            for name in ("data", "runtime", "vault"):
                self._delete_tree(self.root / name)
        state = journal["before"]
        # Rename each verified owned slot before deleting. Recovery can finish an
        # interrupted deletion in its private .trash namespace, never an unknown path.
        for release, record in state["releases"].items():
            require(IDENT.fullmatch(release), "invalid uninstall release ID")
            slot = self.root / "releases" / release
            trash = self.root / "releases" / (".trash-" + release)
            require(not (slot.exists() and trash.exists()), "ambiguous uninstall residue")
            if slot.exists():
                self.verify_slot(release, record)
                os.rename(slot, trash)
                sync_dir(trash.parent)
            if trash.exists():
                self._remove_private_tree(trash)
        state = {**state, "installed": False, "active": None, "previous": None, "releases": {}}
        atomic_json(self.root / "state.json", state)
        self._journal(journal, "committed")
        self._clear_journal()
        return self.status()

    def _remove_private_tree(self, path):
        require(path.parent == self.root / "releases" and
                re.fullmatch(r"\.(stage|trash)-[A-Za-z0-9][A-Za-z0-9._-]{0,79}", path.name), "unowned temporary slot")
        require(path.is_dir() and not path.is_symlink(), "unsafe temporary slot")
        for parent, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                st = (Path(parent) / name).lstat()
                require(st.st_uid == os.geteuid() and (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)), "unexpected temporary-slot contents")
        shutil.rmtree(path)
        sync_dir(path.parent)

    def _delete_tree(self, path):
        if not path.exists() and not path.is_symlink():
            return
        require(path.parent == self.root and path.name in ("data", "runtime", "vault") and not path.is_symlink(), "refusing unowned purge path")
        for parent, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                st = (Path(parent) / name).lstat()
                require(stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode), "purge refuses symlink/special data")
        shutil.rmtree(path)
        sync_dir(self.root)

    def status(self, observe_service=True):
        s = self.state()
        runner = self.runner(s)
        pending = bool(self.pending())
        integrity = "not_applicable"
        if s["active"]:
            if pending:
                integrity = "not_checked_during_recovery"
            else:
                self.verify_slot(s["active"], s["releases"][s["active"]])
                current = self.root / "current"
                require(current.is_symlink() and os.readlink(current) == "releases/" + s["active"], "activation pointer drift")
                integrity = "verified_files_only"
        releases = self.root / "releases"
        untracked = sorted(p.name for p in releases.iterdir() if p.name not in s["releases"]) if releases.is_dir() else []
        return {"installed": s["installed"], "activeRelease": s["active"], "previousRelease": s["previous"],
                "serviceActive": runner.active() if observe_service else None,
                "serviceObservation": "queried" if observe_service else "not_checked_preflight",
                "forwarding": "not_verified", "recoveryRequired": pending, "releaseIntegrity": integrity,
                "retainedData": (self.root / "data").exists(), "untrackedSlots": untracked}

ACTION_WORDS = {"install": "安装", "update": "更新", "rollback": "回滚", "recover": "恢复",
                "start": "启动", "stop": "停止", "uninstall": "卸载"}

def confirm_interactive(plan):
    """Short TTY consent applies only to the exact immutable plan just displayed."""
    action = plan["action"]
    word = ACTION_WORDS[action]
    settings = plan["settings"] or plan["before"]["settings"] or {}
    print(f"\n操作 / Action: {word} ({action})")
    print(f"目标目录 / Directory: {plan['root']}")
    target = plan['target'] or (None if action == 'uninstall' else plan['before']['active'])
    print(f"版本 / Release: {plan['before']['active'] or '(none)'} -> {target or '(none)'}")
    print(f"服务模式 / Service mode: {settings.get('mode', 'none')}")
    print("变更 / Changes:")
    for change in plan["changes"]:
        print("  - " + change)
    print("  - " + ("明确清除 data/runtime/vault，不可恢复" if plan["purgeData"] else "保留 data/runtime/vault"))
    if plan["noOp"]:
        print("相同版本，计划不执行变更 / Identical release: no mutation")
    print("完整计划摘要 / Plan SHA256: " + plan["planHash"])
    print("服务运行不代表协议已验收 / Service state is not protocol certification")
    answer = input(f"输入“{word}”确认本次计划，回车默认取消 / Type '{action}' to confirm, Enter cancels: ").strip()
    if answer not in (word, action):
        return False
    if plan["purgeData"]:
        answer = input("额外确认不可恢复的数据清除：输入“清除数据” / Type 'purge data'; Enter cancels: ").strip()
        if answer not in ("清除数据", "purge data"):
            return False
    return True

def show_status(status, root):
    print(f"目录：{root}")
    print("已安装：" + ("是" if status["installed"] else "否"))
    print("当前版本：" + (status["activeRelease"] or "无"))
    print("服务运行：" + ("未检查（只读预检不调用服务管理器）" if status["serviceActive"] is None else
                       "是（不代表协议验收通过）" if status["serviceActive"] else "否"))
    print("文件完整性：" + status["releaseIntegrity"])
    print("隧道转发：未由安装器验证；请查看管理 API 的真实观测")
    if status["recoveryRequired"]:
        print("存在中断事务：请先选择“恢复”，不要开始另一项变更。")

def interactive_menu():
    choices = [('install', '安装'), ('update', '更新'), ('rollback', '回滚版本'),
               ('start', '启动服务'), ('stop', '停止服务'), ('status', '查看状态'),
               ('uninstall', '卸载（默认保留数据）'), ('recover', '恢复中断操作'),
               ('preflight', '只读检查'), ('configure', '配置隧道协议（调用管理 API）'),
               ('protocols', '查看全部协议预设'), ('export', '订阅导出（后端尚未完成）')]
    print("VP Linux 隧道管理 · vp_core 内核")
    print("当前为本地发布包工程入口；没有已发布下载源，不会安装未知网络脚本。")
    for index, (_, label) in enumerate(choices, 1):
        print(f"  {index:2}. {label}")
    print("   0. 退出")
    answer = input("请选择编号 / Choice [0]: ").strip()
    if answer in ('', '0'):
        return None
    if answer in {action for action, _ in choices}:
        return answer  # Existing typed commands remain compatible.
    require(answer.isdigit() and 1 <= int(answer) <= len(choices), "请选择菜单中的编号 / invalid menu choice")
    return choices[int(answer) - 1][0]

def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("preflight", "install", "update", "rollback", "recover", "start", "stop", "status", "uninstall"), nargs="?")
    p.add_argument("--root", default="/opt/vp")
    p.add_argument("--bundle")
    p.add_argument("--sha256")
    p.add_argument("--release")
    p.add_argument("--service-mode", choices=("files", "systemd"), default="files")
    p.add_argument("--bind", default="127.0.0.1:18080")
    p.add_argument("--bootstrap-file", default="/etc/vp/bootstrap.json")
    p.add_argument("--enable-on-boot", action="store_true")
    p.add_argument("--runtime-profile", choices=("loopback-vless-v1",))
    p.add_argument("--vault-namespace")
    p.add_argument("--purge-data", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true", help="show machine-readable plan/status even in a TTY")
    p.add_argument("--confirm-plan-sha256", "--confirm", dest="confirm",
                   help="noninteractive exact planHash; --confirm is a compatibility alias")
    return p

def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if not args.action:
            require(sys.stdin.isatty(), "action required in noninteractive mode")
            args.action = interactive_menu()
            if not args.action:
                return 0
            if args.action in ('configure', 'protocols'):
                import vp_api
                if args.action == 'protocols':
                    return vp_api.main(['protocols'])
                origin = input("管理 API 地址（例如 http://127.0.0.1:18080，回车取消）: ").strip()
                return vp_api.main(['configure', '--origin', origin]) if origin else 0
            if args.action == 'export':
                raise InstallError("订阅导出依赖 /api/v1/exports 专用令牌/节点导出后端，当前尚未完成；不会生成虚假链接。")
        if sys.stdin.isatty() and args.action in ('install', 'update'):
            if not args.bundle:
                args.bundle = input("已验证本地发布包路径 / Verified local bundle path: ").strip()
            if not args.sha256:
                args.sha256 = input("独立可信渠道提供的 SHA256 / Independently trusted SHA256: ").strip()
        host_arch()
        engine = Installer(args.root)
        requested_settings = {"mode": args.service_mode, "bind": args.bind, "origin": "http://" + args.bind,
                              "bootstrapFile": args.bootstrap_file, "runtimeProfile": args.runtime_profile,
                              "vaultNamespace": args.vault_namespace, "enableOnBoot": args.enable_on_boot}
        if args.action in ("status", "preflight"):
            status = engine.status(observe_service=args.action != 'preflight')
            report = service_preflight(engine.root, engine.state()['settings'] or requested_settings)
            if args.json or not sys.stdin.isatty():
                print(json.dumps({"linuxArchitecture": host_arch(), "root": str(engine.root), "status": status,
                                  "publicReleaseAvailable": False, "preflightReadOnly": True,
                                  "servicePreflight": report}, indent=2))
            else:
                show_status(status, engine.root)
                show_preflight(report)
                print("只读检查完成；尚无公开发布包，未启动服务或修改系统。")
            return 2 if args.action == 'preflight' and any(c['required'] and c['status'] == 'missing_or_invalid' for c in report['checks']) else 0
        with contextlib.ExitStack() as stack:
            bundle = stack.enter_context(Bundle(args.bundle, args.sha256)) if args.bundle else None
            settings = None if engine.state()["settings"] else requested_settings
            if args.action in ('install', 'update', 'start'):
                report = service_preflight(engine.root, engine.state()['settings'] or requested_settings,
                                           bundle.manifest if bundle else None)
                if report['mode'] == 'systemd':
                    if args.json or not sys.stdin.isatty():
                        print(json.dumps({'servicePreflight': report}, indent=2))
                    else:
                        show_preflight(report)
                    require(report['canAttemptServiceDeployment'], "服务依赖未齐，请一次补齐上列依赖；尚未应用安装计划 / prerequisites incomplete")
            while True:
                plan = engine.plan(args.action, bundle, settings if args.action in ("install", "update") else None, args.release, args.purge_data)
                interactive = sys.stdin.isatty() and not args.confirm and not args.dry_run
                if not interactive or args.json:
                    print(json.dumps(plan, indent=2))
                if args.dry_run:
                    return 0
                confirm = args.confirm
                if interactive:
                    if not confirm_interactive(plan):
                        print("已取消，未应用计划 / Canceled; plan was not applied.")
                        return 0
                    confirm = plan["planHash"]
                if not confirm:
                    print("Plan only: rerun with --confirm-plan-sha256 PLAN_HASH; no changes made.")
                    return 0
                try:
                    result = engine.apply(plan, confirm, bundle)
                except StalePlan:
                    if not interactive:
                        raise
                    print("计划已变化，旧确认已失效；请重新核对并确认 / Plan changed; previous consent discarded.")
                    continue
                if args.json or not sys.stdin.isatty():
                    print(json.dumps(result, indent=2))
                else:
                    show_status(result, engine.root)
                return 0
    except (InstallError, OSError, KeyboardInterrupt) as exc:
        print("vp-install: " + (str(exc) if isinstance(exc, InstallError) else "operation interrupted/unavailable; inspect status/recover before retry"), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
