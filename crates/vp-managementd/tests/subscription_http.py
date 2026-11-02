#!/usr/bin/env python3
"""SOURCE-ONLY authored harness; no execution evidence accompanies this file.

When explicitly run in an authorized Linux loopback lane, this exercises actual
HTTP -> shared control/SQLite -> encrypted vault -> immutable managed worker,
then independent subscription authority -> the actual Rust URI-list codec.
All accounts, master keys and node credentials are temporary synthetic test
identities. Explicit development-loopback policy is NOT production HTTPS or an
Android-reachable subscription. Nothing changes routes, trust, proxy or systemd.

Required checker contract: executable reads URI-list bytes only from stdin,
returns exit 0 and JSON {"valid": true, "entries": 1}; it emits no secret data.
Never provide the subscription URL/body/token through argv, env or a temp file.
No caller-controlled executable is discovered or downloaded by this harness.

Failures emit only authored checkpoint codes, never response bodies, URLs,
exception messages, child output or connection credentials. Python cannot
guarantee process-memory zeroization; all sensitive objects stay memory-only.
"""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qsl, unquote, urlsplit
import uuid

from jsonschema import Draft202012Validator


MAX_HTTP_BYTES = 1024 * 1024
MAX_SUBSCRIPTION_BYTES = 256 * 1024
MAX_CHILD_LOG_BYTES = 1024 * 1024
PROFILE = "loopback-vless-v1"


class HarnessFailure(Exception):
    """Only fixed authored codes, never external messages or values."""


def require(condition, code):
    if not condition:
        raise HarnessFailure(code)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def free_port(excluded=()):
    for _ in range(16):
        with socket.socket() as handle:
            handle.bind(("127.0.0.1", 0))
            port = handle.getsockname()[1]
            if port not in excluded:
                return port
    raise HarnessFailure("loopback_port_allocation")


class CapturedProcess:
    """Drain child pipes without logging or unbounded retained diagnostics."""

    def __init__(self, command, limit=MAX_CHILD_LOG_BYTES):
        self.limit = limit
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.overflow = False
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        self.threads = []
        for pipe, output in [
            (self.process.stdout, self.stdout),
            (self.process.stderr, self.stderr),
        ]:
            thread = threading.Thread(target=self._drain, args=(pipe, output), daemon=True)
            thread.start()
            self.threads.append(thread)

    def _drain(self, pipe, output):
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    return
                remaining = max(0, self.limit - len(output))
                output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.overflow = True
        finally:
            pipe.close()

    def input(self, data):
        try:
            self.process.stdin.write(data)
            self.process.stdin.flush()
        finally:
            self.process.stdin.close()

    def wait(self, timeout):
        code = self.process.wait(timeout=timeout)
        for thread in self.threads:
            thread.join(timeout=2)
            require(not thread.is_alive(), "child_pipe_drain_deadline")
        require(not self.overflow, "child_output_limit")
        return code


def local_refs(value):
    if isinstance(value, dict):
        return {
            key: (
                item.replace("../schema/v1.schema.json#/", "#/")
                if key == "$ref" and isinstance(item, str)
                else local_refs(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [local_refs(item) for item in value]
    return value


class Harness:
    def __init__(self, args):
        self.daemon = args.daemon.resolve(strict=True)
        self.worker = args.worker.resolve(strict=True)
        self.codec = args.codec_check.resolve(strict=True)
        for binary in [self.daemon, self.worker, self.codec]:
            require(binary.is_file() and os.access(binary, os.X_OK), "executable_input")
        require(sys.platform == "linux", "linux_required")
        require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "pidfd_required")
        self.identities = {
            "daemonSha256": sha256_file(self.daemon),
            "workerSha256": sha256_file(self.worker),
            "codecSha256": sha256_file(self.codec),
        }
        self.repo = Path(__file__).resolve().parents[3]
        self.source_paths = {
            "harnessSha256": Path(__file__).resolve(),
            "fixtureSha256": Path(__file__).parent / "fixtures/vless_loopback.json",
            "openapiSha256": self.repo / "contracts/openapi/v1.yaml",
            "schemaSha256": self.repo / "contracts/schema/v1.schema.json",
        }
        self.identities.update({name: sha256_file(path) for name, path in self.source_paths.items()})
        self.openapi = json.loads((self.repo / "contracts/openapi/v1.yaml").read_text())
        self.definitions = json.loads((self.repo / "contracts/schema/v1.schema.json").read_text())["$defs"]
        self.schema_count = 0
        self.codec_count = 0
        self.forward_count = 0
        self.rejection_count = 0
        self.shutdown_count = 0
        self.scan_count = 0
        self.checks = []
        self.stage = "initialization"
        self.secrets = []
        self.bootstrap = secrets.token_urlsafe(32)
        self.master = secrets.token_hex(32)
        self.remember(self.bootstrap.encode())
        self.remember(self.master.encode())
        self.remember(bytes.fromhex(self.master))
        self.api_port = free_port()
        self.listener_port = free_port([self.api_port])
        self.host = f"127.0.0.1:{self.api_port}"
        self.origin = f"http://{self.host}"
        self.process = None
        self.children = []
        self.worker_identities = []
        self.root = None

    def remember(self, value):
        require(isinstance(value, bytes) and len(value) >= 16, "sensitive_value_shape")
        if value not in self.secrets:
            self.secrets.append(value)

    def no_plaintext(self, data):
        for value in self.secrets:
            require(value not in data, "plaintext_disclosure")

    def record(self, code):
        self.checks.append(code)

    def validate_response(self, method, path, status, content_type, body):
        for template, methods in self.openapi["paths"].items():
            pattern = re.sub(r"\{[^}]+\}", "[^/]+", template)
            if re.fullmatch(pattern, path) and method.lower() in methods:
                responses = methods[method.lower()]["responses"]
                require(str(status) in responses, "undocumented_http_status")
                content = responses[str(status)].get("content", {})
                media = content_type.split(";", 1)[0].strip()
                require(media in content, "undocumented_http_media_type")
                schema = local_refs(content[media]["schema"])
                schema["$defs"] = self.definitions
                value = json.loads(body) if media == "application/json" else body.decode("utf-8")
                errors = list(Draft202012Validator(schema).iter_errors(value))
                if errors:
                    # Schema paths are authored contract keys, never instance values,
                    # response data, request paths, tokens or validation messages.
                    error = errors[0]
                    location = "/".join(str(x) for x in error.absolute_schema_path)
                    raise HarnessFailure("http_response_contract:" + methods[method.lower()]["operationId"] + ":" + location)
                self.schema_count += 1
                return value
        raise HarnessFailure("uncontracted_http_request")

    def request(self, method, path, payload=None, auth=None, extra=None, public=False, sensitive=False):
        require(path.startswith("/") and "\r" not in path and "\n" not in path, "request_path")
        headers = {"Host": self.host}
        if not public:
            headers.update({"Origin": self.origin, "Content-Type": "application/json"})
        if auth:
            headers.update({"Cookie": auth[0], "X-VP-CSRF": auth[1]})
        if extra:
            headers.update(extra)
        connection = http.client.HTTPConnection("127.0.0.1", self.api_port, timeout=30)
        try:
            connection.request(method, path, None if payload is None else json.dumps(payload).encode(), headers)
            response = connection.getresponse()
            raw = response.read(MAX_HTTP_BYTES + 1)
            require(len(raw) <= MAX_HTTP_BYTES, "http_body_limit")
            headers_out = {key.lower(): value for key, value in response.getheaders()}
            require(headers_out.get("cache-control") == "no-store", "http_cache_protection")
            if public or sensitive:
                require(headers_out.get("referrer-policy") == "no-referrer", "sensitive_referrer_protection")
            if not sensitive:
                self.no_plaintext(raw)
            self.no_plaintext(json.dumps(headers_out).encode())
            result = self.validate_response(method, path, response.status, headers_out.get("content-type", ""), raw)
            return response.status, headers_out, result, raw
        finally:
            connection.close()

    def command(self, method, key, revision, payload):
        return {
            "schemaVersion": 1, "requestId": "actual-subscription-test",
            "idempotencyKey": key, "expectedRevision": revision,
            "method": method, "payload": payload,
        }

    def mutation(self, method, route, name, key, revision, payload, auth, sensitive=False, expected=200):
        response = self.request(
            method, route, self.command(name, key, revision, payload), auth,
            {"If-Match": f'"{revision}"'}, sensitive=sensitive,
        )
        require(response[0] == expected, "mutation_status")
        return response

    def start(self, initialize=False):
        require(self.process is None, "single_owned_daemon")
        command = [
            str(self.daemon), "--state-root", str(self.root / "control"),
            "--bind", self.host, "--origin", self.origin,
            "--runtime-profile", PROFILE, "--runtime-root", str(self.root / "runtime"),
            "--worker", str(self.worker), "--worker-sha256", self.identities["workerSha256"],
            "--vault-root", str(self.root / "vault"), "--vault-namespace", "subscription-http-test",
            "--vault-action", "initialize" if initialize else "open", "--probe-bind", "127.0.0.1:0",
            "--subscription-public-base", self.origin,
            "--subscription-network-profile", "development-loopback",
        ]
        child = CapturedProcess(command)
        self.children.append(child)
        self.process = child
        # No provisioned node refs: this journey must use the authenticated API.
        supplied = {
            "username": "synthetic-subscription-admin", "token": self.bootstrap,
            "vault": {"masterKeyHex": self.master, "credentials": []},
        }
        child.input(json.dumps(supplied).encode())
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            require(child.process.poll() is None, "daemon_startup_failed")
            try:
                if self.request("GET", "/api/v1/build")[0] == 401:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.04)
        raise HarnessFailure("daemon_startup_deadline")

    def login(self):
        status, headers, body, _ = self.request(
            "POST", "/api/v1/auth/login",
            {"username": "synthetic-subscription-admin", "password": self.bootstrap, "secondFactor": None},
            sensitive=True,
        )
        require(status == 200, "login_status")
        cookie_header = headers["set-cookie"]
        lowered = cookie_header.lower()
        require("httponly" in lowered and "secure" in lowered and "samesite=strict" in lowered, "session_cookie_flags")
        cookie = cookie_header.split(";", 1)[0]
        csrf = body["result"]["csrfToken"]
        self.remember(cookie.encode())
        self.remember(cookie.split("=", 1)[1].encode())
        self.remember(csrf.encode())
        return cookie, csrf

    def credential(self, auth, key, active_revision):
        payload = {"kind": {"kind": "uuid"}, "confirmGenerate": True}
        _, _, body, _ = self.mutation("POST", "/api/v1/credentials", "credential_create", key, active_revision, payload, auth)
        summary = body["result"]
        require(summary["state"] == "available" and summary["kind"] == {"kind": "uuid"}, "credential_metadata")
        require(summary["secretRef"].startswith("secret:"), "credential_reference")
        repeated = self.mutation("POST", "/api/v1/credentials", "credential_create", key, active_revision, payload, auth)[2]
        require(repeated["result"] == summary, "credential_safe_retry")
        return summary

    def configuration(self, reference):
        fixture = Path(__file__).parent / "fixtures/vless_loopback.json"
        value = json.loads(fixture.read_text())
        require(len(value["listeners"]) == 1, "shared_fixture_listener_count")
        listener = value["listeners"][0]
        require(listener["bind"]["address"] == "127.0.0.1", "shared_fixture_loopback")
        listener["bind"]["port"] = self.listener_port
        listener["protocol"]["users"][0]["credentialRef"] = reference
        return value

    def apply(self, auth, key, revision, config):
        _, _, created, _ = self.mutation("POST", "/api/v1/drafts", "draft_create", key + "-draft", revision, config, auth)
        draft = created["result"]
        _, _, valid, _ = self.mutation("POST", f'/api/v1/drafts/{draft["id"]}/validate', "validate", key + "-validate", draft["revision"], {}, auth)
        require(valid["result"]["valid"] is True, "actual_validation_failed")
        _, _, planned, _ = self.mutation("POST", "/api/v1/plans", "plan_create", key + "-plan", revision, {"draftId": draft["id"]}, auth)
        plan = planned["result"]
        route = f'/api/v1/plans/{plan["id"]}/apply'
        payload = {"planHash": plan["planHash"], "confirmed": True}
        _, _, accepted, _ = self.mutation("POST", route, "plan_apply", key + "-apply", revision, payload, auth, expected=202)
        operation_id = accepted["operationId"]
        _, _, repeated, _ = self.mutation("POST", route, "plan_apply", key + "-apply", revision, payload, auth, expected=202)
        require(repeated["operationId"] == operation_id, "apply_safe_retry")
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            status, _, result, _ = self.request("GET", f"/api/v1/operations/{operation_id}", auth=auth)
            require(status == 200, "operation_query_status")
            phase = result["result"]["status"]
            if phase in {"succeeded", "failed", "rolled_back", "recovery_required", "canceled"}:
                require(phase == "succeeded", "actual_apply_failed")
                self.capture_workers(require_active=True)
                return result["result"]
            time.sleep(0.04)
        raise HarnessFailure("operation_deadline")

    def snapshot(self, auth, revision):
        status, _, body, _ = self.request("GET", "/api/v1/snapshot", auth=auth)
        require(status == 200, "snapshot_status")
        snapshot = body["result"]
        require(snapshot["desiredRevision"] == revision and snapshot["observedRevision"] == revision, "fresh_revision_observation")
        require(len(snapshot["listeners"]) == 1, "snapshot_listener_count")
        listener = snapshot["listeners"][0]
        require(listener["status"] == "ready" and listener["bound"] and listener["authenticationLoaded"], "fresh_listener_observation")
        require(listener["forwarding"]["status"] == "passed" and listener["forwarding"]["observedAt"] and listener["forwarding"]["evidenceId"], "fresh_forwarding_observation")
        require(listener["generation"] > 0, "fresh_generation")
        return listener["generation"]

    def publication_payload(self, config):
        listener = config["listeners"][0]
        return {
            "name": "Temporary loopback publication", "enabled": True, "format": "uri_list",
            "sources": [{
                "listenerId": listener["id"], "userId": listener["protocol"]["users"][0]["id"],
                "endpoint": {"host": "127.0.0.1", "port": self.listener_port},
                "clientSecurity": {"kind": "none"},
            }], "confirmPublishConnectionSecrets": True,
        }

    def issue(self, auth, publication, key):
        payload = {"expiresInSeconds": 600, "confirmIssueSecretUrl": True}
        route = f'/api/v1/publications/{publication["id"]}/token'
        _, headers, body, _ = self.mutation("POST", route, "publication_token_issue", key, publication["revision"], payload, auth, sensitive=True)
        result = body["result"]
        require(result["displayOnce"] is True, "one_time_secret_response")
        url = result["subscriptionUrl"]
        parsed = urlsplit(url)
        require(parsed.scheme == "http" and parsed.netloc == self.host and not parsed.query and not parsed.fragment, "explicit_development_public_base")
        require(parsed.path.startswith(f'/subscriptions/v1/{publication["id"]}/'), "publication_url_binding")
        token = parsed.path.rsplit("/", 1)[1]
        require(re.fullmatch(r"vps1_[0-9a-f]{64}", token) is not None, "subscription_token_namespace")
        require(token != self.bootstrap, "separate_subscription_authority")
        self.remember(token.encode())
        self.remember(url.encode())
        self.no_plaintext(json.dumps(result["publication"]).encode())
        self.no_plaintext(json.dumps(headers).encode())
        replay = self.mutation("POST", route, "publication_token_issue", key, publication["revision"], payload, auth, expected=409)
        require(replay[2]["error"]["code"] == "SECRET_RESULT_UNAVAILABLE", "no_secret_reissue_by_key")
        return result["publication"], url

    def fetch(self, url, expected=200, cookie=None):
        parsed = urlsplit(url)
        require(parsed.scheme == "http" and parsed.netloc == self.host and not parsed.query and not parsed.fragment, "fetch_exact_loopback_origin")
        extra = {"Cookie": cookie} if cookie else None
        # This is intentionally a new HTTP connection with NO management session,
        # CSRF, Authorization, Origin, proxy, redirect following or ambient cookie jar.
        status, headers, body, raw = self.request("GET", parsed.path, extra=extra, public=True, sensitive=expected == 200)
        require(status == expected, "subscription_fetch_status")
        if status == 200:
            require(headers.get("content-type") == "text/plain; charset=utf-8", "subscription_media_type")
            require(headers.get("content-disposition") == "attachment; filename=vp-subscription.txt", "subscription_attachment")
            require(len(raw) <= MAX_SUBSCRIPTION_BYTES, "subscription_byte_limit")
            return raw, int(headers["x-vp-config-revision"])
        require(isinstance(body, dict) and "error" in body, "subscription_safe_error")
        return body

    def decode_and_check(self, body):
        require(0 < len(body) <= MAX_SUBSCRIPTION_BYTES, "codec_input_limit")
        lines = body.decode("utf-8").splitlines()
        require(len(lines) == 1, "single_fixture_uri")
        uri = urlsplit(lines[0])
        require(uri.scheme == "vless" and uri.hostname == "127.0.0.1" and uri.port == self.listener_port, "fixture_uri_endpoint")
        require(uri.password is None and uri.username is not None, "fixture_uri_auth_shape")
        credential = unquote(uri.username)
        require(str(uuid.UUID(credential)) == credential and uuid.UUID(credential).version == 4, "generated_uuid_v4")
        query = parse_qsl(uri.query, strict_parsing=True)
        require(len(query) == 3 and dict(query) == {"encryption": "none", "type": "tcp", "security": "none"}, "fixture_uri_losslessness")
        self.remember(credential.encode())
        self.remember(uuid.UUID(credential).bytes)
        self.remember(lines[0].encode())
        self.remember(body)
        # Python's narrow fixture checks are NOT a codec replacement. The real
        # Rust parser must accept every node without diagnostics or loss.
        checker = CapturedProcess([str(self.codec)], limit=8192)
        self.children.append(checker)
        checker.input(body)
        try:
            status = checker.wait(timeout=10)
        except subprocess.TimeoutExpired:
            checker.process.kill()
            checker.wait(timeout=5)
            raise HarnessFailure("codec_deadline") from None
        self.no_plaintext(bytes(checker.stdout) + bytes(checker.stderr))
        require(status == 0, "rust_codec_rejected")
        result = json.loads(checker.stdout)
        require(
            result == {"valid": True, "entries": 1}
            and result["valid"] is True
            and type(result["entries"]) is int,
            "rust_codec_safe_receipt",
        )
        require(not checker.stderr, "rust_codec_unexpected_diagnostic")
        self.codec_count += 1
        return credential

    @staticmethod
    def exact_read(stream, length):
        output = bytearray()
        while len(output) < length:
            chunk = stream.recv(length - len(output))
            if not chunk:
                raise EOFError()
            output.extend(chunk)
        return bytes(output)

    def verify_wire(self, credential, expected=True):
        target = socket.socket()
        target.bind(("127.0.0.1", 0))
        target.listen(2)
        target.settimeout(1)
        target_port = target.getsockname()[1]
        marker = secrets.token_bytes(32)
        accepted = []

        def echo():
            try:
                connection, _ = target.accept()
                accepted.append(True)
                with connection:
                    connection.settimeout(1)
                    payload = self.exact_read(connection, len(marker))
                    connection.sendall(payload)
            except (OSError, EOFError):
                pass

        thread = threading.Thread(target=echo, daemon=True)
        thread.start()
        result = False
        try:
            with socket.create_connection(("127.0.0.1", self.listener_port), timeout=2) as connection:
                connection.settimeout(2)
                packet = b"\0" + uuid.UUID(credential).bytes + b"\0\1" + target_port.to_bytes(2, "big") + b"\1\x7f\0\0\1" + marker
                connection.sendall(packet)
                try:
                    result = self.exact_read(connection, 2) == b"\0\0" and self.exact_read(connection, len(marker)) == marker
                except (OSError, EOFError):
                    result = False
        finally:
            thread.join(timeout=3)
            target.close()
        require(not thread.is_alive(), "echo_target_cleanup")
        require(result == expected and bool(accepted) == expected, "actual_forward_or_rejection")
        if expected:
            self.forward_count += 1
        else:
            self.rejection_count += 1

    @staticmethod
    def process_identity(pid):
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            suffix = stat.rsplit(")", 1)[1].split()
            return {
                "pid": pid, "startTicks": suffix[19],
                "bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            }
        except FileNotFoundError:
            return None

    def present(self, identity):
        return self.process_identity(identity["pid"]) == identity

    def capture_workers(self, require_active=False):
        path = self.root / "runtime/runtime.journal.json"
        if not path.exists():
            require(not require_active, "active_runtime_journal_missing")
            return
        require(path.stat().st_size <= 8 * 1024 * 1024, "runtime_journal_limit")
        envelope = json.loads(path.read_bytes())
        journal = envelope["journal"]
        records = [journal.get("active"), journal.get("launching")]
        for stage in journal["stages"].values():
            records.extend([stage.get("candidate"), stage.get("previous")])
        for record in records:
            if record and record.get("process"):
                identity = record["process"]
                require(set(identity) == {"pid", "startTicks", "bootId"}, "journal_process_identity_shape")
                if identity not in self.worker_identities:
                    self.worker_identities.append(identity)
        if require_active:
            active = journal.get("active")
            require(active and active.get("process") and self.present(active["process"]), "exact_active_worker_identity")
            require(sha256_file(Path(f'/proc/{active["process"]["pid"]}/exe')) == self.identities["workerSha256"], "actual_worker_binary_identity")

    def stop(self):
        require(self.process is not None, "owned_daemon_missing")
        self.capture_workers(require_active=True)
        child = self.process
        require(child.process.poll() is None, "daemon_exited_before_shutdown")
        child.process.send_signal(signal.SIGTERM)
        try:
            status = child.wait(timeout=35)
        except subprocess.TimeoutExpired:
            raise HarnessFailure("daemon_shutdown_deadline") from None
        require(status == 0, "daemon_shutdown_status")
        self.process = None
        self.no_plaintext(bytes(child.stdout) + bytes(child.stderr))
        for identity in self.worker_identities:
            require(not self.present(identity), "journal_owned_worker_survived_shutdown")
        for port in [self.listener_port, self.api_port]:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    raise HarnessFailure("listener_survived_shutdown")
            except ConnectionRefusedError:
                pass
            with socket.socket() as released:
                released.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                released.bind(("127.0.0.1", port))
        self.shutdown_count += 1

    def cleanup(self):
        # Cleanup can signal only this Popen child, or a journal-proven exact
        # PID/startTicks/bootId whose open pidfd still points at our worker binary.
        failures = []
        if self.root is not None:
            try:
                self.capture_workers()
            except BaseException:
                # Invalid/missing evidence must not skip terminating our Popen
                # children, nor authorize guessing some unrelated worker PID.
                failures.append("cleanup_journal_unavailable")
        for child in self.children:
            try:
                if child.process.poll() is None:
                    child.process.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.process.kill()
                        child.wait(timeout=5)
            except BaseException:
                failures.append("cleanup_child_failed")
        for identity in self.worker_identities:
            try:
                if not self.present(identity):
                    continue
                descriptor = os.pidfd_open(identity["pid"], 0)
                try:
                    require(self.present(identity), "cleanup_process_identity_changed")
                    require(sha256_file(Path(f'/proc/{identity["pid"]}/exe')) == self.identities["workerSha256"], "cleanup_worker_identity")
                    signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                    deadline = time.monotonic() + 3
                    while self.present(identity) and time.monotonic() < deadline:
                        time.sleep(0.02)
                    if self.present(identity):
                        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                        deadline = time.monotonic() + 3
                        while self.present(identity) and time.monotonic() < deadline:
                            time.sleep(0.02)
                    require(not self.present(identity), "cleanup_worker_exit_unconfirmed")
                finally:
                    os.close(descriptor)
            except ProcessLookupError:
                # Exit between identity inspection and pidfd open/signal is safe.
                if self.present(identity):
                    failures.append("cleanup_worker_outcome_uncertain")
            except BaseException:
                failures.append("cleanup_worker_failed")
        self.process = None
        require(not failures, "owned_process_cleanup_incomplete")

    def scan(self):
        for child in self.children:
            require(child.process.poll() is not None, "child_process_still_running")
            require(not child.overflow, "child_output_limit")
            self.no_plaintext(bytes(child.stdout) + bytes(child.stderr))
        for path in self.root.rglob("*"):
            require(not path.is_symlink(), "unexpected_temporary_state_symlink")
            if path.is_file():
                require(path.stat().st_size <= 128 * 1024 * 1024, "state_scan_limit")
                self.no_plaintext(path.read_bytes())
                self.scan_count += 1

    def run(self):
        with tempfile.TemporaryDirectory(prefix="vp-subscription-http-") as directory:
            self.root = Path(directory)
            os.chmod(self.root, 0o700)
            for name in ["control", "runtime", "vault"]:
                (self.root / name).mkdir(mode=0o700)
            try:
                self.stage = "operator_credential_create"
                self.start(initialize=True)
                auth = self.login()
                status, _, inventory, _ = self.request("GET", "/api/v1/credentials", auth=auth)
                require(status == 200 and inventory["result"]["credentials"] == [], "initial_empty_vault_registry")
                require({"kind": "uuid"} in inventory["result"]["supportedKinds"], "actual_uuid_capability")
                require({"kind": "username_password"} not in inventory["result"]["supportedKinds"] and {"kind": "uuid_password"} not in inventory["result"]["supportedKinds"], "tuple_generation_remains_unavailable")
                require(self.request("GET", "/api/v1/credentials")[0] == 401, "credential_inventory_auth_required")
                first_credential = self.credential(auth, "first-node", 0)
                first_config = self.configuration(first_credential["secretRef"])
                self.stage = "first_actual_apply"
                self.apply(auth, "first", 0, first_config)
                generation_one = self.snapshot(auth, 1)
                self.record("operator-created-vault-credential-through-authenticated-api")
                self.record("actual-http-plan-apply-and-fresh-worker-observation")

                self.stage = "first_publication"
                publication_payload = self.publication_payload(first_config)
                _, _, created, _ = self.mutation("POST", "/api/v1/publications", "publication_create", "first-publication", 1, publication_payload, auth)
                publication = created["result"]
                issued, first_url = self.issue(auth, publication, "first-token")
                body, revision = self.fetch(first_url)
                require(revision == 1, "first_publication_source_revision")
                old_node = self.decode_and_check(body)
                self.verify_wire(old_node)
                self.record("independent-no-session-fetch-rust-codec-parse-real-forward")
                self.record("one-time-token-response-safe-idempotency")

                self.stage = "separate_authorities"
                bad_url = f'{self.origin}/subscriptions/v1/{publication["id"]}/vps1_' + "0" * 64
                require(bad_url != first_url, "negative_token_fixture_collision")
                self.fetch(bad_url, expected=401, cookie=auth[0])
                self.fetch(f'{self.origin}/subscriptions/v1/{publication["id"]}/{self.bootstrap}', expected=401, cookie=auth[0])
                require(self.request("GET", f'/api/v1/publications/{publication["id"]}')[0] == 401, "publication_management_auth_required")
                self.record("management-cookie-and-bootstrap-do-not-authorize-subscription")

                self.stage = "subscription_rotation_and_revoke"
                rotated, second_url = self.issue(auth, issued, "rotate-token")
                require(first_url != second_url, "fresh_subscription_token")
                self.fetch(first_url, expected=401)
                cached, _ = self.fetch(second_url)
                require(self.decode_and_check(cached) == old_node, "token_rotation_does_not_rotate_node")
                _, _, revoked, _ = self.mutation("DELETE", f'/api/v1/publications/{publication["id"]}/token', "publication_token_revoke", "revoke-token", rotated["revision"], {"confirmRevokeAccess": True}, auth)
                require(revoked["result"]["token"]["state"] == "revoked", "subscription_revocation_status")
                self.fetch(second_url, expected=401)
                self.verify_wire(old_node)
                self.record("revoke-stops-fetch-but-cached-node-still-really-forwards")
                resumed, third_url = self.issue(auth, revoked["result"], "explicit-reissue")

                self.stage = "node_rotation_and_stale_publication"
                second_credential = self.credential(auth, "second-node", 1)
                require(second_credential["secretRef"] != first_credential["secretRef"], "immutable_node_rotation_reference")
                second_config = self.configuration(second_credential["secretRef"])
                second_operation = self.apply(auth, "node-rotation", 1, second_config)
                require(self.snapshot(auth, 2) > generation_one, "rotation_generation_increased")
                stale = self.fetch(third_url, expected=412)
                require(stale["error"]["code"] == "REVISION_CONFLICT", "pinned_publication_stale")
                self.verify_wire(old_node, expected=False)
                replace_payload = self.publication_payload(second_config)
                replace_payload["sourceRevision"] = 2
                _, _, replaced, _ = self.mutation("PUT", f'/api/v1/publications/{publication["id"]}', "publication_replace", "explicit-republish", resumed["revision"], replace_payload, auth)
                require(replaced["result"]["sourceRevision"] == 2, "explicit_republish_revision")
                refreshed, revision = self.fetch(third_url)
                require(revision == 2 and refreshed != cached, "republished_uri_changed")
                new_node = self.decode_and_check(refreshed)
                require(new_node != old_node, "republished_node_credential_changed")
                self.verify_wire(new_node)
                self.verify_wire(old_node, expected=False)
                self.record("pinned-source-stale-denial-explicit-republish-and-old-node-rejection")

                self.stage = "safe_metadata_and_history_retention"
                for path in ["/api/v1/credentials", "/api/v1/publications", f'/api/v1/publications/{publication["id"]}']:
                    require(self.request("GET", path, auth=auth)[0] == 200, "safe_metadata_status")
                retire = self.mutation("POST", f'/api/v1/credentials/{first_credential["id"]}/retire', "credential_retire", "retain-rollback-node", first_credential["revision"], {"confirmRetire": True}, auth, expected=409)
                require(retire[2]["error"]["code"] == "REVISION_CONFLICT", "rollback_reference_retention")
                generation_before_restart = self.snapshot(auth, 2)
                old_auth = auth
                self.stage = "first_graceful_shutdown"
                self.stop()
                self.scan()

                self.stage = "vault_and_publication_restart"
                self.start(initialize=False)
                require(self.request("GET", "/api/v1/config", auth=old_auth)[0] == 401, "session_not_persisted")
                auth = self.login()
                require(self.snapshot(auth, 2) > generation_before_restart, "restart_generation_increased")
                after_restart, revision = self.fetch(third_url)
                require(revision == 2 and after_restart == refreshed, "durable_publication_verifier")
                require(self.decode_and_check(after_restart) == new_node, "restart_codec_identity")
                self.fetch(first_url, expected=401)
                self.fetch(second_url, expected=401)
                self.verify_wire(new_node)
                self.verify_wire(old_node, expected=False)
                repeated = self.mutation("POST", f'/api/v1/publications/{publication["id"]}/token', "publication_token_issue", "first-token", publication["revision"], {"expiresInSeconds": 600, "confirmIssueSecretUrl": True}, auth, expected=409)
                require(repeated[2]["error"]["code"] == "SECRET_RESULT_UNAVAILABLE", "durable_consumed_token_key")
                require(self.credential(auth, "first-node", 0) == first_credential, "durable_credential_receipt")
                status, _, reconciled, _ = self.request("GET", "/api/v1/operations/by-idempotency/node-rotation-apply", auth=auth)
                require(status == 200 and reconciled["result"]["id"] == second_operation["id"], "durable_apply_reconciliation")
                self.record("encrypted-vault-open-recovery-verifier-and-safe-idempotency-persist")

                self.stage = "final_graceful_shutdown_and_plaintext_scan"
                self.stop()
                self.scan()
                self.record("exact-journal-pid-startticks-exit-and-loopback-port-release")
                self.record("no-plaintext-node-token-session-or-master-on-disk-or-logs")
            finally:
                self.cleanup()
        self.root = None
        require(sha256_file(self.daemon) == self.identities["daemonSha256"], "daemon_changed_during_test")
        require(sha256_file(self.worker) == self.identities["workerSha256"], "worker_changed_during_test")
        require(sha256_file(self.codec) == self.identities["codecSha256"], "codec_changed_during_test")
        for name, path in self.source_paths.items():
            require(sha256_file(path) == self.identities[name], "bound_source_changed_during_test")

    def receipt(self, status, failure=None):
        result = {
            "status": status, "profile": "loopback-vless-v1-uncertified",
            "subscriptionNetworkProfile": "development-loopback",
            **self.identities,
            "validatedHttpResponses": self.schema_count,
            "rustCodecChecks": self.codec_count,
            "actualForwardingChecks": self.forward_count,
            "actualOldCredentialRejections": self.rejection_count,
            "gracefulShutdownChecks": self.shutdown_count,
            "scannedPrivateFiles": self.scan_count,
            "checks": self.checks,
            "independentProtocolCertification": False,
            "productionHttps": False, "mobileNetworkEndToEnd": False,
            "externalConnectivity": "not_checked", "productionDeployment": False,
        }
        if failure:
            result["failure"] = failure
            result["checkpoint"] = self.stage
        return result


def write_receipt(path, result):
    # Never replace an existing artifact or follow a caller-provided symlink.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", required=True, type=Path)
    parser.add_argument("--worker", required=True, type=Path)
    parser.add_argument("--codec-check", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    harness = None
    try:
        harness = Harness(args)
        harness.run()
        result = harness.receipt("passed")
        code = 0
    except BaseException as error:
        # Do not print repr/str/tracebacks for external exceptions: HTTP libraries,
        # JSON validators or subprocess failures may retain secret-bearing input.
        failure = str(error) if isinstance(error, HarnessFailure) else "external_operation_failed"
        result = harness.receipt("failed", failure) if harness else {"status": "failed", "failure": failure}
        code = 1
    try:
        write_receipt(args.evidence, result)
    except BaseException:
        result = {"status": "failed", "failure": "safe_evidence_write_failed"}
        code = 1
    print(json.dumps(result, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
