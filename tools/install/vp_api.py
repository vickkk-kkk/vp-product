"""Thin authenticated API client. Shared control owns protocol semantics/transactions.

No fallback encoder, token issuer, credential store, local core YAML or fake success.
"""
import argparse
import contextlib
import getpass
import http.client
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit
from vp_install import InstallError, require, read_regular, strict_json, canonical, digest
from vp_form import listener_wizard
import vp_publications

MAX_RESPONSE = 1024 * 1024
API_PREFIX = "/api/v1"

class Api:
    def __init__(self, origin):
        parsed = urlsplit(origin)
        require(parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username and not parsed.password and
                not parsed.query and not parsed.fragment and not parsed.path and len(origin) <= 512,
                "canonical origin required (no trailing slash, credentials or query)")
        require(parsed.scheme == "https" or parsed.hostname in ("127.0.0.1", "localhost", "::1"),
                "HTTP is allowed only on explicit loopback; HTTPS certificate validation cannot be disabled")
        self.origin = origin
        self.parsed = parsed
        self.cookie = None
        self.csrf = None

    def request(self, method, path, payload=None, revision=None, sensitive=False):
        require(path.startswith(API_PREFIX + "/") and "?" not in path and "#" not in path and
                re.fullmatch(r"/api/v1/[A-Za-z0-9_./-]+", path), "invalid API path")
        require(not sensitive or (method == 'POST' and
                re.fullmatch(r'/api/v1/publications/[A-Za-z0-9_-]{1,128}/token', path)),
                'sensitive response allowed only for explicit publication issuance')
        headers = {"Origin": self.origin, "Host": self.parsed.netloc, "Content-Type": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.csrf:
            headers["X-VP-CSRF"] = self.csrf
        if revision is not None:
            headers["If-Match"] = '"' + str(revision) + '"'
        data = None if payload is None else canonical(payload)
        require(data is None or len(data) <= 512 * 1024, "API request too large")
        cls = http.client.HTTPSConnection if self.parsed.scheme == "https" else http.client.HTTPConnection
        conn = cls(self.parsed.hostname, self.parsed.port, timeout=15)
        try:
            conn.request(method, path, data, headers)
            response = conn.getresponse()
            body = response.read(MAX_RESPONSE + 1)
            require(len(body) <= MAX_RESPONSE, "API response too large")
            require(response.getheader("Content-Type", "").split(";")[0] == "application/json", "non-JSON API response")
            result = strict_json(body)
            if not 200 <= response.status < 300:
                code = result.get("error", {}).get("code", "API_REJECTED") if isinstance(result, dict) else "API_REJECTED"
                code = code if isinstance(code, str) and re.fullmatch(r"[A-Z0-9_]{1,80}", code) else "API_REJECTED"
                raise InstallError(f"API HTTP {response.status}: {code}; no local fallback applied")
            require(isinstance(result, dict) and result.get("schemaVersion") == 1 and "result" in result,
                    "unsupported API envelope")
            if sensitive:
                require(response.getheader('Cache-Control', '').lower() == 'no-store' and
                        response.getheader('Pragma', '').lower() == 'no-cache' and
                        response.getheader('Referrer-Policy', '').lower() == 'no-referrer',
                        'sensitive response missing confidentiality headers; outcome uncertain')
            elif path != API_PREFIX + '/exports':
                # Legacy explicit export still writes only to a private file.
                # Subscription issuance is NEVER routed through that path.
                vp_publications.metadata_only(result['result'])
            cookie = response.getheader("Set-Cookie")
            if path.endswith("/auth/login"):
                require(cookie and re.match(r"vp_session=[0-9a-f]{64};", cookie), "invalid authenticated session")
                self.cookie = cookie.split(";", 1)[0]
            return result["result"]
        except (OSError, http.client.HTTPException) as exc:
            raise InstallError("API transport failed; mutation outcome uncertain: retain request key, inspect before retry") from exc
        finally:
            conn.close()

    def login(self, username, token):
        result = self.request("POST", API_PREFIX + "/auth/login", {"username": username, "password": token, "secondFactor": None})
        require(isinstance(result.get("csrfToken"), str) and re.fullmatch(r"[0-9a-f]{64}", result["csrfToken"]), "invalid CSRF session")
        self.csrf = result["csrfToken"]

    def logout(self):
        if self.cookie:
            try:
                self.request("POST", API_PREFIX + "/auth/logout")
            finally:
                self.cookie = self.csrf = None

    def command(self, path, method, key, revision, payload, verb="POST", etag=False, sensitive=False):
        require(isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", key), "stable --request-key required")
        request = {"schemaVersion": 1, "requestId": "cli-" + digest((method + key).encode())[:24],
                   "idempotencyKey": key, "expectedRevision": revision, "method": method, "payload": payload}
        if sensitive:
            return self.request(verb, path, request, revision if etag else None, sensitive=True)
        return self.request(verb, path, request, revision if etag else None)

def catalog(path=None):
    repo = Path(__file__).resolve().parents[2]
    source = Path(path) if path else repo / "contracts/capabilities/presets.json"
    data = strict_json(read_regular(source, 128 * 1024))
    require(data.get("schemaVersion") == 1 and len(data.get("presets", [])) == 22, "shared preset catalog unavailable/drifted")
    return data["presets"]

def print_catalog(presets, capabilities=None):
    for p in presets:
        observed = [] if capabilities is None else [c for c in capabilities if c.get("key") == p["key"]]
        status = "backend_not_checked" if capabilities is None else "backend_not_certified"
        if observed:
            status = ",".join(sorted({c.get("status", "unknown") for c in observed}))
        print(f"{p['id']:>10}  {p['name']:<26}  {status}  {p['scope']}")
    print("Catalog presence is not certification. All 21 baseline presets remain required; Direct scope is pending.")

def configure(api, args):
    presets = catalog(args.catalog)
    caps = api.request("GET", API_PREFIX + "/capabilities")
    print_catalog(presets, caps)
    config_path = args.config
    active = api.request("GET", API_PREFIX + "/config")
    if config_path:
        config = strict_json(read_regular(config_path, 256 * 1024))
    else:
        require(sys.stdin.isatty(), "--config shared ProductConfig JSON required in noninteractive mode")
        print("请选择协议预设：输入编号 1..21 或 P01..P21；Direct 的产品范围尚未决定。")
        print("目录中的项目不代表当前后端已支持；若能力/证书/凭据依赖未完成，API 会明确拒绝。")
        chosen = input("协议编号（回车取消）: ").strip()
        if not chosen:
            return 0
        if chosen.isdigit():
            chosen = f"P{int(chosen):02d}"
        preset = next((p for p in presets if p["id"] == chosen), None)
        require(preset is not None, "unknown preset")
        observations = [c for c in caps if c.get('key') == preset['key']]
        if not any(c.get('status') == 'certified' for c in observations):
            reasons = sorted({c.get('reason', 'capability.not_certified') for c in observations}) or ['capability.not_certified']
            safe_reasons = [r for r in reasons if isinstance(r, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', r)]
            raise InstallError(f"{preset['name']} 尚未通过当前后端认证，依赖：{', '.join(safe_reasons)}；未收集凭据或创建隧道。全部首发预设仍保留。")
        key = vp_publications.request_key(args)
        require(len(key) <= 100, 'configure request key must leave room for deterministic action suffixes')
        # Only UUID-backed protocols use the new managed inventory. Preserve the
        # existing explicit-reference form for all other protocol/cipher kinds;
        # unsupported generators must never be silently replaced with UUID.
        provider = (vp_publications.credential_picker(api, active['revision'], key, preset['protocol'])
                    if preset['protocol'] in ('vmess', 'vless') else None)
        listener = listener_wizard(preset, args.schema, credential_provider=provider)
        config = active["config"] or {"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"listeners":[],"subscriptions":[]}
        config["listeners"] = list(config["listeners"]) + [listener]
        print("Collected shared-schema listener; exact semantic/capability validation still belongs to the API.")
    key = args.request_key
    if not key and sys.stdin.isatty():
        print("操作标识用于中断后的安全重试，不是密码；例如 server-install-001。")
        key = input("本次操作标识（结果不明时请复用）: ").strip()
    require(isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", key), "--request-key requires 1..100 letters/digits/underscore/hyphen; dots are not allowed by the shared wire contract")
    base = active["revision"]
    draft = api.command(API_PREFIX + "/drafts", "draft_create", key + "-draft", base, config)
    print(json.dumps({"draftId": draft["id"], "draftRevision": draft["revision"], "baseRevision": draft["baseRevision"]}))
    api.command(API_PREFIX + f"/drafts/{draft['id']}/validate", "validate", key + "-validate", draft["revision"], {})
    plan = api.command(API_PREFIX + "/plans", "plan_create", key + "-plan", draft["baseRevision"], {"draftId": draft["id"]})
    if not sys.stdin.isatty() or getattr(args, 'json', False):
        print(json.dumps(plan, indent=2))
    else:
        print(f"将应用草稿 {draft['id']}；基准版本 {plan['baseRevision']}；计划 {plan['id']}")
        actions = {'create': '创建', 'update': '更新', 'delete': '删除'}
        for change in plan.get('changes', []):
            print(f"  - {actions.get(change['action'], change['action'])}: {change['resourceId']} ({change['messageKey']})")
        print("运行影响：" + {'no_runtime_change': '无运行时变更', 'route_hot_swap': '热更新路由',
              'controlled_restart': '受控重启，可能断开连接', 'privileged_system_change': '需要特权的系统变更'}.get(plan.get('impact'), str(plan.get('impact'))))
        print("可恢复：" + ('是' if plan.get('recoveryAvailable') else '否；请审慎确认'))
        print("计划摘要 SHA256: " + plan['planHash'])
        print("变更可能中断已有连接；后台将执行统一校验/事务，不能将排队状态当作成功。")
    if args.dry_run:
        print("API plan only: a persistent draft was created, but runtime was not changed.")
        return 0
    confirmation = args.confirm
    if not confirmation and sys.stdin.isatty():
        action = input("输入“应用”确认刚展示的计划，回车保留草稿 / Type 'apply'; Enter cancels: ").strip()
        if action in ('应用', 'apply'):
            confirmation = plan['planHash']
    if not confirmation:
        print("Not applied. Use existing plan via apply-plan; do not claim a tunnel was created.")
        return 0
    require(confirmation == plan["planHash"], "API plan confirmation mismatch")
    return apply_plan(api, plan["id"], plan["baseRevision"], confirmation, key + "-apply", args.wait_seconds)

def apply_plan(api, plan_id, revision, plan_hash, key, wait_seconds):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", plan_id or ""), "valid plan ID required")
    operation = api.command(API_PREFIX + f"/plans/{plan_id}/apply", "plan_apply", key, revision,
                            {"planHash": plan_hash, "confirmed": True})
    print(json.dumps({"operationId": operation["id"], "status": operation["status"]}))
    deadline = time.monotonic() + wait_seconds
    while operation["status"] in ("queued", "running", "rolling_back", "awaiting_confirmation") and time.monotonic() < deadline:
        time.sleep(0.25)
        operation = api.request("GET", API_PREFIX + "/operations/" + operation["id"])
    print(json.dumps(operation, indent=2))
    if operation["status"] == "succeeded":
        return 0
    if operation["status"] in ("queued", "running", "rolling_back", "awaiting_confirmation"):
        print("Operation still pending; inspect operation ID. No success was inferred.", file=sys.stderr)
        return 3
    return 2

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("protocols", "configure", "apply-plan", "snapshot", "drafts", "operation", "export", "build") + vp_publications.ACTIONS)
    p.add_argument("--origin")
    p.add_argument("--credential-stdin", action="store_true", help="bounded external JSON {username,token}; never saved")
    p.add_argument("--catalog")
    p.add_argument("--schema", help="shared generated schema path for the interactive form")
    p.add_argument("--config")
    p.add_argument("--request-key")
    p.add_argument("--confirm-plan-sha256", "--confirm", dest="confirm")
    p.add_argument("--json", action="store_true", help="show machine-readable plan in a TTY")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--plan-id")
    p.add_argument("--revision", type=int)
    p.add_argument("--operation-id")
    p.add_argument("--request-file", help="shared export API payload, no local URI/token generation")
    p.add_argument("--output", help="new private file for sensitive API export; no stdout fallback")
    p.add_argument("--wait-seconds", type=float, default=30)
    p.add_argument('--publication-id')
    p.add_argument('--credential-id', help='managed credential record ID, never a raw credential')
    p.add_argument('--source-revision', type=int, help='explicit current committed revision for republish')
    p.add_argument('--expires-in-seconds', type=int, help='300..2592000; expiry changes require explicit token rotation')
    p.add_argument('--confirm-generate', action='store_true')
    p.add_argument('--confirm-retire', action='store_true')
    p.add_argument('--confirm-publish-connection-secrets', action='store_true')
    p.add_argument('--confirm-revoke-access', action='store_true')
    p.add_argument('--show-secret-url', action='store_true', help='explicit one-time terminal display only; no pipes/files/JSON')
    args = p.parse_args(argv)
    api = None
    try:
        require(0 <= args.wait_seconds <= 300, "wait bound must be 0..300 seconds")
        if args.action == "protocols" and not args.origin:
            print_catalog(catalog(args.catalog))
            return 0
        require(args.origin, "explicit authenticated --origin required")
        api = Api(args.origin)
        if args.credential_stdin:
            raw = sys.stdin.buffer.read(4097)
            require(len(raw) <= 4096, "external credential input too large")
            credential = strict_json(raw)
            raw = None
            require(isinstance(credential, dict) and set(credential) == {"username", "token"}, "external credential input invalid")
            username, token = credential["username"], credential["token"]
            credential.clear()
        else:
            require(sys.stdin.isatty(), "noninteractive API requires --credential-stdin")
            username = input("管理员用户名 / Administrator username: ")
            token = getpass.getpass("管理员预配置令牌（不是订阅令牌，不显示输入）: ")
        api.login(username, token)
        token = None
        if args.action == "protocols":
            print_catalog(catalog(args.catalog), api.request("GET", API_PREFIX + "/capabilities"))
        elif args.action in vp_publications.ACTIONS:
            return vp_publications.run(api, args)
        elif args.action == "configure":
            return configure(api, args)
        elif args.action == "apply-plan":
            require(args.revision is not None and args.confirm and args.request_key, "plan ID/base revision/planHash/request key are required")
            return apply_plan(api, args.plan_id, args.revision, args.confirm, args.request_key, args.wait_seconds)
        elif args.action == "export":
            require(args.request_file and args.output, "export requires shared --request-file and explicit private --output")
            require(not Path(args.output).exists(), "export destination already exists")
            payload = strict_json(read_regular(args.request_file, 256 * 1024))
            result = api.request("POST", API_PREFIX + "/exports", payload)
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(canonical(result) + b"\n")
            print("API export saved privately. No locally invented subscription link/QR/token.")
        else:
            path = API_PREFIX + "/" + args.action
            if args.action == "operation":
                require(args.operation_id and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", args.operation_id), "valid operation ID required")
                path = API_PREFIX + "/operations/" + args.operation_id
            print(json.dumps(api.request("GET", path), indent=2))
        return 0
    except (InstallError, OSError, KeyError, TypeError, ValueError, KeyboardInterrupt) as exc:
        print("vpctl: " + (str(exc) if isinstance(exc, InstallError) else "invalid/unavailable input; no success inferred"), file=sys.stderr)
        return 2
    finally:
        if api:
            with contextlib.suppress(InstallError):
                api.logout()

if __name__ == "__main__":
    sys.exit(main())
