# Linux management daemon composition

This is a real authenticated loopback-only HTTP executable, not an installer or a
claim of production protocol certification. It composes shared SQLite/control and
an owned operation worker. Default management-only mode remains explicitly
unavailable for runtime apply. The deliberate development profile below now has
an actual encrypted-vault/worker HTTP integration pass; it is not a public service
or final ordinary-user credential provisioning UX.

## Deliberate bootstrap interface

Required CLI options: `--state-root ABSOLUTE_PRIVATE_DIRECTORY`,
`--bind 127.0.0.1:PORT` (or explicit IPv6 loopback), `--origin CANONICAL_ORIGIN`.
Optional `--web-root BUILT_FLUTTER_WEB_DIRECTORY` serves same-origin immutable assets.
The operator provisions the private state directory (0700, no writable/symlink
parents as required by storage) and passes a single bounded JSON document on stdin:

`{"username":"operator-selected-name","token":"externally-provisioned-high-entropy-token"}`

**The illustrative token is not usable.** A real token must contain at least 256
random bits encoded as 43+ URL-safe characters. The daemon never generates,
persists, prints or defaults this token. It is not a password-based deployment;
see `vp-api/README.md` for exact security/expiry/limitation details. No public-IP or
wildcard bind is permitted. Production HTTPS edge provisioning is not implemented
or authorized by this executable; its cookie is always Secure. HTTP localhost
behavior must be verified in the actual browser, not weakened to make tests green.

`--web-root` is an explicitly trusted local immutable build root, not an API-supplied
path. GET/HEAD only; normalized canonical paths, denied hidden/encoded traversal,
no directory listing, no symlink escape, allowlisted content types and bounded reads.
Flutter app CSP and a trusted TLS edge remain release work. API routes keep their
own session/Origin/Host/CSRF middleware; static files contain no configuration secrets.

## Authorized isolated verification

```sh
cargo build --locked -p vp-product-managementd
python3 crates/vp-managementd/tests/loopback.py target/debug/vp-product-managementd
```

This starts and stops real loopback TCP daemons using ephemeral synthetic tokens and
private temporary SQLite. It checks restart/durable retries/revoked sessions and
static path isolation, then deletes local state. It changes no system services,
proxy, route, firewall, user configuration or persistent credentials.

For tracked browser QA only, after building Flutter Web, run in the foreground:

```sh
python3 crates/vp-managementd/tests/serve_browser_qa.py \
  --web-root flutter/apps/vp_admin/build/web --port 18080
```

Open **http://localhost:18080** (not 127.0.0.1; canonical Host must match). The account
is `synthetic-admin`; its deliberately public test-only token is the
`SYNTHETIC_TOKEN` constant in the harness. Never use that value for deployment.
Ctrl-C owns daemon shutdown and deletes the temporary database. Do not leave the
harness untracked. The harness does not save credentials/cookies or install a service.

## Explicit local runtime profile (actual local integration verified)

Without runtime flags the daemon still composes `UnavailableRuntime` and returns
truthful 503 for full validation/planning. The new `loopback-vless-v1` opt-in
composes the **same** ControlService/SQLite with encrypted DurableSecretStore,
ManagedExecutor and daemon-owned real bounded active probes. It is an uncertified
integration profile, not a public-network deployment or a reduction of the 21
preset release scope. It supports IPv4 127.0.0.1 VLESS TCP without TLS/flow only;
unsupported protocols, addresses, transports and security fail before a plan.
No certificate issuance, route/firewall/system proxy changes or service installation
occur. The worker enforces the separate loopback development destination policy.

All flags are explicit; values below are placeholders, not runnable credentials:

```text
--state-root /private/control --bind 127.0.0.1:PORT --origin http://127.0.0.1:PORT
--runtime-profile loopback-vless-v1 --runtime-root /private/runtime
--worker /trusted/bundle/bin/vp-core-managed-worker --worker-sha256 EXACT_LOWERCASE_SHA256
--vault-root /private/vault --vault-namespace OPERATOR_NAMESPACE
--vault-action open --probe-bind 127.0.0.1:0
```

The three independently provisioned roots must already be private 0700 absolute
paths with trusted parents. The exact pinned worker binary identity and SHA-256
must match this daemon's compiled release; a different pin is not an upgrade
procedure. `--probe-bind` controls only a local ephemeral echo destination, never
an arbitrary Internet target. Ordinary configuration cannot replace that target.
The bundle installer may generate an **open-only** unit template with these flags,
but must not enable this development profile by default.

One bounded inherited stdin JSON extends the management-only input:

```text
{"username":"operator-name","token":"EXTERNAL_HIGH_ENTROPY_MANAGEMENT_TOKEN",
 "vault":{"masterKeyHex":"EXTERNAL_64_HEX_MASTER_KEY","credentials":[]}}
```

No secret is accepted in flags or environment variables. No key/token/user is
implicitly generated. `--vault-action initialize` is a separate deliberate
one-time provisioning action on an empty root, not a boot-time fallback; only
that action may include `credentials` entries of the exact form
`{"reference":"secret:opaque-immutable-v1","version":1,"value":"EXTERNAL_CREDENTIAL"}`.
Maximum 32 records, 1024 bytes each, stdin 64 KiB. Opening an existing vault
requires an empty credentials list. Wrong keys, partial initialization or repeated
immutable refs fail closed, not reset/retry. Secret fields are wrapped for
best-effort zeroization immediately during deserialization, including rejected
partial input. Core/vault buffers still cannot claim immunity from process
compromise, swap or library copies.

Before HTTP serves, control recovery must finish, then the committed exact config
is reconciled to a new owned generation and actively verified. Status acquires
the existing global writer lease read-only so a probe cannot race an apply;
only one outstanding HTTP active snapshot is permitted (otherwise 429). It proves
process/config/generation identity, bound sockets, accepted credentials, rejected
invalid credentials and payload echo. Applied rotation additionally verifies the
retired credential and released old ports. `observedRevision` is never inferred
from desired state or a persisted receipt. External connectivity stays unchecked.

SIGTERM/Ctrl-C stop the operation worker at its existing transaction boundaries,
then stop/reap only the owned data-plane process and verify released ports.
Committed desired state remains durable for the next explicit restart. A failed
health/rollback/cleanup blocks instead of advertising green health.

Actual test command (see `docs/implementation/MANAGEMENT_RUNTIME_VALIDATION.md`
for exact pin, hashes, executed outcomes and remaining limits):

```sh
python3 crates/vp-managementd/tests/runtime_http.py \
  --daemon /absolute/current/vp-product-managementd \
  --worker /absolute/current/vp-core-managed-worker \
  --evidence /existing/evidence/runtime-http.json
```

The harness provisions **synthetic temporary** tokens/master key/credentials only,
uses real loopback HTTP and workers, tests credential rotation, real occupied-port
rollback, restart reconciliation and negative injection, scans persistent test
state/logs for plaintext credentials, then deletes state and stops owned processes.
It is not an independently implemented protocol interoperability certification.

## Managed credentials/publications and explicit payload upgrade

This implementation adds no startup credential generation. External master key
and bootstrap token still arrive through inherited stdin. A confirmed authenticated
`credential_create` action generates UUIDv4 into the actual encrypted vault and
returns only a reference/metadata. Actual v1 supported generator set is **UUID
only**, not all protocol credential encodings or release certification. Rotation
creates a different immutable reference, then uses the existing draft/plan/apply
and retired-auth probes. Retirement only accepts unused objects, retaining all
historical/recovery references; it never kicks a node user implicitly.

Independent subscription publication requires both explicit flags:

- `--subscription-public-base https://operator-configured.example.invalid`
- `--subscription-network-profile https`

No external origin is inferred from Host or management origin. Local testing alone
can choose `--subscription-network-profile development-loopback` with the exact
HTTP loopback management origin. This is not a phone-reachable/public deployment
profile. Actual current source mapping is plain TCP/no TLS VLESS or representable
UUID VMess/SS shape, but only verified active compiler/runtime/credential kinds can
publish; the actual v1 runtime composition remains narrow local VLESS. Unsupported
TLS/REALITY/compound kinds return failure rather than weaken settings.

Only explicit `publication_token_issue` generates access tokens. Its action key is
durably consumed **before entropy**; committed raw URL is returned once, never
saved in state/audit. Retry returns `SECRET_RESULT_UNAVAILABLE`; read safe metadata,
then explicitly rotate under a new key/revision. Rotation/revocation restricts
future fetches, **not previously downloaded node credentials or existing sessions**.
Publication source revision is pinned; config changes require explicit republish.
All nodes export losslessly as one bounded URI list through the shared Rust codec.
Current bounds: 128 credential records, 16 publications, 32 sources/publication,
256 retained secret actions, 256 KiB URI body, 1 MiB metadata. At capacity, writes
fail rather than silently evict idempotency history. Durable bounded compaction
will require a separately reviewed retention policy; it is not implemented here.

Offline upgrade only (caller must stop and wait for the old daemon first):

```
vp-product-managementd --state-root /operator/private/control --state-upgrade v1-to-v2
```

Exactly these two flag/value pairs are accepted; no bind/runtime/vault/bootstrap
options. Successful maintenance prints a safe checksum receipt then exits. Normal
open reads/writes payload format 2 only; SQL layout remains 1. The explicit legacy
decoder is a migration capability, not dual-read runtime support. No automatic
migration, restore, downgrade or vault rollback exists. A historical backup cannot
authorize dropping later writes or reviving retired credentials. Installer bundle
compatibility must declare both axes separately; do not package this as the old
v1 `storageSchema=1` compatibility claim.

Actual local HTTP/vault/worker, codec, token/credential separation, restart and
old/new binary migration tests are recorded in
`docs/implementation/MANAGEMENT_PUBLICATION_VALIDATION.md`. They do not establish
production HTTPS, mobile subscription networking or 21-protocol certification.
The original frozen e965 daemon is a separate payload1 historical checkpoint.
