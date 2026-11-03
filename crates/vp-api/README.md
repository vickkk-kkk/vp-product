# Authenticated management HTTP boundary

Implemented and locally tested, **not a completed proxy product or deployment**.
The REST handlers consume strict typed domain DTOs and delegate every draft,
listener, plan, submit and cancellation mutation to `ControlService`. SQLite is
the sole durable writer; no shell, system proxy, route or firewall calls exist here.

## Security boundary

- Explicit externally provisioned **256-bit high-entropy bootstrap token**, injected
  once into `BootstrapCredential`, not a human password. SHA-256 constant-time
  verification is suitable for this token contract, **not password hashing**.
  Username is configured; there is no built-in administrator password. The daemon
  takes the token through inherited stdin, not argv/environment/a file/HTTP setup.
  No persistent credentials are generated. The REST field is named `password` only
  to match the established login contract. Human passwords, MFA and multi-user RBAC
  are not implemented; non-null second factors are rejected.
- One explicit canonical Origin/Host, exact duplicate-aware checking; mutation
  Origin required even at login; cross-site Fetch Metadata rejected; CORS disabled.
  Login CSRF cannot establish a foreign session. Query-bearing API requests are
  rejected, so query tokens are never a supported authentication path.
- OS-random 256-bit session and CSRF tokens; session lookup and CSRF comparison use
  digests, constant-time checks; raw CSRF retained only in zeroizing volatile memory
  for authenticated `/auth/session` reload. HttpOnly/Secure/SameSite=Strict cookie,
  no Domain, `/api/v1` scope, no-store responses. Login rotates all administrator
  sessions; logout and restart revoke them; absolute lifetime 30m, idle lifetime 10m.
- Global login limit 10 attempts/minute (including successes), intentionally bounded
  single-admin state. Up to 32 concurrent requests, 4KiB login/512KiB typed commands,
  10s body read deadline, bounded headers; generic typed redacted errors. No raw
  serde/OS/parser messages or credential logging. Credential zeroization is best
  effort, not a claim against process compromise, allocator copies, abort or swap.

## Contract and state

Routes match `contracts/openapi/v1.yaml`. `/build`, `/capabilities`, `/snapshot`,
`/config`, `/drafts` and every operation read require a session. `/config` returns
`{revision:0,config:null}` before a commit; no synthetic active configuration.
Draft create CAS is against active revision. Edit/listener CRUD CAS is against
current draft revision and requires matching quoted `If-Match`. Validate uses the
draft revision; plan/apply uses base active revision. Returned drafts include an
ETag. Draft/create/edit/delete retries preserve their durable original outcome;
method+principal scope prevents cross-operation reuse. Plans and their dedupe record
are one checkpoint. Submit retries return the original durable operation; lookup
`/operations/by-idempotency/{key}` is principal scoped to apply commands.

HTTP cancellation is **queued-only**, atomic and idempotent in shared control.
Only queued operations expose `cancellable:true`; races/in-flight work return 409
`OPERATION_NOT_CANCELABLE`, never a fictional accepted cancellation. The worker's
internal shutdown token honors existing pre-mutation cancellation boundaries.
Supporting durable in-flight user cancellation needs a separately designed intent
port because the transaction owns the writer lease during external actions.

Snapshot revision/listener/operation projections share a read-only use of the
control writer lease, serializing probes with apply/recovery without persisting
any read. Persisted receipts never become live `observedRevision` or readiness.
`RuntimeExecutor::observe_committed` must freshly verify exact operation/revision,
config/release identity, generation, timestamp and every required health check.
Unavailable/failed/stale evidence leaves observed revision null and listeners not
ready. One owned HTTP snapshot permit bounds active probe work even if the caller
drops its request; other concurrent snapshots receive 429.

The daemon's **default management-only composition** remains 503 for full runtime
validation/planning. A new explicit `loopback-vless-v1` composition is implemented
in source with real encrypted vault/executor/probes; see managementd README for
its narrow development-only policy and pending/executed validation status. Its
existence does not certify public presets or external connectivity. Test doubles
exist only in isolated test files and are not runtime/protocol certification.

SSE, import/export, diagnostics and update endpoints fail honestly with structured
503 until their authorized adapters exist. No fabricated events or success output.
No full management feature, browser TLS or public deployment acceptance is claimed.

## Worker and recovery

Daemon startup calls shared recovery before serving. Previously queued confirmations
are canceled, not automatically relaunched after a restart. The owned single worker
scans durable queued work (Notify is only a hint), invokes blocking orchestration off
HTTP tasks and fails closed on uncertain persistence/worker failure. SIGINT/SIGTERM
requests safe pre-boundary cancellation, stops HTTP and joins the owned worker.
Real executor calls must obey their port's finite deadline. The opt-in daemon profile
reconciles committed runtime before serving and reaps owned workers on shutdown.

## Checks

`cargo test --locked -p vp-product-api -p vp-product-control -p vp-product-storage`
includes authentication, duplicate headers, CSRF/Origin/Host, expiry/rotation,
rate-limit, bounded/unknown input, draft/listener CAS/idempotency, immutable plans,
queued cancellation, snapshot consistency, real SQLite, and isolated worker failure.
See `vp-managementd/tests/loopback.py` for real TCP/restart validation and the
management evidence report for exact executed outcomes and remaining blockers.

## Credential/publication boundary (local integration tested)

New admin routes use the same session/Origin/Host/CSRF, strict command metadata,
CAS and shared ControlService; no API-side transaction engine. Credential list
exposes bounded safe metadata + truthful generator kinds, not protocol health.
Publication metadata contains no token/URL. The deliberate one-time secret response
has no Debug/Clone and adds no-store/no-referrer. No raw paths/body logging exists.

`GET /subscriptions/v1/{id}/{token}` has independent token-only authorization and
an explicitly configured trusted base/Host. Session cookies cannot grant access;
Authorization header/query fallback is rejected. No redirects or CORS. Token
rotation/revocation does not revoke cached node credentials. Source revision must
be both committed and freshly observed; unsupported/lossy/stale exports fail as a
whole, before body release. Client must retain old list on failed refresh.

The public route has a fixed 120 attempts/minute bound and one owned blocking-work
permit, including after request cancellation. Successful fetch audit is committed
before body release. Clients must never log full subscription URL/URI body or
include them in ordinary diagnostics. Actual local runtime/codec/HTTP evidence is in
`docs/implementation/MANAGEMENT_PUBLICATION_VALIDATION.md`; production HTTPS,
mobile networking and UI acceptance remain separate required gates.
