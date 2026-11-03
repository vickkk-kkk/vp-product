# vp-product-core-adapter — explicit core boundary

This is the only product package allowed to depend on upstream `vp_core` crates.
It uses the pinned, reproducibly patched source in `integration/vp_core`; it never
substitutes sing-box or another engine. See `tools/core/README.md` for upgrades.

## Two intentionally distinct APIs

- The default `CoreAdapter` is the product-domain **fail-closed gate**. It does
  not claim a VPN exists. Unavailable start/reload, `NotRun` health, generation
  checks, strict product-listener validation and all 21 visible blocked presets
  remain honest until the compiler, vault, independent probes and platform hosts
  can satisfy the full product contract.
- Feature `managed-runtime` adds an **actual Linux worker-process host**, private
  `vp-core-managed-worker` binary and `managed::{VerifiedWorker,ManagedRuntime}`.
  It starts the patched `vp_app::managed::ManagedApp`, observes bound/live accept
  tasks, supports bounded cancellation/drain/stop and restores the previous
  in-memory recipe on failed replacement. `forwarding_verified` stays false:
  an accept loop is not authenticated forwarding evidence or a VPN tunnel.

`inspect_build()` reports feature linkage, exact core/patch identity and
`development=true`. Baseline v1 `requiredFeatures=[]` describes wire negotiation,
not unmet internal runtime prerequisites. Capability rows carry blocked reasons;
no static catalog entry becomes certification because a feature was compiled.

## Managed worker constraints

`VerifiedWorker::new(absolute_path, expected_sha256)` verifies a regular,
non-symlink, non-group/world-writable binary. The expected digest must come from
reviewed build/release metadata, never an API caller. Hash identity is not a
publisher signature; protected release installation/signatures remain WP13.
The worker rechecks digest and a versioned Hello before accepting configuration.

The bounded private stdio protocol has no arbitrary file, plugin, route, shell,
service or TUN API. It accepts loopback binds only and currently raw mixed/HTTP/
anonymous SOCKS5, VLESS, VMess and one-user Shadowsocks listeners. All active
unknown fields fail. Credentials and temporary serialized frames are zeroized.
No credentials are written to a staging file by this module. Authenticated SOCKS,
TLS/carrier/QUIC listener mappings are not silently approximated.

A managed task-scope authority rejects non-loopback IPs **and all domain names**
before DNS/socket work on supported direct TCP/UDP paths. This is separate from
routing rules: upstream raw protocol handlers still bypass the general router.
The development worker cannot be treated as a general production routing engine.

- `start` validates before IO, uses a deadline, and allocates a fresh generation
  for every attempted launch (failed launches are not reused).
- `with_generation(worker,last)` seeds the next generation from a durable journal;
  it never adopts an old process. `start_with_spawn_observer` calls a bounded host
  callback after verified Hello and **before Start/listener action**, allowing the
  journal to fsync PID and OS birth identity. Callback failure kills/reaps child.
- Worker stdin EOF cancels startup or the running app; owner Drop also kills,
  waits and joins pipe workers. A real parent-process-exit regression bypasses
  Rust Drop to test this containment path.
- `stop` checks generation, stops ingress, drains work for the requested bounded
  interval, cancels remaining tasks, waits for actual destruction and child exit.
- `replace` validates first, retains the normalized previous bound ports in
  zeroized memory, and reports candidate failure and restoration failure
  separately. A restored worker gets a new generation, never fake apply success.

Durable transaction staging, immutable secret resolution and independently
observed authentication/retired-credential/forwarding probes belong to the
separate compiler/runtime-executor composition. This module cannot issue those
receipts from readiness alone. Android mobile FFI/protected-socket/TUN source is being implemented by its own
owner under the explicit `mobile-ffi` feature. That source and C header do not
constitute a verified packaged Android runtime; actual FD/protect/packet/revoke
acceptance is recorded separately and must pass before readiness is exposed.

## Evidence

`tools/core/verification.json` identifies the current bounded validation tranche;
raw commands/results including failed attempts are under `tools/core/evidence/runtime/`.
Rust 1.88.0 is pinned. Both standalone core and root product Cargo graphs must be
checked because their exact dependency versions differ. Focused passing loopback
tests are not full release/platform/independent-interoperability acceptance.
