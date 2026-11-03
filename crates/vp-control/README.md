# vp-product-control — shared mutation service

The shared state machine is compiled and locally tested; it is not a working installed
proxy/VPN product. `ControlService` is the only configuration mutation service for CLI/API.
No source in this crate invokes a shell, opens network sockets or generates keys.

## Flow and ownership

1. A verified API/IPC principal supplies a typed `ProductConfig` and exact
   `ReleaseIdentity`. `plan` validates schema + executor/compiler evidence,
   checks resource ownership/drift read-only, and persists an immutable SHA-256
   plan with revision, expiry, permissions/resources and mandatory health checks.
   A plan hash is an integrity/confirmation binding, **not** a signature or login.
2. `submit` binds that hash and expected revision to a principal-scoped,
   method-scoped idempotency key and saves a queued operation. Return HTTP 202.
   Retrying the same key returns its durable operation, even after plan expiry.
   Another payload with the same scoped key is rejected.
3. An owned worker calls blocking `run` off the HTTP/UI thread. The store's writer
   lease covers the entire transaction, including runtime/system calls. Each
   intent checkpoint is individually durable before an external action.
4. The cancellation token is shared with the worker, not tied to an HTTP request.
   `cancel_queued` durably cancels queued work; in-flight cancellation is honored
   only before `ApplyingResources`. After that boundary work finishes or rolls
   back. The daemon owns shutdown tokens; HTTP cancellation is conservatively queued-only.
5. Host resources are snapshotted, applied, then a real runtime generation is
   activated and independently checked. Commit requires the exact operation,
   revision, generation, config and release digests, bounded-age health, every
   listener binding, positive/negative authentication, TLS/REALITY identity,
   explicitly approved forwarding checks and retired listener/credential checks.
   `externalConnectivity=not_checked` remains visibly not checked. Last recorded
   health is not current runtime observation: snapshot `observedRevision` is None.
6. Failure stops the candidate, compare-restores only owned resources, restores
   the previous runtime/config/release and independently checks recovery. A crash
   between intents is recovered conservatively, never by promoting stale health.
   Recovery-required blocks writes and retries only on explicit `recover` calls.
   Queued work is canceled on restart, not unexpectedly launched.

Executors must be idempotent by operation ID, fsync their recovery material before
returning, enforce resource ownership/CAS at their own boundary, and return only
structured non-secret errors. Helper authorization must independently authenticate
caller, plan hash, fixed resources/paths, release verification and freshness.
`UnavailableRuntime`/`UnavailableSystem` fail closed. There is no fake production
executor; all simulated executors live under `#[cfg(test)]`.

## Integration still required

- Compiler/core adapter implements `RuntimeExecutor`; current upstream lacks the
  full readiness, authentication and recovery contract. No listener/credential
  change is presently claimed to work on a real runtime.
- Privileged helper implements `SystemExecutor`, with durable owned-resource
  snapshots and narrowly authorized changes. Vault and certificate adapters must
  remain separate from the general database/artifact store.
- API/daemon implements single-admin bootstrap sessions, CSRF, durable draft CRUD,
  worker scheduling and queued cancellation. Multi-user RBAC, live runtime/SSE,
  retention workflow and recovery operator UI remain incomplete. Callers must not expose `StoredState`
  or unfiltered `PlanBody`; those contain private configuration/reference data.
  Startup must call recovery before accepting writes and independently reconcile
  the last committed runtime after a worker/machine restart. A committed database
  revision is not proof that its process is still alive. Vault references must
  be immutable/versioned; credential rotation creates a new `SecretRef`.
- Snapshot/backup migration, disk-full/permission faults and actual process-kill
  recovery need isolated execution tests, then genuine listener/credential and
  independent protocol probes. Fake executor tests are not ACC-TXN-005 evidence.

## Durable management additions (2026-10-30)

`drafts.rs` implements the API/CLI-shared draft and listener CRUD service, not a
second API mutation engine. Draft edits have base/draft revision CAS, validated
bounded typed configs, principal+method-scoped durable retry outcomes (including
delete tombstones), immutable plan+idempotency records in one checkpoint, and
single-read management projections. Draft quota: 32 live drafts, 128 edit receipts,
256 KiB per config, aggregate editing headroom 24 MiB. Limits reject new writes;
they never silently discard idempotency history. Administrative retention/migration
workflow remains required before a production deployment.

`cancel_request` is atomic, durable and scoped, but deliberately queued-only.
The HTTP facade reports only queued work cancellable. In-flight user cancellation
requires an independently designed durable intent port; it cannot reserve another
write transaction behind an active writer and call a volatile token durable.
Internal shutdown cancellation retains the existing safe pre-mutation semantics.

Persistence adds default-empty draft/plan/cancel history fields to existing typed
aggregate state. Older binaries reject these new fields rather than silently
removing them; production rollback still needs compatible version/snapshot policy.
No historical external database migration/upgrade acceptance is claimed.

## Verification status (2026-10-30)

Authorized Rust 1.88.0 Cargo builds, unit tests, strict Clippy and actual authenticated
loopback HTTP/SQLite restart tests now pass. See
`docs/implementation/MANAGEMENT_VALIDATION.md` for exact counts, commands and hashes.
Production daemon composes `UnavailableRuntime` and `UnavailableSystem`; real
listener/credential commit, privileged host changes and ACC-TXN-005 remain blocked
until exact independent runtime/vault/helper/health evidence exists.
