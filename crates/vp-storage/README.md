# vp-product-storage — shared durable storage

`SqliteStore` implements the control-store port with two safeguards:

- A per-instance mutex **and independently opened OS advisory lock** serialize the
  whole external transaction across processes. Readers lock only the connection.
- Each checkpoint uses an immediate SQLite transaction and version CAS to commit
  the aggregate state plus append-only safe journal event atomically. SQLite uses
  `synchronous=FULL` and DELETE journaling. It never holds one SQL transaction
  across runtime/helper actions, which would erase crash-recovery checkpoints.

The initial aggregate schema is intentionally small: `control_state` and
`operation_journal`. It stores shared typed models, plans, revisions, operations
and scoped idempotency records, not raw core YAML. This is not yet the complete
product database inventory (sessions/subscriptions/certificates, normalized
ownership registry and migrations remain integration work). Unknown database
schema versions fail closed; no destructive/down migration is attempted.

`FileArtifactStore` publishes immutable non-secret content-addressed artifacts:
bounded input, SHA-256, private staging file, file fsync, atomic no-overwrite hard
link, directory fsync, then staging cleanup. Reads verify the digest. It is **not**
a secret store. Compiled artifacts containing resolved credentials must not use
this store; compile to protected executor memory/vault instead.

The installer must provision a private service-owned root and protected parent
ACLs. Existing symlinks or permissive Unix directories/files are rejected, not
silently repaired. Unix mode checks do not establish owner identity or secure a
host already writable by an attacker. Non-Unix construction fails unavailable
until a Windows DACL-aware implementation is supplied. Never unlink/replace the
writer lock file while any writer can run. Filesystem and SQLite checksum checks
are corruption detection, not authentication against a compromised service user.

Storage errors can mean commit outcome is uncertain. Do not run another external
action or blindly retry a write: release the lease, inspect/recover durable state,
and preserve a blocked recovery UI if storage remains unavailable. Historical
idempotency records must not be discarded while their retry contract is live.

Authorized local Rust tests now pass for reopen/corruption/atomic-boundary/private-
path/artifact storage and independently opened writer serialization. Real daemon
loopback tests additionally verify draft/idempotency survival and session revocation
across process restart with private temporary SQLite. See
`docs/implementation/MANAGEMENT_VALIDATION.md` for commands/evidence; this is not
production system/installation/runtime acceptance.

Still unverified: separate-process lock contention, disk-full/readonly fault
injection, abrupt machine loss, consistent backups/restore, production retention,
versioned database migration and real executor crash recovery. No service, firewall,
route, proxy or deployed filesystem installation was changed by this verification.

## Candidate payload format 2 / explicit migration (source only)

This candidate's new stores use **StoredState payload format 2** with the bounded
secret/publication registry. SQL table/user_version schema remains 1; those are
different version domains. A valid old payload does **not** get rewritten on
`open()`/`read()`: it returns `RecoveryRequired`, so the composition can explain
that an explicit maintenance migration is needed. Unknown versions, malformed
state, digest mismatches and unknown old fields fail closed.

The explicit maintenance entrypoint is:

```text
SqliteStore::migrate_v1_to_v2(absolute_private_root, at_ms)
    -> Result<PayloadMigrationReceipt, ControlError>
SqliteStore::verify_v1_rollback_backup(absolute_private_root)
    -> Result<PayloadMigrationReceipt, ControlError>
```

The migration requires an existing database and the operator to quiesce the
service. It owns the exact same OS writer lock as normal control transactions,
then reserves SQLite's writer with BEGIN IMMEDIATE. A separately frozen v1
aggregate/journal decoder retains the four original empty defaults and denies new
fields. Frozen integrity checks and enum vocabularies are used instead of assuming
new v2 verifier rules are a valid old decoder. Stable public-v1 config/ID/plan
record encodings are still reused; any future change to those encodings must keep
this migration decoder compatible or introduce another explicit format.

Before updating any database page, it publishes and fsyncs an immutable private
full SQLite copy `control.v1-before-v2.db`, then a checksum-bound private
`control.v1-to-v2.receipt.json`. Both are 0600, bounded, no-overwrite hard-link
publications. The source must use the supported DELETE journal mode and exact
expected table/column layout; checksum-valid original journal rows must be
contiguous and consistent with the source version. The copy is opened read-only
and independently decoded/verified. The format2 payload, its incremented storage
version, and one migration journal boundary are then committed atomically by CAS.

A repeated explicit call verifies the original receipt and historical copy. It
never increments the version again or resets later v2 writes. A complete prepared
copy/receipt from an interrupted pre-commit action can be reused only for the same
exact source. An incomplete/mismatched pending file is preserved and blocked, not
deleted/repaired opportunistically. An uncertain commit/fsync returns failure;
the next deliberate call reconciles actual v1/v2 state plus receipt before doing
anything. Timestamp changes on retry do not rewrite the original receipt.

**There is deliberately no restore/downgrade function.** The historical copy is
recovery evidence, not permission to replace current state. Later credential
creation/retirement, token rotation/revocation or other v2 writes must never be
lost or resurrected by an old-binary rollback. The old strict reader rejects
format2; the installer must reject cross-format code rollback until a separately
reviewed data-compatibility procedure exists. The migration does not snapshot,
restore, rotate or touch the encrypted vault.

Bounds: state payload 32 MiB; full SQLite backup 128 MiB; receipt 16 KiB; migration
journal verification at most 1,000,000 rows. Reaching a bound is an explicit failure,
not pruning or partial copying. Root/ancestor ownership and ACLs remain the existing
installer boundary; checksums are corruption detection, not protection against a
compromised service owner. Normal filesystem/kernel IO and writer-lock waits are
not represented as hard real-time deadlines.

Twelve new migration tests are authored, not executed in the Android guest quiet
lane: v1 defaults/unknown-v2 rejection, no read migration, populated draft/retry
preservation, immutable backup/modes/symlinks, source/journal/digest/version failures,
pre-commit fault with atomic rollback, prepared-copy retry, later-v2 writes preserved
and missing-database refusal. No Cargo/build or Rust test execution has occurred
for this candidate; `rustfmt` only. No production or user state was migrated.
