# Bundle v2: control-state compatibility handoff

**Generic migration contract remains proposed and unavailable.**

A separate strict schema-2 `fresh-runtime-v1` reader is implemented for private
fresh-only development bundles; see FRESH_BUNDLE_CONTRACT.md. It supports only
its exact executable-derived descriptor, SQL1/private payload3, journal2 and vault
binding kind5. It does not implement the migration/rollback proposal below. The
historical v1 installer still accepts only schema1 and refuses this profile.
The current installer accepts only manifest v1 / `storageSchema=1`; the frozen
`e96584f` daemon+worker test remains on that existing contract. Do not relabel a new
payload-format-2 daemon as a compatible v1 release. A successful code-slot rollback
is not proof that an older binary can read current control state.

## Separate versions, not a single ambiguous storage number

The management API owner and installer must agree the exact generated metadata
before v2 is accepted. Proposed manifest fields:

```json
{
  "schemaVersion": 2,
  "controlState": {
    "sqlLayout": {"readVersions": [1], "writeVersion": 1},
    "payload": {"readVersions": [2], "writeVersion": 2}
  }
}
```

This fragment is **not a complete accepted manifest**. Other existing release,
engine, core-lock and file-hash fields remain required; v2 must reject unknown or
missing fields. Read versions are explicit sorted distinct positive integers, not
an inferred range. A binary must not advertise `[1,2]` unless both exact decoders
are really supported. The writer format is independent of the reader set and SQL
layout: SQL layout 1 with payload 2 is not payload-1 compatibility.

The producer must bind these claims to the exact daemon artifact through generated
build/release metadata and the trusted bundle digest/signature contract. Neither
package version nor a caller-selected release label proves storage compatibility.
A future v2 packager must obtain this metadata rather than hardcode a format.

## Authoritative state inspection and exclusion

Before installation/migration/rollback, obtain through the agreed shared control
interface (not a second installer SQLite decoder):

- current SQL-layout and payload versions;
- committed configuration revision and durable post-migration write watermark;
- credential retirement/revocation watermark and any subscription retirement state;
- active migration/recovery journal state and exact source release identity.

The operation must hold the same writer exclusion as the control service while
validating those observations and making the transition. Stopping a daemon alone
is not proof that no other writer exists. No file-copy backup of a live SQLite/WAL
database is accepted. Snapshot creation, exact decoder/digest validation, migration
and restore belong to the coordinated storage/control implementation. The installer
orchestrates only the fixed, reviewed entry point—never arbitrary hooks or SQL.

## Rollback policy

| Situation | Default installer outcome |
|---|---|
| Target artifact proves it can read the actual SQL and payload versions, and all remaining release/vault/runtime compatibility checks pass | A new explicit code-rollback plan may be offered; not automatic success |
| Target cannot read either current version | Refuse code rollback; leave current data intact |
| A pre-migration backup exists but new config/secret/publication writes occurred | Refuse old-state restore; do not silently lose new writes |
| Credential/subscription retirement occurred after the snapshot | Refuse a restore that could revive retired material |
| No post-migration writes/retirement, exact trusted snapshot verified, and shared control provides a reviewed lossless restore procedure | Separate explicit recovery plan only; never an implicit fallback from failed startup |
| Inspection, writer exclusion, watermark history or compatibility is uncertain | Refuse and retain evidence for explicit recovery |

**Never automatically restore an old vault snapshot.** Restoring control state must
also preserve the monotonic retirement/revocation history; the existence of a file
backup is not authority to reactivate old credentials. The installer cannot infer
“no writes” from an unchanged config revision if secret/publication state can change
independently. A restore may require a forward recovery operation rather than
resetting state to older bytes.

## Consent and acceptance gates

The deterministic plan must bind the exact old/new bundle digests, both version
axes, authoritative state/watermarks, snapshot identity (if relevant), proposed
writer transition and recovery limitations. TTY short-action consent remains bound
to that whole hash; changed state invalidates consent. Automation supplies the
explicit hash. Migration and data restore are separate actions and confirmations,
not hidden side effects of `update` or `rollback`.

Required future tests include SQL1/payload1 → SQL1/payload2, old-binary fail-closed,
failed atomic commit recovery, stale-plan rejection, new-write rollback refusal,
retirement rollback refusal, corrupted/truncated/foreign snapshot refusal, and
controlled recovery that preserves newer retirement records. These are pending;
current installer unit/PTY tests do not establish v2 migration acceptance.

Exact version-metadata producer, inspection endpoint/flags, writer lease, snapshot
format, migration/restore entry points and watermark definitions await API/control
owner agreement. No current v1 artifact or existing acceptance result is rewritten
by this proposal.
