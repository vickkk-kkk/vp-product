//! Explicit control payload-format upgrade. This module NEVER restores a backup,
//! downgrades a database, touches the vault or repairs unknown/corrupt state.
//! The v1 decoder and integrity checks below are intentionally frozen separately
//! from the current StoredState verifier.
use crate::sqlite::{check_private_directory, private_file, sync_directory};
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::Duration,
};
use vp_product_control::{
    CancelIdempotencyRecord, ChangePlan, ContentDigest, ControlError, DraftIdempotencyRecord,
    DraftRecord, IdempotencyRecord, JournalEvent, Operation, OperationState, PlanIdempotencyRecord,
    RevisionRecord, SecretState, StoredState,
};

const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;
const MAX_BACKUP_BYTES: usize = 128 * 1024 * 1024;
const MAX_JOURNAL_ROWS: u64 = 1_000_000;
const MAX_WIRE_INTEGER: u64 = 9_007_199_254_740_991;
const BACKUP: &str = "control.v1-before-v2.db";
const RECEIPT: &str = "control.v1-to-v2.receipt.json";
const BACKUP_PENDING: &str = "control.v1-before-v2.pending.db";
const RECEIPT_PENDING: &str = "control.v1-to-v2.pending.json";

/// Safe local migration evidence, not permission to restore a historical database.
/// A later v2 write can contain credentials/retirement/publication state absent
/// from this backup. Automatic rollback would lose or resurrect authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PayloadMigrationReceipt {
    pub receipt_version: u16,
    pub source_format: u16,
    pub target_format: u16,
    pub source_state_version: u64,
    pub target_state_version: u64,
    pub at_ms: u64,
    pub source_payload_digest: ContentDigest,
    pub target_payload_digest: ContentDigest,
    pub backup_digest: ContentDigest,
}
impl PayloadMigrationReceipt {
    fn validate(&self) -> Result<(), ControlError> {
        if self.receipt_version != 1
            || self.source_format != 1
            || self.target_format != 2
            || self.source_state_version.checked_add(1) != Some(self.target_state_version)
            || self.target_state_version > i64::MAX as u64
            || self.at_ms > MAX_WIRE_INTEGER
        {
            return Err(ControlError::CorruptState);
        }
        Ok(())
    }
}

/// Exact original v1 aggregate shape. String map keys are subsequently decoded
/// by the unchanged v1 typed records in `to_v2`; invalid IDs still reject. The
/// four historical optional fields retain ONLY their original empty defaults.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoredStateV1 {
    #[serde(default)]
    cancel_idempotency: Vec<CancelIdempotencyRecord>,
    #[serde(default)]
    drafts: BTreeMap<String, DraftRecord>,
    #[serde(default)]
    draft_idempotency: Vec<DraftIdempotencyRecord>,
    #[serde(default)]
    plan_idempotency: Vec<PlanIdempotencyRecord>,
    schema_version: u16,
    version: u64,
    next_id: u64,
    active_revision: u64,
    revisions: Vec<RevisionRecord>,
    plans: BTreeMap<String, ChangePlan>,
    operations: BTreeMap<String, Operation>,
    idempotency: Vec<IdempotencyRecord>,
}
impl StoredStateV1 {
    fn decode(payload: &[u8], column_version: u64) -> Result<Self, ControlError> {
        let old: Self = serde_json::from_slice(payload).map_err(|_| ControlError::CorruptState)?;
        if old.schema_version != 1 || old.version != column_version {
            return Err(ControlError::CorruptState);
        }
        // The converted typed view is not verified by the evolving v2 rules.
        // Frozen v1 invariants are applied independently before any backup/write.
        let typed = old.to_v2()?;
        verify_v1_integrity(&typed)?;
        Ok(old)
    }
    fn to_v2(&self) -> Result<StoredState, ControlError> {
        let mut value = serde_json::to_value(self).map_err(|_| ControlError::CorruptState)?;
        let object = value.as_object_mut().ok_or(ControlError::CorruptState)?;
        object.insert("schemaVersion".into(), serde_json::json!(2));
        object.insert(
            "secrets".into(),
            serde_json::to_value(SecretState::default()).map_err(|_| ControlError::CorruptState)?,
        );
        serde_json::from_value(value).map_err(|_| ControlError::CorruptState)
    }
}
/// Original state-1 checks, deliberately not `StoredState::verify_integrity`.
fn verify_v1_integrity(state: &StoredState) -> Result<(), ControlError> {
    if state.active_revision.get() != 0 && state.active().is_none() {
        return Err(ControlError::CorruptState);
    }
    macro_rules! bounded_config {
        ($config:expr) => {{
            let config = $config;
            if serde_json::to_vec(config)
                .map_err(|_| ControlError::CorruptState)?
                .len()
                > 256 * 1024
                || config.listeners.len() > 128
                || config.nodes.len() > 256
                || config.subscriptions.len() > 128
                || config.validate().is_err()
            {
                return Err(ControlError::CorruptState);
            }
        }};
    }
    let mut seen = BTreeSet::new();
    for (id, record) in &state.drafts {
        let draft = &record.summary;
        if id != &draft.id
            || draft.revision.get() == 0
            || draft.base_revision > state.active_revision
        {
            return Err(ControlError::CorruptState);
        }
        bounded_config!(&draft.config);
    }
    for entry in &state.draft_idempotency {
        if !seen.insert((&entry.principal, entry.method.as_str(), &entry.key)) {
            return Err(ControlError::CorruptState);
        }
        if let Some(draft) = &entry.result {
            bounded_config!(&draft.config);
        }
    }
    let mut seen = BTreeSet::new();
    for entry in &state.plan_idempotency {
        if !seen.insert((&entry.principal, &entry.key)) || !state.plans.contains_key(&entry.plan_id)
        {
            return Err(ControlError::CorruptState);
        }
    }
    let mut seen = BTreeSet::new();
    for entry in &state.cancel_idempotency {
        if !seen.insert((&entry.principal, &entry.key))
            || !state.operations.get(&entry.operation_id).is_some_and(|op| {
                op.state == OperationState::Canceled && op.principal == entry.principal
            })
        {
            return Err(ControlError::CorruptState);
        }
    }
    for (id, plan) in &state.plans {
        let body = plan.body();
        if id != &body.id
            || plan.hash() != &ContentDigest::of("vp.change-plan.v1", body)?
            || body.validation.config_digest
                != ContentDigest::of("vp.product-config.v1", &body.config)?
            || body.validation.release_digest
                != ContentDigest::of("vp.release-identity.v1", &body.release)?
            || body.base_revision.next() != Some(body.target_revision)
            || body.expires_at_ms <= body.created_at_ms
            || body.schema_version != 1
        {
            return Err(ControlError::CorruptState);
        }
    }
    for (id, op) in &state.operations {
        if !is_v1_state(&op.state)?
            || op
                .failure
                .as_ref()
                .map(is_v1_error)
                .transpose()?
                .is_some_and(|valid| !valid)
        {
            return Err(ControlError::CorruptState);
        }
        if id != &op.id
            || !state.plans.contains_key(&op.plan_id)
            || (op.mutation_started && op.snapshot.is_none())
            || (op.state == OperationState::Committed
                && (op.health.is_none()
                    || op.activation.is_none()
                    || !state.revisions.iter().any(|r| r.operation_id == op.id)))
        {
            return Err(ControlError::CorruptState);
        }
    }
    let mut seen = BTreeSet::new();
    for revision in &state.revisions {
        if !seen.insert(revision.revision)
            || revision.revision.get() == 0
            || revision.config_digest
                != ContentDigest::of("vp.product-config.v1", &revision.config)?
            || revision.release_digest
                != ContentDigest::of("vp.release-identity.v1", &revision.release)?
            || !state
                .operations
                .get(&revision.operation_id)
                .is_some_and(|op| op.state == OperationState::Committed)
        {
            return Err(ControlError::CorruptState);
        }
    }
    let mut seen = BTreeSet::new();
    for entry in &state.idempotency {
        if !state.operations.contains_key(&entry.operation_id)
            || !seen.insert((&entry.principal, &entry.method, &entry.key))
        {
            return Err(ControlError::CorruptState);
        }
    }
    Ok(())
}

// These lists freeze enum vocabulary that the current control crate may extend.
// In particular SECRET_RESULT_UNAVAILABLE is valid v2 but never valid v1 state.
fn is_v1_error(error: &ControlError) -> Result<bool, ControlError> {
    let value = serde_json::to_value(error).map_err(|_| ControlError::CorruptState)?;
    Ok(matches!(
        value.get("code").and_then(serde_json::Value::as_str),
        Some(
            "REVISION_CONFLICT"
                | "IDEMPOTENCY_CONFLICT"
                | "PLAN_EXPIRED"
                | "CONFIRMATION_MISMATCH"
                | "PERMISSION_DENIED"
                | "NOT_FOUND"
                | "INVALID_CONFIGURATION"
                | "INVALID_REQUEST"
                | "EXECUTOR_UNAVAILABLE"
                | "RESOURCE_CONFLICT"
                | "HEALTH_FAILED"
                | "CANCELED"
                | "CANNOT_CANCEL"
                | "RECOVERY_REQUIRED"
                | "STORAGE_UNAVAILABLE"
                | "CORRUPT_STATE"
                | "EXECUTOR_FAILED"
                | "COUNTER_EXHAUSTED"
        )
    ))
}
fn is_v1_state(state: &OperationState) -> Result<bool, ControlError> {
    let value = serde_json::to_value(state).map_err(|_| ControlError::CorruptState)?;
    Ok(matches!(
        value.as_str(),
        Some(
            "queued"
                | "staging"
                | "snapshotting"
                | "applying_resources"
                | "activating"
                | "verifying"
                | "committing"
                | "committed"
                | "canceling"
                | "canceled"
                | "rolling_back"
                | "rolled_back"
                | "failed"
                | "recovery_required"
        )
    ))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct JournalEventV1 {
    sequence: u64,
    at_ms: u64,
    // Original nullable field behavior is retained. Value type is validated by
    // conversion to current unchanged ID/state types, not accepted as free JSON.
    operation_id: Option<serde_json::Value>,
    state: Option<OperationState>,
}
fn verify_journal_v1(connection: &Connection, state_version: u64) -> Result<(), ControlError> {
    verify_journal(connection, state_version, true)
}
fn verify_journal(
    connection: &Connection,
    state_version: u64,
    legacy: bool,
) -> Result<(), ControlError> {
    if state_version > MAX_JOURNAL_ROWS {
        return Err(ControlError::InvalidRequest);
    }
    let mut query = connection
        .prepare("SELECT sequence,at_ms,payload,digest FROM operation_journal ORDER BY sequence")
        .map_err(|_| ControlError::CorruptState)?;
    let mut rows = query.query([]).map_err(|_| ControlError::CorruptState)?;
    let mut expected = 0u64;
    while let Some(row) = rows.next().map_err(|_| ControlError::CorruptState)? {
        expected = expected
            .checked_add(1)
            .ok_or(ControlError::CounterExhausted)?;
        if expected > state_version {
            return Err(ControlError::CorruptState);
        }
        let column: i64 = row.get(0).map_err(|_| ControlError::CorruptState)?;
        let at_ms: i64 = row.get(1).map_err(|_| ControlError::CorruptState)?;
        let payload: Vec<u8> = row.get(2).map_err(|_| ControlError::CorruptState)?;
        let digest: String = row.get(3).map_err(|_| ControlError::CorruptState)?;
        if payload.len() > 16 * 1024 || ContentDigest::bytes(&payload).as_str() != digest {
            return Err(ControlError::CorruptState);
        }
        if legacy {
            let old: JournalEventV1 =
                serde_json::from_slice(&payload).map_err(|_| ControlError::CorruptState)?;
            if old
                .state
                .as_ref()
                .map(is_v1_state)
                .transpose()?
                .is_some_and(|valid| !valid)
            {
                return Err(ControlError::CorruptState);
            }
        }
        let event: JournalEvent =
            serde_json::from_slice(&payload).map_err(|_| ControlError::CorruptState)?;
        if to_i64(expected)? != column
            || event.sequence != expected
            || to_i64(event.at_ms)? != at_ms
        {
            return Err(ControlError::CorruptState);
        }
    }
    if expected != state_version {
        return Err(ControlError::CorruptState);
    }
    Ok(())
}
struct RawState {
    version: u64,
    payload: Vec<u8>,
    digest: ContentDigest,
}
fn raw_state(connection: &Connection) -> Result<RawState, ControlError> {
    let (version, payload, digest): (i64, Vec<u8>, String) = connection
        .query_row(
            "SELECT version,payload,digest FROM control_state WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| ControlError::CorruptState)?;
    let version = u64::try_from(version).map_err(|_| ControlError::CorruptState)?;
    let digest = ContentDigest::parse(digest).map_err(|_| ControlError::CorruptState)?;
    if payload.len() > MAX_STATE_BYTES || ContentDigest::bytes(&payload) != digest {
        return Err(ControlError::CorruptState);
    }
    Ok(RawState {
        version,
        payload,
        digest,
    })
}
fn format_of(payload: &[u8]) -> Result<u64, ControlError> {
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| ControlError::CorruptState)?;
    value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ControlError::CorruptState)
}
/// Current reads refuse valid legacy payloads with an actionable recovery boundary;
/// they do not mutate them or call the migration machinery as a fallback.
pub(crate) fn decode_current(payload: &[u8], version: u64) -> Result<StoredState, ControlError> {
    match format_of(payload)? {
        1 => {
            StoredStateV1::decode(payload, version)?;
            Err(ControlError::RecoveryRequired)
        }
        2 => {
            let state: StoredState =
                serde_json::from_slice(payload).map_err(|_| ControlError::CorruptState)?;
            if state.version != version {
                return Err(ControlError::CorruptState);
            }
            state.verify_integrity()?;
            Ok(state)
        }
        _ => Err(ControlError::CorruptState),
    }
}
fn validate_sql_layout(connection: &Connection) -> Result<(), ControlError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| ControlError::CorruptState)?;
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| ControlError::CorruptState)?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| ControlError::CorruptState)?;
    let mut query = connection
        .prepare(
            "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
        )
        .map_err(|_| ControlError::CorruptState)?;
    let rows = query
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| ControlError::CorruptState)?;
    let objects: Vec<_> = rows
        .collect::<Result<_, _>>()
        .map_err(|_| ControlError::CorruptState)?;
    if version != 1
        || journal != "delete"
        || integrity != "ok"
        || objects
            != [
                ("table".to_owned(), "control_state".to_owned()),
                ("table".to_owned(), "operation_journal".to_owned()),
            ]
    {
        return Err(ControlError::CorruptState);
    }
    for (statement, expected) in [
        (
            "PRAGMA table_info(control_state)",
            vec![
                ("singleton", "INTEGER", 0, 1),
                ("version", "INTEGER", 1, 0),
                ("payload", "BLOB", 1, 0),
                ("digest", "TEXT", 1, 0),
            ],
        ),
        (
            "PRAGMA table_info(operation_journal)",
            vec![
                ("sequence", "INTEGER", 0, 1),
                ("at_ms", "INTEGER", 1, 0),
                ("payload", "BLOB", 1, 0),
                ("digest", "TEXT", 1, 0),
            ],
        ),
    ] {
        let mut query = connection
            .prepare(statement)
            .map_err(|_| ControlError::CorruptState)?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|_| ControlError::CorruptState)?;
        let columns: Vec<_> = rows
            .collect::<Result<_, _>>()
            .map_err(|_| ControlError::CorruptState)?;
        if columns.len() != expected.len()
            || columns.iter().zip(expected).any(|(actual, expected)| {
                actual.0 != expected.0
                    || actual.1 != expected.1
                    || actual.2 != expected.2
                    || actual.3.is_some()
                    || actual.4 != expected.3
            })
        {
            return Err(ControlError::CorruptState);
        }
    }
    Ok(())
}
fn private_existing(path: &Path, limit: usize) -> Result<Vec<u8>, ControlError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ControlError::StorageUnavailable)?;
    if metadata.is_symlink() || !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(ControlError::PermissionDenied);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ControlError::PermissionDenied);
        }
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| ControlError::StorageUnavailable)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ControlError::StorageUnavailable)?;
    if bytes.len() > limit {
        return Err(ControlError::InvalidRequest);
    }
    Ok(bytes)
}
fn exists(path: &Path) -> Result<bool, ControlError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ControlError::StorageUnavailable),
    }
}
/// Never replaces published evidence. A crash-left pending file is accepted only
/// if already complete and byte-for-byte equal to this exact expected artifact.
fn publish_immutable(
    root: &Path,
    name: &str,
    pending_name: &str,
    bytes: &[u8],
    limit: usize,
) -> Result<(), ControlError> {
    let target = root.join(name);
    if exists(&target)? {
        if private_existing(&target, limit)? != bytes {
            return Err(ControlError::RecoveryRequired);
        }
        return Ok(());
    }
    let pending = root.join(pending_name);
    if exists(&pending)? {
        if private_existing(&pending, limit)? != bytes {
            return Err(ControlError::RecoveryRequired);
        }
    } else {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&pending)
            .map_err(|_| ControlError::StorageUnavailable)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| ControlError::StorageUnavailable)?;
    }
    fs::hard_link(&pending, &target).map_err(|_| ControlError::StorageUnavailable)?;
    sync_directory(root)?;
    fs::remove_file(&pending).map_err(|_| ControlError::StorageUnavailable)?;
    sync_directory(root)
}
fn verify_backup(root: &Path) -> Result<PayloadMigrationReceipt, ControlError> {
    let bytes = private_existing(&root.join(RECEIPT), 16 * 1024)?;
    let receipt: PayloadMigrationReceipt =
        serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
    receipt.validate()?;
    let backup = private_existing(&root.join(BACKUP), MAX_BACKUP_BYTES)?;
    if ContentDigest::bytes(&backup) != receipt.backup_digest {
        return Err(ControlError::CorruptState);
    }
    let connection =
        Connection::open_with_flags(root.join(BACKUP), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| ControlError::CorruptState)?;
    validate_sql_layout(&connection)?;
    let old = raw_state(&connection)?;
    StoredStateV1::decode(&old.payload, old.version)?;
    verify_journal_v1(&connection, old.version)?;
    if old.version != receipt.source_state_version || old.digest != receipt.source_payload_digest {
        return Err(ControlError::CorruptState);
    }
    let mut next = StoredStateV1::decode(&old.payload, old.version)?.to_v2()?;
    next.version = receipt.target_state_version;
    next.verify_integrity()?;
    let payload = serde_json::to_vec(&next).map_err(|_| ControlError::CorruptState)?;
    if ContentDigest::bytes(&payload) != receipt.target_payload_digest {
        return Err(ControlError::CorruptState);
    }
    Ok(receipt)
}

pub(crate) fn inspect_backup(root: &Path) -> Result<PayloadMigrationReceipt, ControlError> {
    if !root.is_absolute() {
        return Err(ControlError::InvalidRequest);
    }
    check_private_directory(root)?;
    // Inspection cannot create a writer lock or repair evidence.
    verify_backup(root)
}

/// Explicit opt-in only. Owns the normal control writer lock and also reserves
/// SQLite's writer before making the verified copy. Call as a maintenance action,
/// not while holding another lease on the same store.
pub(crate) fn migrate(root: &Path, at_ms: u64) -> Result<PayloadMigrationReceipt, ControlError> {
    migrate_with_boundary(root, at_ms, || Ok(()))
}
fn migrate_with_boundary(
    root: &Path,
    at_ms: u64,
    before_commit: impl FnOnce() -> Result<(), ControlError>,
) -> Result<PayloadMigrationReceipt, ControlError> {
    if !root.is_absolute() || at_ms > MAX_WIRE_INTEGER {
        return Err(ControlError::InvalidRequest);
    }
    check_private_directory(root)?;
    // Require an existing DB before creating/opening the shared lock. This is
    // not an alternative initialize command for a wrong/empty directory.
    private_existing(&root.join("control.db"), MAX_BACKUP_BYTES)?;
    let lock = private_file(&root.join("control.writer.lock"))?;
    FileExt::lock_exclusive(&lock).map_err(|_| ControlError::StorageUnavailable)?;
    let mut connection =
        Connection::open_with_flags(root.join("control.db"), OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|_| ControlError::StorageUnavailable)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| ControlError::StorageUnavailable)?;
    validate_sql_layout(&connection)?;
    connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
        .map_err(|_| ControlError::StorageUnavailable)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ControlError::StorageUnavailable)?;
    let raw = raw_state(&transaction)?;
    if format_of(&raw.payload)? == 2 {
        decode_current(&raw.payload, raw.version)?;
        let receipt = verify_backup(root)?;
        verify_journal(&transaction, raw.version, false)?;
        let migration_event: Vec<u8> = transaction
            .query_row(
                "SELECT payload FROM operation_journal WHERE sequence=?1",
                params![to_i64(receipt.target_state_version)?],
                |row| row.get(0),
            )
            .map_err(|_| ControlError::CorruptState)?;
        let migration_event: JournalEvent =
            serde_json::from_slice(&migration_event).map_err(|_| ControlError::CorruptState)?;
        if migration_event.at_ms != receipt.at_ms
            || migration_event.operation_id.is_some()
            || migration_event.state.is_some()
            || migration_event.security.is_some()
        {
            return Err(ControlError::CorruptState);
        }
        if raw.version < receipt.target_state_version
            || (raw.version == receipt.target_state_version
                && raw.digest != receipt.target_payload_digest)
        {
            return Err(ControlError::CorruptState);
        }
        // Already migrated; later v2 writes are preserved, never reset to receipt.
        return Ok(receipt);
    }
    let old = StoredStateV1::decode(&raw.payload, raw.version)?;
    verify_journal_v1(&transaction, raw.version)?;
    let mut next = old.to_v2()?;
    next.version = old
        .version
        .checked_add(1)
        .ok_or(ControlError::CounterExhausted)?;
    to_i64(next.version)?;
    next.verify_integrity()?;
    let target_payload = serde_json::to_vec(&next).map_err(|_| ControlError::CorruptState)?;
    if target_payload.len() > MAX_STATE_BYTES {
        return Err(ControlError::InvalidRequest);
    }
    // BEGIN IMMEDIATE has not modified any page: DELETE-journal source is a
    // stable committed database while both conforming and SQLite writers wait.
    let backup_bytes = private_existing(&root.join("control.db"), MAX_BACKUP_BYTES)?;
    publish_immutable(
        root,
        BACKUP,
        BACKUP_PENDING,
        &backup_bytes,
        MAX_BACKUP_BYTES,
    )?;
    let receipt = if exists(&root.join(RECEIPT))? {
        let prior = verify_backup(root)?;
        if prior.source_state_version != raw.version
            || prior.source_payload_digest != raw.digest
            || prior.target_payload_digest != ContentDigest::bytes(&target_payload)
        {
            return Err(ControlError::RecoveryRequired);
        }
        prior
    } else {
        let receipt = PayloadMigrationReceipt {
            receipt_version: 1,
            source_format: 1,
            target_format: 2,
            source_state_version: raw.version,
            target_state_version: next.version,
            at_ms,
            source_payload_digest: raw.digest.clone(),
            target_payload_digest: ContentDigest::bytes(&target_payload),
            backup_digest: ContentDigest::bytes(&backup_bytes),
        };
        receipt.validate()?;
        let encoded = serde_json::to_vec(&receipt).map_err(|_| ControlError::CorruptState)?;
        publish_immutable(root, RECEIPT, RECEIPT_PENDING, &encoded, 16 * 1024)?;
        verify_backup(root)?
    };
    let event = JournalEvent {
        sequence: next.version,
        at_ms: receipt.at_ms,
        operation_id: None,
        state: None,
        security: None,
    };
    let event_payload = serde_json::to_vec(&event).map_err(|_| ControlError::CorruptState)?;
    let changed = transaction.execute("UPDATE control_state SET version=?1,payload=?2,digest=?3 WHERE singleton=1 AND version=?4 AND digest=?5",
        params![to_i64(next.version)?, target_payload, receipt.target_payload_digest.as_str(), to_i64(raw.version)?, raw.digest.as_str()])
        .map_err(|_| ControlError::StorageUnavailable)?;
    if changed != 1 {
        return Err(ControlError::CorruptState);
    }
    transaction
        .execute(
            "INSERT INTO operation_journal(sequence,at_ms,payload,digest) VALUES(?1,?2,?3,?4)",
            params![
                to_i64(event.sequence)?,
                to_i64(event.at_ms)?,
                event_payload,
                ContentDigest::bytes(&event_payload).as_str()
            ],
        )
        .map_err(|_| ControlError::StorageUnavailable)?;
    before_commit()?;
    transaction
        .commit()
        .map_err(|_| ControlError::StorageUnavailable)?;
    sync_directory(root)?;
    // On any uncertain commit/fsync error return without automatic restore/retry.
    // A future explicit call inspects the actual v1/v2 state plus immutable receipt.
    Ok(receipt)
}
fn to_i64(value: u64) -> Result<i64, ControlError> {
    i64::try_from(value).map_err(|_| ControlError::CounterExhausted)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::SqliteStore;
    use vp_product_control::ControlStore;

    fn empty_v1(include_defaults: bool) -> Vec<u8> {
        let mut value = serde_json::json!({
            "schemaVersion":1,"version":0,"nextId":1,"activeRevision":0,
            "revisions":[],"plans":{},"operations":{},"idempotency":[]
        });
        if include_defaults {
            let object = value.as_object_mut().unwrap();
            object.insert("drafts".into(), serde_json::json!({}));
            for field in ["cancelIdempotency", "draftIdempotency", "planIdempotency"] {
                object.insert(field.into(), serde_json::json!([]));
            }
        }
        serde_json::to_vec(&value).unwrap()
    }
    fn fixture(include_defaults: bool) -> tempfile::TempDir {
        let dir = crate::private_test_directory();
        let path = dir.path().join("control.db");
        drop(private_file(&path).unwrap());
        let connection = Connection::open(path).unwrap();
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            CREATE TABLE control_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,payload BLOB NOT NULL,digest TEXT NOT NULL);
            CREATE TABLE operation_journal(sequence INTEGER PRIMARY KEY,at_ms INTEGER NOT NULL,payload BLOB NOT NULL,digest TEXT NOT NULL);
            PRAGMA user_version=1;").unwrap();
        let payload = empty_v1(include_defaults);
        connection
            .execute(
                "INSERT INTO control_state VALUES(1,0,?1,?2)",
                params![payload, ContentDigest::bytes(&payload).as_str()],
            )
            .unwrap();
        dir
    }
    // Actual child-process exit without Rust/SQLite destructors. This hook exists
    // only in the test binary; no daemon flag or production failure switch.
    #[test]
    fn migration_crash_child() {
        let Some(root) = std::env::var_os("VP_TEST_STORAGE_MIGRATION_ROOT") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        match std::env::var("VP_TEST_STORAGE_MIGRATION_BOUNDARY")
            .unwrap()
            .as_str()
        {
            "before_commit" => {
                let _ = migrate_with_boundary(&root, 1000, || std::process::exit(91));
                panic!("child did not reach precommit boundary");
            }
            "after_commit_before_receipt" => {
                migrate(&root, 1000).unwrap();
                std::process::exit(92);
            }
            _ => panic!("unknown child boundary"),
        }
    }
    fn crash_process(root: &Path, boundary: &str, expected: i32) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "migration::tests::migration_crash_child",
                "--nocapture",
            ])
            .env("VP_TEST_STORAGE_MIGRATION_ROOT", root)
            .env("VP_TEST_STORAGE_MIGRATION_BOUNDARY", boundary)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected));
    }
    #[test]
    fn actual_process_exit_before_commit_recovers_hot_journal_without_restoring_backup() {
        let dir = fixture(false);
        crash_process(dir.path(), "before_commit", 91);
        assert!(matches!(
            SqliteStore::open(dir.path()),
            Err(ControlError::RecoveryRequired)
        ));
        let connection = Connection::open(dir.path().join("control.db")).unwrap();
        let raw = raw_state(&connection).unwrap();
        assert_eq!(raw.version, 0);
        assert_eq!(format_of(&raw.payload).unwrap(), 1);
        drop(connection);
        let backup = fs::read(dir.path().join(BACKUP)).unwrap();
        let prepared = inspect_backup(dir.path()).unwrap();
        let completed = migrate(dir.path(), 2000).unwrap();
        assert_eq!(prepared, completed);
        assert_eq!(fs::read(dir.path().join(BACKUP)).unwrap(), backup);
        assert_eq!(
            SqliteStore::open(dir.path())
                .unwrap()
                .read()
                .unwrap()
                .schema_version,
            2
        );
    }
    #[test]
    fn actual_process_exit_after_commit_reconciles_without_reapplying_or_downgrading() {
        let dir = fixture(true);
        crash_process(dir.path(), "after_commit_before_receipt", 92);
        let before = fs::read(dir.path().join("control.db")).unwrap();
        let recorded = inspect_backup(dir.path()).unwrap();
        assert_eq!(migrate(dir.path(), 2000).unwrap(), recorded);
        assert_eq!(fs::read(dir.path().join("control.db")).unwrap(), before);
        let state = SqliteStore::open(dir.path()).unwrap().read().unwrap();
        assert_eq!(state.schema_version, 2);
        assert_eq!(state.version, 1);
    }
    #[test]
    fn v1_decoder_preserves_exact_historical_defaults_and_rejects_v2_unknowns() {
        for defaults in [false, true] {
            let old = StoredStateV1::decode(&empty_v1(defaults), 0).unwrap();
            assert_eq!(old.to_v2().unwrap().schema_version, 2);
            let next = serde_json::to_vec(&old.to_v2().unwrap()).unwrap();
            // This is the same strict old aggregate boundary: v2 has an unknown
            // secrets field and is not accepted as a new empty v1 configuration.
            assert!(serde_json::from_slice::<StoredStateV1>(&next).is_err());
        }
        let mut value: serde_json::Value = serde_json::from_slice(&empty_v1(false)).unwrap();
        value.as_object_mut().unwrap().remove("plans");
        assert!(StoredStateV1::decode(&serde_json::to_vec(&value).unwrap(), 0).is_err());
        assert!(is_v1_error(&ControlError::ExecutorFailed).unwrap());
        assert!(!is_v1_error(&ControlError::SecretResultUnavailable).unwrap());
        let duplicate = b"{\"schemaVersion\":1,\"schemaVersion\":1,\"version\":0,\"nextId\":1,\"activeRevision\":0,\"revisions\":[],\"plans\":{},\"operations\":{},\"idempotency\":[]}";
        assert!(StoredStateV1::decode(duplicate, 0).is_err());
    }
    #[test]
    fn ordinary_open_refuses_valid_v1_without_rewriting_or_creating_backup() {
        let dir = fixture(false);
        let before = fs::read(dir.path().join("control.db")).unwrap();
        assert!(matches!(
            SqliteStore::open(dir.path()),
            Err(ControlError::RecoveryRequired)
        ));
        assert_eq!(fs::read(dir.path().join("control.db")).unwrap(), before);
        assert!(!dir.path().join(BACKUP).exists());
        assert!(!dir.path().join(RECEIPT).exists());
    }
    #[test]
    fn explicit_upgrade_has_verified_immutable_backup_and_same_action_retry() {
        let dir = fixture(false);
        let before = fs::read(dir.path().join("control.db")).unwrap();
        let receipt = SqliteStore::migrate_v1_to_v2(dir.path(), 1000).unwrap();
        assert_eq!(receipt.source_state_version, 0);
        assert_eq!(receipt.target_state_version, 1);
        assert_eq!(fs::read(dir.path().join(BACKUP)).unwrap(), before);
        assert_eq!(
            SqliteStore::verify_v1_rollback_backup(dir.path()).unwrap(),
            receipt
        );
        let after = fs::read(dir.path().join("control.db")).unwrap();
        // Retry retains the original timestamp/digests and performs no new write.
        assert_eq!(
            SqliteStore::migrate_v1_to_v2(dir.path(), 2000).unwrap(),
            receipt
        );
        assert_eq!(fs::read(dir.path().join("control.db")).unwrap(), after);
        let store = SqliteStore::open(dir.path()).unwrap();
        let state = store.read().unwrap();
        assert_eq!(state.schema_version, 2);
        assert_eq!(state.version, 1);
        assert_eq!(state.next_id, 1);
        assert_eq!(
            serde_json::to_value(&state.secrets).unwrap(),
            serde_json::json!({"credentials":{},"publications":{},"actions":[]})
        );
        assert_eq!(store.journal_after(0, 10).unwrap().len(), 1);
    }
    #[test]
    fn later_v2_writes_are_never_reset_or_restored_by_migration_retry() {
        let dir = fixture(true);
        let receipt = SqliteStore::migrate_v1_to_v2(dir.path(), 1000).unwrap();
        let backup = fs::read(dir.path().join(BACKUP)).unwrap();
        let store = SqliteStore::open(dir.path()).unwrap();
        let mut writer = store.writer().unwrap();
        let mut next = writer.state().clone();
        next.version += 1;
        next.next_id = 73;
        writer
            .persist(
                next,
                JournalEvent {
                    sequence: 2,
                    at_ms: 1001,
                    operation_id: None,
                    state: None,
                    security: None,
                },
            )
            .unwrap();
        drop(writer);
        drop(store);
        let current = fs::read(dir.path().join("control.db")).unwrap();
        assert_eq!(
            SqliteStore::migrate_v1_to_v2(dir.path(), 2000).unwrap(),
            receipt
        );
        assert_eq!(fs::read(dir.path().join("control.db")).unwrap(), current);
        assert_eq!(fs::read(dir.path().join(BACKUP)).unwrap(), backup);
        assert_eq!(
            SqliteStore::open(dir.path())
                .unwrap()
                .read()
                .unwrap()
                .next_id,
            73
        );
    }
    #[test]
    fn prepared_backup_survives_precommit_failure_then_explicit_recovery() {
        let dir = fixture(true);
        assert!(matches!(
            migrate_with_boundary(dir.path(), 1000, || Err(ControlError::ExecutorFailed)),
            Err(ControlError::ExecutorFailed)
        ));
        // SQLite transaction rolled back; published recovery evidence is retained.
        let connection = Connection::open(dir.path().join("control.db")).unwrap();
        let state = raw_state(&connection).unwrap();
        assert_eq!(format_of(&state.payload).unwrap(), 1);
        assert_eq!(state.version, 0);
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM operation_journal", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        drop(connection);
        let prepared = SqliteStore::verify_v1_rollback_backup(dir.path()).unwrap();
        assert_eq!(prepared.at_ms, 1000);
        assert_eq!(
            SqliteStore::migrate_v1_to_v2(dir.path(), 2000).unwrap(),
            prepared
        );
        assert_eq!(
            SqliteStore::open(dir.path())
                .unwrap()
                .read()
                .unwrap()
                .version,
            1
        );
    }
    #[test]
    fn partial_or_tampered_evidence_is_not_overwritten_or_automatically_repaired() {
        let dir = fixture(true);
        let pending = dir.path().join(BACKUP_PENDING);
        let mut file = private_file(&pending).unwrap();
        file.write_all(b"incomplete-crash-fixture").unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            SqliteStore::migrate_v1_to_v2(dir.path(), 1000),
            Err(ControlError::RecoveryRequired)
        ));
        assert_eq!(fs::read(pending).unwrap(), b"incomplete-crash-fixture");
        assert!(!dir.path().join(RECEIPT).exists());
        let fresh = fixture(true);
        SqliteStore::migrate_v1_to_v2(fresh.path(), 1000).unwrap();
        let current = fs::read(fresh.path().join("control.db")).unwrap();
        fs::write(fresh.path().join(BACKUP), b"tampered-test-only-backup").unwrap();
        assert!(SqliteStore::verify_v1_rollback_backup(fresh.path()).is_err());
        assert!(SqliteStore::migrate_v1_to_v2(fresh.path(), 2000).is_err());
        assert_eq!(fs::read(fresh.path().join("control.db")).unwrap(), current);
    }
    #[test]
    fn corrupt_digest_future_schema_or_unknown_fields_never_migrate() {
        for mutation in ["digest", "future", "unknown", "column"] {
            let dir = fixture(true);
            let connection = Connection::open(dir.path().join("control.db")).unwrap();
            let mut payload: serde_json::Value = serde_json::from_slice(&empty_v1(true)).unwrap();
            match mutation {
                "future" => payload["schemaVersion"] = serde_json::json!(3),
                "unknown" => {
                    payload["inventedFallback"] = serde_json::json!(true);
                }
                _ => (),
            }
            let bytes = serde_json::to_vec(&payload).unwrap();
            let digest = if mutation == "digest" {
                "0".repeat(64)
            } else {
                ContentDigest::bytes(&bytes).as_str().to_owned()
            };
            let column = if mutation == "column" { 1 } else { 0 };
            connection
                .execute(
                    "UPDATE control_state SET version=?1,payload=?2,digest=?3",
                    params![column, bytes, digest],
                )
                .unwrap();
            drop(connection);
            let before = fs::read(dir.path().join("control.db")).unwrap();
            assert!(SqliteStore::migrate_v1_to_v2(dir.path(), 1000).is_err());
            assert_eq!(fs::read(dir.path().join("control.db")).unwrap(), before);
            assert!(!dir.path().join(BACKUP).exists());
        }
    }
    #[cfg(unix)]
    #[test]
    fn backup_receipt_private_modes_and_symlinks_are_enforced() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = fixture(true);
        let unrelated = dir.path().join("unrelated");
        fs::write(&unrelated, b"unchanged").unwrap();
        symlink(&unrelated, dir.path().join(BACKUP)).unwrap();
        assert!(SqliteStore::migrate_v1_to_v2(dir.path(), 1000).is_err());
        assert_eq!(fs::read(unrelated).unwrap(), b"unchanged");
        let fresh = fixture(true);
        SqliteStore::migrate_v1_to_v2(fresh.path(), 1000).unwrap();
        for name in [BACKUP, RECEIPT] {
            assert_eq!(
                fs::metadata(fresh.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn missing_database_is_not_initialized_by_migration() {
        let dir = crate::private_test_directory();
        assert!(SqliteStore::migrate_v1_to_v2(dir.path(), 1000).is_err());
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
    }
    fn seed_legacy_draft(root: &Path) -> serde_json::Value {
        let mut value: serde_json::Value = serde_json::from_slice(&empty_v1(true)).unwrap();
        let summary = serde_json::json!({"id":"draft-original","revision":1,"baseRevision":0,
            "config":{"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"listeners":[],"subscriptions":[]}});
        value["version"] = serde_json::json!(1);
        value["nextId"] = serde_json::json!(2);
        value["drafts"] =
            serde_json::json!({"draft-original":{"principal":"test-admin","summary":summary}});
        value["draftIdempotency"] = serde_json::json!([{"principal":"test-admin","method":"drafts.create.v1","key":"original-retry","requestDigest":"0".repeat(64),"result":summary}]);
        let bytes = serde_json::to_vec(&value).unwrap();
        let event = serde_json::to_vec(&JournalEventV1 {
            sequence: 1,
            at_ms: 900,
            operation_id: None,
            state: None,
        })
        .unwrap();
        let connection = Connection::open(root.join("control.db")).unwrap();
        connection
            .execute(
                "UPDATE control_state SET version=1,payload=?1,digest=?2",
                params![bytes, ContentDigest::bytes(&bytes).as_str()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO operation_journal VALUES(1,900,?1,?2)",
                params![event, ContentDigest::bytes(&event).as_str()],
            )
            .unwrap();
        value
    }
    #[test]
    fn populated_v1_draft_retry_and_journal_are_preserved_not_reinvented() {
        let dir = fixture(true);
        let old = seed_legacy_draft(dir.path());
        let receipt = SqliteStore::migrate_v1_to_v2(dir.path(), 1000).unwrap();
        assert_eq!(receipt.source_state_version, 1);
        assert_eq!(receipt.target_state_version, 2);
        let store = SqliteStore::open(dir.path()).unwrap();
        let current = serde_json::to_value(store.read().unwrap()).unwrap();
        for field in ["nextId", "drafts", "draftIdempotency", "activeRevision"] {
            assert_eq!(old[field], current[field]);
        }
        assert_eq!(store.journal_after(0, 10).unwrap().len(), 2);
    }
    #[test]
    fn corrupt_original_journal_rejects_before_any_backup_or_upgrade() {
        let dir = fixture(true);
        seed_legacy_draft(dir.path());
        let connection = Connection::open(dir.path().join("control.db")).unwrap();
        connection
            .execute(
                "UPDATE operation_journal SET digest=?1",
                params!["0".repeat(64)],
            )
            .unwrap();
        drop(connection);
        assert!(SqliteStore::migrate_v1_to_v2(dir.path(), 1000).is_err());
        assert!(!dir.path().join(BACKUP).exists());
    }
    #[test]
    fn complete_backup_without_receipt_resumes_but_never_replaces_the_copy() {
        let dir = fixture(true);
        let bytes = fs::read(dir.path().join("control.db")).unwrap();
        publish_immutable(dir.path(), BACKUP, BACKUP_PENDING, &bytes, MAX_BACKUP_BYTES).unwrap();
        assert!(!dir.path().join(RECEIPT).exists());
        SqliteStore::migrate_v1_to_v2(dir.path(), 1000).unwrap();
        assert_eq!(fs::read(dir.path().join(BACKUP)).unwrap(), bytes);
    }
}
