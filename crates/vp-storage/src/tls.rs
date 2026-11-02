//! Private new-instance-only SQL1/envelope4 store. Not selected by management.
//! Shares the same writer lease for ordinary and registry writes; no side file.
//! Root and writer locks are held for the complete fresh-profile process life.
use crate::AnchoredControlRoot;
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::{
    fs::File,
    sync::{Mutex, MutexGuard},
    time::Duration,
};
use vp_product_control::{
    ContentDigest, ControlError, ControlStore, GenesisPhase, InstanceBinding, JournalEvent,
    StoredState, TlsAssetEvent, TlsAssetMutation, TlsControlEnvelope, WriterLease,
};
const MAX_PAYLOAD: usize = 32 * 1024 * 1024;
const DB: &str = "control.db";
const LOCK: &str = "control.writer.lock";

pub struct TlsSqliteStore {
    root: AnchoredControlRoot,
    _writer_file: File,
    _database_file: File,
    connection: Mutex<Connection>,
    writer: Mutex<()>,
    binding: InstanceBinding,
}
impl TlsSqliteStore {
    pub fn create(
        root: AnchoredControlRoot,
        binding: InstanceBinding,
    ) -> Result<Self, ControlError> {
        binding.validate_tls_profile()?;
        root.check_cwd()?;
        root.0.require_empty()?;
        let lock = root.0.create_file(LOCK)?;
        lock.try_lock_exclusive()
            .map_err(|_| ControlError::RecoveryRequired)?;
        lock.sync_all()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let db = root.0.create_file(DB)?;
        db.sync_all()
            .map_err(|_| ControlError::StorageUnavailable)?;
        root.0.sync()?;
        let mut connection = Self::connection(false)?;
        let initial = TlsControlEnvelope::preparing(binding.clone())?;
        let payload = encode(&initial)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        transaction.execute_batch("CREATE TABLE control_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,payload BLOB NOT NULL CHECK(length(payload)<=33554432),digest TEXT NOT NULL); CREATE TABLE operation_journal(sequence INTEGER PRIMARY KEY,at_ms INTEGER NOT NULL,payload BLOB NOT NULL CHECK(length(payload)<=16384),digest TEXT NOT NULL); PRAGMA user_version=1;").map_err(unavailable)?;
        transaction
            .execute(
                "INSERT INTO control_state(singleton,version,payload,digest) VALUES(1,0,?1,?2)",
                params![payload, ContentDigest::bytes(&payload).as_str()],
            )
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)?;
        root.0.sync()?;
        Ok(Self {
            root,
            _writer_file: lock,
            _database_file: db,
            connection: Mutex::new(connection),
            writer: Mutex::new(()),
            binding,
        })
    }
    /// Caller must first authenticate the matching immutable vault binding.
    /// No unknown/partial genesis is adopted, repaired or implicitly upgraded.
    pub fn open_initialized(
        root: AnchoredControlRoot,
        binding: InstanceBinding,
    ) -> Result<Self, ControlError> {
        binding.validate_tls_profile()?;
        root.check_cwd()?;
        if root.0.names()? != [DB.to_owned(), LOCK.to_owned()] {
            return Err(ControlError::RecoveryRequired);
        }
        let lock = root.0.open_file(LOCK)?;
        lock.try_lock_exclusive()
            .map_err(|_| ControlError::RecoveryRequired)?;
        let db = root.0.open_file(DB)?;
        if db
            .metadata()
            .map_err(|_| ControlError::StorageUnavailable)?
            .len()
            > 128 * 1024 * 1024
        {
            return Err(ControlError::CorruptState);
        }
        let observed = Self::connection(true)?;
        validate_layout(&observed)?;
        let (_, envelope, _) = read_envelope(&observed)?;
        if envelope.binding() != &binding || envelope.phase() != GenesisPhase::Initialized {
            return Err(ControlError::RecoveryRequired);
        }
        validate_journal(&observed, envelope.state().version)?;
        drop(observed);
        root.check_cwd()?;
        let connection = Self::connection(false)?;
        validate_layout(&connection)?;
        let store = Self {
            root,
            _writer_file: lock,
            _database_file: db,
            connection: Mutex::new(connection),
            writer: Mutex::new(()),
            binding,
        };
        store.envelope(true)?;
        Ok(store)
    }
    fn connection(read_only: bool) -> Result<Connection, ControlError> {
        let flags = if read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        let connection = Connection::open_with_flags(DB, flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)
            .map_err(unavailable)?;
        connection
            .busy_timeout(Duration::from_secs(2))
            .map_err(unavailable)?;
        connection
            .set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(unavailable)?;
        connection
            .execute_batch("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;")
            .map_err(unavailable)?;
        if !read_only {
            connection
                .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
                .map_err(unavailable)?;
        }
        Ok(connection)
    }
    fn envelope(&self, initialized: bool) -> Result<TlsControlEnvelope, ControlError> {
        self.root.check_cwd()?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let (_, e, _) = read_envelope(&connection)?;
        if e.binding() != &self.binding || (initialized && e.phase() != GenesisPhase::Initialized) {
            return Err(ControlError::RecoveryRequired);
        }
        Ok(e)
    }
    /// The vault claim and bound runtime reservation must already be durable.
    /// This transition is one-shot and is not proof of HTTP/process liveness.
    pub fn mark_initialized(&self) -> Result<(), ControlError> {
        let _guard = self
            .writer
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        self.root.check_cwd()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let (version, mut e, old_digest) = read_envelope(&connection)?;
        if e.binding() != &self.binding || e.phase() != GenesisPhase::Preparing || version != 0 {
            return Err(ControlError::RecoveryRequired);
        }
        e.mark_initialized()?;
        let payload = encode(&e)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let changed=tx.execute("UPDATE control_state SET payload=?1,digest=?2 WHERE singleton=1 AND version=0 AND digest=?3",params![payload,ContentDigest::bytes(&payload).as_str(),old_digest]).map_err(unavailable)?;
        if changed != 1 {
            return Err(ControlError::CorruptState);
        }
        tx.commit().map_err(unavailable)?;
        self.root.0.sync()
    }
}
impl ControlStore for TlsSqliteStore {
    fn read(&self) -> Result<StoredState, ControlError> {
        let e = self.envelope(true)?;
        e.require_ordinary_access()?;
        Ok(e.state().clone())
    }
    fn writer(&self) -> Result<Box<dyn WriterLease + '_>, ControlError> {
        let guard = self
            .writer
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let aggregate = self.envelope(true)?;
        aggregate.require_ordinary_access()?;
        Ok(Box::new(TlsWriter {
            store: self,
            _guard: guard,
            aggregate,
        }))
    }
}
impl TlsSqliteStore {
    /// Recovery-capable lease. Does not grant authorization or verified facts.
    pub fn asset_writer(&self) -> Result<TlsWriter<'_>, ControlError> {
        let guard = self
            .writer
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let aggregate = self.envelope(true)?;
        Ok(TlsWriter {
            store: self,
            _guard: guard,
            aggregate,
        })
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    content = "event",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum AggregateEvent {
    Control(JournalEvent),
    Asset(TlsAssetEvent),
}
pub struct TlsWriter<'a> {
    store: &'a TlsSqliteStore,
    _guard: MutexGuard<'a, ()>,
    aggregate: TlsControlEnvelope,
}
impl TlsWriter<'_> {
    pub fn aggregate(&self) -> &TlsControlEnvelope {
        &self.aggregate
    }
    pub fn persist_asset(&mut self, mutation: TlsAssetMutation) -> Result<(), ControlError> {
        let (previous, next, event) = mutation.into_parts();
        if previous != self.aggregate.digest()?
            || next.binding() != self.aggregate.binding()
            || event.sequence != next.state().version
        {
            return Err(ControlError::ResourceConflict);
        }
        let at = event.at_ms;
        self.commit(next, AggregateEvent::Asset(event), at)
    }
    fn commit(
        &mut self,
        next: TlsControlEnvelope,
        event: AggregateEvent,
        at: u64,
    ) -> Result<(), ControlError> {
        self.store.root.check_cwd()?;
        let mut connection = self
            .store
            .connection
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        persist_aggregate(&mut connection, &self.aggregate, &next, event, at)?;
        self.aggregate = next;
        Ok(())
    }
}
impl WriterLease for TlsWriter<'_> {
    fn state(&self) -> &StoredState {
        self.aggregate.state()
    }
    fn persist(&mut self, next: StoredState, event: JournalEvent) -> Result<(), ControlError> {
        if event.sequence != next.version {
            return Err(ControlError::CorruptState);
        }
        let next = self.aggregate.with_ordinary_state(next)?;
        let at = event.at_ms;
        self.commit(next, AggregateEvent::Control(event), at)
    }
}

fn persist_aggregate(
    connection: &mut Connection,
    previous: &TlsControlEnvelope,
    next: &TlsControlEnvelope,
    event: AggregateEvent,
    at: u64,
) -> Result<(), ControlError> {
    if previous.state().version.checked_add(1) != Some(next.state().version) {
        return Err(ControlError::CorruptState);
    }
    let payload = encode(next)?;
    let journal = serde_json::to_vec(&event).map_err(|_| ControlError::CorruptState)?;
    if journal.len() > 16384 {
        return Err(ControlError::InvalidRequest);
    }
    let (_, old, old_digest) = read_envelope(connection)?;
    if old.digest()? != previous.digest()? {
        return Err(ControlError::ResourceConflict);
    }
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    let changed=tx.execute("UPDATE control_state SET version=?1,payload=?2,digest=?3 WHERE singleton=1 AND version=?4 AND digest=?5",
            params![integer(next.state().version)?,payload,ContentDigest::bytes(&payload).as_str(),integer(previous.state().version)?,old_digest]).map_err(unavailable)?;
    if changed != 1 {
        return Err(ControlError::ResourceConflict);
    }
    tx.execute(
        "INSERT INTO operation_journal(sequence,at_ms,payload,digest) VALUES(?1,?2,?3,?4)",
        params![
            integer(next.state().version)?,
            integer(at)?,
            journal,
            ContentDigest::bytes(&journal).as_str()
        ],
    )
    .map_err(unavailable)?;
    tx.commit().map_err(unavailable)?;
    Ok(())
}
fn integer(v: u64) -> Result<i64, ControlError> {
    i64::try_from(v).map_err(|_| ControlError::CounterExhausted)
}
fn unavailable(_: rusqlite::Error) -> ControlError {
    ControlError::StorageUnavailable
}
fn encode(e: &TlsControlEnvelope) -> Result<Vec<u8>, ControlError> {
    e.validate()?;
    let bytes = serde_json::to_vec(e).map_err(|_| ControlError::CorruptState)?;
    if bytes.len() > MAX_PAYLOAD {
        return Err(ControlError::InvalidRequest);
    }
    Ok(bytes)
}
fn read_envelope(c: &Connection) -> Result<(u64, TlsControlEnvelope, String), ControlError> {
    let (version, bytes, digest): (i64, Vec<u8>, String) = c
        .query_row(
            "SELECT version,payload,digest FROM control_state WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(unavailable)?;
    if bytes.len() > MAX_PAYLOAD || ContentDigest::bytes(&bytes).as_str() != digest {
        return Err(ControlError::CorruptState);
    }
    let e: TlsControlEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
    e.validate()?;
    let version = u64::try_from(version).map_err(|_| ControlError::CorruptState)?;
    if e.state().version != version {
        return Err(ControlError::CorruptState);
    }
    Ok((version, e, digest))
}
fn validate_layout(c: &Connection) -> Result<(), ControlError> {
    let v: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(unavailable)?;
    let mode: String = c
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .map_err(unavailable)?;
    let mut q = c
        .prepare("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(unavailable)?;
    let names = q
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(unavailable)?;
    if v != 1
        || mode != "delete"
        || names
            != vec![
                ("table".into(), "control_state".into()),
                ("table".into(), "operation_journal".into()),
            ]
    {
        return Err(ControlError::CorruptState);
    }
    Ok(())
}

fn validate_journal(c: &Connection, version: u64) -> Result<(), ControlError> {
    let mut q = c
        .prepare("SELECT sequence,at_ms,payload,digest FROM operation_journal ORDER BY sequence")
        .map_err(unavailable)?;
    let mut rows = q.query([]).map_err(unavailable)?;
    let mut sequence = 0u64;
    while let Some(row) = rows.next().map_err(unavailable)? {
        sequence = sequence.checked_add(1).ok_or(ControlError::CorruptState)?;
        if sequence > version {
            return Err(ControlError::CorruptState);
        }
        let stored: i64 = row.get(0).map_err(unavailable)?;
        let at: i64 = row.get(1).map_err(unavailable)?;
        let bytes: Vec<u8> = row.get(2).map_err(unavailable)?;
        let digest: String = row.get(3).map_err(unavailable)?;
        if stored != integer(sequence)?
            || at < 0
            || bytes.len() > 16384
            || ContentDigest::bytes(&bytes).as_str() != digest
        {
            return Err(ControlError::CorruptState);
        }
        let event: AggregateEvent =
            serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
        let (seq, time) = match event {
            AggregateEvent::Control(e) => (e.sequence, e.at_ms),
            AggregateEvent::Asset(e) => (e.sequence, e.at_ms),
        };
        if seq != sequence || integer(time)? != at {
            return Err(ControlError::CorruptState);
        }
    }
    if sequence != version {
        return Err(ControlError::CorruptState);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;
    fn empty() -> TlsControlEnvelope {
        let d = ContentDigest::bytes(b"synthetic");
        let mut e = TlsControlEnvelope::preparing(InstanceBinding {
            binding_version: 1,
            genesis_id: "1".repeat(32),
            vault_id: "2".repeat(32),
            namespace_digest: d.clone(),
            administrator_commitment: d.clone(),
            preparation_digest: d.clone(),
            activation_intent_digest: d.clone(),
            artifact_set_digest: d,
            profile: vp_product_control::FRESH_TLS_RUNTIME_PROFILE.into(),
        })
        .unwrap();
        e.mark_initialized().unwrap();
        e
    }
    // Fixture injection exists only in this test module. It is NOT a validator,
    // import entry point, production proof constructor or trusted material source.
    fn fixture(phase: &str) -> TlsControlEnvelope {
        let mut v = serde_json::to_value(empty()).unwrap();
        let d = serde_json::to_value(ContentDigest::bytes(b"synthetic-public-fact")).unwrap();
        v["state"]["version"] = 1.into();
        v["certificateAssets"] = json!({"cert":{"id":"cert","revision":1,"importAction":"action","chainRef":"secret:chain","chainKind":6,"chainVersion":1,"keyRef":"secret:key","keyKind":2,"keyVersion":1,"keyRole":"tls-server-key","encoding":"pem-v1","phase":phase,"facts":{"chainDigest":d,"chainSize":10,"leafDigest":d,"spkiDigest":d,"notBefore":-1,"notAfter":-1,"policy":"synthetic-test-only","displayDnsNames":[]}}});
        let action_phase = if phase == "pending_import" {
            "import_reserved"
        } else {
            "import_completed"
        };
        v["certificateActions"] = json!({"action":{"id":"action","assetId":"cert","actor":"actor","idempotency":"request","createdAtMs":1,"phase":action_phase,"historicalLoss":false}});
        let e: TlsControlEnvelope = serde_json::from_value(v).unwrap();
        e.validate().unwrap();
        e
    }
    fn initialize(c: &Connection, e: &TlsControlEnvelope) {
        c.execute_batch("CREATE TABLE control_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,payload BLOB NOT NULL,digest TEXT NOT NULL); CREATE TABLE operation_journal(sequence INTEGER PRIMARY KEY,at_ms INTEGER NOT NULL,payload BLOB NOT NULL,digest TEXT NOT NULL); PRAGMA user_version=1;").unwrap();
        let bytes = encode(e).unwrap();
        c.execute(
            "INSERT INTO control_state VALUES(1,?1,?2,?3)",
            params![
                integer(e.state().version).unwrap(),
                bytes,
                ContentDigest::bytes(&bytes).as_str()
            ],
        )
        .unwrap();
        if e.state().version == 1 {
            let phase = if e.needs_recovery() {
                "import_reserved"
            } else {
                "import_completed"
            };
            let bytes=serde_json::to_vec(&json!({"kind":"asset","event":{"sequence":1,"atMs":1,"action":"action","asset":"cert","transition":phase}})).unwrap();
            c.execute(
                "INSERT INTO operation_journal VALUES(1,1,?1,?2)",
                params![bytes, ContentDigest::bytes(&bytes).as_str()],
            )
            .unwrap();
        }
    }
    fn control_event(seq: u64) -> AggregateEvent {
        AggregateEvent::Control(JournalEvent {
            security: None,
            sequence: seq,
            at_ms: 2,
            operation_id: None,
            state: None,
        })
    }
    #[test]
    fn disk_restart_preserves_registry_through_ordinary_write() {
        let temp = crate::private_test_directory();
        let path = temp.path().join("test.db");
        let mut c = Connection::open(&path).unwrap();
        let e = fixture("available");
        initialize(&c, &e);
        let mut state = e.state().clone();
        state.version += 1;
        let next = e.with_ordinary_state(state).unwrap();
        persist_aggregate(&mut c, &e, &next, control_event(2), 2).unwrap();
        drop(c);
        let c = Connection::open(&path).unwrap();
        let (_, read, _) = read_envelope(&c).unwrap();
        assert_eq!(read.digest().unwrap(), next.digest().unwrap());
        validate_journal(&c, 2).unwrap();
        assert!(read.require_admission(1).is_err());
        assert!(read.require_admission(2).is_ok());
    }
    #[test]
    fn pending_survives_restart_abort_keeps_reserved_pair() {
        let mut c = Connection::open_in_memory().unwrap();
        let e = fixture("pending_import");
        initialize(&c, &e);
        let (_, read, _) = read_envelope(&c).unwrap();
        assert!(read.require_admission(1).is_err());
        let (_, next, event) = read.abort_import(1, "action", 2).unwrap().into_parts();
        persist_aggregate(&mut c, &e, &next, AggregateEvent::Asset(event), 2).unwrap();
        let (_, read, _) = read_envelope(&c).unwrap();
        assert!(!read.needs_recovery());
        validate_journal(&c, 2).unwrap();
        let v = serde_json::to_value(read).unwrap();
        assert_eq!(v["certificateAssets"]["cert"]["phase"], "aborted");
        assert_eq!(v["certificateAssets"]["cert"]["chainRef"], "secret:chain");
    }
    #[test]
    fn stale_full_aggregate_cannot_commit_even_same_config_revision() {
        let mut c = Connection::open_in_memory().unwrap();
        let e = fixture("available");
        initialize(&c, &e);
        let mut state = e.state().clone();
        state.version += 1;
        let next = e.with_ordinary_state(state).unwrap();
        persist_aggregate(&mut c, &e, &next, control_event(2), 2).unwrap();
        assert!(persist_aggregate(&mut c, &e, &next, control_event(2), 2).is_err());
        assert_eq!(read_envelope(&c).unwrap().0, 2);
    }
    #[test]
    fn journal_insert_failure_rolls_back_aggregate() {
        let mut c = Connection::open_in_memory().unwrap();
        let e = empty();
        initialize(&c, &e);
        c.execute_batch("CREATE TRIGGER reject_journal BEFORE INSERT ON operation_journal BEGIN SELECT RAISE(ABORT,'synthetic fault'); END;").unwrap();
        let mut state = e.state().clone();
        state.version = 1;
        let next = e.with_ordinary_state(state).unwrap();
        assert!(persist_aggregate(&mut c, &e, &next, control_event(1), 2).is_err());
        assert_eq!(
            read_envelope(&c).unwrap().1.digest().unwrap(),
            e.digest().unwrap()
        );
        assert_eq!(
            c.query_row("SELECT count(*) FROM operation_journal", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn strict_journal_refuses_unknown_events_gaps_and_bad_hash() {
        let c = Connection::open_in_memory().unwrap();
        initialize(&c, &fixture("available"));
        validate_journal(&c, 1).unwrap();
        c.execute("UPDATE operation_journal SET digest='wrong'", [])
            .unwrap();
        assert!(validate_journal(&c, 1).is_err());
        let bytes = b"{\"kind\":\"future\",\"event\":{}}";
        c.execute(
            "UPDATE operation_journal SET payload=?1,digest=?2",
            params![bytes.as_slice(), ContentDigest::bytes(bytes).as_str()],
        )
        .unwrap();
        assert!(validate_journal(&c, 1).is_err());
        c.execute("DELETE FROM operation_journal", []).unwrap();
        assert!(validate_journal(&c, 1).is_err());
    }
    #[test]
    fn old_payload_and_tampered_digest_refused_without_writes() {
        let c = Connection::open_in_memory().unwrap();
        let e = empty();
        initialize(&c, &e);
        let mut v = serde_json::to_value(&e).unwrap();
        v["schemaVersion"] = 3.into();
        let bytes = serde_json::to_vec(&v).unwrap();
        c.execute(
            "UPDATE control_state SET payload=?1,digest=?2",
            params![bytes, ContentDigest::bytes(&bytes).as_str()],
        )
        .unwrap();
        assert!(read_envelope(&c).is_err());
        assert_eq!(
            c.query_row("SELECT payload FROM control_state", [], |r| r
                .get::<_, Vec<u8>>(0))
                .unwrap(),
            bytes
        );
        c.execute("UPDATE control_state SET digest='wrong'", [])
            .unwrap();
        assert!(read_envelope(&c).is_err());
    }
    #[test]
    fn missing_registry_unknown_field_and_pair_alias_refused() {
        for kind in 0..3 {
            let mut v = serde_json::to_value(fixture("available")).unwrap();
            match kind {
                0 => {
                    v.as_object_mut().unwrap().remove("certificateAssets");
                }
                1 => v["future"] = true.into(),
                _ => v["certificateAssets"]["cert"]["keyRef"] = "secret:chain".into(),
            };
            match serde_json::from_value::<TlsControlEnvelope>(v) {
                Ok(e) => assert!(e.validate().is_err()),
                Err(_) => {}
            }
        }
    }
    #[test]
    fn equal_version_forged_metadata_snapshot_cannot_authorize_mutation() {
        let mut c = Connection::open_in_memory().unwrap();
        let e = fixture("pending_import");
        initialize(&c, &e);
        let mut v = serde_json::to_value(&e).unwrap();
        v["certificateActions"]["action"]["actor"] = "different".into();
        let forged: TlsControlEnvelope = serde_json::from_value(v).unwrap();
        let (_, next, event) = forged.abort_import(1, "action", 2).unwrap().into_parts();
        assert!(
            persist_aggregate(&mut c, &forged, &next, AggregateEvent::Asset(event), 2).is_err()
        );
        assert_eq!(
            read_envelope(&c).unwrap().1.digest().unwrap(),
            e.digest().unwrap()
        );
    }
    #[test]
    fn sqlite_full_rolls_back_without_exhausting_host_disk() {
        let mut c = Connection::open_in_memory().unwrap();
        let e = empty();
        initialize(&c, &e);
        let pages: i64 = c
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        c.pragma_update(None, "max_page_count", pages).unwrap();
        let mut state = e.state().clone();
        state.version = 1;
        let next = e.with_ordinary_state(state).unwrap();
        let mut event = match control_event(1) {
            AggregateEvent::Control(e) => e,
            _ => unreachable!(),
        };
        event.security = Some(vp_product_control::SecurityAuditEvent {
            actor: vp_product_control::SecurityAuditActor::Administrator {
                id: serde_json::from_str("\"test-actor\"").unwrap(),
            },
            action: vp_product_control::SecurityAuditAction::PublicationFetched,
            subject: "x".repeat(12000),
        });
        assert!(persist_aggregate(&mut c, &e, &next, AggregateEvent::Control(event), 2).is_err());
        assert_eq!(
            read_envelope(&c).unwrap().1.digest().unwrap(),
            e.digest().unwrap()
        );
        validate_journal(&c, 0).unwrap();
    }
}

#[cfg(feature = "private-tls")]
impl vp_product_control::TlsAssetWriterLease for TlsWriter<'_> {
    fn aggregate(&self) -> &TlsControlEnvelope {
        TlsWriter::aggregate(self)
    }
    fn persist_asset(&mut self, mutation: TlsAssetMutation) -> Result<(), ControlError> {
        TlsWriter::persist_asset(self, mutation)
    }
}
