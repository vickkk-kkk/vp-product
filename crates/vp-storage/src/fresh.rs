//! Separate cwd-anchored SQL1/payload3 store. Legacy SqliteStore is unchanged.
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
    ContentDigest, ControlError, ControlStore, FreshControlEnvelope, GenesisPhase, InstanceBinding,
    JournalEvent, StoredState, WriterLease,
};
const MAX_PAYLOAD: usize = 32 * 1024 * 1024;
const DB: &str = "control.db";
const LOCK: &str = "control.writer.lock";

pub struct FreshSqliteStore {
    root: AnchoredControlRoot,
    _writer_file: File,
    _database_file: File,
    connection: Mutex<Connection>,
    writer: Mutex<()>,
    binding: InstanceBinding,
}
impl FreshSqliteStore {
    pub fn create(
        root: AnchoredControlRoot,
        binding: InstanceBinding,
    ) -> Result<Self, ControlError> {
        binding.validate_fresh_profile()?;
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
        let initial = FreshControlEnvelope::preparing(binding.clone())?;
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
        binding.validate_fresh_profile()?;
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
        if envelope.binding != binding || envelope.phase != GenesisPhase::Initialized {
            return Err(ControlError::RecoveryRequired);
        }
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
    fn envelope(&self, initialized: bool) -> Result<FreshControlEnvelope, ControlError> {
        self.root.check_cwd()?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let (_, e, _) = read_envelope(&connection)?;
        if e.binding != self.binding || (initialized && e.phase != GenesisPhase::Initialized) {
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
        if e.binding != self.binding || e.phase != GenesisPhase::Preparing || version != 0 {
            return Err(ControlError::RecoveryRequired);
        }
        e.phase = GenesisPhase::Initialized;
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
impl ControlStore for FreshSqliteStore {
    fn read(&self) -> Result<StoredState, ControlError> {
        Ok(self.envelope(true)?.state)
    }
    fn writer(&self) -> Result<Box<dyn WriterLease + '_>, ControlError> {
        let guard = self
            .writer
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let state = self.envelope(true)?.state;
        Ok(Box::new(FreshWriter {
            store: self,
            _guard: guard,
            state,
        }))
    }
}
struct FreshWriter<'a> {
    store: &'a FreshSqliteStore,
    _guard: MutexGuard<'a, ()>,
    state: StoredState,
}
impl WriterLease for FreshWriter<'_> {
    fn state(&self) -> &StoredState {
        &self.state
    }
    fn persist(&mut self, next: StoredState, event: JournalEvent) -> Result<(), ControlError> {
        self.store.root.check_cwd()?;
        if self.state.version.checked_add(1) != Some(next.version) || event.sequence != next.version
        {
            return Err(ControlError::CorruptState);
        }
        next.verify_integrity()?;
        let envelope = FreshControlEnvelope {
            schema_version: 3,
            binding: self.store.binding.clone(),
            phase: GenesisPhase::Initialized,
            state: next.clone(),
        };
        let payload = encode(&envelope)?;
        let journal = serde_json::to_vec(&event).map_err(|_| ControlError::CorruptState)?;
        if journal.len() > 16384 {
            return Err(ControlError::InvalidRequest);
        }
        let mut connection = self
            .store
            .connection
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let (_, old, old_digest) = read_envelope(&connection)?;
        if old.binding != self.store.binding
            || old.phase != GenesisPhase::Initialized
            || old.state.version != self.state.version
        {
            return Err(ControlError::CorruptState);
        }
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let changed=tx.execute("UPDATE control_state SET version=?1,payload=?2,digest=?3 WHERE singleton=1 AND version=?4 AND digest=?5",params![integer(next.version)?,payload,ContentDigest::bytes(&payload).as_str(),integer(self.state.version)?,old_digest]).map_err(unavailable)?;
        if changed != 1 {
            return Err(ControlError::CorruptState);
        }
        tx.execute(
            "INSERT INTO operation_journal(sequence,at_ms,payload,digest) VALUES(?1,?2,?3,?4)",
            params![
                integer(event.sequence)?,
                integer(event.at_ms)?,
                journal,
                ContentDigest::bytes(&journal).as_str()
            ],
        )
        .map_err(unavailable)?;
        tx.commit().map_err(unavailable)?;
        self.state = next;
        Ok(())
    }
}
fn integer(v: u64) -> Result<i64, ControlError> {
    i64::try_from(v).map_err(|_| ControlError::CounterExhausted)
}
fn unavailable(_: rusqlite::Error) -> ControlError {
    ControlError::StorageUnavailable
}
fn encode(e: &FreshControlEnvelope) -> Result<Vec<u8>, ControlError> {
    e.validate()?;
    let bytes = serde_json::to_vec(e).map_err(|_| ControlError::CorruptState)?;
    if bytes.len() > MAX_PAYLOAD {
        return Err(ControlError::InvalidRequest);
    }
    Ok(bytes)
}
fn read_envelope(c: &Connection) -> Result<(u64, FreshControlEnvelope, String), ControlError> {
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
    let e: FreshControlEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
    e.validate()?;
    let version = u64::try_from(version).map_err(|_| ControlError::CorruptState)?;
    if e.state.version != version {
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
