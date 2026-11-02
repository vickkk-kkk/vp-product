use fs2::FileExt;
use rusqlite::{params, Connection, TransactionBehavior};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::Duration,
};
use vp_product_control::{
    ContentDigest, ControlError, ControlStore, JournalEvent, StoredState, WriterLease,
};

const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;
const DB_SCHEMA: i64 = 1;

pub struct SqliteStore {
    root: PathBuf,
    connection: Mutex<Connection>,
    writer: Mutex<()>,
}
impl SqliteStore {
    /// Explicit maintenance action, never a read/open fallback. Requires an
    /// existing schema-1 SQL database containing payload-format 1 or a verified
    /// prior completion receipt. No vault or automatic restore/downgrade action.
    pub fn migrate_v1_to_v2(
        root: impl AsRef<Path>,
        at_ms: u64,
    ) -> Result<crate::PayloadMigrationReceipt, ControlError> {
        crate::migration::migrate(root.as_ref(), at_ms)
    }

    /// Verify the immutable historical copy and its format-upgrade receipt.
    /// This is evidence only: it is deliberately NOT a database restore API.
    pub fn verify_v1_rollback_backup(
        root: impl AsRef<Path>,
    ) -> Result<crate::PayloadMigrationReceipt, ControlError> {
        crate::migration::inspect_backup(root.as_ref())
    }

    /// The composition root must provision an owned private directory. Existing
    /// symlinks or group/world-accessible Unix roots are rejected, not chmodded.
    /// Parent directory ACL/ownership must also be protected by the installer.
    /// Windows requires an installer-provisioned service-only ACL (mode bits do
    /// not express Windows DACLs); this constructor deliberately fails there.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ControlError> {
        let root = root.as_ref();
        check_private_directory(root)?;
        let lock = private_file(&root.join("control.writer.lock"))?;
        FileExt::lock_exclusive(&lock).map_err(|_| ControlError::StorageUnavailable)?;
        let db_path = root.join("control.db");
        let db_guard = private_file(&db_path)?;
        db_guard
            .sync_all()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let mut connection =
            Connection::open(&db_path).map_err(|_| ControlError::StorageUnavailable)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| ControlError::StorageUnavailable)?;
        // FULL fsync durability; DELETE avoids sharing a WAL across backup/copy
        // callers who might otherwise copy only the main database file.
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;",
            )
            .map_err(|_| ControlError::StorageUnavailable)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| ControlError::StorageUnavailable)?;
        if version != 0 && version != DB_SCHEMA {
            return Err(ControlError::CorruptState);
        }
        if version == 0 {
            let existing_tables: i64 = connection.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", [], |row| row.get(0))
                .map_err(|_| ControlError::StorageUnavailable)?;
            if existing_tables != 0 {
                return Err(ControlError::CorruptState);
            }
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| ControlError::StorageUnavailable)?;
            transaction
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS control_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL,
                payload BLOB NOT NULL CHECK(length(payload)<=33554432), digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS operation_journal (
                sequence INTEGER PRIMARY KEY, at_ms INTEGER NOT NULL,
                payload BLOB NOT NULL CHECK(length(payload)<=16384), digest TEXT NOT NULL);
                PRAGMA user_version=1;",
                )
                .map_err(|_| ControlError::StorageUnavailable)?;
            let initial = StoredState::default();
            let payload = serde_json::to_vec(&initial).map_err(|_| ControlError::CorruptState)?;
            transaction.execute("INSERT OR IGNORE INTO control_state(singleton,version,payload,digest) VALUES(1,0,?1,?2)",
                params![payload, ContentDigest::bytes(&payload).as_str()]).map_err(|_| ControlError::StorageUnavailable)?;
            transaction
                .commit()
                .map_err(|_| ControlError::StorageUnavailable)?;
            sync_directory(root)?;
        }
        let store = Self {
            root: root.to_path_buf(),
            connection: Mutex::new(connection),
            writer: Mutex::new(()),
        };
        store.read()?;
        FileExt::unlock(&lock).map_err(|_| ControlError::StorageUnavailable)?;
        Ok(store)
    }

    /// Journal contains only IDs, states and timestamps. Raw executor diagnostics
    /// and full configuration never enter this public audit stream.
    pub fn journal_after(
        &self,
        sequence: u64,
        limit: usize,
    ) -> Result<Vec<JournalEvent>, ControlError> {
        let limit = limit.clamp(1, 1000);
        let connection = self
            .connection
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let mut query = connection.prepare("SELECT sequence,payload,digest FROM operation_journal WHERE sequence>?1 ORDER BY sequence LIMIT ?2")
            .map_err(|_| ControlError::StorageUnavailable)?;
        let mut rows = query
            .query(params![to_i64(sequence)?, limit as i64])
            .map_err(|_| ControlError::StorageUnavailable)?;
        let mut events = Vec::new();
        while let Some(row) = rows.next().map_err(|_| ControlError::StorageUnavailable)? {
            let stored_sequence: i64 = row.get(0).map_err(|_| ControlError::CorruptState)?;
            let bytes: Vec<u8> = row.get(1).map_err(|_| ControlError::CorruptState)?;
            let digest: String = row.get(2).map_err(|_| ControlError::CorruptState)?;
            if bytes.len() > 16 * 1024 || ContentDigest::bytes(&bytes).as_str() != digest {
                return Err(ControlError::CorruptState);
            }
            let event: JournalEvent =
                serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
            if to_i64(event.sequence)? != stored_sequence {
                return Err(ControlError::CorruptState);
            }
            events.push(event);
        }
        Ok(events)
    }
}
impl ControlStore for SqliteStore {
    fn read(&self) -> Result<StoredState, ControlError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let (version, payload, digest): (i64, Vec<u8>, String) = connection
            .query_row(
                "SELECT version,payload,digest FROM control_state WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| ControlError::CorruptState)?;
        if payload.len() > MAX_STATE_BYTES || ContentDigest::bytes(&payload).as_str() != digest {
            return Err(ControlError::CorruptState);
        }
        crate::migration::decode_current(
            &payload,
            u64::try_from(version).map_err(|_| ControlError::CorruptState)?,
        )
    }
    fn writer(&self) -> Result<Box<dyn WriterLease + '_>, ControlError> {
        let guard = self
            .writer
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let file = private_file(&self.root.join("control.writer.lock"))?;
        FileExt::lock_exclusive(&file).map_err(|_| ControlError::StorageUnavailable)?;
        let state = self.read()?;
        Ok(Box::new(SqliteWriter {
            store: self,
            _guard: guard,
            _file: file,
            state,
        }))
    }
}
struct SqliteWriter<'a> {
    store: &'a SqliteStore,
    _guard: MutexGuard<'a, ()>,
    // Dropping this independently opened file releases the process lock. Never
    // remove/replace the lock path while a daemon can still be running.
    _file: File,
    state: StoredState,
}
impl WriterLease for SqliteWriter<'_> {
    fn state(&self) -> &StoredState {
        &self.state
    }
    fn persist(&mut self, next: StoredState, event: JournalEvent) -> Result<(), ControlError> {
        if next.version
            != self
                .state
                .version
                .checked_add(1)
                .ok_or(ControlError::CounterExhausted)?
            || event.sequence != next.version
        {
            return Err(ControlError::CorruptState);
        }
        next.verify_integrity()?;
        let payload = serde_json::to_vec(&next).map_err(|_| ControlError::CorruptState)?;
        if payload.len() > MAX_STATE_BYTES {
            return Err(ControlError::StorageUnavailable);
        }
        let journal = serde_json::to_vec(&event).map_err(|_| ControlError::CorruptState)?;
        let mut connection = self
            .store
            .connection
            .lock()
            .map_err(|_| ControlError::StorageUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ControlError::StorageUnavailable)?;
        // DB-level CAS protects against other conforming/nonconforming writers;
        // a resource mutation never happens solely on an in-memory revision check.
        let changed = transaction.execute("UPDATE control_state SET version=?1,payload=?2,digest=?3 WHERE singleton=1 AND version=?4",
            params![to_i64(next.version)?, payload, ContentDigest::bytes(&payload).as_str(), to_i64(self.state.version)?])
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
                    journal,
                    ContentDigest::bytes(&journal).as_str()
                ],
            )
            .map_err(|_| ControlError::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ControlError::StorageUnavailable)?;
        self.state = next;
        Ok(())
    }
}

fn to_i64(value: u64) -> Result<i64, ControlError> {
    i64::try_from(value).map_err(|_| ControlError::CounterExhausted)
}

pub(crate) fn check_private_directory(root: &Path) -> Result<(), ControlError> {
    let meta = fs::symlink_metadata(root).map_err(|_| ControlError::StorageUnavailable)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(ControlError::StorageUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(ControlError::PermissionDenied);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(ControlError::ExecutorUnavailable)
    }
}
pub(crate) fn private_file(path: &Path) -> Result<File, ControlError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(ControlError::PermissionDenied);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(ControlError::PermissionDenied);
                }
            }
            // Safe only under the private, installer-provisioned root. A process
            // that can replace entries there is outside this directory boundary.
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|_| ControlError::StorageUnavailable)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(path)
                .map_err(|_| ControlError::StorageUnavailable)
        }
        Err(_) => Err(ControlError::StorageUnavailable),
    }
}
pub(crate) fn sync_directory(path: &Path) -> Result<(), ControlError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| ControlError::StorageUnavailable)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn durable_checkpoints_survive_reopen() {
        let dir = crate::private_test_directory();
        let store = SqliteStore::open(dir.path()).unwrap();
        let mut writer = store.writer().unwrap();
        let mut next = writer.state().clone();
        next.version = 1;
        next.next_id = 7;
        writer
            .persist(
                next,
                JournalEvent {
                    sequence: 1,
                    at_ms: 1,
                    operation_id: None,
                    state: None,
                    security: None,
                },
            )
            .unwrap();
        drop(writer);
        drop(store);
        let reopened = SqliteStore::open(dir.path()).unwrap();
        assert_eq!(reopened.read().unwrap().next_id, 7);
        assert_eq!(reopened.journal_after(0, 10).unwrap().len(), 1);
    }
    #[test]
    fn journal_and_state_commit_atomically_and_reject_wrong_sequence() {
        let dir = crate::private_test_directory();
        let store = SqliteStore::open(dir.path()).unwrap();
        let mut writer = store.writer().unwrap();
        let mut next = writer.state().clone();
        next.version = 1;
        assert!(writer
            .persist(
                next,
                JournalEvent {
                    sequence: 9,
                    at_ms: 1,
                    operation_id: None,
                    state: None,
                    security: None,
                }
            )
            .is_err());
        drop(writer);
        assert_eq!(store.read().unwrap().version, 0);
        assert!(store.journal_after(0, 10).unwrap().is_empty());
    }
    #[test]
    fn payload_corruption_is_detected_without_leaking_bytes() {
        let dir = crate::private_test_directory();
        let store = SqliteStore::open(dir.path()).unwrap();
        let conn = Connection::open(dir.path().join("control.db")).unwrap();
        conn.execute(
            "UPDATE control_state SET payload=?1 WHERE singleton=1",
            params![b"fixture-private-value".to_vec()],
        )
        .unwrap();
        assert!(matches!(store.read(), Err(ControlError::CorruptState)));
    }
    #[test]
    fn independently_opened_writers_serialize_their_checkpoints() {
        let directory = crate::private_test_directory();
        let first = std::sync::Arc::new(SqliteStore::open(directory.path()).unwrap());
        let second = std::sync::Arc::new(SqliteStore::open(directory.path()).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for store in [first.clone(), second] {
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let mut lease = store.writer().unwrap();
                let mut state = lease.state().clone();
                state.version += 1;
                state.next_id += 1;
                let event = JournalEvent {
                    sequence: state.version,
                    at_ms: 1000,
                    operation_id: None,
                    state: None,
                    security: None,
                };
                lease.persist(state, event).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(first.read().unwrap().version, 2);
        assert_eq!(first.read().unwrap().next_id, 3);
        assert_eq!(first.journal_after(0, 10).unwrap().len(), 2);
    }
    #[test]
    fn unknown_existing_database_is_not_migrated_or_overwritten() {
        let directory = crate::private_test_directory();
        let path = directory.path().join("control.db");
        let file = private_file(&path).unwrap();
        drop(file);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute("CREATE TABLE unrelated(value TEXT)", [])
            .unwrap();
        drop(connection);
        assert!(matches!(
            SqliteStore::open(directory.path()),
            Err(ControlError::CorruptState)
        ));
    }
    #[cfg(unix)]
    #[test]
    fn permissive_directory_and_symlink_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = crate::private_test_directory();
        let public = root.path().join("public");
        fs::create_dir(&public).unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            SqliteStore::open(&public),
            Err(ControlError::PermissionDenied)
        ));
        let link = root.path().join("link");
        symlink(&public, &link).unwrap();
        assert!(SqliteStore::open(&link).is_err());
    }
}
