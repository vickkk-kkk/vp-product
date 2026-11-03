//! Retained, non-repairing TLS SQL observation. This is NOT store promotion,
//! instance admission, process readiness, migration or cleanup authority.
use super::{read_envelope, unavailable, validate_journal, validate_table_layout, DB, LOCK};
use crate::{AnchoredControlRoot, DirectoryIdentity};
use fs2::FileExt;
use rusqlite::{config::DbConfig, Connection, OpenFlags};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt};
use vp_product_control::{ContentDigest, ControlError, GenesisPhase, InstanceBinding, StoredState};

const MAX_DATABASE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Eq, PartialEq)]
struct Fingerprint {
    identity: DirectoryIdentity,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl Fingerprint {
    fn read(file: &File) -> Result<Self, ControlError> {
        let metadata = file
            .metadata()
            .map_err(|_| ControlError::StorageUnavailable)?;
        Ok(Self {
            identity: DirectoryIdentity::of(file)?,
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

/// Checked data, not a serialized authority or freshness/anti-rollback proof.
/// The caller must supply the expected binding from its authenticated vault.
pub struct TlsControlSnapshot {
    binding: InstanceBinding,
    state: StoredState,
    aggregate_digest: ContentDigest,
    requires_recovery: bool,
}
impl TlsControlSnapshot {
    pub fn binding(&self) -> &InstanceBinding {
        &self.binding
    }
    pub fn state(&self) -> &StoredState {
        &self.state
    }
    pub fn aggregate_digest(&self) -> &ContentDigest {
        &self.aggregate_digest
    }
    /// Pending ordinary/TLS operations remain visible, never normalized away.
    /// True does not grant permission to mutate or recover them.
    pub fn requires_recovery(&self) -> bool {
        self.requires_recovery
    }
}

/// Owns root/writer/database handles and a read transaction for its entire life.
/// There is deliberately no writable connection, promotion or into_store method.
pub struct TlsControlInspection {
    // Rust drops fields in declaration order: end the SQLite transaction before
    // releasing its retained database handle, writer lease, and finally root lease.
    _connection: Connection,
    database: File,
    writer: File,
    writer_fingerprint: Fingerprint,
    database_fingerprint: Fingerprint,
    snapshot: TlsControlSnapshot,
    root: AnchoredControlRoot,
}
impl TlsControlInspection {
    /// Rechecks retained identities/inventory before lending the checked snapshot.
    /// This cannot close the broader control/vault/runtime pairing by itself.
    pub fn snapshot(&self) -> Result<&TlsControlSnapshot, ControlError> {
        self.check_unchanged()?;
        Ok(&self.snapshot)
    }
    fn check_unchanged(&self) -> Result<(), ControlError> {
        self.root.check_cwd()?;
        if self.root.0.names()? != [DB.to_owned(), LOCK.to_owned()] {
            return Err(ControlError::RecoveryRequired);
        }
        for (name, retained, fingerprint) in [
            (DB, &self.database, &self.database_fingerprint),
            (LOCK, &self.writer, &self.writer_fingerprint),
        ] {
            self.root.0.check_file(retained)?;
            if Fingerprint::read(retained)? != *fingerprint {
                return Err(ControlError::ResourceConflict);
            }
            let current = self.root.0.open_file_read_only(name)?;
            if Fingerprint::read(&current)? != *fingerprint {
                return Err(ControlError::ResourceConflict);
            }
        }
        Ok(())
    }
}

/// Observe existing initialized TLS state under retained lifetime leases.
/// No SQL PRAGMA, RW open, creation, migration, checkpoint, cleanup or promotion.
/// SQLite opens the existing relative name in READ_ONLY|NOFOLLOW mode; the
/// anchored stable-path/cooperative same-UID model is unchanged.
pub fn inspect_tls_control_read_only(
    root: AnchoredControlRoot,
    expected_binding: &InstanceBinding,
) -> Result<TlsControlInspection, ControlError> {
    expected_binding.validate_tls_profile()?;
    root.check_cwd()?;
    // Re-locking the same retained open description is safe; an admitted but
    // unlocked caller must not accidentally bypass the root lifetime lease.
    let root = AnchoredControlRoot(root.0.lock()?);
    if root.0.names()? != [DB.to_owned(), LOCK.to_owned()] {
        return Err(ControlError::RecoveryRequired);
    }
    let writer = root.0.open_file_read_only(LOCK)?;
    writer
        .try_lock_exclusive()
        .map_err(|_| ControlError::RecoveryRequired)?;
    let writer_fingerprint = Fingerprint::read(&writer)?;
    if writer_fingerprint.length != 0 {
        return Err(ControlError::CorruptState);
    }
    let database = root.0.open_file_read_only(DB)?;
    let database_fingerprint = Fingerprint::read(&database)?;
    if database_fingerprint.length < 100 || database_fingerprint.length > MAX_DATABASE_BYTES {
        return Err(ControlError::CorruptState);
    }
    // SQLite's stable header fields: rollback-mode read/write versions and
    // user_version. WAL and unknown SQL layout refuse before SQLite opens it.
    let mut header = [0u8; 100];
    (&database)
        .read_exact(&mut header)
        .map_err(|_| ControlError::StorageUnavailable)?;
    if &header[..16] != b"SQLite format 3\0"
        || header[18] != 1
        || header[19] != 1
        || u32::from_be_bytes(
            header[60..64]
                .try_into()
                .map_err(|_| ControlError::CorruptState)?,
        ) != 1
    {
        return Err(ControlError::CorruptState);
    }
    root.check_cwd()?;
    let connection = Connection::open_with_flags(
        DB,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(unavailable)?;
    // Connection-local C API flags, never SQL PRAGMA or on-disk changes.
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(unavailable)?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
        .map_err(unavailable)?;
    connection
        .execute_batch("BEGIN DEFERRED")
        .map_err(unavailable)?;
    validate_table_layout(&connection)?;
    let (_, envelope, _) = read_envelope(&connection)?;
    if envelope.binding() != expected_binding || envelope.phase() != GenesisPhase::Initialized {
        return Err(ControlError::RecoveryRequired);
    }
    // Bound inspection work independently of an attacker-controlled counter.
    if envelope.state().version > 1_000_000 {
        return Err(ControlError::RecoveryRequired);
    }
    let rows: i64 = connection
        .query_row("SELECT count(*) FROM control_state", [], |r| r.get(0))
        .map_err(unavailable)?;
    if rows != 1 {
        return Err(ControlError::CorruptState);
    }
    validate_journal(&connection, envelope.state().version)?;
    let snapshot = TlsControlSnapshot {
        binding: envelope.binding().clone(),
        state: envelope.state().clone(),
        aggregate_digest: envelope.digest()?,
        requires_recovery: envelope.needs_recovery(),
    };
    let inspection = TlsControlInspection {
        root,
        writer,
        database,
        writer_fingerprint,
        database_fingerprint,
        _connection: connection,
        snapshot,
    };
    inspection.check_unchanged()?;
    Ok(inspection)
}
