//! Strict DELETE-only offline observation. SQLite never opens the target DB:
//! under its existing writer lock we copy a bounded main file into a private
//! temporary directory, query that copy without create/migration, then remove it.
//! WAL/SHM/journal/unknown entries are refused, not checkpointed or ignored.
use rusqlite::{Connection, OpenFlags};
use rustix::{
    fs::{self, FileType, FlockOperation, Mode, OFlags},
    io::Errno,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
use vp_product_control::{ContentDigest, JournalEvent};

#[path = "inspection_scratch.rs"]
mod scratch;
use scratch::PrivateScratch;

const DB: &str = "control.db";
const LOCK: &str = "control.writer.lock";
const MAX_DB: u64 = 128 * 1024 * 1024;
const MAX_PAYLOAD: i64 = 32 * 1024 * 1024;
const MAX_JOURNAL: u64 = 1_000_000;
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionError {
    InvalidInput,
    PermissionDenied,
    Missing,
    Busy,
    DeadlineExceeded,
    Unsupported,
    RecoveryRequired,
    Integrity,
    LimitExceeded,
    Unavailable,
    CleanupRequired,
}
/// An observation, not a stable control authority identity or monotonic counter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlInspectionReceipt {
    pub sql_layout: u16,
    pub payload_format: u16,
    pub state_version: u64,
    pub active_revision: u64,
    pub payload_digest: String,
    pub journal_digest: String,
    pub database_digest: String,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    size: i64,
    mtime: i64,
    mtime_ns: u64,
    ctime: i64,
    ctime_ns: u64,
}
impl Fingerprint {
    fn of(file: &File) -> Result<Self, InspectionError> {
        let stat = fs::fstat(file).map_err(os_error)?;
        Ok(Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
            size: stat.st_size,
            mtime: stat.st_mtime,
            mtime_ns: stat.st_mtime_nsec as u64,
            ctime: stat.st_ctime,
            ctime_ns: stat.st_ctime_nsec as u64,
        })
    }
}
pub struct ControlInspection {
    root: File,
    _lock: File,
    database: File,
    fingerprint: Fingerprint,
    owner: u32,
    receipt: ControlInspectionReceipt,
    expected_vault_directory: Option<(u64, u64)>,
    _admitted_vault: Option<File>,
}
impl ControlInspection {
    pub fn receipt(&self) -> &ControlInspectionReceipt {
        &self.receipt
    }
    /// Internal composition guard, not a public authority or recovery receipt.
    pub fn expected_vault_directory(&self) -> Option<(u64, u64)> {
        self.expected_vault_directory
    }
    /// Keep this guard alive while inspecting the paired vault. Recheck before
    /// issuing the final combined receipt; no cooperative writer can intervene.
    pub fn recheck(&self, deadline: Instant) -> Result<(), InspectionError> {
        within(deadline)?;
        check_root(&self.root, self.owner)?;
        exact_entries(&self.root, deadline)?;
        let current = private_file(&self.root, DB, self.owner)?;
        if Fingerprint::of(&current)? != self.fingerprint
            || Fingerprint::of(&self.database)? != self.fingerprint
        {
            return Err(InspectionError::Integrity);
        }
        let digest = hash_file(&current, deadline)?;
        if digest != self.receipt.database_digest {
            return Err(InspectionError::Integrity);
        }
        within(deadline)
    }
}

pub fn inspect_control_read_only(
    root: impl AsRef<Path>,
    deadline: Instant,
) -> Result<ControlInspection, InspectionError> {
    inspect_with_temporary(root.as_ref(), deadline, |_| {
        private_temporary().map(Temporary::Default)
    })
}

// Private shared inspection implementation. The default exported entry always
// uses root-owned sticky /tmp; the explicit scratch entry has separate admission.
fn inspect_with_temporary<F>(
    root: &Path,
    deadline: Instant,
    create_temporary: F,
) -> Result<ControlInspection, InspectionError>
where
    F: FnOnce(&File) -> Result<Temporary, InspectionError>,
{
    within(deadline)?;
    let owner = rustix::process::geteuid().as_raw();
    let root = open_root(root, owner, deadline)?;
    // Open only an already-existing regular private lock. No O_CREAT, symlink,
    // blocking flock or fallback that creates a fresh unrelated writer identity.
    let lock = private_file(&root, LOCK, owner)?;
    fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(os_error)?;
    within(deadline)?;
    exact_entries(&root, deadline)?;
    let mut database = private_file(&root, DB, owner)?;
    let fingerprint = Fingerprint::of(&database)?;
    if fingerprint.size < 100 || fingerprint.size as u64 > MAX_DB {
        return Err(InspectionError::LimitExceeded);
    }
    let mut header = [0; 100];
    database
        .read_exact(&mut header)
        .map_err(|_| InspectionError::Integrity)?;
    if &header[..16] != b"SQLite format 3\0" {
        return Err(InspectionError::Integrity);
    }
    // WAL uses read/write version 2. Do not use immutable=1 to ignore its state.
    if header[18] != 1 || header[19] != 1 {
        return Err(InspectionError::Unsupported);
    }
    let raw_page_size = u16::from_be_bytes([header[16], header[17]]);
    let page_size = if raw_page_size == 1 {
        65536
    } else {
        u64::from(raw_page_size)
    };
    if !(512..=65536).contains(&page_size)
        || !page_size.is_power_of_two()
        || fingerprint.size as u64 % page_size != 0
    {
        return Err(InspectionError::Integrity);
    }
    database
        .seek(SeekFrom::Start(0))
        .map_err(|_| InspectionError::Unavailable)?;
    // No public/stable filename, no output of this path, no plaintext secret
    // bytes in the source control DB. This copy is not a recovery backup.
    let mut temporary = create_temporary(&root)?;
    let admitted_vault = temporary.take_vault_guard();
    let expected_vault_directory = temporary.expected_vault_directory();
    let inspected = (|| {
        let copy_path = temporary.copy_path();
        let mut copy = temporary.create_copy()?;
        let mut hash = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0; 8192];
        loop {
            within(deadline)?;
            let count = database
                .read(&mut buffer)
                .map_err(|_| InspectionError::Unavailable)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .filter(|n| *n <= MAX_DB)
                .ok_or(InspectionError::LimitExceeded)?;
            copy.write_all(&buffer[..count])
                .map_err(|_| InspectionError::Unavailable)?;
            hash.update(&buffer[..count]);
        }
        drop(copy);
        if total != fingerprint.size as u64 || Fingerprint::of(&database)? != fingerprint {
            return Err(InspectionError::Integrity);
        }
        exact_entries(&root, deadline)?;
        let current = private_file(&root, DB, owner)?;
        if Fingerprint::of(&current)? != fingerprint {
            return Err(InspectionError::Integrity);
        }
        let database_digest = format!("{:x}", hash.finalize());
        if hash_file(&current, deadline)? != database_digest {
            return Err(InspectionError::Integrity);
        }
        temporary.validate_copy(total, &database_digest, deadline)?;
        let result = inspect_copy(&copy_path, database_digest.clone(), deadline);
        temporary.validate_copy(total, &database_digest, deadline)?;
        result
    })();
    // Report cleanup failure even when another validation failed. Drop alone
    // would silently swallow it and leave sensitive metadata behind.
    let cleanup = temporary.close();
    if cleanup.is_err() {
        return Err(InspectionError::CleanupRequired);
    }
    let receipt = inspected?;
    let observation = ControlInspection {
        root,
        _lock: lock,
        database,
        fingerprint,
        owner,
        receipt,
        expected_vault_directory,
        _admitted_vault: admitted_vault,
    };
    observation.recheck(deadline)?;
    Ok(observation)
}

/// Explicit private-scratch profile. Default inspection policy is unchanged.
/// Cooperative same-UID/root trust: identity checks detect changes but do not
/// claim safety against hostile same-UID rename-and-restore races.
pub fn inspect_control_read_only_in_scratch(
    root: impl AsRef<Path>,
    vault: impl AsRef<Path>,
    scratch: impl AsRef<Path>,
    deadline: Instant,
) -> Result<ControlInspection, InspectionError> {
    let root = root.as_ref();
    inspect_with_temporary(root, deadline, |retained_state| {
        PrivateScratch::new(
            scratch.as_ref(),
            root,
            vault.as_ref(),
            retained_state,
            deadline,
        )
        .map(Temporary::Scratch)
    })
}

enum Temporary {
    Default(tempfile::TempDir),
    Scratch(PrivateScratch),
}
impl Temporary {
    fn take_vault_guard(&mut self) -> Option<File> {
        match self {
            Self::Default(_) => None,
            Self::Scratch(t) => t.take_vault_guard(),
        }
    }
    fn expected_vault_directory(&self) -> Option<(u64, u64)> {
        match self {
            Self::Default(_) => None,
            Self::Scratch(t) => Some(t.expected_vault_directory()),
        }
    }
    fn copy_path(&self) -> PathBuf {
        match self {
            Self::Default(t) => t.path().join("snapshot.db"),
            Self::Scratch(t) => t.copy_path(),
        }
    }
    fn create_copy(&self) -> Result<File, InspectionError> {
        match self {
            Self::Scratch(t) => t.create_copy(),
            Self::Default(_) => {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(self.copy_path())
                    .map_err(|_| InspectionError::Unavailable)
            }
        }
    }
    fn validate_copy(
        &self,
        size: u64,
        digest: &str,
        deadline: Instant,
    ) -> Result<(), InspectionError> {
        match self {
            Self::Default(_) => Ok(()),
            Self::Scratch(t) => t.validate_copy(size, digest, deadline),
        }
    }
    fn close(self) -> Result<(), InspectionError> {
        match self {
            Self::Default(t) => t.close().map_err(|_| InspectionError::CleanupRequired),
            Self::Scratch(t) => t.close(),
        }
    }
}

fn inspect_copy(
    path: &Path,
    database_digest: String,
    deadline: Instant,
) -> Result<ControlInspectionReceipt, InspectionError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| InspectionError::Unavailable)?;
    connection
        .busy_timeout(Duration::ZERO)
        .map_err(|_| InspectionError::Unavailable)?;
    let result = (|| {
        within(deadline)?;
        let layout: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| InspectionError::Integrity)?;
        if layout != 1 {
            return Err(InspectionError::Unsupported);
        }
        let check: String = connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(|_| InspectionError::Integrity)?;
        if check != "ok" {
            return Err(InspectionError::Integrity);
        }
        let mut schema_query = connection.prepare("SELECT type,name FROM sqlite_master WHERE substr(name,1,7) != 'sqlite_' ORDER BY type,name")
            .map_err(|_| InspectionError::Integrity)?;
        let objects: Vec<(String, String)> = schema_query
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|_| InspectionError::Integrity)?
            .collect::<Result<_, _>>()
            .map_err(|_| InspectionError::Integrity)?;
        if objects
            != [
                ("table".into(), "control_state".into()),
                ("table".into(), "operation_journal".into()),
            ]
        {
            return Err(InspectionError::Unsupported);
        }
        drop(schema_query);
        // Query lengths before materializing any BLOB from an untrusted file.
        let (rows, bad): (i64, i64) = connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN singleton != 1 OR length(payload) > 33554432 OR length(digest) != 64 THEN 1 ELSE 0 END),0) FROM control_state", [],
            |row| Ok((row.get(0)?, row.get(1)?))).map_err(|_| InspectionError::Integrity)?;
        if rows != 1 || bad != 0 {
            return Err(InspectionError::Integrity);
        }
        let (version, payload, digest): (i64, Vec<u8>, String) = connection.query_row(
            "SELECT version,payload,digest FROM control_state WHERE singleton=1 AND length(payload)<=?1",
            [MAX_PAYLOAD], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|_| InspectionError::Integrity)?;
        let version = u64::try_from(version).map_err(|_| InspectionError::Integrity)?;
        if ContentDigest::bytes(&payload).as_str() != digest {
            return Err(InspectionError::Integrity);
        }
        let state = crate::migration::decode_current(&payload, version)
            .map_err(|_| InspectionError::Unsupported)?;
        if state.needs_recovery() {
            return Err(InspectionError::RecoveryRequired);
        }
        let (journal_rows, bad): (i64, i64) = connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN length(payload)>16384 OR length(digest)!=64 THEN 1 ELSE 0 END),0) FROM operation_journal", [],
            |row| Ok((row.get(0)?, row.get(1)?))).map_err(|_| InspectionError::Integrity)?;
        if journal_rows >= 0 && journal_rows as u64 > MAX_JOURNAL {
            return Err(InspectionError::LimitExceeded);
        }
        if journal_rows < 0 || journal_rows as u64 != version || bad != 0 {
            return Err(InspectionError::Integrity);
        }
        let mut statement = connection
            .prepare("SELECT sequence,payload,digest FROM operation_journal ORDER BY sequence")
            .map_err(|_| InspectionError::Integrity)?;
        let mut rows = statement
            .query([])
            .map_err(|_| InspectionError::Integrity)?;
        let mut sequence = 0u64;
        let mut journal = Sha256::new();
        journal.update(b"vp.control.journal-observation.v1\0");
        while let Some(row) = rows.next().map_err(|_| InspectionError::Integrity)? {
            within(deadline)?;
            sequence += 1;
            let actual: i64 = row.get(0).map_err(|_| InspectionError::Integrity)?;
            let payload: Vec<u8> = row.get(1).map_err(|_| InspectionError::Integrity)?;
            let digest: String = row.get(2).map_err(|_| InspectionError::Integrity)?;
            if u64::try_from(actual).ok() != Some(sequence)
                || ContentDigest::bytes(&payload).as_str() != digest
            {
                return Err(InspectionError::Integrity);
            }
            let event: JournalEvent =
                serde_json::from_slice(&payload).map_err(|_| InspectionError::Integrity)?;
            if event.sequence != sequence {
                return Err(InspectionError::Integrity);
            }
            journal.update(sequence.to_be_bytes());
            journal.update((payload.len() as u64).to_be_bytes());
            journal.update(Sha256::digest(&payload));
        }
        if sequence != version {
            return Err(InspectionError::Integrity);
        }
        within(deadline)?;
        Ok(ControlInspectionReceipt {
            sql_layout: 1,
            payload_format: state.schema_version,
            state_version: version,
            active_revision: state.active_revision.get(),
            payload_digest: digest,
            journal_digest: format!("{:x}", journal.finalize()),
            database_digest,
        })
    })();
    if connection.close().is_err() {
        return Err(InspectionError::CleanupRequired);
    }
    result
}

fn trusted_temporary_root(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o7777 == 0o1777
}

fn private_temporary() -> Result<tempfile::TempDir, InspectionError> {
    // Do not honor TMPDIR: it could point inside the target state/vault root and
    // turn an otherwise read-only inspection into target writes. A fixed trusted
    // root-owned sticky /tmp cannot itself be an accepted 0700 target root.
    let temporary_root = fs::open("/tmp", DIR_FLAGS, Mode::empty()).map_err(os_error)?;
    let stat = fs::fstat(&temporary_root).map_err(os_error)?;
    if !trusted_temporary_root(stat.st_uid, stat.st_mode) {
        return Err(InspectionError::Unavailable);
    }
    tempfile::Builder::new()
        .prefix("vp-private-inspect-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .map_err(|_| InspectionError::Unavailable)
}
#[cfg(test)]
fn finish_temporary<T>(
    result: Result<T, InspectionError>,
    cleanup: std::io::Result<()>,
) -> Result<T, InspectionError> {
    cleanup.map_err(|_| InspectionError::CleanupRequired)?;
    result
}

fn hash_file(file: &File, deadline: Instant) -> Result<String, InspectionError> {
    let mut file = file.try_clone().map_err(|_| InspectionError::Unavailable)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| InspectionError::Unavailable)?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut bytes = [0; 8192];
    loop {
        within(deadline)?;
        let count = file
            .read(&mut bytes)
            .map_err(|_| InspectionError::Unavailable)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > MAX_DB {
            return Err(InspectionError::LimitExceeded);
        }
        hash.update(&bytes[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn open_root(path: &Path, owner: u32, deadline: Instant) -> Result<File, InspectionError> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .any(|part| part == b"." || part == b"..")
    {
        return Err(InspectionError::InvalidInput);
    }
    let mut descriptor = fs::open("/", DIR_FLAGS, Mode::empty()).map_err(os_error)?;
    let components: Vec<_> = path.components().collect();
    if components.len() < 2 {
        return Err(InspectionError::PermissionDenied);
    }
    for (index, component) in components.iter().enumerate().skip(1) {
        within(deadline)?;
        let stat = fs::fstat(&descriptor).map_err(os_error)?;
        let trusted_sticky = stat.st_uid == 0 && stat.st_mode & 0o1000 != 0;
        if (stat.st_uid != 0 && stat.st_uid != owner)
            || (stat.st_mode & 0o022 != 0 && !trusted_sticky)
        {
            return Err(InspectionError::PermissionDenied);
        }
        let Component::Normal(name) = component else {
            return Err(InspectionError::InvalidInput);
        };
        let flags = DIR_FLAGS
            | if index + 1 == components.len() {
                OFlags::NOATIME
            } else {
                OFlags::empty()
            };
        descriptor = fs::openat(&descriptor, *name, flags, Mode::empty()).map_err(os_error)?;
    }
    let root = File::from(descriptor);
    check_root(&root, owner)?;
    Ok(root)
}
fn check_root(root: &File, owner: u32) -> Result<(), InspectionError> {
    let stat = fs::fstat(root).map_err(os_error)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o700
        || stat.st_nlink == 0
    {
        return Err(InspectionError::PermissionDenied);
    }
    Ok(())
}
fn private_file(root: &File, name: &str, owner: u32) -> Result<File, InspectionError> {
    let descriptor = fs::openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOATIME,
        Mode::empty(),
    )
    .map_err(os_error)?;
    let stat = fs::fstat(&descriptor).map_err(os_error)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(InspectionError::PermissionDenied);
    }
    Ok(File::from(descriptor))
}
fn exact_entries(root: &File, deadline: Instant) -> Result<(), InspectionError> {
    let directory = fs::Dir::read_from(root).map_err(os_error)?;
    let mut count = 0;
    for entry in directory {
        within(deadline)?;
        let entry = entry.map_err(os_error)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if [
            b"control.db-wal".as_slice(),
            b"control.db-shm",
            b"control.db-journal",
        ]
        .contains(&name)
        {
            return Err(InspectionError::Unsupported);
        }
        if name != DB.as_bytes() && name != LOCK.as_bytes() {
            return Err(InspectionError::RecoveryRequired);
        }
        count += 1;
        if count > 2 {
            return Err(InspectionError::Integrity);
        }
    }
    if count != 2 {
        return Err(InspectionError::Missing);
    }
    Ok(())
}
fn within(deadline: Instant) -> Result<(), InspectionError> {
    if Instant::now() >= deadline {
        Err(InspectionError::DeadlineExceeded)
    } else {
        Ok(())
    }
}
fn os_error(error: Errno) -> InspectionError {
    match error {
        Errno::NOENT => InspectionError::Missing,
        Errno::WOULDBLOCK => InspectionError::Busy,
        Errno::LOOP | Errno::NOTDIR | Errno::ACCESS | Errno::PERM => {
            InspectionError::PermissionDenied
        }
        _ => InspectionError::Unavailable,
    }
}
#[cfg(test)]
#[path = "inspection_tests.rs"]
mod tests;
