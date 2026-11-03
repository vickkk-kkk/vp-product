use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use vp_product_control::{ContentDigest, ControlError};
use vp_product_domain::{OperationId, Revision};

const LIMIT: u64 = 8 * 1024 * 1024;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RuntimeRecord {
    pub operation: OperationId,
    pub revision: Revision,
    pub config_digest: ContentDigest,
    pub release_digest: ContentDigest,
    pub recipe_digest: ContentDigest,
    pub generation: u64,
    pub process: Option<ProcessIdentity>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ProcessIdentity {
    pid: u32,
    start_ticks: String,
    boot_id: String,
}
impl ProcessIdentity {
    pub fn read(pid: u32) -> Result<Self, ControlError> {
        if !cfg!(target_os = "linux") {
            return Err(ControlError::ExecutorUnavailable);
        }
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| ControlError::RecoveryRequired)?;
        // comm may contain whitespace and ')' characters; field3 starts after
        // the last ')' and starttime is field22, i.e. index19 of that suffix.
        let start_ticks = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(19))
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or(ControlError::RecoveryRequired)?
            .to_owned();
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|_| ControlError::RecoveryRequired)?
            .trim()
            .to_owned();
        Ok(Self {
            pid,
            start_ticks,
            boot_id,
        })
    }
    /// Translate a live /proc observation into the V2 journal representation.
    /// A PID observation alone is never authority to adopt or signal a process.
    #[cfg(feature = "server-v2-journal")]
    pub(crate) fn as_server_v2(&self) -> crate::server_v2_journal::ProcessIdentity {
        crate::server_v2_journal::ProcessIdentity {
            pid: self.pid, start_ticks: self.start_ticks.clone(), boot_id: self.boot_id.clone(),
        }
    }
    pub fn is_present(&self) -> Result<bool, ControlError> {
        match fs::metadata(format!("/proc/{}", self.pid)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(ControlError::RecoveryRequired),
            Ok(_) => Ok(Self::read(self.pid)? == *self),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Staged,
    Candidate,
    Stopped,
    Restored,
    Discarded,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Stage {
    pub plan_hash: ContentDigest,
    pub candidate: RuntimeRecord,
    pub previous: Option<RuntimeRecord>,
    pub phase: Phase,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Journal {
    pub schema_version: u16,
    pub release_digest: ContentDigest,
    pub worker_digest: ContentDigest,
    pub high_water: u64,
    pub active: Option<RuntimeRecord>,
    /// Durable intent, written BEFORE launching. A missing process identity after
    /// restart is uncertain; never guess a PID or kill a process based on a port.
    pub launching: Option<RuntimeRecord>,
    pub stages: BTreeMap<OperationId, Stage>,
}
pub(crate) struct Durable {
    backend: DurableBackend,
}
enum DurableBackend {
    Legacy {
        root: PathBuf,
        _lease: File,
    },
    #[cfg(target_os = "linux")]
    Bound {
        root: vp_product_storage::BoundDirectory,
        genesis: ContentDigest,
        release: ContentDigest,
        worker: ContentDigest,
    },
}
fn private_dir(path: &Path) -> Result<(), ControlError> {
    let meta = fs::symlink_metadata(path).map_err(|_| ControlError::StorageUnavailable)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(ControlError::PermissionDenied);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o777 != 0o700 {
            return Err(ControlError::PermissionDenied);
        }
    }
    #[cfg(not(unix))]
    {
        return Err(ControlError::ExecutorUnavailable);
    }
    Ok(())
}
fn file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}
fn check_file(path: &Path) -> Result<(), ControlError> {
    let meta = fs::symlink_metadata(path).map_err(|_| ControlError::StorageUnavailable)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > LIMIT {
        return Err(ControlError::CorruptState);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o777 != 0o600 || meta.nlink() != 1 {
            return Err(ControlError::PermissionDenied);
        }
    }
    Ok(())
}
impl Durable {
    pub fn open(
        root: &Path,
        release_digest: ContentDigest,
        worker_digest: ContentDigest,
    ) -> Result<(Self, Journal), ControlError> {
        if !root.is_absolute() {
            return Err(ControlError::PermissionDenied);
        }
        private_dir(root)?;
        // Current legacy code rejects bound profiles before creating its file
        // lock. Historical versions are stopped by the unsupported sentinel,
        // but can create their old lock before decoding it.
        for marker in [
            "journal",
            "artifacts",
            "fresh-runtime.v1",
            "runtime.profile.pending",
        ] {
            match fs::symlink_metadata(root.join(marker)) {
                Ok(_) => return Err(ControlError::RecoveryRequired),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err(ControlError::StorageUnavailable),
            }
        }
        // Reject an already present unsupported/partial profile before making
        // the legacy lock. The authoritative journal is still reread under its
        // existing writer lock below; this preflight is not a substitute lock.
        let preflight = root.join("runtime.journal.json");
        match fs::symlink_metadata(&preflight) {
            Ok(_) => {
                check_file(&preflight)?;
                let mut bytes = Vec::new();
                File::open(&preflight)
                    .map_err(|_| ControlError::StorageUnavailable)?
                    .take(LIMIT + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| ControlError::StorageUnavailable)?;
                if bytes.len() as u64 > LIMIT {
                    return Err(ControlError::CorruptState);
                }
                let value: Envelope =
                    serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
                if value.journal.schema_version != 1
                    || value.digest != ContentDigest::of("vp.runtime-journal.v1", &value.journal)?
                {
                    return Err(ControlError::CorruptState);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(ControlError::StorageUnavailable),
        }
        let lock_path = root.join("runtime.writer.lock");
        match fs::symlink_metadata(&lock_path) {
            Ok(_) => check_file(&lock_path)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                file_options()
                    .create_new(true)
                    .open(&lock_path)
                    .map_err(|_| ControlError::StorageUnavailable)?
                    .sync_all()
                    .map_err(|_| ControlError::StorageUnavailable)?;
                File::open(root)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| ControlError::StorageUnavailable)?;
            }
            Err(_) => return Err(ControlError::StorageUnavailable),
        }
        let lease = file_options()
            .open(&lock_path)
            .map_err(|_| ControlError::StorageUnavailable)?;
        lease
            .try_lock_exclusive()
            .map_err(|_| ControlError::RecoveryRequired)?;
        let this = Self {
            backend: DurableBackend::Legacy {
                root: root.to_owned(),
                _lease: lease,
            },
        };
        let path = root.join("runtime.journal.json");
        let journal = match fs::symlink_metadata(&path) {
            Ok(_) => {
                check_file(&path)?;
                let mut bytes = Vec::new();
                File::open(&path)
                    .map_err(|_| ControlError::StorageUnavailable)?
                    .take(LIMIT + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| ControlError::StorageUnavailable)?;
                if bytes.len() as u64 > LIMIT {
                    return Err(ControlError::CorruptState);
                }
                let envelope: Envelope =
                    serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
                if ContentDigest::of("vp.runtime-journal.v1", &envelope.journal)? != envelope.digest
                {
                    return Err(ControlError::CorruptState);
                }
                envelope.journal
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Journal {
                schema_version: 1,
                release_digest: release_digest.clone(),
                worker_digest: worker_digest.clone(),
                high_water: 0,
                active: None,
                launching: None,
                stages: BTreeMap::new(),
            },
            Err(_) => return Err(ControlError::StorageUnavailable),
        };
        if journal.schema_version != 1
            || journal.release_digest != release_digest
            || journal.worker_digest != worker_digest
        {
            return Err(ControlError::CorruptState);
        }
        this.save(&journal)?;
        Ok((this, journal))
    }
    pub fn save(&self, journal: &Journal) -> Result<(), ControlError> {
        let root = match &self.backend {
            DurableBackend::Legacy { root, .. } => root,
            #[cfg(target_os = "linux")]
            DurableBackend::Bound {
                root,
                genesis,
                release,
                worker,
            } => {
                if &journal.release_digest != release || &journal.worker_digest != worker {
                    return Err(ControlError::CorruptState);
                }
                return Self::save_bound(root, genesis, journal, true);
            }
        };
        private_dir(root)?;
        let bytes = serde_json::to_vec(&Envelope {
            digest: ContentDigest::of("vp.runtime-journal.v1", journal)?,
            journal: journal.clone(),
        })
        .map_err(|_| ControlError::CorruptState)?;
        if bytes.len() as u64 > LIMIT {
            return Err(ControlError::StorageUnavailable);
        }
        let pending = root.join("runtime.journal.pending");
        match fs::symlink_metadata(&pending) {
            Ok(_) => {
                check_file(&pending)?;
                fs::remove_file(&pending).map_err(|_| ControlError::StorageUnavailable)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(ControlError::StorageUnavailable),
        }
        let mut file = file_options()
            .create_new(true)
            .open(&pending)
            .map_err(|_| ControlError::StorageUnavailable)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| ControlError::StorageUnavailable)?;
        let destination = root.join("runtime.journal.json");
        if destination.exists() {
            check_file(&destination)?;
        }
        fs::rename(&pending, &destination).map_err(|_| ControlError::StorageUnavailable)?;
        File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(|_| ControlError::StorageUnavailable)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Envelope {
    digest: ContentDigest,
    journal: Journal,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    fn private() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    #[test]
    fn atomic_journal_checksum_and_exact_release_worker_identity() {
        let root = private();
        let release = ContentDigest::bytes(b"release");
        let worker = ContentDigest::bytes(b"worker");
        let (store, mut journal) =
            Durable::open(root.path(), release.clone(), worker.clone()).unwrap();
        journal.high_water = 41;
        store.save(&journal).unwrap();
        drop(store);
        let (store, restored) =
            Durable::open(root.path(), release.clone(), worker.clone()).unwrap();
        assert_eq!(restored.high_water, 41);
        drop(store);
        assert!(matches!(
            Durable::open(
                root.path(),
                release.clone(),
                ContentDigest::bytes(b"different-worker")
            ),
            Err(ControlError::CorruptState)
        ));
        assert!(matches!(
            Durable::open(
                root.path(),
                ContentDigest::bytes(b"different-release"),
                worker.clone()
            ),
            Err(ControlError::CorruptState)
        ));
        let path = root.path().join("runtime.journal.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["journal"]["highWater"] = 1.into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            Durable::open(root.path(), release, worker),
            Err(ControlError::CorruptState)
        ));
    }
    #[test]
    fn locks_modes_and_symlink_pending_never_silently_overwrite() {
        let root = private();
        let release = ContentDigest::bytes(b"r");
        let worker = ContentDigest::bytes(b"w");
        let (store, journal) = Durable::open(root.path(), release.clone(), worker.clone()).unwrap();
        assert!(matches!(
            Durable::open(root.path(), release, worker),
            Err(ControlError::RecoveryRequired)
        ));
        let untouched = root.path().join("untouched");
        fs::write(&untouched, b"keep").unwrap();
        std::os::unix::fs::symlink(&untouched, root.path().join("runtime.journal.pending"))
            .unwrap();
        assert!(store.save(&journal).is_err());
        assert_eq!(fs::read(untouched).unwrap(), b"keep");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(root.path().join("runtime.journal.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn process_identity_uses_birth_and_boot_not_pid_alone() {
        let current = ProcessIdentity::read(std::process::id()).unwrap();
        assert!(current.is_present().unwrap());
        let mut stale = current.clone();
        stale.start_ticks = "0".into();
        assert!(!stale.is_present().unwrap());
        let mut stale_boot = current;
        stale_boot.boot_id = "another-boot".into();
        assert!(!stale_boot.is_present().unwrap());
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BoundEnvelope {
    schema_version: u16,
    genesis: ContentDigest,
    digest: ContentDigest,
    journal: Journal,
}
#[cfg(target_os = "linux")]
impl Durable {
    pub fn open_bound(
        root: vp_product_storage::BoundDirectory,
        genesis: ContentDigest,
        mode: vp_product_storage::BoundOpenMode,
        release_digest: ContentDigest,
        worker_digest: ContentDigest,
    ) -> Result<(Self, Journal), ControlError> {
        use vp_product_storage::BoundOpenMode;
        let root = root.lock()?;
        let journal = match mode {
            BoundOpenMode::CreateFresh => {
                root.require_empty()?;
                let journal = Journal {
                    schema_version: 2,
                    release_digest: release_digest.clone(),
                    worker_digest: worker_digest.clone(),
                    high_water: 0,
                    active: None,
                    launching: None,
                    stages: BTreeMap::new(),
                };
                Self::save_bound(&root, &genesis, &journal, false)?;
                journal
            }
            BoundOpenMode::OpenExisting => {
                if root.names()? != ["runtime.journal.json"] {
                    return Err(ControlError::RecoveryRequired);
                }
                let value: BoundEnvelope =
                    serde_json::from_slice(&root.read("runtime.journal.json", LIMIT as usize)?)
                        .map_err(|_| ControlError::CorruptState)?;
                if value.schema_version != 2
                    || value.genesis != genesis
                    || value.digest
                        != ContentDigest::of(
                            "vp.bound-runtime-journal.v2",
                            &(&value.genesis, &value.journal),
                        )?
                {
                    return Err(ControlError::CorruptState);
                }
                value.journal
            }
        };
        if journal.schema_version != 2
            || journal.release_digest != release_digest
            || journal.worker_digest != worker_digest
        {
            return Err(ControlError::CorruptState);
        }
        Ok((
            Self {
                backend: DurableBackend::Bound {
                    root,
                    genesis,
                    release: release_digest,
                    worker: worker_digest,
                },
            },
            journal,
        ))
    }
    fn save_bound(
        root: &vp_product_storage::BoundDirectory,
        genesis: &ContentDigest,
        journal: &Journal,
        replace: bool,
    ) -> Result<(), ControlError> {
        if journal.schema_version != 2 {
            return Err(ControlError::CorruptState);
        }
        let expected: &[&str] = if replace {
            &["runtime.journal.json"]
        } else {
            &[]
        };
        if root.names()? != expected {
            return Err(ControlError::RecoveryRequired);
        }
        let bytes = serde_json::to_vec(&BoundEnvelope {
            schema_version: 2,
            genesis: genesis.clone(),
            digest: ContentDigest::of("vp.bound-runtime-journal.v2", &(genesis, journal))?,
            journal: journal.clone(),
        })
        .map_err(|_| ControlError::CorruptState)?;
        root.atomic_file(
            "runtime.journal.json",
            "runtime.journal.pending",
            &bytes,
            LIMIT as usize,
            replace,
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod bound_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use vp_product_storage::{BoundDirectory, BoundOpenMode, DirectoryIdentity};
    fn setup() -> (tempfile::TempDir, PathBuf) {
        let parent = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = parent.path().join("journal");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        (parent, path)
    }
    fn dir(path: &Path) -> BoundDirectory {
        BoundDirectory::open(
            path,
            DirectoryIdentity::of(&File::open(path).unwrap()).unwrap(),
        )
        .unwrap()
    }
    fn open(
        path: &Path,
        mode: BoundOpenMode,
        g: &ContentDigest,
    ) -> Result<(Durable, Journal), ControlError> {
        Durable::open_bound(
            dir(path),
            g.clone(),
            mode,
            ContentDigest::bytes(b"r"),
            ContentDigest::bytes(b"w"),
        )
    }
    #[test]
    fn bound_journal_pairing_and_retained_inode() {
        let (parent, path) = setup();
        let moved = parent.path().join("retained");
        let g = ContentDigest::bytes(b"genesis");
        let (store, mut journal) = open(&path, BoundOpenMode::CreateFresh, &g).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        journal.high_water = 18;
        store.save(&journal).unwrap();
        assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
        drop(store);
        let (store, journal) = open(&moved, BoundOpenMode::OpenExisting, &g).unwrap();
        assert_eq!(journal.high_water, 18);
        drop(store);
        assert!(open(
            &moved,
            BoundOpenMode::OpenExisting,
            &ContentDigest::bytes(b"wrong")
        )
        .is_err());
        assert!(open(&moved, BoundOpenMode::CreateFresh, &g).is_err());
    }
    #[test]
    fn bound_journal_rejects_release_mutation_and_staging_without_cleanup() {
        let (_p, path) = setup();
        let g = ContentDigest::bytes(b"g");
        let (store, mut journal) = open(&path, BoundOpenMode::CreateFresh, &g).unwrap();
        let original = fs::read(path.join("runtime.journal.json")).unwrap();
        journal.release_digest = ContentDigest::bytes(b"changed");
        assert!(store.save(&journal).is_err());
        assert_eq!(
            fs::read(path.join("runtime.journal.json")).unwrap(),
            original
        );
        journal.release_digest = ContentDigest::bytes(b"r");
        fs::write(path.join("runtime.journal.pending"), b"keep").unwrap();
        assert!(store.save(&journal).is_err());
        drop(store);
        assert!(open(&path, BoundOpenMode::OpenExisting, &g).is_err());
        assert_eq!(
            fs::read(path.join("runtime.journal.pending")).unwrap(),
            b"keep"
        );
    }
    #[test]
    fn bound_journal_does_not_create_missing_state_on_paired_open() {
        let (_p, path) = setup();
        let g = ContentDigest::bytes(b"g");
        assert!(open(&path, BoundOpenMode::OpenExisting, &g).is_err());
        assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
    }
    #[test]
    fn bound_root_marker_cannot_be_decoded_as_legacy_journal() {
        let marker = crate::BoundRuntimeMarker {
            schema_version: 2,
            profile: "vp.bound-runtime.v2".into(),
            genesis: ContentDigest::bytes(b"g"),
            release_digest: ContentDigest::bytes(b"r"),
            worker_digest: ContentDigest::bytes(b"w"),
        };
        let bytes = serde_json::to_vec(&marker).unwrap();
        assert!(serde_json::from_slice::<Envelope>(&bytes).is_err());
    }
    #[test]
    fn current_legacy_open_refuses_partial_sentinel_or_pending_before_lock() {
        let (_p, path) = setup();
        let marker = crate::BoundRuntimeMarker {
            schema_version: 2,
            profile: "vp.bound-runtime.v2".into(),
            genesis: ContentDigest::bytes(b"g"),
            release_digest: ContentDigest::bytes(b"r"),
            worker_digest: ContentDigest::bytes(b"w"),
        };
        dir(&path)
            .publish(
                "runtime.journal.json",
                &serde_json::to_vec(&marker).unwrap(),
            )
            .unwrap();
        assert!(Durable::open(
            &path,
            ContentDigest::bytes(b"r"),
            ContentDigest::bytes(b"w")
        )
        .is_err());
        assert!(!path.join("runtime.writer.lock").exists());
        let (_p2, path2) = setup();
        dir(&path2)
            .publish("runtime.profile.pending", b"interrupted")
            .unwrap();
        assert!(Durable::open(
            &path2,
            ContentDigest::bytes(b"r"),
            ContentDigest::bytes(b"w")
        )
        .is_err());
        assert!(!path2.join("runtime.writer.lock").exists());
    }
}
