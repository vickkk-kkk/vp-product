//! Linux directory capabilities for the separate fresh startup profile.
//! Never changes permissions or follows a replaced pathname after admission.
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
    sync::atomic::{AtomicBool, Ordering},
};
use vp_product_control::ControlError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}
impl DirectoryIdentity {
    pub fn of(file: &File) -> Result<Self, ControlError> {
        let s = fs::fstat(file).map_err(failure)?;
        Ok(Self {
            device: s.st_dev,
            inode: s.st_ino,
        })
    }
}
const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
fn failure(_: rustix::io::Errno) -> ControlError {
    ControlError::StorageUnavailable
}
pub struct BoundDirectory {
    root: File,
    ancestry: Vec<DirectoryIdentity>,
    owner: u32,
    #[cfg(test)]
    sync_failure_countdown: std::sync::atomic::AtomicUsize,
}
/// Retained read-only observation of one private file, not a writable authority.
/// No descriptor, clone, mutation or generic repair interface is exposed.
/// Revalidation is under the same admitted directory capability, not its pathname.
pub struct ReadOnlyBoundFile {
    file: File,
    fingerprint: ReadOnlyFingerprint,
    root: DirectoryIdentity,
    name: String,
    maximum: usize,
    bytes: Vec<u8>,
}
#[derive(Clone, Eq, PartialEq)]
struct ReadOnlyFingerprint {
    identity: DirectoryIdentity,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
    owner: u32,
    links: u64,
}
impl ReadOnlyFingerprint {
    fn read(file: &File) -> Result<Self, ControlError> {
        use std::os::unix::fs::MetadataExt;
        let m = file
            .metadata()
            .map_err(|_| ControlError::StorageUnavailable)?;
        Ok(Self {
            identity: DirectoryIdentity::of(file)?,
            length: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
            mode: m.mode(),
            owner: m.uid(),
            links: m.nlink(),
        })
    }
}
impl ReadOnlyBoundFile {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Checks retained identity and the still-named file without a writable open.
    /// A cooperating same-UID owner/retained directory lease remains required;
    /// this is not a hostile-root or adversarial rollback guarantee.
    pub fn revalidate(&self, directory: &BoundDirectory) -> Result<(), ControlError> {
        directory.check()?;
        if directory.identity()? != self.root {
            return Err(ControlError::ResourceConflict);
        }
        directory.check_file(&self.file)?;
        if ReadOnlyFingerprint::read(&self.file)? != self.fingerprint
            || self.fingerprint.length > self.maximum as u64
            || self.bytes.len() as u64 != self.fingerprint.length
        {
            return Err(ControlError::ResourceConflict);
        }
        let named = directory.open_file_read_only(&self.name)?;
        if ReadOnlyFingerprint::read(&named)? != self.fingerprint {
            return Err(ControlError::ResourceConflict);
        }
        Ok(())
    }
}
impl BoundDirectory {
    pub fn open(path: &Path, expected: DirectoryIdentity) -> Result<Self, ControlError> {
        Self::admit(path, expected)?.lock()
    }
    pub fn admit(path: &Path, expected: DirectoryIdentity) -> Result<Self, ControlError> {
        use std::os::unix::ffi::OsStrExt;
        if !path.is_absolute()
            || path.as_os_str().len() > 4096
            || path
                .as_os_str()
                .as_bytes()
                .split(|b| *b == b'/')
                .any(|v| v == b"." || v == b"..")
        {
            return Err(ControlError::InvalidRequest);
        }
        let owner = rustix::process::geteuid().as_raw();
        let mut fd = fs::open("/", DIR, Mode::empty()).map_err(failure)?;
        let mut ancestry = Vec::new();
        for part in path.components().skip(1) {
            let stat = fs::fstat(&fd).map_err(failure)?;
            let trusted_sticky = stat.st_uid == 0 && stat.st_mode & 0o1000 != 0;
            if (stat.st_uid != 0 && stat.st_uid != owner)
                || (stat.st_mode & 0o022 != 0 && !trusted_sticky)
            {
                return Err(ControlError::PermissionDenied);
            }
            ancestry.push(DirectoryIdentity {
                device: stat.st_dev,
                inode: stat.st_ino,
            });
            let Component::Normal(name) = part else {
                return Err(ControlError::InvalidRequest);
            };
            fd = fs::openat(&fd, name, DIR, Mode::empty()).map_err(failure)?;
        }
        let root = File::from(fd);
        let value = Self {
            root,
            ancestry,
            owner,
            #[cfg(test)]
            sync_failure_countdown: std::sync::atomic::AtomicUsize::new(0),
        };
        value.check()?;
        if value.identity()? != expected {
            return Err(ControlError::PermissionDenied);
        }
        Ok(value)
    }
    pub fn lock(self) -> Result<Self, ControlError> {
        self.check()?;
        fs::flock(&self.root, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| ControlError::RecoveryRequired)?;
        Ok(self)
    }
    /// Retain bounded bytes and the original RDONLY descriptor. This operation
    /// creates no files and does not request a writable descriptor. Filesystem
    /// read-atime behavior is not changed or represented as a no-write guarantee.
    pub fn inspect_file_read_only(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<ReadOnlyBoundFile, ControlError> {
        if maximum == 0 || maximum > 64 * 1024 * 1024 {
            return Err(ControlError::InvalidRequest);
        }
        let file = self.open_file_read_only(name)?;
        let before = ReadOnlyFingerprint::read(&file)?;
        if before.length > maximum as u64 {
            return Err(ControlError::CorruptState);
        }
        let mut bytes = Vec::with_capacity(before.length as usize);
        (&file)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ControlError::StorageUnavailable)?;
        self.check_file(&file)?;
        if bytes.len() > maximum
            || bytes.len() as u64 != before.length
            || ReadOnlyFingerprint::read(&file)? != before
        {
            return Err(ControlError::ResourceConflict);
        }
        let value = ReadOnlyBoundFile {
            file,
            fingerprint: before,
            root: self.identity()?,
            name: name.to_owned(),
            maximum,
            bytes,
        };
        value.revalidate(self)?;
        Ok(value)
    }
    /// Revalidate the named linkage of a retained child without relocking it.
    /// This rejects replacement but never reacquires a child lease or follows a
    /// replaced absolute pathname. Rename of the root itself preserves authority.
    pub fn revalidate_child(&self, name: &str, child: &Self) -> Result<(), ControlError> {
        Self::name(name)?;
        self.check()?;
        child.check()?;
        let named = File::from(fs::openat(&self.root, name, DIR, Mode::empty()).map_err(failure)?);
        if DirectoryIdentity::of(&named)? != child.identity()? {
            return Err(ControlError::ResourceConflict);
        }
        let mount = |file: &File| -> Result<u64, ControlError> {
            let stat = fs::statx(
                file,
                "",
                fs::AtFlags::EMPTY_PATH | fs::AtFlags::SYMLINK_NOFOLLOW,
                fs::StatxFlags::MNT_ID,
            )
            .map_err(failure)?;
            if stat.stx_mask & fs::StatxFlags::MNT_ID.bits() == 0 || stat.stx_mnt_id == 0 {
                return Err(ControlError::ExecutorUnavailable);
            }
            Ok(stat.stx_mnt_id)
        };
        if mount(&named)? != mount(&child.root)? || mount(&named)? != mount(&self.root)? {
            return Err(ControlError::ResourceConflict);
        }
        Ok(())
    }
    pub fn identity(&self) -> Result<DirectoryIdentity, ControlError> {
        DirectoryIdentity::of(&self.root)
    }
    pub fn disjoint(&self, other: &Self) -> Result<(), ControlError> {
        let a = self.identity()?;
        let b = other.identity()?;
        if a == b || self.ancestry.contains(&b) || other.ancestry.contains(&a) {
            Err(ControlError::InvalidRequest)
        } else {
            Ok(())
        }
    }
    pub fn check(&self) -> Result<(), ControlError> {
        let s = fs::fstat(&self.root).map_err(failure)?;
        if FileType::from_raw_mode(s.st_mode) != FileType::Directory
            || s.st_uid != self.owner
            || s.st_mode & 0o7777 != 0o700
            || s.st_nlink == 0
        {
            Err(ControlError::PermissionDenied)
        } else {
            Ok(())
        }
    }
    pub fn names(&self) -> Result<Vec<String>, ControlError> {
        self.names_bounded(32)
    }
    pub fn names_bounded(&self, maximum: usize) -> Result<Vec<String>, ControlError> {
        if maximum == 0 || maximum > 4096 {
            return Err(ControlError::InvalidRequest);
        }
        self.check()?;
        let mut out = Vec::new();
        let fd = fs::openat(&self.root, ".", DIR, Mode::empty()).map_err(failure)?;
        for entry in fs::Dir::read_from(&fd).map_err(failure)? {
            let entry = entry.map_err(failure)?;
            let n = entry.file_name().to_bytes();
            if n == b"." || n == b".." {
                continue;
            }
            if out.len() >= maximum {
                return Err(ControlError::CorruptState);
            }
            out.push(
                std::str::from_utf8(n)
                    .map_err(|_| ControlError::CorruptState)?
                    .to_owned(),
            );
        }
        out.sort();
        Ok(out)
    }
    pub fn require_empty(&self) -> Result<(), ControlError> {
        if self.names()?.is_empty() {
            Ok(())
        } else {
            Err(ControlError::RecoveryRequired)
        }
    }
    fn name(name: &str) -> Result<(), ControlError> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || name == "."
            || name == ".."
        {
            Err(ControlError::InvalidRequest)
        } else {
            Ok(())
        }
    }
    pub fn create_file(&self, name: &str) -> Result<File, ControlError> {
        Self::name(name)?;
        self.check()?;
        let fd = fs::openat(
            &self.root,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(failure)?;
        let file = File::from(fd);
        self.check_file(&file)?;
        Ok(file)
    }
    pub fn open_file(&self, name: &str) -> Result<File, ControlError> {
        Self::name(name)?;
        self.check()?;
        let fd = fs::openat(
            &self.root,
            name,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        let file = File::from(fd);
        self.check_file(&file)?;
        Ok(file)
    }
    /// Non-creating, read-only file capability for retained offline inspection.
    /// Advisory locks may be held on this descriptor; no writable handle escapes.
    pub(crate) fn open_file_read_only(&self, name: &str) -> Result<File, ControlError> {
        Self::name(name)?;
        self.check()?;
        let fd = fs::openat(
            &self.root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        let file = File::from(fd);
        self.check_file(&file)?;
        Ok(file)
    }
    pub fn check_file(&self, file: &File) -> Result<(), ControlError> {
        let s = fs::fstat(file).map_err(failure)?;
        if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
            || s.st_uid != self.owner
            || s.st_mode & 0o7777 != 0o600
            || s.st_nlink != 1
        {
            Err(ControlError::PermissionDenied)
        } else {
            Ok(())
        }
    }
    pub fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), ControlError> {
        if bytes.len() > 16384 {
            return Err(ControlError::InvalidRequest);
        }
        let mut f = self.create_file(name)?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| ControlError::StorageUnavailable)?;
        self.sync()
    }
    pub fn read(&self, name: &str, max: usize) -> Result<Vec<u8>, ControlError> {
        let f = self.open_file(name)?;
        let before = fs::fstat(&f).map_err(failure)?;
        if before.st_size < 0 || before.st_size as usize > max {
            return Err(ControlError::CorruptState);
        }
        let mut bytes = Vec::new();
        (&f).take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ControlError::StorageUnavailable)?;
        let after = fs::fstat(&f).map_err(failure)?;
        if bytes.len() > max
            || before.st_size != after.st_size
            || before.st_mtime != after.st_mtime
            || before.st_mtime_nsec != after.st_mtime_nsec
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(ControlError::CorruptState);
        }
        self.check_file(&f)?;
        Ok(bytes)
    }
    #[cfg(test)]
    pub(crate) fn fail_sync_on(&self, nth: usize) {
        self.sync_failure_countdown.store(nth, Ordering::SeqCst);
    }
    pub fn sync(&self) -> Result<(), ControlError> {
        self.check()?;
        #[cfg(test)]
        if self
            .sync_failure_countdown
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                if n > 0 {
                    Some(n - 1)
                } else {
                    None
                }
            })
            .ok()
            == Some(1)
        {
            return Err(ControlError::StorageUnavailable);
        }
        self.root
            .sync_all()
            .map_err(|_| ControlError::StorageUnavailable)
    }
    /// Dedicated process startup only: call before spawning ANY thread. The
    /// anchor is intentionally never restored, including on error/drop.
    pub fn anchor_before_threads(self) -> Result<AnchoredControlRoot, ControlError> {
        static ANCHORED: AtomicBool = AtomicBool::new(false);
        let count = std::fs::read_dir("/proc/self/task")
            .map_err(|_| ControlError::ExecutorUnavailable)?
            .take(2)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ControlError::ExecutorUnavailable)?
            .len();
        if count != 1 || ANCHORED.swap(true, Ordering::SeqCst) {
            return Err(ControlError::InvalidRequest);
        }
        self.check()?;
        rustix::process::fchdir(&self.root).map_err(failure)?;
        let value = AnchoredControlRoot(self);
        value.check_cwd()?;
        Ok(value)
    }
}
pub struct AnchoredControlRoot(pub(crate) BoundDirectory);
impl AnchoredControlRoot {
    pub fn check_cwd(&self) -> Result<(), ControlError> {
        self.0.check()?;
        let fd = File::from(fs::open(".", DIR, Mode::empty()).map_err(failure)?);
        if DirectoryIdentity::of(&fd)? != self.0.identity()? {
            Err(ControlError::PermissionDenied)
        } else {
            Ok(())
        }
    }
}

/// Fresh creation never adopts residue; paired open never creates missing state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundOpenMode {
    CreateFresh,
    OpenExisting,
}
impl BoundDirectory {
    /// Child capabilities never reopen a parent pathname. Their independent
    /// lifetime lease is nonblocking; a failed creation retains residue.
    pub fn child(&self, name: &str, mode: BoundOpenMode) -> Result<Self, ControlError> {
        Self::name(name)?;
        self.check()?;
        if mode == BoundOpenMode::CreateFresh {
            fs::mkdirat(&self.root, name, Mode::from_raw_mode(0o700)).map_err(failure)?;
            self.sync()?;
        }
        let root = File::from(fs::openat(&self.root, name, DIR, Mode::empty()).map_err(failure)?);
        fn mount(file: &File) -> Result<u64, ControlError> {
            let value = fs::statx(
                file,
                "",
                fs::AtFlags::EMPTY_PATH | fs::AtFlags::SYMLINK_NOFOLLOW,
                fs::StatxFlags::MNT_ID,
            )
            .map_err(failure)?;
            if value.stx_mask & fs::StatxFlags::MNT_ID.bits() == 0 || value.stx_mnt_id == 0 {
                return Err(ControlError::ExecutorUnavailable);
            }
            Ok(value.stx_mnt_id)
        }
        if mount(&self.root)? != mount(&root)? {
            return Err(ControlError::PermissionDenied);
        }
        let mut ancestry = self.ancestry.clone();
        ancestry.push(self.identity()?);
        if ancestry.contains(&DirectoryIdentity::of(&root)?) {
            return Err(ControlError::PermissionDenied);
        }
        let child = Self {
            root,
            ancestry,
            owner: self.owner,
            #[cfg(test)]
            sync_failure_countdown: std::sync::atomic::AtomicUsize::new(0),
        }
        .lock()?;
        if mode == BoundOpenMode::CreateFresh {
            child.require_empty()?;
        }
        Ok(child)
    }
    /// Atomic, descriptor-relative publication. Any pre-existing staging entry
    /// is uncertain and is never deleted/adopted. On failure the caller must stop.
    pub fn atomic_file(
        &self,
        destination: &str,
        pending: &str,
        bytes: &[u8],
        max: usize,
        replace_existing: bool,
    ) -> Result<(), ControlError> {
        Self::name(destination)?;
        Self::name(pending)?;
        self.check()?;
        if destination == pending || max == 0 || max > 64 * 1024 * 1024 || bytes.len() > max {
            return Err(ControlError::InvalidRequest);
        }
        if replace_existing {
            self.open_file(destination)?;
        }
        let mut file = self.create_file(pending)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| ControlError::StorageUnavailable)?;
        self.check_file(&file)?;
        self.sync()?;
        if replace_existing {
            // Parent lifetime lease serializes cooperating writers. Destination
            // must still be a validated private regular file; never a symlink.
            self.open_file(destination)?;
            fs::renameat(&self.root, pending, &self.root, destination).map_err(failure)?;
        } else {
            fs::renameat_with(
                &self.root,
                pending,
                &self.root,
                destination,
                fs::RenameFlags::NOREPLACE,
            )
            .map_err(failure)?;
        }
        self.sync()?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod runtime_capability_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn setup() -> (tempfile::TempDir, BoundDirectory) {
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let expected = DirectoryIdentity::of(&File::open(temp.path()).unwrap()).unwrap();
        let directory = BoundDirectory::open(temp.path(), expected).unwrap();
        (temp, directory)
    }
    #[test]
    fn child_capabilities_are_locked_and_do_not_follow_replacements() {
        let (temp, parent) = setup();
        let child = parent.child("journal", BoundOpenMode::CreateFresh).unwrap();
        assert!(parent
            .child("journal", BoundOpenMode::OpenExisting)
            .is_err());
        std::fs::rename(temp.path().join("journal"), temp.path().join("old")).unwrap();
        std::fs::create_dir(temp.path().join("journal")).unwrap();
        child
            .atomic_file("record", "pending", b"one", 1024, false)
            .unwrap();
        assert_eq!(child.read("record", 1024).unwrap(), b"one");
        assert_eq!(
            std::fs::read_dir(temp.path().join("journal"))
                .unwrap()
                .count(),
            0
        );
        assert!(parent.child("../old", BoundOpenMode::OpenExisting).is_err());
        std::os::unix::fs::symlink(temp.path().join("old"), temp.path().join("alias")).unwrap();
        assert!(parent.child("alias", BoundOpenMode::OpenExisting).is_err());
    }
    #[test]
    fn atomic_publication_rejects_symlinks_and_keeps_pending_evidence() {
        let (temp, directory) = setup();
        directory
            .atomic_file("record", "pending", b"old", 1024, false)
            .unwrap();
        directory
            .atomic_file("record", "pending", b"new", 1024, true)
            .unwrap();
        assert_eq!(directory.read("record", 1024).unwrap(), b"new");
        directory.publish("pending", b"uncertain").unwrap();
        assert!(directory
            .atomic_file("record", "pending", b"replace", 1024, true)
            .is_err());
        assert_eq!(directory.read("record", 1024).unwrap(), b"new");
        assert_eq!(directory.read("pending", 1024).unwrap(), b"uncertain");
        std::os::unix::fs::symlink(temp.path().join("record"), temp.path().join("link")).unwrap();
        assert!(directory
            .atomic_file("link", "other-pending", b"bad", 1024, true)
            .is_err());
        assert!(!temp.path().join("other-pending").exists());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod readonly_snapshot_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn setup() -> (tempfile::TempDir, BoundDirectory) {
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let identity = DirectoryIdentity::of(&File::open(temp.path()).unwrap()).unwrap();
        let root = BoundDirectory::open(temp.path(), identity).unwrap();
        (temp, root)
    }
    #[test]
    fn snapshot_retains_readonly_descriptor_without_content_or_inventory_changes() {
        let (temp, root) = setup();
        root.publish("record", b"immutable reference bytes")
            .unwrap();
        let before = std::fs::metadata(temp.path().join("record")).unwrap();
        let names = root.names().unwrap();
        let snapshot = root.inspect_file_read_only("record", 1024).unwrap();
        assert_eq!(snapshot.bytes(), b"immutable reference bytes");
        snapshot.revalidate(&root).unwrap();
        assert_eq!(root.names().unwrap(), names);
        let after = std::fs::metadata(temp.path().join("record")).unwrap();
        assert_eq!(
            (
                before.ino(),
                before.len(),
                before.mode(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.ino(),
                after.len(),
                after.mode(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
        // Test-only access to the private descriptor proves write permission was
        // never requested; callers cannot obtain this descriptor from the API.
        assert!((&snapshot.file).write_all(b"forbidden").is_err());
        assert_eq!(
            std::fs::read(temp.path().join("record")).unwrap(),
            snapshot.bytes()
        );
    }
    #[test]
    fn replacement_and_in_place_mutation_invalidate_observation() {
        let (temp, root) = setup();
        root.publish("record", b"same").unwrap();
        let snapshot = root.inspect_file_read_only("record", 16).unwrap();
        std::fs::rename(temp.path().join("record"), temp.path().join("old-record")).unwrap();
        root.publish("record", b"same").unwrap();
        assert!(
            snapshot.revalidate(&root).is_err(),
            "equal bytes do not adopt new inode"
        );
        let current = root.inspect_file_read_only("record", 16).unwrap();
        std::fs::write(temp.path().join("record"), b"changed-length").unwrap();
        assert!(current.revalidate(&root).is_err());
        assert_eq!(
            current.bytes(),
            b"same",
            "snapshot bytes never silently refresh"
        );
    }
    #[test]
    fn rejects_wrong_root_missing_symlink_hardlink_permissions_and_bounds() {
        let (temp, root) = setup();
        let (_other_temp, other) = setup();
        root.publish("record", b"12345678").unwrap();
        let snapshot = root.inspect_file_read_only("record", 8).unwrap();
        assert!(snapshot.revalidate(&other).is_err());
        assert!(root.inspect_file_read_only("record", 7).is_err());
        assert!(root.inspect_file_read_only("record", 0).is_err());
        assert!(root
            .inspect_file_read_only("record", 64 * 1024 * 1024 + 1)
            .is_err());
        assert!(root.inspect_file_read_only("missing", 8).is_err());
        assert!(!temp.path().join("missing").exists());
        assert!(root.inspect_file_read_only("../record", 8).is_err());
        std::os::unix::fs::symlink("record", temp.path().join("alias")).unwrap();
        assert!(root.inspect_file_read_only("alias", 8).is_err());
        std::fs::hard_link(temp.path().join("record"), temp.path().join("hardlink")).unwrap();
        assert!(snapshot.revalidate(&root).is_err());
        assert!(root.inspect_file_read_only("record", 8).is_err());
        std::fs::remove_file(temp.path().join("hardlink")).unwrap();
        std::fs::set_permissions(
            temp.path().join("record"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(root.inspect_file_read_only("record", 8).is_err());
    }
    #[test]
    fn root_rename_retains_authority_while_named_child_replacement_is_rejected() {
        let (temp, root) = setup();
        let child = root.child("journal", BoundOpenMode::CreateFresh).unwrap();
        child.publish("record", b"old").unwrap();
        let snapshot = child.inspect_file_read_only("record", 8).unwrap();
        root.revalidate_child("journal", &child).unwrap();
        // This is a check only, not another exclusive lock acquisition.
        root.revalidate_child("journal", &child).unwrap();
        std::fs::rename(temp.path().join("journal"), temp.path().join("retained")).unwrap();
        let replacement = root.child("journal", BoundOpenMode::CreateFresh).unwrap();
        assert!(root.revalidate_child("journal", &child).is_err());
        root.revalidate_child("journal", &replacement).unwrap();
        snapshot.revalidate(&child).unwrap();
        root.revalidate_child("retained", &child).unwrap();
        assert!(root.revalidate_child("../retained", &child).is_err());
        std::os::unix::fs::symlink("retained", temp.path().join("alias")).unwrap();
        assert!(root.revalidate_child("alias", &child).is_err());
        // Renaming the admitted root itself does not redirect descriptor-relative
        // reads to a different root recreated at the old path.
        let (outer_temp, outer) = setup();
        let adopted = outer.child("root", BoundOpenMode::CreateFresh).unwrap();
        adopted.publish("record", b"retained-root").unwrap();
        let observation = adopted.inspect_file_read_only("record", 32).unwrap();
        let outer_path = outer_temp.path();
        std::fs::rename(outer_path.join("root"), outer_path.join("renamed-root")).unwrap();
        let new_root = outer.child("root", BoundOpenMode::CreateFresh).unwrap();
        new_root.publish("record", b"replacement-root").unwrap();
        observation.revalidate(&adopted).unwrap();
        assert!(observation.revalidate(&new_root).is_err());
        assert_eq!(observation.bytes(), b"retained-root");
    }
}
