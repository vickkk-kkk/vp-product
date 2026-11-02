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
