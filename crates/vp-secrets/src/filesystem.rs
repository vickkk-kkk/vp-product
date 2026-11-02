use crate::{types::within, VaultError};
use rustix::{
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags},
    io::Errno,
};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
    time::Instant,
};

pub(crate) const PENDING: &str = ".pending";
pub(crate) const MANIFEST_NAME: &str = "vault.v1";
const PRIVATE_FILE: Mode = Mode::from_raw_mode(0o600);
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(crate) struct Directory {
    root: File,
    owner: u32,
    #[cfg(test)]
    pub fault: std::sync::atomic::AtomicU8,
}
impl Directory {
    /// Walk from / using directory descriptors. No canonicalize-then-open gap,
    /// no symlink ancestors, no path reuse after acquiring the trusted dirfd.
    pub fn open(path: &Path, deadline: Instant) -> Result<Self, VaultError> {
        within(deadline)?;
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(VaultError::InvalidInput);
        }
        // Reject explicit dot segments too: Path::components normalizes `.`.
        use std::os::unix::ffi::OsStrExt;
        if path
            .as_os_str()
            .as_bytes()
            .split(|&b| b == b'/')
            .any(|c| c == b"." || c == b"..")
        {
            return Err(VaultError::InvalidInput);
        }
        let owner = rustix::process::geteuid().as_raw();
        let mut fd = fs::open("/", DIR_FLAGS, Mode::empty()).map_err(os_error)?;
        check_ancestor(&fd, owner)?;
        let components: Vec<_> = path.components().collect();
        if components.len() < 2 {
            return Err(VaultError::PermissionDenied);
        }
        for component in components.iter().skip(1) {
            within(deadline)?;
            let Component::Normal(name) = component else {
                return Err(VaultError::InvalidInput);
            };
            fd = fs::openat(&fd, *name, DIR_FLAGS, Mode::empty()).map_err(os_error)?;
            check_ancestor(&fd, owner)?;
        }
        let directory = Self {
            root: File::from(fd),
            owner,
            #[cfg(test)]
            fault: std::sync::atomic::AtomicU8::new(0),
        };
        directory.check()?;
        fs::flock(&directory.root, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == Errno::WOULDBLOCK {
                VaultError::Busy
            } else {
                os_error(e)
            }
        })?;
        within(deadline)?;
        Ok(directory)
    }
    pub fn opened_identity(&self) -> Result<(u64, u64), VaultError> {
        self.check()?;
        let stat = fs::fstat(&self.root).map_err(os_error)?;
        Ok((stat.st_dev, stat.st_ino))
    }
    pub fn require_identity(
        &self,
        expected: crate::VaultDirectoryIdentity,
    ) -> Result<(), VaultError> {
        // Check the descriptor after lifetime lock acquisition, never a pathname.
        self.check()?;
        let stat = fs::fstat(&self.root).map_err(os_error)?;
        if stat.st_dev != expected.device || stat.st_ino != expected.inode {
            return Err(VaultError::MetadataMismatch);
        }
        Ok(())
    }
    pub fn check(&self) -> Result<(), VaultError> {
        let stat = fs::fstat(&self.root).map_err(os_error)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || stat.st_uid != self.owner
            || stat.st_mode & 0o7777 != 0o700
            || stat.st_nlink == 0
        {
            return Err(VaultError::PermissionDenied);
        }
        Ok(())
    }
    pub fn names(&self, maximum: usize, deadline: Instant) -> Result<Vec<String>, VaultError> {
        self.names_with_flags(maximum, deadline, false)
    }
    pub fn names_no_atime(
        &self,
        maximum: usize,
        deadline: Instant,
    ) -> Result<Vec<String>, VaultError> {
        self.names_with_flags(maximum, deadline, true)
    }
    fn names_with_flags(
        &self,
        maximum: usize,
        deadline: Instant,
        no_atime: bool,
    ) -> Result<Vec<String>, VaultError> {
        self.check()?;
        let descriptor = fs::openat(
            &self.root,
            ".",
            DIR_FLAGS
                | if no_atime {
                    OFlags::NOATIME
                } else {
                    OFlags::empty()
                },
            Mode::empty(),
        )
        .map_err(os_error)?;
        let directory = fs::Dir::read_from(&descriptor).map_err(os_error)?;
        let mut names = Vec::new();
        for entry in directory {
            within(deadline)?;
            let entry = entry.map_err(os_error)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if names.len() == maximum {
                return Err(VaultError::LimitExceeded);
            }
            names.push(
                std::str::from_utf8(name)
                    .map_err(|_| VaultError::Integrity)?
                    .to_owned(),
            );
        }
        names.sort();
        Ok(names)
    }
    fn private_file(&self, name: &str, no_atime: bool) -> Result<File, VaultError> {
        valid_name(name)?;
        let fd = fs::openat(
            &self.root,
            name,
            OFlags::RDONLY
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK
                | if no_atime {
                    OFlags::NOATIME
                } else {
                    OFlags::empty()
                },
            Mode::empty(),
        )
        .map_err(os_error)?;
        check_file(&fd, self.owner)?;
        Ok(File::from(fd))
    }
    pub fn read(&self, name: &str, maximum: u64, deadline: Instant) -> Result<Vec<u8>, VaultError> {
        self.read_with_flags(name, maximum, deadline, false)
    }
    pub fn read_no_atime(
        &self,
        name: &str,
        maximum: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, VaultError> {
        self.read_with_flags(name, maximum, deadline, true)
    }
    fn read_with_flags(
        &self,
        name: &str,
        maximum: u64,
        deadline: Instant,
        no_atime: bool,
    ) -> Result<Vec<u8>, VaultError> {
        within(deadline)?;
        let file = self.private_file(name, no_atime)?;
        if file
            .metadata()
            .map_err(|_| VaultError::StorageUnavailable)?
            .len()
            > maximum
        {
            return Err(VaultError::LimitExceeded);
        }
        let mut bytes = Vec::new();
        file.take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| VaultError::StorageUnavailable)?;
        within(deadline)?;
        if bytes.len() as u64 > maximum {
            return Err(VaultError::LimitExceeded);
        }
        Ok(bytes)
    }
    pub fn free_space(&self, needed: u64, reserve: u64) -> Result<(), VaultError> {
        let info = fs::fstatvfs(&self.root).map_err(os_error)?;
        let free = info.f_bavail.saturating_mul(info.f_frsize);
        // This is a preflight, not a reservation: IO errors still fail closed.
        if free < reserve.saturating_add(needed).saturating_add(4096) {
            return Err(VaultError::LimitExceeded);
        }
        Ok(())
    }
    /// Finish an authenticated recovery, including the rename-before-directory-
    /// fsync crash window where there is already no staging file to remove.
    pub fn recover_staging(&self, maximum: u64, deadline: Instant) -> Result<(), VaultError> {
        match self.read(PENDING, maximum, deadline) {
            Ok(_) => {
                fs::unlinkat(&self.root, PENDING, AtFlags::empty()).map_err(os_error)?;
            }
            Err(VaultError::NotFound) => {}
            Err(error) => return Err(error),
        }
        self.maybe_fail(5)?;
        self.root
            .sync_all()
            .map_err(|_| VaultError::RecoveryRequired)?;
        within(deadline)
    }
    /// Atomic no-replace publish: write -> fsync(file) -> renameat2(NOREPLACE)
    /// -> fsync(directory). Any uncertain IO/timeout requires authenticated reopen.
    pub fn publish(&self, name: &str, bytes: &[u8], deadline: Instant) -> Result<(), VaultError> {
        within(deadline)?;
        self.check()?;
        valid_name(name)?;
        let fd = fs::openat(
            &self.root,
            PENDING,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            PRIVATE_FILE,
        )
        .map_err(os_error)?;
        check_file(&fd, self.owner)?;
        let mut file = File::from(fd);
        file.write_all(bytes)
            .map_err(|_| VaultError::RecoveryRequired)?;
        self.maybe_fail(1)?;
        file.sync_all().map_err(|_| VaultError::RecoveryRequired)?;
        self.maybe_fail(2)?;
        within(deadline)?;
        fs::renameat_with(
            &self.root,
            PENDING,
            &self.root,
            name,
            RenameFlags::NOREPLACE,
        )
        .map_err(os_error)?;
        self.maybe_fail(3)?;
        self.root
            .sync_all()
            .map_err(|_| VaultError::RecoveryRequired)?;
        self.maybe_fail(4)?;
        within(deadline)
    }
    fn maybe_fail(&self, _point: u8) -> Result<(), VaultError> {
        #[cfg(test)]
        if self
            .fault
            .compare_exchange(
                _point,
                0,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            return Err(VaultError::RecoveryRequired);
        }
        Ok(())
    }
}
fn valid_name(name: &str) -> Result<(), VaultError> {
    if name.is_empty()
        || name.len() > 128
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
    {
        Err(VaultError::InvalidInput)
    } else {
        Ok(())
    }
}
fn check_ancestor(fd: &impl std::os::fd::AsFd, owner: u32) -> Result<(), VaultError> {
    let stat = fs::fstat(fd).map_err(os_error)?;
    let trusted_sticky = stat.st_uid == 0 && stat.st_mode & 0o1000 != 0;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != 0 && stat.st_uid != owner)
        || (stat.st_mode & 0o022 != 0 && !trusted_sticky)
    {
        return Err(VaultError::PermissionDenied);
    }
    Ok(())
}
fn check_file(fd: &impl std::os::fd::AsFd, owner: u32) -> Result<(), VaultError> {
    let stat = fs::fstat(fd).map_err(os_error)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(VaultError::PermissionDenied);
    }
    Ok(())
}
fn os_error(error: Errno) -> VaultError {
    match error {
        Errno::NOENT => VaultError::NotFound,
        Errno::EXIST => VaultError::AlreadyExists,
        Errno::LOOP | Errno::NOTDIR | Errno::ACCESS | Errno::PERM => VaultError::PermissionDenied,
        _ => VaultError::StorageUnavailable,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod ownership_tests {
    use super::*;
    #[test]
    fn recovery_sync_is_attempted_even_without_a_pending_entry() {
        use std::{os::unix::fs::PermissionsExt, time::Duration};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let directory = Directory::open(root.path(), deadline).unwrap();
        directory
            .fault
            .store(5, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            directory.recover_staging(1024, deadline),
            Err(VaultError::RecoveryRequired)
        );
        assert!(directory.recover_staging(1024, deadline).is_ok());
    }
    #[test]
    fn descriptor_owner_must_match_expected_service_uid() {
        // Validate a deliberately different expected identity; no chown/root
        // privileges or non-synthetic account/filesystem mutations are needed.
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let actual = fs::fstat(temporary.as_file()).unwrap().st_uid;
        let different = if actual == u32::MAX {
            actual - 1
        } else {
            actual + 1
        };
        assert_eq!(
            check_file(temporary.as_file(), different),
            Err(VaultError::PermissionDenied)
        );
        assert!(check_file(temporary.as_file(), actual).is_ok());
    }
}
