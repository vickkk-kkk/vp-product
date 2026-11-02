//! Explicit private scratch. No ambient fallback; cooperative same-UID model.
use super::*;
use rustix::fs::{AtFlags, StatxFlags};
use std::{cell::RefCell, collections::BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Identity(u64, u64);
fn identity(file: &File) -> Result<Identity, InspectionError> {
    let s = fs::fstat(file).map_err(os_error)?;
    Ok(Identity(s.st_dev, s.st_ino))
}
fn mount_id(file: &File) -> Result<u64, InspectionError> {
    let observed = fs::statx(
        file,
        "",
        AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID,
    )
    .map_err(|_| InspectionError::Unsupported)?;
    if observed.stx_mask & StatxFlags::MNT_ID.bits() == 0 || observed.stx_mnt_id == 0 {
        return Err(InspectionError::Unsupported);
    }
    Ok(observed.stx_mnt_id)
}
fn require_same_mount(ids: [u64; 3]) -> Result<(), InspectionError> {
    if ids[0] == 0 || ids.iter().any(|id| *id != ids[0]) {
        return Err(InspectionError::Unsupported);
    }
    Ok(())
}
fn chain(
    path: &Path,
    strict: bool,
    deadline: Instant,
) -> Result<(File, Vec<Identity>), InspectionError> {
    let owner = rustix::process::geteuid().as_raw();
    // Reuse baseline final-root/path admission, but independently enforce the
    // stricter scratch ancestry below; the sticky exception is not inherited.
    let admitted = open_root(path, owner, deadline)?;
    let mut fd = File::from(fs::open("/", DIR_FLAGS, Mode::empty()).map_err(os_error)?);
    let mut ids = vec![identity(&fd)?];
    let components: Vec<_> = path.components().skip(1).collect();
    if components.len() > 512 {
        return Err(InspectionError::LimitExceeded);
    }
    for component in components {
        within(deadline)?;
        let st = fs::fstat(&fd).map_err(os_error)?;
        let sticky = !strict && st.st_uid == 0 && st.st_mode & 0o1000 != 0;
        if (st.st_uid != 0 && st.st_uid != owner) || (st.st_mode & 0o022 != 0 && !sticky) {
            return Err(InspectionError::PermissionDenied);
        }
        let Component::Normal(name) = component else {
            return Err(InspectionError::InvalidInput);
        };
        fd = File::from(fs::openat(&fd, name, DIR_FLAGS, Mode::empty()).map_err(os_error)?);
        let id = identity(&fd)?;
        // Repeated identities can be bind/canonical ambiguity, not proof of safety.
        if ids.contains(&id) {
            return Err(InspectionError::Unsupported);
        }
        ids.push(id);
    }
    check_root(&fd, owner)?;
    if identity(&admitted)? != identity(&fd)? {
        return Err(InspectionError::Integrity);
    }
    Ok((fd, ids))
}
fn names(fd: &File) -> Result<BTreeSet<String>, InspectionError> {
    let mut result = BTreeSet::new();
    for e in fs::Dir::read_from(fd).map_err(os_error)? {
        let e = e.map_err(os_error)?;
        let n = e
            .file_name()
            .to_str()
            .map_err(|_| InspectionError::Integrity)?;
        if n == "." || n == ".." {
            continue;
        }
        if result.len() > 2 {
            return Err(InspectionError::RecoveryRequired);
        }
        result.insert(n.to_owned());
    }
    Ok(result)
}
fn overlap(a: &[Identity], b: &[Identity]) -> bool {
    a.last().is_some_and(|id| b.contains(id)) || b.last().is_some_and(|id| a.contains(id))
}

pub(super) struct PrivateScratch {
    root: File,
    root_id: Identity,
    mount_id: u64,
    expected_vault_directory: Identity,
    vault_guard: Option<File>,
    root_path: PathBuf,
    child: File,
    child_id: Identity,
    child_name: String,
    copy: RefCell<Option<Identity>>,
    closed: bool,
}
impl PrivateScratch {
    pub(super) fn new(
        path: &Path,
        state: &Path,
        vault: &Path,
        retained_state: &File,
        deadline: Instant,
    ) -> Result<Self, InspectionError> {
        let (root, initial) = chain(path, true, deadline)?;
        fs::flock(&root, FlockOperation::NonBlockingLockExclusive).map_err(os_error)?;
        // Validate disjointness and current path only after the lease, BEFORE writes.
        let (current, roots) = chain(path, true, deadline)?;
        if identity(&root)? != identity(&current)? || initial != roots {
            return Err(InspectionError::Integrity);
        }
        let (state_fd, states) = chain(state, false, deadline)?;
        if identity(&state_fd)? != identity(retained_state)? {
            return Err(InspectionError::Integrity);
        }
        let (vault_fd, vaults) = chain(vault, false, deadline)?;
        if mount_id(&state_fd)? != mount_id(retained_state)? {
            return Err(InspectionError::Unsupported);
        }
        let mount = mount_id(&root)?;
        require_same_mount([mount, mount_id(&state_fd)?, mount_id(&vault_fd)?])?;
        if overlap(&roots, &states) || overlap(&roots, &vaults) || overlap(&states, &vaults) {
            return Err(InspectionError::InvalidInput);
        }
        if !names(&root)?.is_empty() {
            return Err(InspectionError::RecoveryRequired);
        }
        within(deadline)?;
        let mut random = [0u8; 16];
        let mut offset = 0;
        while offset < random.len() {
            within(deadline)?;
            match rustix::rand::getrandom(
                &mut random[offset..],
                rustix::rand::GetRandomFlags::NONBLOCK,
            ) {
                Ok(0) => return Err(InspectionError::Unavailable),
                Ok(n) => offset += n,
                Err(Errno::INTR) => continue,
                Err(_) => return Err(InspectionError::Unavailable),
            }
        }
        let name = format!(
            "vp-inspect-{}",
            random
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        );
        fs::mkdirat(&root, name.as_str(), Mode::from_raw_mode(0o700)).map_err(os_error)?;
        let child_result: Result<File, InspectionError> = (|| {
            let child = File::from(
                fs::openat(&root, name.as_str(), DIR_FLAGS, Mode::empty()).map_err(os_error)?,
            );
            check_root(&child, rustix::process::geteuid().as_raw())?;
            Ok(child)
        })();
        let child = match child_result {
            Ok(c) => c,
            // An uncertain child identity is retained, never recursively removed.
            Err(_) => return Err(InspectionError::CleanupRequired),
        };
        Ok(Self {
            root_id: identity(&root).map_err(|_| InspectionError::CleanupRequired)?,
            mount_id: mount,
            expected_vault_directory: identity(&vault_fd)
                .map_err(|_| InspectionError::CleanupRequired)?,
            vault_guard: Some(vault_fd),
            child_id: identity(&child).map_err(|_| InspectionError::CleanupRequired)?,
            root,
            child,
            root_path: path.to_owned(),
            child_name: name,
            copy: RefCell::new(None),
            closed: false,
        })
    }
    pub(super) fn take_vault_guard(&mut self) -> Option<File> {
        self.vault_guard.take()
    }
    pub(super) fn expected_vault_directory(&self) -> (u64, u64) {
        (
            self.expected_vault_directory.0,
            self.expected_vault_directory.1,
        )
    }
    pub(super) fn copy_path(&self) -> PathBuf {
        self.root_path.join(&self.child_name).join("snapshot.db")
    }
    fn recheck(&self, deadline: Instant) -> Result<(), InspectionError> {
        let (root, _) = chain(&self.root_path, true, deadline)?;
        if identity(&root)? != self.root_id
            || identity(&self.root)? != self.root_id
            || mount_id(&root)? != self.mount_id
        {
            return Err(InspectionError::Integrity);
        }
        if names(&self.root)? != BTreeSet::from([self.child_name.clone()]) {
            return Err(InspectionError::Integrity);
        }
        let child = File::from(
            fs::openat(&root, self.child_name.as_str(), DIR_FLAGS, Mode::empty())
                .map_err(os_error)?,
        );
        check_root(&child, rustix::process::geteuid().as_raw())?;
        if identity(&child)? != self.child_id
            || identity(&self.child)? != self.child_id
            || mount_id(&child)? != self.mount_id
        {
            return Err(InspectionError::Integrity);
        }
        Ok(())
    }
    pub(super) fn create_copy(&self) -> Result<File, InspectionError> {
        if !names(&self.child)?.is_empty() {
            return Err(InspectionError::Integrity);
        }
        let fd = fs::openat(
            &self.child,
            "snapshot.db",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(os_error)?;
        let file = File::from(fd);
        self.copy.replace(Some(identity(&file)?));
        Ok(file)
    }
    pub(super) fn validate_copy(
        &self,
        size: u64,
        digest: &str,
        deadline: Instant,
    ) -> Result<(), InspectionError> {
        self.recheck(deadline)?;
        if names(&self.child)? != BTreeSet::from(["snapshot.db".into()]) {
            return Err(InspectionError::Integrity);
        }
        let file = private_file(
            &self.child,
            "snapshot.db",
            rustix::process::geteuid().as_raw(),
        )?;
        if Some(identity(&file)?) != *self.copy.borrow()
            || file
                .metadata()
                .map_err(|_| InspectionError::Unavailable)?
                .len()
                != size
            || hash_file(&file, deadline)? != digest
        {
            return Err(InspectionError::Integrity);
        }
        // Check the actual absolute path SQLite will consume, not just dirfd contents.
        let absolute = File::from(
            fs::open(
                self.copy_path(),
                OFlags::RDONLY
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC
                    | OFlags::NOATIME,
                Mode::empty(),
            )
            .map_err(os_error)?,
        );
        if identity(&absolute)? != identity(&file)? {
            return Err(InspectionError::Integrity);
        }
        Ok(())
    }
    fn cleanup(&mut self) -> Result<(), InspectionError> {
        // Cleanup has its own bounded budget even after the operation expires.
        self.recheck(Instant::now() + Duration::from_secs(2))
            .map_err(|_| InspectionError::CleanupRequired)?;
        let entries = names(&self.child).map_err(|_| InspectionError::CleanupRequired)?;
        match *self.copy.borrow() {
            Some(expected) => {
                if entries != BTreeSet::from(["snapshot.db".into()]) {
                    return Err(InspectionError::CleanupRequired);
                }
                let file = private_file(
                    &self.child,
                    "snapshot.db",
                    rustix::process::geteuid().as_raw(),
                )
                .map_err(|_| InspectionError::CleanupRequired)?;
                if identity(&file).map_err(|_| InspectionError::CleanupRequired)? != expected {
                    return Err(InspectionError::CleanupRequired);
                }
                fs::unlinkat(&self.child, "snapshot.db", AtFlags::empty())
                    .map_err(|_| InspectionError::CleanupRequired)?;
            }
            None => {
                if !entries.is_empty() {
                    return Err(InspectionError::CleanupRequired);
                }
            }
        }
        fs::unlinkat(&self.root, self.child_name.as_str(), AtFlags::REMOVEDIR)
            .map_err(|_| InspectionError::CleanupRequired)?;
        self.closed = true;
        Ok(())
    }
    pub(super) fn close(mut self) -> Result<(), InspectionError> {
        let result = self.cleanup();
        self.closed = true; // Never silently retry failed explicit cleanup in Drop.
        result
    }
}
impl Drop for PrivateScratch {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.cleanup();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::{fs as stdfs, os::unix::fs::symlink};
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let p = crate::private_test_directory();
        let paths = [
            p.path().join("state"),
            p.path().join("vault"),
            p.path().join("scratch"),
        ];
        for x in &paths {
            stdfs::create_dir(x).unwrap();
            stdfs::set_permissions(x, stdfs::Permissions::from_mode(0o700)).unwrap();
        }
        drop(crate::SqliteStore::open(&paths[0]).unwrap());
        (p, paths[0].clone(), paths[1].clone(), paths[2].clone())
    }
    fn scratch_new(
        path: &Path,
        state: &Path,
        vault: &Path,
        until: Instant,
    ) -> Result<PrivateScratch, InspectionError> {
        let retained = open_root(state, rustix::process::geteuid().as_raw(), until)?;
        PrivateScratch::new(path, state, vault, &retained, until)
    }
    #[test]
    fn state_path_must_match_the_actual_retained_control_root_before_any_write() {
        let (p, state, vault, scratch) = fixture();
        let retained = open_root(&state, rustix::process::geteuid().as_raw(), deadline()).unwrap();
        let moved = p.path().join("old-state");
        stdfs::rename(&state, &moved).unwrap();
        stdfs::create_dir(&state).unwrap();
        stdfs::set_permissions(&state, stdfs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            PrivateScratch::new(&scratch, &state, &vault, &retained, deadline()),
            Err(InspectionError::Integrity)
        ));
        assert_eq!(stdfs::read_dir(scratch).unwrap().count(), 0);
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    #[test]
    fn mount_policy_rejects_unknown_or_distinct_ids_without_claiming_bind_execution() {
        assert!(require_same_mount([7, 7, 7]).is_ok());
        for ids in [[0, 0, 0], [7, 8, 7], [7, 7, 8], [7, 0, 7]] {
            assert_eq!(require_same_mount(ids), Err(InspectionError::Unsupported));
        }
    }
    #[test]
    fn real_private_scratch_sqlite_inspection_preserves_targets_and_cleans_child() {
        let (_p, state, vault, scratch) = fixture();
        let before = stdfs::read(state.join(DB)).unwrap();
        let observation =
            inspect_control_read_only_in_scratch(&state, &vault, &scratch, deadline()).unwrap();
        assert_eq!(observation.receipt().state_version, 0);
        observation.recheck(deadline()).unwrap();
        assert_eq!(stdfs::read(state.join(DB)).unwrap(), before);
        assert_eq!(stdfs::read_dir(&scratch).unwrap().count(), 0);
        assert_eq!(stdfs::read_dir(&vault).unwrap().count(), 0);
    }
    #[test]
    fn admitted_vault_descriptor_survives_scratch_cleanup_and_pins_identity() {
        use std::os::unix::fs::MetadataExt;
        let (_p, state, vault, scratch) = fixture();
        let before = stdfs::metadata(&vault).unwrap();
        let observation =
            inspect_control_read_only_in_scratch(&state, &vault, &scratch, deadline()).unwrap();
        assert_eq!(stdfs::read_dir(&scratch).unwrap().count(), 0);
        let pinned = observation._admitted_vault.as_ref().unwrap();
        assert_eq!(pinned.metadata().unwrap().ino(), before.ino());
        stdfs::remove_dir(&vault).unwrap();
        assert_eq!(pinned.metadata().unwrap().nlink(), 0);
        stdfs::create_dir(&vault).unwrap();
        stdfs::set_permissions(&vault, stdfs::Permissions::from_mode(0o700)).unwrap();
        assert_ne!(stdfs::metadata(&vault).unwrap().ino(), before.ino());
        assert_eq!(
            observation.expected_vault_directory(),
            Some((before.dev(), before.ino()))
        );
    }
    #[test]
    fn real_directory_lease_refuses_busy_and_existing_residue() {
        let (_p, state, vault, scratch) = fixture();
        let root = File::open(&scratch).unwrap();
        fs::flock(&root, FlockOperation::NonBlockingLockExclusive).unwrap();
        assert!(matches!(
            scratch_new(&scratch, &state, &vault, deadline()),
            Err(InspectionError::Busy)
        ));
        drop(root);
        stdfs::write(scratch.join("foreign"), b"synthetic").unwrap();
        assert!(matches!(
            scratch_new(&scratch, &state, &vault, deadline()),
            Err(InspectionError::RecoveryRequired)
        ));
        assert_eq!(stdfs::read(scratch.join("foreign")).unwrap(), b"synthetic");
    }
    #[test]
    fn disjointness_rejects_equal_and_both_nested_directions_before_create() {
        let (p, state, vault, scratch) = fixture();
        assert!(matches!(
            scratch_new(&state, &state, &vault, deadline()),
            Err(InspectionError::InvalidInput)
        ));
        let inner = state.join("inner");
        stdfs::create_dir(&inner).unwrap();
        stdfs::set_permissions(&inner, stdfs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            scratch_new(&inner, &state, &vault, deadline()),
            Err(InspectionError::InvalidInput)
        ));
        assert!(matches!(
            scratch_new(p.path(), &state, &vault, deadline()),
            Err(InspectionError::InvalidInput)
        ));
        assert_eq!(stdfs::read_dir(inner).unwrap().count(), 0);
        assert_eq!(stdfs::read_dir(scratch).unwrap().count(), 0);
    }
    #[test]
    fn unsafe_ancestry_modes_and_symlinks_rejected() {
        let (p, state, vault, scratch) = fixture();
        let alias = p.path().join("alias");
        symlink(&scratch, &alias).unwrap();
        assert!(scratch_new(&alias, &state, &vault, deadline()).is_err());
        stdfs::set_permissions(&scratch, stdfs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            scratch_new(&scratch, &state, &vault, deadline()),
            Err(InspectionError::PermissionDenied)
        ));
        stdfs::set_permissions(&scratch, stdfs::Permissions::from_mode(0o700)).unwrap();
        stdfs::set_permissions(p.path(), stdfs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            scratch_new(&scratch, &state, &vault, deadline()),
            Err(InspectionError::PermissionDenied)
        ));
        stdfs::set_permissions(p.path(), stdfs::Permissions::from_mode(0o700)).unwrap();
    }
    #[test]
    fn partial_copy_hash_mismatch_and_expiry_cleanup_only_owned_child() {
        let (_p, state, vault, scratch) = fixture();
        let temporary = scratch_new(&scratch, &state, &vault, deadline()).unwrap();
        temporary
            .create_copy()
            .unwrap()
            .write_all(b"partial")
            .unwrap();
        assert!(matches!(
            temporary.validate_copy(8, "bad", deadline()),
            Err(InspectionError::Integrity)
        ));
        assert!(matches!(
            temporary.validate_copy(7, "bad", Instant::now()),
            Err(InspectionError::DeadlineExceeded)
        ));
        temporary.close().unwrap();
        assert_eq!(stdfs::read_dir(scratch).unwrap().count(), 0);
    }
    #[test]
    fn unexpected_sidecar_retained_and_explicit_cleanup_failure_not_retried() {
        let (_p, state, vault, scratch) = fixture();
        let temporary = scratch_new(&scratch, &state, &vault, deadline()).unwrap();
        temporary
            .create_copy()
            .unwrap()
            .write_all(b"partial")
            .unwrap();
        let child = temporary.copy_path().parent().unwrap().to_owned();
        stdfs::write(child.join("foreign"), b"synthetic").unwrap();
        assert_eq!(temporary.close(), Err(InspectionError::CleanupRequired));
        assert!(child.join("snapshot.db").exists() && child.join("foreign").exists());
    }
    #[test]
    fn replaced_absolute_path_is_rejected_and_original_child_not_swept() {
        let (p, state, vault, scratch) = fixture();
        let temporary = scratch_new(&scratch, &state, &vault, deadline()).unwrap();
        temporary.create_copy().unwrap();
        let moved = p.path().join("moved");
        stdfs::rename(&scratch, &moved).unwrap();
        stdfs::create_dir(&scratch).unwrap();
        stdfs::set_permissions(&scratch, stdfs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(temporary.close(), Err(InspectionError::CleanupRequired));
        assert_eq!(stdfs::read_dir(&moved).unwrap().count(), 1);
        assert_eq!(stdfs::read_dir(&scratch).unwrap().count(), 0);
    }
    #[test]
    fn exact_copy_hash_and_replaced_inode_are_required_before_sqlite() {
        let (_p, state, vault, scratch) = fixture();
        let temporary = scratch_new(&scratch, &state, &vault, deadline()).unwrap();
        let mut original = temporary.create_copy().unwrap();
        original.write_all(b"1234567").unwrap();
        assert!(matches!(
            temporary.validate_copy(7, "bad", deadline()),
            Err(InspectionError::Integrity)
        ));
        let path = temporary.copy_path();
        stdfs::remove_file(&path).unwrap();
        stdfs::write(&path, b"1234567").unwrap();
        stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            temporary.validate_copy(7, &format!("{:x}", Sha256::digest(b"1234567")), deadline()),
            Err(InspectionError::Integrity)
        ));
        assert_eq!(temporary.close(), Err(InspectionError::CleanupRequired));
        assert!(path.exists());
    }
    #[test]
    fn changed_child_permissions_are_retained_and_report_cleanup_required() {
        let (_p, state, vault, scratch) = fixture();
        let temporary = scratch_new(&scratch, &state, &vault, deadline()).unwrap();
        temporary
            .create_copy()
            .unwrap()
            .write_all(b"partial")
            .unwrap();
        let child = temporary.copy_path().parent().unwrap().to_owned();
        stdfs::set_permissions(&child, stdfs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(temporary.close(), Err(InspectionError::CleanupRequired));
        assert!(child.join("snapshot.db").exists());
        stdfs::set_permissions(child, stdfs::Permissions::from_mode(0o700)).unwrap();
    }
    #[test]
    fn scratch_wal_negative_preserves_source_and_allocates_no_child() {
        let (_p, state, vault, scratch) = fixture();
        stdfs::write(state.join("control.db-wal"), b"synthetic").unwrap();
        assert!(matches!(
            inspect_control_read_only_in_scratch(&state, &vault, &scratch, deadline()),
            Err(InspectionError::Unsupported)
        ));
        assert_eq!(stdfs::read_dir(scratch).unwrap().count(), 0);
        assert_eq!(
            stdfs::read(state.join("control.db-wal")).unwrap(),
            b"synthetic"
        );
    }
}
