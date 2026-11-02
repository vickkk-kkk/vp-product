#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::SqliteStore;
use std::{
    collections::BTreeMap,
    fs as stdfs,
    os::unix::fs::{symlink, MetadataExt},
};
use vp_product_control::{ControlStore, JournalEvent};

// These lifecycle tests inject a private temporary factory because the cloud
// sandbox does not provide the production-required UID0/1777 /tmp. This tests
// the exact copy/SQLite/cleanup implementation, NOT production temp admission.
fn private_test_temporary() -> Result<tempfile::TempDir, InspectionError> {
    tempfile::Builder::new()
        .prefix("vp-private-inspect-")
        .permissions(stdfs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .map_err(|_| InspectionError::Unavailable)
}
fn inspect_using_private_test_temp(
    root: impl AsRef<Path>,
    until: Instant,
) -> Result<ControlInspection, InspectionError> {
    inspect_with_temporary(root.as_ref(), until, |_| {
        private_test_temporary().map(Temporary::Default)
    })
}
#[test]
fn production_temporary_root_policy_accepts_only_root_owned_sticky_1777() {
    assert!(trusted_temporary_root(0, 0o41777));
    for (uid, mode) in [
        (1000, 0o40755),
        (1000, 0o41777),
        (0, 0o40755),
        (0, 0o40777),
        (0, 0o41755),
        (0, 0o43777),
    ] {
        assert!(!trusted_temporary_root(uid, mode));
    }
}
#[test]
fn production_entrypoint_enforces_actual_temporary_root_policy() {
    let root = fixture();
    let metadata = stdfs::metadata("/tmp").unwrap();
    let result = super::inspect_control_read_only(root.path(), deadline());
    if trusted_temporary_root(metadata.uid(), metadata.mode()) {
        assert!(result.is_ok());
    } else {
        assert!(matches!(result, Err(InspectionError::Unavailable)));
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn fixture() -> tempfile::TempDir {
    let root = crate::private_test_directory();
    drop(SqliteStore::open(root.path()).unwrap());
    root
}
fn target_manifest(root: &Path) -> BTreeMap<String, (u64, u64, u32, i64, i64, String)> {
    let owner = rustix::process::geteuid().as_raw();
    let root = open_root(root, owner, deadline()).unwrap();
    let mut result = BTreeMap::new();
    for entry in fs::Dir::read_from(&root).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_str().unwrap();
        if name == "." || name == ".." {
            continue;
        }
        let file = private_file(&root, name, owner).unwrap();
        let metadata = file.metadata().unwrap();
        result.insert(
            name.into(),
            (
                metadata.ino(),
                metadata.len(),
                metadata.mode(),
                metadata.mtime(),
                metadata.ctime(),
                hash_file(&file, deadline()).unwrap(),
            ),
        );
    }
    result
}
fn private_extra(root: &Path, name: &str) {
    stdfs::write(root.join(name), b"synthetic-only").unwrap();
    stdfs::set_permissions(root.join(name), stdfs::Permissions::from_mode(0o600)).unwrap();
}
#[test]
fn existing_default_delete_state_is_observed_without_target_changes() {
    let root = fixture();
    let before = target_manifest(root.path());
    let observation = inspect_using_private_test_temp(root.path(), deadline()).unwrap();
    assert_eq!(observation.receipt().sql_layout, 1);
    assert_eq!(observation.receipt().payload_format, 2);
    assert_eq!(observation.receipt().state_version, 0);
    assert_eq!(observation.receipt().active_revision, 0);
    observation.recheck(deadline()).unwrap();
    assert_eq!(target_manifest(root.path()), before);
    assert!(matches!(
        inspect_using_private_test_temp(root.path(), deadline()),
        Err(InspectionError::Busy)
    ));
}
#[test]
fn full_journal_and_payload_are_checked_under_existing_writer_exclusion() {
    let root = fixture();
    let store = SqliteStore::open(root.path()).unwrap();
    {
        let mut writer = store.writer().unwrap();
        assert!(matches!(
            inspect_using_private_test_temp(root.path(), deadline()),
            Err(InspectionError::Busy)
        ));
        let mut next = writer.state().clone();
        next.version += 1;
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
    }
    let before = target_manifest(root.path());
    assert_eq!(
        inspect_using_private_test_temp(root.path(), deadline())
            .unwrap()
            .receipt()
            .state_version,
        1
    );
    assert_eq!(target_manifest(root.path()), before);
    let connection = Connection::open(root.path().join(DB)).unwrap();
    connection
        .execute("DELETE FROM operation_journal", [])
        .unwrap();
    drop(connection);
    let before = target_manifest(root.path());
    assert!(matches!(
        inspect_using_private_test_temp(root.path(), deadline()),
        Err(InspectionError::Integrity)
    ));
    assert_eq!(target_manifest(root.path()), before);
}
#[test]
fn wal_shm_journal_and_unknown_entries_are_not_ignored_deleted_or_checkpointed() {
    for name in [
        "control.db-wal",
        "control.db-shm",
        "control.db-journal",
        ".pending",
        "foreign",
    ] {
        let root = fixture();
        private_extra(root.path(), name);
        let before = target_manifest(root.path());
        assert!(matches!(
            inspect_using_private_test_temp(root.path(), deadline()),
            Err(InspectionError::Unsupported | InspectionError::RecoveryRequired)
        ));
        assert_eq!(target_manifest(root.path()), before);
    }
}
#[test]
fn real_wal_mode_header_is_refused_even_after_sqlite_removes_sidecars() {
    let root = fixture();
    let connection = Connection::open(root.path().join(DB)).unwrap();
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    drop(connection);
    let before = target_manifest(root.path());
    assert!(matches!(
        inspect_using_private_test_temp(root.path(), deadline()),
        Err(InspectionError::Unsupported)
    ));
    assert_eq!(target_manifest(root.path()), before);
}
#[test]
fn missing_lock_or_db_never_causes_creation_or_new_authority() {
    for name in [DB, LOCK] {
        let root = fixture();
        stdfs::remove_file(root.path().join(name)).unwrap();
        let before = target_manifest(root.path());
        assert!(matches!(
            inspect_using_private_test_temp(root.path(), deadline()),
            Err(InspectionError::Missing)
        ));
        assert_eq!(target_manifest(root.path()), before);
    }
}
#[test]
fn target_symlinks_permissions_oversize_and_deadline_fail_closed() {
    let root = fixture();
    assert!(matches!(
        inspect_using_private_test_temp(root.path(), Instant::now()),
        Err(InspectionError::DeadlineExceeded)
    ));
    let alias_root = crate::private_test_directory();
    symlink(root.path(), alias_root.path().join("alias")).unwrap();
    assert!(matches!(
        inspect_using_private_test_temp(alias_root.path().join("alias"), deadline()),
        Err(InspectionError::PermissionDenied)
    ));
    stdfs::set_permissions(root.path().join(LOCK), stdfs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        inspect_using_private_test_temp(root.path(), deadline()),
        Err(InspectionError::PermissionDenied)
    ));
    stdfs::set_permissions(root.path().join(LOCK), stdfs::Permissions::from_mode(0o600)).unwrap();
    stdfs::remove_file(root.path().join(LOCK)).unwrap();
    symlink(root.path().join(DB), root.path().join(LOCK)).unwrap();
    assert!(matches!(
        inspect_using_private_test_temp(root.path(), deadline()),
        Err(InspectionError::PermissionDenied)
    ));
    let other = fixture();
    stdfs::OpenOptions::new()
        .write(true)
        .open(other.path().join(DB))
        .unwrap()
        .set_len(MAX_DB + 4096)
        .unwrap();
    assert!(matches!(
        inspect_using_private_test_temp(other.path(), deadline()),
        Err(InspectionError::LimitExceeded)
    ));
}
#[test]
fn payload_hash_corruption_and_foreign_schema_are_not_successful_observations() {
    let root = fixture();
    let connection = Connection::open(root.path().join(DB)).unwrap();
    connection
        .execute("UPDATE control_state SET digest=?1", ["f".repeat(64)])
        .unwrap();
    drop(connection);
    let before = target_manifest(root.path());
    assert!(matches!(
        inspect_using_private_test_temp(root.path(), deadline()),
        Err(InspectionError::Integrity)
    ));
    assert_eq!(target_manifest(root.path()), before);
    for sql in [
        "CREATE TABLE unknown_schema(x)",
        "CREATE TABLE sqliteXforeign(x)",
    ] {
        let other = fixture();
        let connection = Connection::open(other.path().join(DB)).unwrap();
        connection.execute(sql, []).unwrap();
        drop(connection);
        assert!(matches!(
            inspect_using_private_test_temp(other.path(), deadline()),
            Err(InspectionError::Unsupported)
        ));
    }
}
#[test]
fn protected_temporary_copy_is_ephemeral_and_cleanup_failure_is_not_swallowed() {
    let temporary = private_test_temporary().unwrap();
    let path = temporary.path().to_owned();
    let metadata = stdfs::metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o700);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert!(path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("vp-private-inspect-"));
    finish_temporary(Ok(()), temporary.close()).unwrap();
    assert!(!path.exists());
    let failed_cleanup = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        finish_temporary::<()>(Err(InspectionError::Integrity), Err(failed_cleanup)),
        Err(InspectionError::CleanupRequired)
    );
}
#[test]
fn nonconforming_changed_target_invalidates_the_held_observation() {
    let root = fixture();
    let observation = inspect_using_private_test_temp(root.path(), deadline()).unwrap();
    let mut bytes = stdfs::read(root.path().join(DB)).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    stdfs::write(root.path().join(DB), bytes).unwrap();
    assert!(matches!(
        observation.recheck(deadline()),
        Err(InspectionError::Integrity)
    ));
}
