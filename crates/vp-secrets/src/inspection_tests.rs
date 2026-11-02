#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::DurableSecretStore;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    time::Duration,
};
use vp_product_domain::SecretBytes;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn namespace() -> Namespace {
    Namespace::new("offline-inspection-tests").unwrap()
}
fn key(byte: u8) -> MasterKey {
    MasterKey::new(SecretBytes::new(vec![byte; 32])).unwrap()
}
fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn initialize(root: &Path) -> DurableSecretStore {
    DurableSecretStore::initialize(root, namespace(), key(19), Limits::default(), deadline())
        .unwrap()
}
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}
#[test]
fn cold_and_held_inspection_match_without_target_file_changes() {
    let root = private_root();
    let store = initialize(root.path());
    let receipt = store.inspect_read_only(deadline()).unwrap();
    assert_eq!(receipt.vault_id.len(), 32);
    assert_eq!(receipt.format_version, 1);
    assert!(matches!(
        inspect_vault_read_only(root.path(), namespace(), key(19), deadline()),
        Err(VaultError::Busy)
    ));
    drop(store);
    let before = snapshot(root.path());
    let inspection =
        inspect_vault_read_only(root.path(), namespace(), key(19), deadline()).unwrap();
    assert_eq!(*inspection.receipt(), receipt);
    assert_eq!(snapshot(root.path()), before);
    assert!(!format!("{:?}", inspection.receipt()).contains("secret:"));
}
#[test]
fn pending_staging_is_never_removed_or_repaired_by_inspection() {
    let root = private_root();
    drop(initialize(root.path()));
    let pending = root.path().join(PENDING);
    fs::write(&pending, b"synthetic incomplete ciphertext").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    let before = snapshot(root.path());
    assert!(matches!(
        inspect_vault_read_only(root.path(), namespace(), key(19), deadline()),
        Err(VaultError::RecoveryRequired)
    ));
    assert_eq!(snapshot(root.path()), before);
}
#[test]
fn wrong_key_and_unknown_files_fail_without_repair_or_partial_receipt() {
    let root = private_root();
    drop(initialize(root.path()));
    let before = snapshot(root.path());
    assert!(matches!(
        inspect_vault_read_only(root.path(), namespace(), key(20), deadline()),
        Err(VaultError::Integrity)
    ));
    assert_eq!(snapshot(root.path()), before);
    let unknown = root.path().join("unknown");
    fs::write(&unknown, b"synthetic").unwrap();
    fs::set_permissions(&unknown, fs::Permissions::from_mode(0o600)).unwrap();
    let before = snapshot(root.path());
    assert!(matches!(
        inspect_vault_read_only(root.path(), namespace(), key(19), deadline()),
        Err(VaultError::Integrity)
    ));
    assert_eq!(snapshot(root.path()), before);
}
#[test]
fn ciphertext_inventory_changes_on_retirement_but_is_not_a_monotonic_watermark() {
    let root = private_root();
    let store = initialize(root.path());
    let reference = SecretRef::new("synthetic-only").unwrap();
    store
        .put(
            &reference,
            SecretKind::Credential,
            3,
            SecretBytes::new(b"inspection-test-only-not-deployment".to_vec()),
            deadline(),
        )
        .unwrap();
    let before = store.inspect_read_only(deadline()).unwrap();
    store
        .retire(&reference, SecretKind::Credential, 3, deadline())
        .unwrap();
    let after = store.inspect_read_only(deadline()).unwrap();
    assert_eq!(before.vault_id, after.vault_id);
    assert_eq!(before.manifest_digest, after.manifest_digest);
    assert_ne!(before.inventory_digest, after.inventory_digest);
    assert!(!format!("{after:?}").contains("inspection-test-only-not-deployment"));
    drop(store);
    assert_eq!(
        *inspect_vault_read_only(root.path(), namespace(), key(19), deadline())
            .unwrap()
            .receipt(),
        after
    );
}
#[test]
fn missing_expired_permissions_and_symlink_roots_are_refused() {
    let root = private_root();
    assert!(matches!(
        inspect_vault_read_only(root.path(), namespace(), key(19), deadline()),
        Err(VaultError::NotFound)
    ));
    assert!(snapshot(root.path()).is_empty());
    drop(initialize(root.path()));
    assert!(matches!(
        inspect_vault_read_only(root.path(), namespace(), key(19), Instant::now()),
        Err(VaultError::DeadlineExceeded)
    ));
    let parent = private_root();
    let alias = parent.path().join("alias");
    symlink(root.path(), &alias).unwrap();
    assert!(matches!(
        inspect_vault_read_only(&alias, namespace(), key(19), deadline()),
        Err(VaultError::PermissionDenied)
    ));
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(
        inspect_vault_read_only(root.path(), namespace(), key(19), deadline()),
        Err(VaultError::PermissionDenied)
    ));
}

#[test]
fn bound_readonly_observation_checks_actual_opened_directory_before_reading() {
    use std::os::unix::fs::MetadataExt;
    let root = private_root();
    drop(initialize(root.path()));
    let md = fs::metadata(root.path()).unwrap();
    let expected = (md.dev(), md.ino());
    let seen = inspect_vault_read_only_at_identity(
        root.path(),
        namespace(),
        key(19),
        expected,
        deadline(),
    )
    .unwrap();
    drop(seen);
    let before = snapshot(root.path());
    assert!(matches!(
        inspect_vault_read_only_at_identity(
            root.path(),
            namespace(),
            key(19),
            (expected.0, expected.1 + 1),
            deadline()
        ),
        Err(VaultError::MetadataMismatch)
    ));
    assert_eq!(snapshot(root.path()), before);
    let parent = private_root();
    let path = parent.path().join("vault");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let old = fs::metadata(&path).unwrap();
    let moved = parent.path().join("old");
    fs::rename(&path, &moved).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        inspect_vault_read_only_at_identity(
            &path,
            namespace(),
            key(19),
            (old.dev(), old.ino()),
            deadline()
        ),
        Err(VaultError::MetadataMismatch)
    ));
    assert!(snapshot(&path).is_empty());
}

#[test]
fn bound_readonly_keeps_descriptor_identity_after_path_replacement() {
    use std::os::unix::fs::MetadataExt;
    let parent = private_root();
    let original = parent.path().join("vault");
    let moved = parent.path().join("moved");
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    drop(initialize(&original));
    let metadata = fs::metadata(&original).unwrap();
    let expected = (metadata.dev(), metadata.ino());
    let before = snapshot(&original);
    let seen =
        inspect_vault_read_only_at_identity(&original, namespace(), key(19), expected, deadline())
            .unwrap();
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(seen._directory.opened_identity().unwrap(), expected);
    assert!(matches!(
        inspect_vault_read_only(&moved, namespace(), key(19), deadline()),
        Err(VaultError::Busy)
    ));
    assert!(matches!(
        inspect_vault_read_only_at_identity(&original, namespace(), key(19), expected, deadline()),
        Err(VaultError::MetadataMismatch)
    ));
    assert_eq!(snapshot(&moved), before);
    assert!(snapshot(&original).is_empty());
    drop(seen);
}
