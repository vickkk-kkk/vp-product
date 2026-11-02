use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};
use vp_product_control::ControlError;
use vp_product_domain::{SecretBytes, SecretRef};
use vp_product_runtime_executor::ImmutableSecretStore;

const SYNTHETIC: &[u8] = b"synthetic-test-only-credential-not-deployment";
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn key(byte: u8) -> MasterKey {
    MasterKey::new(SecretBytes::new(vec![byte; 32])).unwrap()
}
fn ns() -> Namespace {
    Namespace::new("synthetic-tests").unwrap()
}
fn reference(id: &str) -> SecretRef {
    SecretRef::new(id).unwrap()
}
fn secret() -> SecretBytes {
    SecretBytes::new(SYNTHETIC.to_vec())
}
fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn initialize(root: &Path) -> DurableSecretStore {
    DurableSecretStore::initialize(root, ns(), key(17), Limits::default(), deadline()).unwrap()
}
fn reopen(root: &Path) -> Result<DurableSecretStore, VaultError> {
    DurableSecretStore::open(root, ns(), key(17), deadline())
}
fn record_path(root: &Path, reference: &SecretRef) -> PathBuf {
    root.join(format!(
        "{:x}.record",
        Sha256::digest(reference.as_str().as_bytes())
    ))
}
fn put(store: &DurableSecretStore, reference: &SecretRef) {
    store
        .put(reference, SecretKind::Credential, 1, secret(), deadline())
        .unwrap();
}
fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn durable_exact_roundtrip_has_only_encrypted_plaintext_on_disk() {
    let dir = directory();
    let r = reference("credential-v1");
    let store = initialize(dir.path());
    put(&store, &r);
    assert_eq!(
        store
            .get_exact(&r, SecretKind::Credential, 1, deadline())
            .unwrap()
            .expose(),
        SYNTHETIC
    );
    for entry in fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.windows(SYNTHETIC.len()).any(|w| w == SYNTHETIC));
        assert!(!bytes.windows(32).any(|w| w == [17; 32]));
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    drop(store);
    let store = reopen(dir.path()).unwrap();
    assert_eq!(
        store.resolve_immutable(&r, deadline()).unwrap().expose(),
        SYNTHETIC
    );
}

#[test]
fn wrong_key_and_namespace_never_reinitialize_or_modify_vault() {
    let dir = directory();
    let r = reference("original");
    let store = initialize(dir.path());
    put(&store, &r);
    drop(store);
    let before = fs::read(dir.path().join("vault.v1")).unwrap();
    assert!(matches!(
        DurableSecretStore::open(dir.path(), ns(), key(18), deadline()),
        Err(VaultError::Integrity)
    ));
    assert!(matches!(
        DurableSecretStore::open(
            dir.path(),
            Namespace::new("other").unwrap(),
            key(17),
            deadline()
        ),
        Err(VaultError::Integrity)
    ));
    assert!(matches!(
        DurableSecretStore::initialize(dir.path(), ns(), key(17), Limits::default(), deadline()),
        Err(VaultError::AlreadyExists)
    ));
    assert_eq!(fs::read(dir.path().join("vault.v1")).unwrap(), before);
    assert_eq!(
        reopen(dir.path())
            .unwrap()
            .get(&r, deadline())
            .unwrap()
            .bytes
            .expose(),
        SYNTHETIC
    );
}

#[test]
fn immutable_duplicates_rotation_retirement_and_tombstones_survive_reopen() {
    let dir = directory();
    let first = reference("user-v1");
    let second = reference("user-v2");
    let store = initialize(dir.path());
    put(&store, &first);
    for version in [1, 2, u64::MAX] {
        assert_eq!(
            store.put(
                &first,
                SecretKind::Credential,
                version,
                secret(),
                deadline()
            ),
            Err(VaultError::AlreadyExists)
        );
    }
    store
        .put(
            &second,
            SecretKind::Credential,
            2,
            SecretBytes::new(b"second-synthetic-credential".to_vec()),
            deadline(),
        )
        .unwrap();
    assert_eq!(
        store.retire(&first, SecretKind::PrivateKey, 1, deadline()),
        Err(VaultError::MetadataMismatch)
    );
    store
        .retire(&first, SecretKind::Credential, 1, deadline())
        .unwrap();
    store
        .retire(&first, SecretKind::Credential, 1, deadline())
        .unwrap();
    assert!(matches!(
        store.get(&first, deadline()),
        Err(VaultError::Retired)
    ));
    drop(store);
    let store = reopen(dir.path()).unwrap();
    assert!(matches!(
        store.get(&first, deadline()),
        Err(VaultError::Retired)
    ));
    assert_eq!(
        store.put(&first, SecretKind::Credential, 3, secret(), deadline()),
        Err(VaultError::AlreadyExists)
    );
    assert_eq!(store.get(&second, deadline()).unwrap().version, 2);
    assert!(record_path(dir.path(), &first).is_file()); // retention is explicit, not secure erasure
}

#[test]
fn typed_resolution_and_runtime_port_refuse_kind_or_version_confusion() {
    let dir = directory();
    let store = initialize(dir.path());
    let r = reference("key-v7");
    store
        .put(&r, SecretKind::PrivateKey, 7, secret(), deadline())
        .unwrap();
    assert!(matches!(
        store.get_exact(&r, SecretKind::Credential, 7, deadline()),
        Err(VaultError::MetadataMismatch)
    ));
    assert!(matches!(
        store.get_exact(&r, SecretKind::PrivateKey, 8, deadline()),
        Err(VaultError::MetadataMismatch)
    ));
    assert_eq!(
        store.validate_immutable(&r, deadline()),
        Err(ControlError::InvalidConfiguration)
    );
    assert!(matches!(
        store.resolve_immutable(&r, deadline()),
        Err(ControlError::InvalidConfiguration)
    ));
    assert!(store
        .get_exact(&r, SecretKind::PrivateKey, 7, deadline())
        .is_ok());
}

#[test]
fn no_secrets_or_references_in_debug_errors() {
    let bytes = secret();
    let master = key(17);
    let namespace = ns();
    assert_eq!(format!("{bytes:?}"), "SecretBytes([REDACTED])");
    assert_eq!(format!("{master:?}"), "MasterKey([REDACTED])");
    assert_eq!(format!("{namespace:?}"), "Namespace([REDACTED])");
    for error in [
        VaultError::Integrity,
        VaultError::StorageUnavailable,
        VaultError::PermissionDenied,
    ] {
        assert!(!format!("{error:?}: {error}").contains("synthetic"));
    }
}

#[test]
fn invalid_namespace_key_ref_version_and_empty_secret_fail_before_writes() {
    for value in [
        "",
        "../vault",
        "/tmp/vault",
        "a/b",
        "a\\b",
        "Capital",
        ".",
        "a\0b",
    ] {
        assert!(Namespace::new(value).is_err());
    }
    assert!(Namespace::new(&"a".repeat(65)).is_err());
    for size in [0, 1, 31, 33, 128] {
        assert!(MasterKey::new(SecretBytes::new(vec![0; size])).is_err());
    }
    for value in ["../a", "a/b", "/absolute", "a\0b"] {
        assert!(SecretRef::new(value).is_err());
    }
    let dir = directory();
    let store = initialize(dir.path());
    let r = reference("test");
    assert_eq!(
        store.put(&r, SecretKind::Credential, 0, secret(), deadline()),
        Err(VaultError::InvalidInput)
    );
    assert_eq!(
        store.put(
            &r,
            SecretKind::Credential,
            1,
            SecretBytes::new(vec![]),
            deadline()
        ),
        Err(VaultError::InvalidInput)
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn missing_expired_and_concurrent_open_fail_closed() {
    let dir = directory();
    let store = initialize(dir.path());
    let r = reference("missing");
    assert!(matches!(
        store.get(&r, deadline()),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        store.resolve_immutable(&r, deadline()),
        Err(ControlError::NotFound)
    ));
    assert!(matches!(reopen(dir.path()), Err(VaultError::Busy)));
    let expired = Instant::now() - Duration::from_secs(1);
    assert_eq!(
        store.put(&r, SecretKind::Credential, 1, secret(), expired),
        Err(VaultError::DeadlineExceeded)
    );
    assert!(matches!(
        store.resolve_immutable(&r, expired),
        Err(ControlError::ExecutorUnavailable)
    ));
    assert!(matches!(
        DurableSecretStore::open(dir.path(), ns(), key(17), expired),
        Err(VaultError::DeadlineExceeded)
    ));
}

#[test]
fn ciphertext_nonce_metadata_and_unknown_versions_are_authenticated_or_refused() {
    // Mutate each class of header field plus ciphertext/tag separately.
    for offset in [0, 8, 10, 11, 12, 19, 20, 35, 36, 38, 49, 50, 70, 90] {
        let dir = directory();
        let r = reference("test-record");
        let store = initialize(dir.path());
        put(&store, &r);
        drop(store);
        let path = record_path(dir.path(), &r);
        let mut bytes = fs::read(&path).unwrap();
        let index = offset.min(bytes.len() - 1);
        bytes[index] ^= 0x80;
        fs::write(path, bytes).unwrap();
        assert!(
            matches!(
                reopen(dir.path()),
                Err(VaultError::Integrity | VaultError::UnsupportedVersion)
            ),
            "offset {offset}"
        );
    }
}

#[test]
fn committed_truncation_and_oversize_are_not_treated_as_absence() {
    for length in [0, 1, 49, 50, 65, 66, 70] {
        let dir = directory();
        let r = reference("truncated");
        let store = initialize(dir.path());
        put(&store, &r);
        drop(store);
        let path = record_path(dir.path(), &r);
        let bytes = fs::read(&path).unwrap();
        fs::write(path, &bytes[..length]).unwrap();
        assert!(matches!(reopen(dir.path()), Err(VaultError::Integrity)));
    }
    let dir = directory();
    let r = reference("oversize");
    let store = initialize(dir.path());
    put(&store, &r);
    drop(store);
    fs::OpenOptions::new()
        .write(true)
        .open(record_path(dir.path(), &r))
        .unwrap()
        .set_len(10 * 1024 * 1024)
        .unwrap();
    assert!(matches!(reopen(dir.path()), Err(VaultError::LimitExceeded)));
}

#[test]
fn copied_records_cannot_change_refs_or_cross_vault_identity() {
    let dir = directory();
    let a = reference("a");
    let b = reference("b");
    let store = initialize(dir.path());
    put(&store, &a);
    drop(store);
    fs::rename(record_path(dir.path(), &a), record_path(dir.path(), &b)).unwrap();
    assert!(matches!(reopen(dir.path()), Err(VaultError::Integrity)));
    let one = directory();
    let two = directory();
    let store = initialize(one.path());
    put(&store, &a);
    drop(store);
    drop(initialize(two.path()));
    fs::copy(record_path(one.path(), &a), record_path(two.path(), &a)).unwrap();
    assert!(matches!(reopen(two.path()), Err(VaultError::Integrity)));
}

#[test]
fn root_ancestors_files_and_staging_refuse_symlinks() {
    let parent = directory();
    let real = parent.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&real, parent.path().join("alias")).unwrap();
    assert!(matches!(
        DurableSecretStore::initialize(
            parent.path().join("alias"),
            ns(),
            key(17),
            Limits::default(),
            deadline()
        ),
        Err(VaultError::PermissionDenied)
    ));
    let child = real.join("child");
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        DurableSecretStore::initialize(
            parent.path().join("alias/child"),
            ns(),
            key(17),
            Limits::default(),
            deadline()
        ),
        Err(VaultError::PermissionDenied)
    ));
    let store = initialize(&child);
    let r = reference("test");
    put(&store, &r);
    drop(store);
    let record = record_path(&child, &r);
    let outside = parent.path().join("external");
    fs::rename(&record, &outside).unwrap();
    symlink(&outside, &record).unwrap();
    assert!(matches!(reopen(&child), Err(VaultError::PermissionDenied)));
    fs::remove_file(&record).unwrap();
    fs::rename(&outside, &record).unwrap();
    symlink(&record, child.join(".pending")).unwrap();
    assert!(matches!(reopen(&child), Err(VaultError::PermissionDenied)));
    fs::remove_file(child.join(".pending")).unwrap();
    let manifest = child.join("vault.v1");
    fs::rename(&manifest, &outside).unwrap();
    symlink(&outside, &manifest).unwrap();
    assert!(matches!(reopen(&child), Err(VaultError::PermissionDenied)));
}

#[test]
fn insecure_modes_hardlinks_special_files_and_parent_traversal_are_refused() {
    let dir = directory();
    let store = initialize(dir.path());
    let r = reference("test");
    put(&store, &r);
    drop(store);
    let path = record_path(dir.path(), &r);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        reopen(dir.path()),
        Err(VaultError::PermissionDenied)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, dir.path().join("another-link")).unwrap();
    assert!(matches!(
        reopen(dir.path()),
        Err(VaultError::Integrity | VaultError::PermissionDenied)
    ));
    fs::remove_file(dir.path().join("another-link")).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(
        reopen(dir.path()),
        Err(VaultError::PermissionDenied)
    ));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        reopen(&dir.path().join(".")),
        Err(VaultError::InvalidInput)
    ));
    assert!(matches!(
        reopen(&dir.path().join("../")),
        Err(VaultError::InvalidInput)
    ));
    assert!(matches!(
        reopen(Path::new("relative")),
        Err(VaultError::InvalidInput)
    ));
    fs::remove_file(path.clone()).unwrap();
    fs::create_dir(path).unwrap();
    assert!(matches!(
        reopen(dir.path()),
        Err(VaultError::PermissionDenied)
    ));
}

#[test]
fn directory_descriptor_does_not_follow_replaced_root_path() {
    let parent = directory();
    let root = parent.path().join("root");
    let moved = parent.path().join("moved");
    let other = parent.path().join("other");
    for path in [&root, &other] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = initialize(&root);
    let r = reference("anchored");
    put(&store, &r);
    fs::rename(&root, &moved).unwrap();
    symlink(&other, &root).unwrap();
    assert_eq!(store.get(&r, deadline()).unwrap().bytes.expose(), SYNTHETIC);
    assert_eq!(fs::read_dir(&other).unwrap().count(), 0);
    put(&store, &reference("still-anchored"));
    assert_eq!(fs::read_dir(&moved).unwrap().count(), 3);
}

#[test]
fn authenticated_reopen_cleans_only_bounded_incomplete_staging() {
    let dir = directory();
    let store = initialize(dir.path());
    let r = reference("good");
    put(&store, &r);
    drop(store);
    write_private(&dir.path().join(".pending"), b"incomplete encrypted stage");
    assert!(matches!(
        DurableSecretStore::open(dir.path(), ns(), key(18), deadline()),
        Err(VaultError::Integrity)
    ));
    assert!(dir.path().join(".pending").exists());
    let store = reopen(dir.path()).unwrap();
    assert!(!dir.path().join(".pending").exists());
    assert!(store.get(&r, deadline()).is_ok());
    drop(store);
    write_private(&dir.path().join("unknown-file"), b"unrecognized");
    assert!(matches!(reopen(dir.path()), Err(VaultError::Integrity)));
    let fresh = directory();
    write_private(&fresh.path().join(".pending"), b"partial initial manifest");
    assert!(matches!(
        DurableSecretStore::initialize(fresh.path(), ns(), key(17), Limits::default(), deadline()),
        Err(VaultError::RecoveryRequired)
    ));
}

#[test]
fn interrupted_publication_never_serves_partial_records_or_reuses_committed_refs() {
    for point in 1..=4 {
        let dir = directory();
        let store = initialize(dir.path());
        let r = reference("interrupted");
        store.inject_fault(point);
        assert_eq!(
            store.put(&r, SecretKind::Credential, 1, secret(), deadline()),
            Err(VaultError::RecoveryRequired)
        );
        assert!(matches!(
            store.get(&r, deadline()),
            Err(VaultError::RecoveryRequired)
        ));
        drop(store);
        let store = reopen(dir.path()).unwrap();
        if point <= 2 {
            assert!(matches!(
                store.get(&r, deadline()),
                Err(VaultError::NotFound)
            ));
            put(&store, &r);
        } else {
            assert_eq!(store.get(&r, deadline()).unwrap().bytes.expose(), SYNTHETIC);
            assert_eq!(
                store.put(&r, SecretKind::Credential, 1, secret(), deadline()),
                Err(VaultError::AlreadyExists)
            );
        }
        assert!(!dir.path().join(".pending").exists());
    }
}

#[test]
fn interrupted_retirement_is_resolved_by_authenticated_committed_tombstone() {
    for point in 1..=4 {
        let dir = directory();
        let r = reference("old");
        let store = initialize(dir.path());
        put(&store, &r);
        store.inject_fault(point);
        assert_eq!(
            store.retire(&r, SecretKind::Credential, 1, deadline()),
            Err(VaultError::RecoveryRequired)
        );
        drop(store);
        let store = reopen(dir.path()).unwrap();
        if point <= 2 {
            assert!(store.get(&r, deadline()).is_ok());
            store
                .retire(&r, SecretKind::Credential, 1, deadline())
                .unwrap();
        } else {
            assert!(matches!(
                store.get(&r, deadline()),
                Err(VaultError::Retired)
            ));
        }
        assert_eq!(
            store.put(&r, SecretKind::Credential, 2, secret(), deadline()),
            Err(VaultError::AlreadyExists)
        );
    }
}

#[test]
fn byte_count_record_count_and_retirement_reserve_are_bounded() {
    let dir = directory();
    let limits = Limits {
        max_secret_bytes: 32,
        max_records: 1,
        max_total_bytes: 4096,
        min_free_bytes: 0,
    };
    let store =
        DurableSecretStore::initialize(dir.path(), ns(), key(17), limits, deadline()).unwrap();
    let a = reference("a");
    assert_eq!(
        store.put(
            &a,
            SecretKind::Credential,
            1,
            SecretBytes::new(vec![1; 33]),
            deadline()
        ),
        Err(VaultError::InvalidInput)
    );
    store
        .put(
            &a,
            SecretKind::Credential,
            1,
            SecretBytes::new(vec![1; 32]),
            deadline(),
        )
        .unwrap();
    store
        .retire(&a, SecretKind::Credential, 1, deadline())
        .unwrap();
    assert_eq!(
        store.put(
            &reference("b"),
            SecretKind::Credential,
            1,
            SecretBytes::new(vec![2]),
            deadline()
        ),
        Err(VaultError::LimitExceeded)
    );
    drop(store);
    assert_eq!(reopen(dir.path()).unwrap().limits(), limits);
    let dir = directory();
    let limits = Limits {
        max_secret_bytes: 4096,
        max_records: 100,
        max_total_bytes: 4096,
        min_free_bytes: 0,
    };
    let store =
        DurableSecretStore::initialize(dir.path(), ns(), key(17), limits, deadline()).unwrap();
    assert_eq!(
        store.put(
            &a,
            SecretKind::Credential,
            1,
            SecretBytes::new(vec![1; 3900]),
            deadline()
        ),
        Err(VaultError::LimitExceeded)
    );
    store
        .put(
            &a,
            SecretKind::Credential,
            1,
            SecretBytes::new(vec![1; 3700]),
            deadline(),
        )
        .unwrap();
    store
        .retire(&a, SecretKind::Credential, 1, deadline())
        .unwrap();
    assert!(
        fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum::<u64>()
            <= 4096
    );
}

#[test]
fn disk_reserve_preflight_refuses_without_publishing_manifest() {
    let dir = directory();
    let limits = Limits {
        min_free_bytes: 1024 * 1024 * 1024 * 1024,
        ..Limits::default()
    };
    assert!(matches!(
        DurableSecretStore::initialize(dir.path(), ns(), key(17), limits, deadline()),
        Err(VaultError::LimitExceeded)
    ));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn concurrent_put_reserves_exactly_one_immutable_reference() {
    let dir = directory();
    let store = Arc::new(initialize(dir.path()));
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.put(
                    &reference("same"),
                    SecretKind::Credential,
                    1,
                    secret(),
                    deadline(),
                )
            })
        })
        .collect();
    let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(outcomes.iter().all(|r| matches!(
        r,
        Ok(()) | Err(VaultError::Busy | VaultError::AlreadyExists)
    )));
    assert!(store.get(&reference("same"), deadline()).is_ok());
}

#[test]
fn changed_live_record_is_not_returned_from_a_plaintext_cache() {
    let dir = directory();
    let store = initialize(dir.path());
    let r = reference("mutated");
    put(&store, &r);
    let path = record_path(dir.path(), &r);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(matches!(
        store.get(&r, deadline()),
        Err(VaultError::Integrity)
    ));
}

#[test]
fn tombstone_tamper_or_orphan_never_revives_a_credential() {
    for orphan in [false, true] {
        let dir = directory();
        let store = initialize(dir.path());
        let r = reference("retired");
        put(&store, &r);
        store
            .retire(&r, SecretKind::Credential, 1, deadline())
            .unwrap();
        drop(store);
        if orphan {
            fs::remove_file(record_path(dir.path(), &r)).unwrap();
        } else {
            let path = dir.path().join(format!(
                "{:x}.retired",
                Sha256::digest(r.as_str().as_bytes())
            ));
            let mut bytes = fs::read(&path).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            fs::write(path, bytes).unwrap();
        }
        assert!(matches!(reopen(dir.path()), Err(VaultError::Integrity)));
    }
}

#[test]
fn manifest_format_policy_and_authenticated_known_metadata_changes_fail_closed() {
    for offset in [8usize, 70, 89] {
        let dir = directory();
        drop(initialize(dir.path()));
        let path = dir.path().join("vault.v1");
        let mut bytes = fs::read(&path).unwrap();
        bytes[offset] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(matches!(
            reopen(dir.path()),
            Err(VaultError::Integrity | VaultError::UnsupportedVersion)
        ));
    }
    for (offset, value) in [(11usize, 2u8), (19, 2), (50 + 7, b'b')] {
        let dir = directory();
        let r = reference("aaaaaaaa");
        let store = initialize(dir.path());
        put(&store, &r);
        drop(store);
        let path = record_path(dir.path(), &r);
        let mut bytes = fs::read(&path).unwrap();
        bytes[offset] = value;
        fs::write(path, bytes).unwrap();
        assert!(matches!(reopen(dir.path()), Err(VaultError::Integrity)));
    }
}

#[test]
fn record_and_tombstone_encryption_use_distinct_nonces() {
    let dir = directory();
    let store = initialize(dir.path());
    for index in 0..64 {
        let r = reference(&format!("nonce-test-{index}"));
        put(&store, &r);
        store
            .retire(&r, SecretKind::Credential, 1, deadline())
            .unwrap();
    }
    let mut nonces = std::collections::BTreeSet::new();
    for entry in fs::read_dir(dir.path()).unwrap() {
        let encoded = fs::read(entry.unwrap().path()).unwrap();
        assert!(nonces.insert(encoded[38..50].to_vec()));
    }
    assert_eq!(nonces.len(), 129);
}

#[test]
fn group_writable_ancestor_and_changed_root_mode_are_refused() {
    let parent = directory();
    let root = parent.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        DurableSecretStore::initialize(&root, ns(), key(17), Limits::default(), deadline()),
        Err(VaultError::PermissionDenied)
    ));
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = initialize(&root);
    let r = reference("root-mode");
    put(&store, &r);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        store.get(&r, deadline()),
        Err(VaultError::PermissionDenied)
    ));
}

#[test]
fn fifo_record_is_rejected_without_blocking_or_reading() {
    let dir = directory();
    let r = reference("fifo");
    let store = initialize(dir.path());
    put(&store, &r);
    drop(store);
    let path = record_path(dir.path(), &r);
    fs::remove_file(&path).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .unwrap();
    let start = Instant::now();
    assert!(matches!(
        reopen(dir.path()),
        Err(VaultError::PermissionDenied)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
}

fn directory_identity(root: &Path) -> VaultDirectoryIdentity {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(root).unwrap();
    VaultDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}
#[test]
fn bound_init_checks_actual_opened_directory_before_any_write() {
    let parent = directory();
    let original = parent.path().join("vault");
    let moved = parent.path().join("original");
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    let expected = directory_identity(&original);
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        DurableSecretStore::initialize_bound(
            &original,
            ns(),
            key(17),
            Limits::default(),
            expected,
            deadline()
        ),
        Err(VaultError::MetadataMismatch)
    ));
    assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
    fs::remove_dir(&original).unwrap();
    fs::rename(&moved, &original).unwrap();
    let store = DurableSecretStore::initialize_bound(
        &original,
        ns(),
        key(17),
        Limits::default(),
        expected,
        deadline(),
    )
    .unwrap();
    assert!(store.inspect_read_only(deadline()).is_ok());
}
#[test]
fn bound_init_refuses_wrong_device_inode_and_insecure_mode_without_writes() {
    let root = directory();
    let expected = directory_identity(root.path());
    for mismatch in [
        VaultDirectoryIdentity {
            device: expected.device ^ 1,
            ..expected
        },
        VaultDirectoryIdentity {
            inode: expected.inode ^ 1,
            ..expected
        },
    ] {
        assert!(matches!(
            DurableSecretStore::initialize_bound(
                root.path(),
                ns(),
                key(17),
                Limits::default(),
                mismatch,
                deadline()
            ),
            Err(VaultError::MetadataMismatch)
        ));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        DurableSecretStore::initialize_bound(
            root.path(),
            ns(),
            key(17),
            Limits::default(),
            expected,
            deadline()
        ),
        Err(VaultError::PermissionDenied)
    ));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}
#[test]
fn bound_init_expired_and_busy_requests_preserve_empty_directory() {
    let root = directory();
    let expected = directory_identity(root.path());
    assert!(matches!(
        DurableSecretStore::initialize_bound(
            root.path(),
            ns(),
            key(17),
            Limits::default(),
            expected,
            Instant::now()
        ),
        Err(VaultError::DeadlineExceeded)
    ));
    let _held = crate::filesystem::Directory::open(root.path(), deadline()).unwrap();
    assert!(matches!(
        DurableSecretStore::initialize_bound(
            root.path(),
            ns(),
            key(17),
            Limits::default(),
            expected,
            deadline()
        ),
        Err(VaultError::Busy)
    ));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}
#[test]
fn bound_descriptor_after_check_never_follows_replaced_root_path() {
    let parent = directory();
    let original = parent.path().join("vault");
    let moved = parent.path().join("original");
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    let expected = directory_identity(&original);
    let directory = crate::filesystem::Directory::open(&original, deadline()).unwrap();
    directory.require_identity(expected).unwrap();
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    directory
        .publish("bound-test", b"synthetic", deadline())
        .unwrap();
    assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
    assert_eq!(fs::read(moved.join("bound-test")).unwrap(), b"synthetic");
}

fn instance_binding(store: &DurableSecretStore) -> vp_product_control::InstanceBinding {
    use vp_product_control::{ContentDigest, InstanceBinding, FRESH_ADMIN_PROFILE};
    let observed = store.inspect_read_only(deadline()).unwrap();
    InstanceBinding {
        binding_version: 1,
        genesis_id: "1".repeat(32),
        vault_id: observed.vault_id,
        namespace_digest: ContentDigest::parse(observed.namespace_digest).unwrap(),
        administrator_commitment: ContentDigest::bytes(b"synthetic-administrator"),
        preparation_digest: ContentDigest::bytes(b"prepare"),
        activation_intent_digest: ContentDigest::bytes(b"intent"),
        artifact_set_digest: ContentDigest::bytes(b"artifact"),
        profile: FRESH_ADMIN_PROFILE.into(),
    }
}
#[test]
fn instance_claim_is_once_encrypted_reserved_and_reopens_exactly() {
    let dir = directory();
    let store = initialize(dir.path());
    let binding = instance_binding(&store);
    store.require_manifest_only(deadline()).unwrap();
    let manifest = fs::read(dir.path().join("vault.v1")).unwrap();
    store.claim_instance_binding(&binding, deadline()).unwrap();
    assert!(store.require_manifest_only(deadline()).is_err());
    assert!(store.instance_binding(deadline()).unwrap() == binding);
    assert!(store.claim_instance_binding(&binding, deadline()).is_err());
    let reserved = reference("vp-instance-binding-v1");
    assert!(store.get(&reserved, deadline()).is_err());
    assert!(store
        .put(&reserved, SecretKind::Credential, 1, secret(), deadline())
        .is_err());
    assert!(store
        .put(
            &reference("other"),
            SecretKind::InstanceBinding,
            1,
            secret(),
            deadline()
        )
        .is_err());
    assert!(store
        .retire(&reserved, SecretKind::InstanceBinding, 1, deadline())
        .is_err());
    assert_eq!(manifest, fs::read(dir.path().join("vault.v1")).unwrap());
    let bytes = fs::read(record_path(dir.path(), &reserved)).unwrap();
    assert!(!bytes
        .windows(binding.genesis_id.len())
        .any(|w| w == binding.genesis_id.as_bytes()));
    drop(store);
    assert!(reopen(dir.path()).is_err());
    let store = DurableSecretStore::open_fresh_profile(
        dir.path(),
        ns(),
        key(17),
        directory_identity(dir.path()),
        deadline(),
    )
    .unwrap();
    assert!(store.instance_binding(deadline()).unwrap() == binding);
}
#[test]
fn instance_claim_rejects_nonempty_and_wrong_vault_without_write() {
    let a = directory();
    let b = directory();
    let store = initialize(a.path());
    let other = initialize(b.path());
    let binding = instance_binding(&other);
    assert!(store.claim_instance_binding(&binding, deadline()).is_err());
    assert_eq!(fs::read_dir(a.path()).unwrap().count(), 1);
    let binding = instance_binding(&store);
    put(&store, &reference("existing"));
    assert!(store.require_manifest_only(deadline()).is_err());
    assert!(store.claim_instance_binding(&binding, deadline()).is_err());
    store
        .retire(
            &reference("existing"),
            SecretKind::Credential,
            1,
            deadline(),
        )
        .unwrap();
    assert!(store.require_manifest_only(deadline()).is_err());
    assert!(store.claim_instance_binding(&binding, deadline()).is_err());
    assert!(store.instance_binding(deadline()).is_err());
}

#[test]
fn legacy_open_cannot_repair_or_adopt_fresh_binding() {
    let dir = directory();
    let store = initialize(dir.path());
    store
        .claim_instance_binding(&instance_binding(&store), deadline())
        .unwrap();
    drop(store);
    write_private(
        &dir.path().join(crate::filesystem::PENDING),
        b"synthetic-partial-evidence",
    );
    let snapshot = || {
        let mut entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| {
                let path = e.unwrap().path();
                (
                    path.file_name().unwrap().to_owned(),
                    fs::read(&path).unwrap(),
                )
            })
            .collect();
        entries.sort();
        entries
    };
    let before = snapshot();
    assert!(reopen(dir.path()).is_err());
    assert_eq!(before, snapshot());
    assert!(DurableSecretStore::open_fresh_profile(
        dir.path(),
        ns(),
        key(17),
        directory_identity(dir.path()),
        deadline()
    )
    .is_err());
    assert_eq!(before, snapshot());
}
