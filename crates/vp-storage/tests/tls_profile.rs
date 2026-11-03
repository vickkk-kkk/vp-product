//! Isolated processes exercise the actual cwd-anchored private profile. No vault,
//! network, material importer or production instance participates in this test.
#![allow(clippy::unwrap_used)]
use std::os::unix::fs::MetadataExt;
use std::{fs::File, path::Path, process::Command};
use vp_product_control::{ContentDigest, ControlStore, GenesisPhase, InstanceBinding, JournalEvent};
use vp_product_storage::{BoundDirectory, DirectoryIdentity, FreshSqliteStore, TlsSqliteStore};
#[path = "support/tls_lifecycle.rs"]
mod lifecycle;
fn binding() -> InstanceBinding {
    let d = ContentDigest::bytes(b"synthetic-test-binding");
    InstanceBinding {
        binding_version: 1,
        genesis_id: "1".repeat(32),
        vault_id: "2".repeat(32),
        namespace_digest: d.clone(),
        administrator_commitment: d.clone(),
        preparation_digest: d.clone(),
        activation_intent_digest: d.clone(),
        artifact_set_digest: d,
        profile: vp_product_control::FRESH_TLS_RUNTIME_PROFILE.into(),
    }
}
fn snapshot(root: &Path) -> Vec<(String, Vec<u8>, u64, u64)> {
    let mut files: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
                e.metadata().unwrap().dev(),
                e.metadata().unwrap().ino(),
            )
        })
        .collect();
    files.sort();
    files
}
fn child(root: &Path, mode: &str) {
    let identity = DirectoryIdentity::of(&File::open(root).unwrap()).unwrap();
    let root = BoundDirectory::open(root, identity)
        .unwrap()
        .anchor_before_threads()
        .unwrap();
    if mode.starts_with("lifecycle-") {
        lifecycle::child(root, mode);
        return;
    }
    match mode {
        "reject-tls-create-legacy-profile" => {
            let mut legacy = binding();
            legacy.profile = vp_product_control::FRESH_ADMIN_PROFILE.into();
            assert!(TlsSqliteStore::create(root, legacy).is_err());
        }
        "reject-fresh-create-tls-profile" => {
            assert!(FreshSqliteStore::create(root, binding()).is_err());
        }
        "reject-tls-open-legacy-profile" => {
            let mut legacy = binding();
            legacy.profile = vp_product_control::FRESH_RUNTIME_PROFILE.into();
            assert!(TlsSqliteStore::open_initialized(root, legacy).is_err());
        }
        "reject-fresh-open-tls-profile" => {
            assert!(FreshSqliteStore::open_initialized(root, binding()).is_err());
        }
        "create-preparing" => {
            TlsSqliteStore::create(root, binding()).unwrap();
        }
        "reject-preparing" => {
            assert!(TlsSqliteStore::open_initialized(root, binding()).is_err());
        }
        "create" => {
            let store = TlsSqliteStore::create(root, binding()).unwrap();
            assert!(store.read().is_err());
            store.with_preparing(|e| { assert!(e.phase() == GenesisPhase::Preparing); assert!(e.binding() == &binding()); Ok(()) }).unwrap();
            store.mark_initialized().unwrap();
            assert!(store.with_preparing(|_| Ok(())).is_err());
            assert!(store.mark_initialized().is_err());
            let mut writer = store.writer().unwrap();
            let mut state = writer.state().clone();
            state.version = 1;
            writer
                .persist(
                    state,
                    JournalEvent {
                        security: None,
                        sequence: 1,
                        at_ms: 1,
                        operation_id: None,
                        state: None,
                    },
                )
                .unwrap();
        }
        "open" => {
            let store = TlsSqliteStore::open_initialized(root, binding()).unwrap();
            assert_eq!(store.read().unwrap().version, 1);
            let writer = store.asset_writer().unwrap();
            assert!(writer.aggregate().require_admission(0).is_err());
            assert!(writer.aggregate().require_admission(1).is_ok());
        }
        "legacy" => {
            assert!(FreshSqliteStore::open_initialized(root, binding()).is_err());
        }
        "wrong-binding" => {
            let mut b = binding();
            b.artifact_set_digest = ContentDigest::bytes(b"different-ELF");
            assert!(TlsSqliteStore::open_initialized(root, b).is_err());
        }
        "legacy-create" => {
            let mut legacy = binding();
            legacy.profile = vp_product_control::FRESH_ADMIN_PROFILE.into();
            let store = FreshSqliteStore::create(root, legacy).unwrap();
            store.mark_initialized().unwrap();
        }
        "reject-legacy" => {
            assert!(TlsSqliteStore::open_initialized(root, binding()).is_err());
        }
        _ => panic!("unknown fixture mode"),
    }
}
fn run(root: &Path, mode: &str) {
    assert!(Command::new(std::env::current_exe().unwrap())
        .arg(mode)
        .arg(root)
        .status()
        .unwrap()
        .success());
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 {
        child(Path::new(&args[2]), &args[1]);
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    run(root.path(), "create");
    let before = snapshot(root.path());
    for mode in ["open", "legacy", "wrong-binding"] {
        run(root.path(), mode);
        assert_eq!(snapshot(root.path()), before);
    }
    let legacy = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    run(legacy.path(), "legacy-create");
    let before = snapshot(legacy.path());
    run(legacy.path(), "reject-legacy");
    assert_eq!(snapshot(legacy.path()), before);
    println!("PASS: 6 isolated profile stages; read-only old/new refusal and exact artifact binding, no byte mutation");
    let new_root = || {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    };
    for mode in [
        "reject-tls-create-legacy-profile",
        "reject-fresh-create-tls-profile",
        "reject-tls-open-legacy-profile",
        "reject-fresh-open-tls-profile",
    ] {
        let root = new_root();
        let before = snapshot(root.path());
        run(root.path(), mode);
        assert_eq!(snapshot(root.path()), before);
    }
    let partial = new_root();
    run(partial.path(), "create-preparing");
    let before = snapshot(partial.path());
    run(partial.path(), "reject-preparing");
    assert_eq!(snapshot(partial.path()), before);
    println!("PASS: 6 additional closed-profile/preparing stages; wrong profile refuses before creating files");
    for mode in ["lifecycle-apply", "lifecycle-failure"] {
        let root = new_root();
        run(root.path(), mode);
    }
    let root = new_root();
    let crashed = Command::new(std::env::current_exe().unwrap())
        .arg("lifecycle-crash")
        .arg(root.path())
        .status()
        .unwrap();
    assert_eq!(crashed.code(), Some(73));
    run(root.path(), "lifecycle-recover");
    for mode in ["lifecycle-credential", "lifecycle-credential-uncertain"] {
        let root = new_root();
        run(root.path(), mode);
        run(root.path(), "lifecycle-verify-credential");
    }
    let root = new_root();
    run(root.path(), "lifecycle-credential-pending");
    run(root.path(), "lifecycle-credential-recover");
    println!("PASS: 10 ordinary service process stages: apply, failure rollback, real exit/restart/recovery, credential create/uncertain completion and pending-intent restart recovery");
}
