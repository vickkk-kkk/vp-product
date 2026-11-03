//! New synthetic roots only. Real SQL and descriptor/lease inspection; no vault,
//! runtime, network, secrets, admission promotion or production instance.
#![allow(clippy::unwrap_used)]
use fs2::FileExt;
use std::{
    fs::{self, File},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
};
use vp_product_control::{ContentDigest, ControlStore, InstanceBinding, JournalEvent};
use vp_product_storage::{
    inspect_tls_control_read_only, AnchoredControlRoot, BoundDirectory, DirectoryIdentity,
    FreshSqliteStore, TlsSqliteStore,
};
fn binding() -> InstanceBinding {
    let d = ContentDigest::bytes(b"synthetic-inspection");
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
fn identity(path: &Path) -> DirectoryIdentity {
    DirectoryIdentity::of(&File::open(path).unwrap()).unwrap()
}
fn anchor(path: &Path) -> AnchoredControlRoot {
    // Inspection must acquire the root lifetime lease even when a caller merely
    // admitted the path. This enables an independent held-root negative test.
    BoundDirectory::admit(path, identity(path))
        .unwrap()
        .anchor_before_threads()
        .unwrap()
}
fn snapshot(path: &Path) -> Vec<(String, Vec<u8>, u64, u64, u32)> {
    let mut out: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let m = e.metadata().unwrap();
            (
                e.file_name().to_str().unwrap().to_owned(),
                fs::read(e.path()).unwrap(),
                m.dev(),
                m.ino(),
                m.mode(),
            )
        })
        .collect();
    out.sort();
    out
}
fn child(path: &Path, mode: &str) {
    if mode == "wrong-directory-identity" {
        let mut expected = identity(path);
        expected.inode += 1;
        assert!(BoundDirectory::admit(path, expected).is_err());
        return;
    }
    let root = anchor(path);
    match mode {
        "create" | "create-preparing" => {
            let store = TlsSqliteStore::create(root, binding()).unwrap();
            if mode == "create-preparing" {
                return;
            }
            store.mark_initialized().unwrap();
            let mut writer = store.writer().unwrap();
            let mut state = writer.state().clone();
            state.version = 1;
            writer
                .persist(
                    state,
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
        "create-legacy" => {
            let mut b = binding();
            b.profile = vp_product_control::FRESH_ADMIN_PROFILE.into();
            let store = FreshSqliteStore::create(root, b).unwrap();
            store.mark_initialized().unwrap();
        }
        "success" => {
            let b = binding();
            let inspection = inspect_tls_control_read_only(root, &b).unwrap();
            let observed = inspection.snapshot().unwrap();
            assert!(observed.binding() == &b);
            assert_eq!(observed.state().version, 1);
            assert!(!observed.requires_recovery());
            assert_eq!(observed.aggregate_digest().as_str().len(), 64);
            // Both root and writer leases remain held for the inspection life.
            assert!(BoundDirectory::open(path, identity(path)).is_err());
            let lock = File::open(path.join("control.writer.lock")).unwrap();
            assert!(lock.try_lock_exclusive().is_err());
            drop(inspection);
            lock.try_lock_exclusive().unwrap();
        }
        "wrong-profile" => {
            let mut b = binding();
            b.profile = vp_product_control::FRESH_RUNTIME_PROFILE.into();
            assert!(inspect_tls_control_read_only(root, &b).is_err());
        }
        "wrong-binding" => {
            let mut b = binding();
            b.artifact_set_digest = ContentDigest::bytes(b"wrong-executable");
            assert!(inspect_tls_control_read_only(root, &b).is_err());
        }
        "wrong-cwd" => {
            std::env::set_current_dir(path.parent().unwrap()).unwrap();
            assert!(inspect_tls_control_read_only(root, &binding()).is_err());
        }
        "replace-db-after-observation" => {
            let inspection = inspect_tls_control_read_only(root, &binding()).unwrap();
            let db = path.join("control.db");
            let moved = path.join("moved.db");
            fs::rename(&db, &moved).unwrap();
            fs::copy(&moved, &db).unwrap();
            fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
            fs::remove_file(&moved).unwrap(); // Only this test's new synthetic fixture.
            let before = snapshot(path);
            assert!(inspection.snapshot().is_err());
            assert_eq!(snapshot(path), before);
        }
        "change-lock-after-observation" => {
            let inspection = inspect_tls_control_read_only(root, &binding()).unwrap();
            fs::write(path.join("control.writer.lock"), b"synthetic-change").unwrap();
            let before = snapshot(path);
            assert!(inspection.snapshot().is_err());
            assert_eq!(snapshot(path), before);
        }
        "reject" => assert!(inspect_tls_control_read_only(root, &binding()).is_err()),
        _ => panic!("unknown synthetic mode"),
    }
}
fn run(path: &Path, mode: &str) {
    assert!(Command::new(std::env::current_exe().unwrap())
        .arg(mode)
        .arg(path)
        .status()
        .unwrap()
        .success());
}
fn fresh() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn initialized() -> tempfile::TempDir {
    let root = fresh();
    run(root.path(), "create");
    root
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 {
        child(Path::new(&args[2]), &args[1]);
        return;
    }
    let root = initialized();
    for mode in [
        "success",
        "wrong-profile",
        "wrong-binding",
        "wrong-cwd",
        "wrong-directory-identity",
    ] {
        let before = snapshot(root.path());
        run(root.path(), mode);
        assert_eq!(snapshot(root.path()), before);
    }
    let empty = fresh();
    let before = snapshot(empty.path());
    run(empty.path(), "reject");
    assert_eq!(snapshot(empty.path()), before);
    for create in ["create-legacy", "create-preparing"] {
        let root = fresh();
        run(root.path(), create);
        let before = snapshot(root.path());
        run(root.path(), "reject");
        assert_eq!(snapshot(root.path()), before);
    }
    for name in [
        "control.db-wal",
        "control.db-shm",
        "control.db-journal",
        "control.pending",
        "unexpected",
    ] {
        let root = initialized();
        fs::write(root.path().join(name), b"synthetic-pending").unwrap();
        fs::set_permissions(root.path().join(name), fs::Permissions::from_mode(0o600)).unwrap();
        let before = snapshot(root.path());
        run(root.path(), "reject");
        assert_eq!(snapshot(root.path()), before);
    }
    for missing in ["control.db", "control.writer.lock"] {
        let root = initialized();
        fs::remove_file(root.path().join(missing)).unwrap();
        let before = snapshot(root.path());
        run(root.path(), "reject");
        assert_eq!(snapshot(root.path()), before);
    }
    for offset in [18usize, 19, 63] {
        let root = initialized();
        let p = root.path().join("control.db");
        let mut bytes = fs::read(&p).unwrap();
        bytes[offset] = 2;
        fs::write(&p, bytes).unwrap();
        let before = snapshot(root.path());
        run(root.path(), "reject");
        assert_eq!(snapshot(root.path()), before);
    }
    let root = initialized();
    let root_lock = BoundDirectory::open(root.path(), identity(root.path())).unwrap();
    let before = snapshot(root.path());
    run(root.path(), "reject");
    assert_eq!(snapshot(root.path()), before);
    drop(root_lock);
    let writer = File::open(root.path().join("control.writer.lock")).unwrap();
    writer.try_lock_exclusive().unwrap();
    let before = snapshot(root.path());
    run(root.path(), "reject");
    assert_eq!(snapshot(root.path()), before);
    drop(writer);
    for mode in [
        "replace-db-after-observation",
        "change-lock-after-observation",
    ] {
        let root = initialized();
        run(root.path(), mode);
    }
    println!("PASS: retained TLS SQL snapshot; 22 observation/negative stages; setup mutations only in new synthetic fixtures; no runtime or vault admission");
}
