#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]
use std::{
    fs::{self, File},
    os::unix::fs::{symlink, PermissionsExt},
};
use vp_product_storage::{BoundDirectory, DirectoryIdentity};
fn root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn identity(p: &std::path::Path) -> DirectoryIdentity {
    DirectoryIdentity::of(&File::open(p).unwrap()).unwrap()
}
#[test]
fn held_directory_writes_original_after_path_replacement() {
    let parent = root();
    let path = parent.path().join("root");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let held = BoundDirectory::open(&path, identity(&path)).unwrap();
    let moved = parent.path().join("moved");
    fs::rename(&path, &moved).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    held.publish("receipt", b"synthetic").unwrap();
    assert_eq!(fs::read(moved.join("receipt")).unwrap(), b"synthetic");
    assert!(fs::read_dir(path).unwrap().next().is_none());
}
#[test]
fn identity_symlink_permissions_overlap_and_locks_fail_closed() {
    let parent = root();
    let a = parent.path().join("a");
    let b = parent.path().join("b");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    for p in [&a, &b] {
        fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap()
    }
    assert!(BoundDirectory::open(&a, identity(&b)).is_err());
    let alias = parent.path().join("alias");
    symlink(&a, &alias).unwrap();
    assert!(BoundDirectory::open(&alias, identity(&a)).is_err());
    let held = BoundDirectory::open(&a, identity(&a)).unwrap();
    assert!(BoundDirectory::open(&a, identity(&a)).is_err());
    let ancestor = BoundDirectory::admit(parent.path(), identity(parent.path())).unwrap();
    assert!(ancestor.disjoint(&held).is_err());
    let peer = BoundDirectory::admit(&b, identity(&b)).unwrap();
    held.disjoint(&peer).unwrap();
    fs::set_permissions(&a, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(held.publish("no-write", b"x").is_err());
    assert!(!a.join("no-write").exists());
}
#[test]
fn publication_never_replaces_or_follows_links() {
    let a = root();
    let held = BoundDirectory::open(a.path(), identity(a.path())).unwrap();
    held.publish("record", b"first").unwrap();
    assert!(held.publish("record", b"second").is_err());
    assert_eq!(held.read("record", 32).unwrap(), b"first");
    assert!(held.read("record", 2).is_err());
    symlink("record", a.path().join("alias")).unwrap();
    assert!(held.read("alias", 32).is_err());
    assert!(held.publish("../escape", b"x").is_err());
    fs::hard_link(a.path().join("record"), a.path().join("hard")).unwrap();
    assert!(held.read("record", 32).is_err());
}
