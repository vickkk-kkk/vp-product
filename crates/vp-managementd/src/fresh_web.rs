//! Admission for package-verified immutable assets, not a file manager.
//! Cooperative trusted-owner/stable-path model; no hostile same-UID race claim.
use crate::web::WebRoot;
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};
const MAX_FILES: usize = 4096;
const MAX_FILE: u64 = 32 * 1024 * 1024;
const MAX_TOTAL: u64 = 256 * 1024 * 1024;
fn identity(m: &fs::Metadata) -> (u64, u64) {
    (m.dev(), m.ino())
}
fn owner(m: &fs::Metadata) -> bool {
    m.uid() == 0 || m.uid() == rustix::process::geteuid().as_raw()
}
fn ancestors(path: &Path) -> Result<Vec<(u64, u64)>, &'static str> {
    path.ancestors()
        .map(|p| {
            let m = fs::symlink_metadata(p).map_err(|_| "WEB_ANCESTOR_UNAVAILABLE")?;
            let trusted_sticky = m.uid() == 0 && m.mode() & 0o1000 != 0;
            if !m.is_dir() || !owner(&m) || (m.mode() & 0o022 != 0 && !trusted_sticky) {
                return Err("WEB_ANCESTOR_UNTRUSTED");
            }
            Ok(identity(&m))
        })
        .collect()
}
pub fn open(
    path: PathBuf,
    origin: &str,
    private: [&Path; 3],
) -> Result<Arc<WebRoot>, &'static str> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err("INVALID_WEB_ROOT");
    }
    let canonical = path.canonicalize().map_err(|_| "WEB_ROOT_UNAVAILABLE")?;
    // Reject root/ancestor symlink aliases rather than silently trust a target.
    if canonical != path {
        return Err("WEB_ROOT_NOT_CANONICAL");
    }
    let meta = fs::symlink_metadata(&canonical).map_err(|_| "WEB_ROOT_UNAVAILABLE")?;
    if !meta.is_dir() || !owner(&meta) || meta.mode() & 0o022 != 0 {
        return Err("WEB_ROOT_UNTRUSTED");
    }
    let web_id = identity(&meta);
    let web_ancestors = ancestors(&canonical)?;
    let mut private_ids = Vec::new();
    for root in private {
        let root = root
            .canonicalize()
            .map_err(|_| "PRIVATE_ROOT_UNAVAILABLE")?;
        let m = fs::symlink_metadata(&root).map_err(|_| "PRIVATE_ROOT_UNAVAILABLE")?;
        let id = identity(&m);
        if canonical.starts_with(&root)
            || root.starts_with(&canonical)
            || web_ancestors.contains(&id)
            || ancestors(&root)?.contains(&web_id)
        {
            return Err("WEB_PRIVATE_ROOT_OVERLAP");
        }
        private_ids.push(id);
    }
    let mut pending = vec![(canonical.clone(), 0usize)];
    let mut count = 0usize;
    let mut bytes = 0u64;
    while let Some((directory, depth)) = pending.pop() {
        if depth > 32 {
            return Err("WEB_TREE_LIMIT");
        }
        for entry in fs::read_dir(directory).map_err(|_| "WEB_TREE_UNAVAILABLE")? {
            count += 1;
            if count > MAX_FILES {
                return Err("WEB_TREE_LIMIT");
            }
            let entry = entry.map_err(|_| "WEB_TREE_UNAVAILABLE")?;
            let m = fs::symlink_metadata(entry.path()).map_err(|_| "WEB_TREE_UNAVAILABLE")?;
            if !owner(&m) || m.mode() & 0o022 != 0 {
                return Err("WEB_ENTRY_UNTRUSTED");
            }
            if m.is_dir() {
                if private_ids.contains(&identity(&m)) {
                    return Err("WEB_PRIVATE_ROOT_OVERLAP");
                }
                pending.push((entry.path(), depth + 1));
            } else if m.is_file() && m.nlink() == 1 {
                if m.len() > MAX_FILE {
                    return Err("WEB_FILE_LIMIT");
                }
                bytes = bytes.checked_add(m.len()).ok_or("WEB_TREE_LIMIT")?;
                if bytes > MAX_TOTAL {
                    return Err("WEB_TREE_LIMIT");
                }
            } else {
                return Err("WEB_ENTRY_UNTRUSTED");
            }
        }
    }
    WebRoot::open(canonical, origin)
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn fixture() -> (tempfile::TempDir, PathBuf, [PathBuf; 3]) {
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let web = t.path().join("web");
        fs::create_dir(&web).unwrap();
        fs::set_permissions(&web, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(web.join("index.html"), b"synthetic public test asset").unwrap();
        fs::set_permissions(web.join("index.html"), fs::Permissions::from_mode(0o644)).unwrap();
        let roots = ["control", "vault", "runtime"].map(|n| {
            let p = t.path().join(n);
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            p
        });
        (t, web, roots)
    }
    fn admitted(web: &Path, roots: &[PathBuf; 3]) -> bool {
        open(
            web.to_owned(),
            "http://127.0.0.1:18080",
            [&roots[0], &roots[1], &roots[2]],
        )
        .is_ok()
    }
    #[test]
    fn immutable_public_tree_is_separate_from_private_roots() {
        let (t, web, roots) = fixture();
        assert!(admitted(&web, &roots));
        assert!(!admitted(t.path(), &roots));
        fs::write(roots[0].join("index.html"), b"not an asset root").unwrap();
        assert!(!admitted(&roots[0], &roots));
    }
    #[test]
    fn symlinks_hardlinks_and_writable_assets_are_refused() {
        let (_t, web, roots) = fixture();
        symlink(web.join("index.html"), web.join("alias.js")).unwrap();
        assert!(!admitted(&web, &roots));
        fs::remove_file(web.join("alias.js")).unwrap();
        fs::hard_link(web.join("index.html"), web.join("linked.js")).unwrap();
        assert!(!admitted(&web, &roots));
        fs::remove_file(web.join("linked.js")).unwrap();
        fs::set_permissions(web.join("index.html"), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!admitted(&web, &roots));
    }
    #[test]
    #[ignore = "AF_UNIX fixture bind denied with EPERM in this sandbox; opt-in only in an authorized environment"]
    fn unix_socket_asset_is_refused_opt_in() {
        let (_t, web, roots) = fixture();
        let _socket = std::os::unix::net::UnixListener::bind(web.join("local.socket")).unwrap();
        assert!(!admitted(&web, &roots));
    }
    #[test]
    fn fifo_asset_is_refused_without_opening_or_reading() {
        let (_t, web, roots) = fixture();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            web.join("fifo"),
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        assert!(!admitted(&web, &roots));
    }
    #[test]
    fn untrusted_ancestors_are_refused() {
        let (t, web, roots) = fixture();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!admitted(&web, &roots));
    }
    #[test]
    fn oversized_asset_and_alias_root_are_refused() {
        let (t, web, roots) = fixture();
        let alias = t.path().join("alias");
        symlink(&web, &alias).unwrap();
        assert!(!admitted(&alias, &roots));
        let file = fs::File::create(web.join("huge.bin")).unwrap();
        file.set_len(MAX_FILE + 1).unwrap();
        assert!(!admitted(&web, &roots));
    }
}
