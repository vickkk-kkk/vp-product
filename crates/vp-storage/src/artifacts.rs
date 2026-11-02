use crate::sqlite::{check_private_directory, private_file, sync_directory};
use fs2::FileExt;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use vp_product_control::{ContentDigest, ControlError};

/// Immutable, content-addressed *non-secret* artifacts. Raw credentials/private
/// keys must never be written here; they belong to a separate vault. The writer
/// daemon is the only allowed producer. IDs are digests, never arbitrary paths.
pub trait ArtifactStore: Send + Sync {
    fn put(&self, bytes: &[u8]) -> Result<ContentDigest, ControlError>;
    fn get(&self, digest: &ContentDigest) -> Result<Vec<u8>, ControlError>;
}
pub struct FileArtifactStore {
    root: ArtifactRoot,
    max_bytes: usize,
}
enum ArtifactRoot {
    Legacy(PathBuf),
    #[cfg(target_os = "linux")]
    Bound {
        directory: crate::BoundDirectory,
        writer: std::sync::Mutex<bool>,
        binding: ArtifactBinding,
    },
}
impl FileArtifactStore {
    pub fn open(root: impl AsRef<Path>, max_bytes: usize) -> Result<Self, ControlError> {
        check_private_directory(root.as_ref())?;
        // Do not let the legacy producer write into an explicitly bound store.
        match fs::symlink_metadata(root.as_ref().join("artifacts.binding.json")) {
            Ok(_) => return Err(ControlError::RecoveryRequired),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(ControlError::StorageUnavailable),
        }
        if max_bytes == 0 || max_bytes > 64 * 1024 * 1024 {
            return Err(ControlError::InvalidRequest);
        }
        Ok(Self {
            root: ArtifactRoot::Legacy(root.as_ref().to_path_buf()),
            max_bytes,
        })
    }
}
impl ArtifactStore for FileArtifactStore {
    fn put(&self, bytes: &[u8]) -> Result<ContentDigest, ControlError> {
        if bytes.len() > self.max_bytes {
            return Err(ControlError::InvalidRequest);
        }
        let root = match &self.root {
            ArtifactRoot::Legacy(root) => root,
            #[cfg(target_os = "linux")]
            ArtifactRoot::Bound {
                directory,
                writer,
                binding,
            } => {
                let mut poisoned = writer.lock().map_err(|_| ControlError::RecoveryRequired)?;
                if *poisoned {
                    return Err(ControlError::RecoveryRequired);
                }
                let result = self.put_bound(directory, binding, bytes);
                if result.is_err() {
                    *poisoned = true;
                }
                return result;
            }
        };
        let lock = private_file(&root.join("artifacts.writer.lock"))?;
        FileExt::lock_exclusive(&lock).map_err(|_| ControlError::StorageUnavailable)?;
        let digest = ContentDigest::bytes(bytes);
        let destination = root.join(digest.as_str());
        if destination.exists() {
            if self.get(&digest)? != bytes {
                return Err(ControlError::CorruptState);
            }
            return Ok(digest);
        }
        // One fixed temporary name is safe under the cross-process lock. A crash
        // leaves only this non-active staging file, which the next put replaces.
        let temporary = root.join("artifact.pending");
        match fs::symlink_metadata(&temporary) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
                fs::remove_file(&temporary).map_err(|_| ControlError::StorageUnavailable)?
            }
            Ok(_) => return Err(ControlError::PermissionDenied),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(ControlError::StorageUnavailable),
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| ControlError::StorageUnavailable)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| ControlError::StorageUnavailable)?;
        // Hard-link is atomic and fails if another publisher already created the
        // content address; unlike rename it cannot replace an immutable artifact.
        fs::hard_link(&temporary, &destination).map_err(|_| ControlError::StorageUnavailable)?;
        sync_directory(root)?;
        fs::remove_file(&temporary).map_err(|_| ControlError::StorageUnavailable)?;
        sync_directory(root)?;
        Ok(digest)
    }
    fn get(&self, digest: &ContentDigest) -> Result<Vec<u8>, ControlError> {
        let root = match &self.root {
            ArtifactRoot::Legacy(root) => root,
            #[cfg(target_os = "linux")]
            ArtifactRoot::Bound {
                directory,
                writer,
                binding,
            } => {
                let mut poisoned = writer.lock().map_err(|_| ControlError::RecoveryRequired)?;
                if *poisoned {
                    return Err(ControlError::RecoveryRequired);
                }
                let result = self.get_bound(directory, binding, digest);
                if result.is_err() {
                    *poisoned = true;
                }
                return result;
            }
        };
        let path = root.join(digest.as_str());
        let metadata = fs::symlink_metadata(&path).map_err(|_| ControlError::StorageUnavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > self.max_bytes as u64
        {
            return Err(ControlError::CorruptState);
        }
        let file = private_file(&path)?;
        let mut bytes = Vec::new();
        file.take(self.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ControlError::StorageUnavailable)?;
        if bytes.len() > self.max_bytes || ContentDigest::bytes(&bytes) != *digest {
            return Err(ControlError::CorruptState);
        }
        Ok(bytes)
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn content_addresses_are_immutable_and_verified() {
        let directory = crate::private_test_directory();
        let store = FileArtifactStore::open(directory.path(), 1024).unwrap();
        let digest = store.put(b"non-secret-reference-config").unwrap();
        assert_eq!(store.put(b"non-secret-reference-config").unwrap(), digest);
        assert_eq!(store.get(&digest).unwrap(), b"non-secret-reference-config");
        fs::write(directory.path().join(digest.as_str()), b"corrupted").unwrap();
        assert!(matches!(
            store.get(&digest),
            Err(ControlError::CorruptState)
        ));
    }
    #[test]
    fn oversized_artifact_is_rejected_without_a_file() {
        let directory = crate::private_test_directory();
        let store = FileArtifactStore::open(directory.path(), 3).unwrap();
        assert!(store.put(b"four").is_err());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ArtifactBinding {
    schema_version: u16,
    genesis: ContentDigest,
    max_bytes: usize,
}
#[cfg(target_os = "linux")]
impl FileArtifactStore {
    /// A separate content store for the bound runtime profile. Existing files
    /// are accepted only with the exact immutable genesis and bounded format.
    pub fn open_bound(
        directory: crate::BoundDirectory,
        genesis: ContentDigest,
        mode: crate::BoundOpenMode,
        max_bytes: usize,
    ) -> Result<Self, ControlError> {
        if max_bytes == 0 || max_bytes > 64 * 1024 * 1024 {
            return Err(ControlError::InvalidRequest);
        }
        let directory = directory.lock()?;
        let binding = ArtifactBinding {
            schema_version: 1,
            genesis,
            max_bytes,
        };
        match mode {
            crate::BoundOpenMode::CreateFresh => {
                directory.require_empty()?;
                let bytes = serde_json::to_vec(&binding).map_err(|_| ControlError::CorruptState)?;
                directory.atomic_file(
                    "artifacts.binding.json",
                    "artifacts.binding.pending",
                    &bytes,
                    16384,
                    false,
                )?;
            }
            crate::BoundOpenMode::OpenExisting => {
                let observed: ArtifactBinding =
                    serde_json::from_slice(&directory.read("artifacts.binding.json", 16384)?)
                        .map_err(|_| ControlError::CorruptState)?;
                if observed != binding {
                    return Err(ControlError::CorruptState);
                }
                for name in directory.names_bounded(4096)? {
                    if name != "artifacts.binding.json"
                        && (name.len() != 64
                            || !name
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
                    {
                        return Err(ControlError::RecoveryRequired);
                    }
                    directory.open_file(&name)?;
                }
            }
        }
        Ok(Self {
            root: ArtifactRoot::Bound {
                directory,
                writer: std::sync::Mutex::new(false),
                binding,
            },
            max_bytes,
        })
    }
    fn validate_bound_inventory(
        directory: &crate::BoundDirectory,
        binding: &ArtifactBinding,
    ) -> Result<Vec<String>, ControlError> {
        let observed: ArtifactBinding =
            serde_json::from_slice(&directory.read("artifacts.binding.json", 16384)?)
                .map_err(|_| ControlError::CorruptState)?;
        if &observed != binding {
            return Err(ControlError::CorruptState);
        }
        let names = directory.names_bounded(4096)?;
        for name in &names {
            if name != "artifacts.binding.json"
                && (name.len() != 64
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            {
                return Err(ControlError::RecoveryRequired);
            }
            directory.open_file(name)?;
        }
        Ok(names)
    }
    fn get_bound(
        &self,
        directory: &crate::BoundDirectory,
        binding: &ArtifactBinding,
        digest: &ContentDigest,
    ) -> Result<Vec<u8>, ControlError> {
        Self::validate_bound_inventory(directory, binding)?;
        let bytes = directory.read(digest.as_str(), self.max_bytes)?;
        if ContentDigest::bytes(&bytes) != *digest {
            return Err(ControlError::CorruptState);
        }
        Ok(bytes)
    }
    fn put_bound(
        &self,
        directory: &crate::BoundDirectory,
        binding: &ArtifactBinding,
        bytes: &[u8],
    ) -> Result<ContentDigest, ControlError> {
        let digest = ContentDigest::bytes(bytes);
        let names = Self::validate_bound_inventory(directory, binding)?;
        if names.iter().any(|name| name.ends_with(".pending")) {
            return Err(ControlError::RecoveryRequired);
        }
        if names.iter().any(|name| name == digest.as_str()) {
            if self.get_bound(directory, binding, &digest)? != bytes {
                return Err(ControlError::CorruptState);
            }
            directory.sync()?;
            return Ok(digest);
        }
        if names.len() >= 4095 {
            return Err(ControlError::StorageUnavailable);
        }
        directory.atomic_file(
            digest.as_str(),
            "artifact.pending",
            bytes,
            self.max_bytes,
            false,
        )?;
        Ok(digest)
    }
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod bound_tests {
    use super::*;
    use crate::{BoundDirectory, BoundOpenMode, DirectoryIdentity};
    use std::os::unix::fs::PermissionsExt;
    fn setup() -> (tempfile::TempDir, PathBuf) {
        let parent = crate::private_test_directory();
        let path = parent.path().join("artifacts");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        (parent, path)
    }
    fn directory(path: &Path) -> BoundDirectory {
        let identity = DirectoryIdentity::of(&std::fs::File::open(path).unwrap()).unwrap();
        BoundDirectory::open(path, identity).unwrap()
    }
    #[test]
    fn bound_artifacts_pairing_lock_roundtrip_and_legacy_are_separate() {
        let (_p, path) = setup();
        let genesis = ContentDigest::bytes(b"genesis");
        let store = FileArtifactStore::open_bound(
            directory(&path),
            genesis.clone(),
            BoundOpenMode::CreateFresh,
            1024,
        )
        .unwrap();
        assert!(FileArtifactStore::open(&path, 1024).is_err());
        assert!(!path.join("artifacts.writer.lock").exists());
        let d = store.put(b"ordinary recipe").unwrap();
        assert_eq!(store.get(&d).unwrap(), b"ordinary recipe");
        assert_eq!(store.put(b"ordinary recipe").unwrap(), d);
        let identity = DirectoryIdentity::of(&std::fs::File::open(&path).unwrap()).unwrap();
        assert!(BoundDirectory::open(&path, identity).is_err());
        drop(store);
        assert!(FileArtifactStore::open_bound(
            directory(&path),
            ContentDigest::bytes(b"wrong"),
            BoundOpenMode::OpenExisting,
            1024
        )
        .is_err());
        let store = FileArtifactStore::open_bound(
            directory(&path),
            genesis.clone(),
            BoundOpenMode::OpenExisting,
            1024,
        )
        .unwrap();
        assert_eq!(store.get(&d).unwrap(), b"ordinary recipe");
        drop(store);
        assert!(FileArtifactStore::open_bound(
            directory(&path),
            genesis,
            BoundOpenMode::CreateFresh,
            1024
        )
        .is_err());
    }
    #[test]
    fn bound_artifact_operations_ignore_replaced_parent_path() {
        let (p, path) = setup();
        let moved = p.path().join("retained");
        let store = FileArtifactStore::open_bound(
            directory(&path),
            ContentDigest::bytes(b"g"),
            BoundOpenMode::CreateFresh,
            1024,
        )
        .unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        let d = store.put(b"retained fd").unwrap();
        assert_eq!(store.get(&d).unwrap(), b"retained fd");
        assert!(moved.join(d.as_str()).exists());
        assert_eq!(fs::read_dir(path).unwrap().count(), 0);
    }
    #[test]
    fn bound_artifact_residue_and_unsafe_entries_are_never_removed() {
        let (_p, path) = setup();
        let g = ContentDigest::bytes(b"g");
        let store = FileArtifactStore::open_bound(
            directory(&path),
            g.clone(),
            BoundOpenMode::CreateFresh,
            1024,
        )
        .unwrap();
        fs::write(path.join("artifact.pending"), b"retain").unwrap();
        assert!(store.put(b"new").is_err());
        assert_eq!(fs::read(path.join("artifact.pending")).unwrap(), b"retain");
        drop(store);
        assert!(FileArtifactStore::open_bound(
            directory(&path),
            g,
            BoundOpenMode::OpenExisting,
            1024
        )
        .is_err());
    }
    #[test]
    fn bound_artifact_digest_and_hardlink_validation_fail_closed() {
        let (_p, path) = setup();
        let store = FileArtifactStore::open_bound(
            directory(&path),
            ContentDigest::bytes(b"g"),
            BoundOpenMode::CreateFresh,
            1024,
        )
        .unwrap();
        let d = store.put(b"content").unwrap();
        fs::hard_link(path.join(d.as_str()), path.join("other")).unwrap();
        assert!(store.get(&d).is_err());
        assert!(store.put(b"content").is_err());
    }
    #[test]
    fn uncertain_final_sync_poisons_store_and_never_promotes_retry() {
        let (_p, path) = setup();
        let g = ContentDigest::bytes(b"g");
        let store = FileArtifactStore::open_bound(
            directory(&path),
            g.clone(),
            BoundOpenMode::CreateFresh,
            1024,
        )
        .unwrap();
        if let ArtifactRoot::Bound { directory, .. } = &store.root {
            directory.fail_sync_on(2);
        }
        let digest = ContentDigest::bytes(b"uncertain bytes");
        assert!(store.put(b"uncertain bytes").is_err());
        assert!(path.join(digest.as_str()).exists());
        assert!(matches!(
            store.put(b"uncertain bytes"),
            Err(ControlError::RecoveryRequired)
        ));
        assert!(matches!(
            store.get(&digest),
            Err(ControlError::RecoveryRequired)
        ));
        drop(store);
        let reopened =
            FileArtifactStore::open_bound(directory(&path), g, BoundOpenMode::OpenExisting, 1024)
                .unwrap();
        // An explicit paired reopen can verify existing immutable data, but put
        // must perform a new directory durability barrier before reporting success.
        if let ArtifactRoot::Bound { directory, .. } = &reopened.root {
            directory.fail_sync_on(1);
        }
        assert!(reopened.put(b"uncertain bytes").is_err());
    }
}
