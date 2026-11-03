//! Explicit private new-instance TLS profile. Never selected by legacy/fresh APIs.
use super::*;
use vp_product_control::{TlsRawRecord, TlsTombstone, TlsVaultIo};

mod credentials;
pub use credentials::TlsPasswordSecretManager;
#[cfg(feature = "experimental-public")]
pub use credentials::TlsExperimentalSecretManager;

pub struct TlsSecretStore {
    inner: DurableSecretStore,
}
impl TlsSecretStore {
    pub fn initialize_bound(
        root: impl AsRef<Path>,
        namespace: Namespace,
        key: MasterKey,
        limits: Limits,
        expected: VaultDirectoryIdentity,
        deadline: Instant,
    ) -> Result<Self, VaultError> {
        let mut inner =
            DurableSecretStore::initialize_bound(root, namespace, key, limits, expected, deadline)?;
        inner.crypto.enable_tls_profile();
        Ok(Self { inner })
    }
    /// Authenticate only an unclaimed manifest under the retained vault lock.
    /// This cannot adopt any legacy or partially initialized bound instance.
    pub fn open_manifest_only(
        root: impl AsRef<Path>,
        namespace: Namespace,
        key: MasterKey,
        expected: VaultDirectoryIdentity,
        deadline: Instant,
    ) -> Result<Self, VaultError> {
        let inner = DurableSecretStore::open_profile_inner(
            root.as_ref(),
            namespace,
            key,
            Some(expected),
            false,
            true,
            deadline,
        )?;
        inner.require_manifest_only(deadline)?;
        Ok(Self { inner })
    }
    /// Exact authenticated vault pairing only. Caller must also admit control,
    /// runtime, actual artifacts and fresh/reopen intent before any mutation.
    pub fn open_bound(
        root: impl AsRef<Path>,
        namespace: Namespace,
        key: MasterKey,
        expected: VaultDirectoryIdentity,
        binding: &vp_product_control::InstanceBinding,
        deadline: Instant,
    ) -> Result<Self, VaultError> {
        binding
            .validate_tls_profile()
            .map_err(|_| VaultError::MetadataMismatch)?;
        let store = Self::open(root, namespace, key, expected, deadline)?;
        if store.inner.instance_binding(deadline)? != *binding {
            return Err(VaultError::MetadataMismatch);
        }
        Ok(store)
    }
    /// No staging repair. Requires an authenticated TLS profile binding, but
    /// does not by itself admit control/runtime/artifacts or authorize migration.
    pub fn open(
        root: impl AsRef<Path>,
        namespace: Namespace,
        key: MasterKey,
        expected: VaultDirectoryIdentity,
        deadline: Instant,
    ) -> Result<Self, VaultError> {
        let inner = DurableSecretStore::open_profile_inner(
            root.as_ref(),
            namespace,
            key,
            Some(expected),
            false,
            true,
            deadline,
        )?;
        inner.instance_binding(deadline)?;
        Ok(Self { inner })
    }
    pub fn claim_instance_binding(
        &self,
        binding: &vp_product_control::InstanceBinding,
        deadline: Instant,
    ) -> Result<(), VaultError> {
        self.inner.claim_instance_binding(binding, deadline)
    }
    pub fn inspect_read_only(
        &self,
        deadline: Instant,
    ) -> Result<crate::VaultInspectionReceipt, VaultError> {
        self.inner.inspect_read_only(deadline)
    }
    /// Kind-1-only immutable credential port. Shared control owns confirmation,
    /// CAS, intent journaling and reference reachability; this is not an apply API.
    pub fn put_credential(
        &self,
        reference: &SecretRef,
        version: u64,
        bytes: SecretBytes,
        deadline: Instant,
    ) -> Result<(), VaultError> {
        self.inner
            .instance_binding(deadline)?
            .validate_tls_profile()
            .map_err(|_| VaultError::MetadataMismatch)?;
        self.inner
            .put(reference, SecretKind::Credential, version, bytes, deadline)
    }
    /// No retired fallback, implicit version choice or access to other kinds.
    pub fn get_credential(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<SecretRecord, VaultError> {
        self.inner
            .instance_binding(deadline)?
            .validate_tls_profile()
            .map_err(|_| VaultError::MetadataMismatch)?;
        let record = self.inner.get(reference, deadline)?;
        if record.kind != SecretKind::Credential {
            return Err(VaultError::MetadataMismatch);
        }
        Ok(record)
    }
    /// Idempotent only for this exact credential kind/version. Historical bytes
    /// remain encrypted; control must first authorize retirement/reachability.
    pub fn retire_credential(
        &self,
        reference: &SecretRef,
        version: u64,
        deadline: Instant,
    ) -> Result<(), VaultError> {
        self.inner
            .instance_binding(deadline)?
            .validate_tls_profile()
            .map_err(|_| VaultError::MetadataMismatch)?;
        self.inner
            .retire(reference, SecretKind::Credential, version, deadline)
    }
    fn tls_kind(kind: u8) -> Result<SecretKind, VaultError> {
        match kind {
            6 => Ok(SecretKind::CertificateChain),
            2 => Ok(SecretKind::PrivateKey),
            _ => Err(VaultError::InvalidInput),
        }
    }
    fn tombstone_exact(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<TlsTombstone, VaultError> {
        let state = self.inner.lock(deadline)?;
        let entry = state.entries.get(reference).ok_or(VaultError::NotFound)?;
        Self::tls_kind(entry.kind as u8)?;
        if !entry.retired {
            return Err(VaultError::MetadataMismatch);
        }
        self.inner.read_record(reference, entry, deadline)?;
        let encoded =
            self.inner
                .directory
                .read(&filename(reference, TOMBSTONE), MAX_FILE_BYTES, deadline)?;
        let decoded = self.inner.crypto.open(&encoded)?;
        let (actual_ref, kind, version) = record_metadata(&decoded, TOMBSTONE)?;
        if actual_ref != reference
            || kind != entry.kind
            || version != entry.version
            || !decoded.bytes.expose().is_empty()
        {
            return Err(VaultError::Integrity);
        }
        within(deadline)?;
        Ok(TlsTombstone {
            reference: reference.clone(),
            kind: kind as u8,
            version,
        })
    }
}
impl TlsVaultIo for TlsSecretStore {
    fn binding(
        &self,
        deadline: Instant,
    ) -> Result<vp_product_control::InstanceBinding, ControlError> {
        self.inner.instance_binding(deadline).map_err(control_error)
    }
    fn read(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<Option<TlsRawRecord>, ControlError> {
        self.binding(deadline)?;
        match self.inner.get(reference, deadline) {
            Err(VaultError::NotFound) => Ok(None),
            Err(e) => Err(control_error(e)),
            Ok(record) => {
                Self::tls_kind(record.kind as u8).map_err(control_error)?;
                Ok(Some(TlsRawRecord {
                    reference: reference.clone(),
                    kind: record.kind as u8,
                    version: record.version,
                    bytes: record.bytes,
                }))
            }
        }
    }
    fn put(&self, record: TlsRawRecord, deadline: Instant) -> Result<(), ControlError> {
        self.binding(deadline)?;
        if record.reference.as_str() == INSTANCE_BINDING_REF {
            return Err(ControlError::InvalidRequest);
        }
        let kind = Self::tls_kind(record.kind).map_err(control_error)?;
        self.inner
            .put_record(
                &record.reference,
                kind,
                record.version,
                record.bytes,
                false,
                deadline,
            )
            .map_err(control_error)
    }
    fn retire(
        &self,
        reference: &SecretRef,
        kind: u8,
        version: u64,
        deadline: Instant,
    ) -> Result<(), ControlError> {
        self.binding(deadline)?;
        self.inner
            .retire(
                reference,
                Self::tls_kind(kind).map_err(control_error)?,
                version,
                deadline,
            )
            .map_err(control_error)
    }
    fn tombstone(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<TlsTombstone, ControlError> {
        self.binding(deadline)?;
        self.tombstone_exact(reference, deadline)
            .map_err(control_error)
    }
}

// Read-only, kind-restricted bridge. Retired/uncertain records remain errors.
impl vp_product_control::TlsMaterialVault for TlsSecretStore {
    #[cfg(feature = "experimental-public")]
    fn retained_directory_identity(&self) -> Result<(u64, u64), vp_product_control::ControlError> {
        self.inner.directory.opened_identity().map_err(|_| vp_product_control::ControlError::ResourceConflict)
    }
    fn material_binding(
        &self,
        deadline: Instant,
    ) -> Result<vp_product_control::InstanceBinding, ControlError> {
        self.inner.instance_binding(deadline).map_err(control_error)
    }
    fn read_tls_material(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<Option<TlsRawRecord>, ControlError> {
        TlsVaultIo::read(self, reference, deadline)
    }
    fn read_credential_material(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<Option<TlsRawRecord>, ControlError> {
        self.inner
            .instance_binding(deadline)
            .map_err(control_error)?;
        match self.inner.get(reference, deadline) {
            Err(VaultError::NotFound) => Ok(None),
            Err(error) => Err(control_error(error)),
            Ok(record) if record.kind == SecretKind::Credential => Ok(Some(TlsRawRecord {
                reference: reference.clone(),
                kind: 1,
                version: record.version,
                bytes: record.bytes,
            })),
            Ok(_) => Err(ControlError::ResourceConflict),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        time::Duration,
    };
    use vp_product_control::{ContentDigest, InstanceBinding};
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn ns() -> Namespace {
        Namespace::new("tls-synthetic").unwrap()
    }
    fn key() -> MasterKey {
        MasterKey::new(SecretBytes::new(vec![47; 32])).unwrap()
    }
    fn identity(path: &Path) -> VaultDirectoryIdentity {
        let m = fs::metadata(path).unwrap();
        VaultDirectoryIdentity {
            device: m.dev(),
            inode: m.ino(),
        }
    }
    fn record(id: &str, kind: u8, version: u64) -> TlsRawRecord {
        TlsRawRecord {
            reference: SecretRef::new(id).unwrap(),
            kind,
            version,
            bytes: SecretBytes::new(b"synthetic-material-only".to_vec()),
        }
    }
    fn fixture() -> (tempfile::TempDir, TlsSecretStore) {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let v = TlsSecretStore::initialize_bound(
            d.path(),
            ns(),
            key(),
            Limits::default(),
            identity(d.path()),
            deadline(),
        )
        .unwrap();
        let observed = v.inspect_read_only(deadline()).unwrap();
        let digest = ContentDigest::bytes(b"synthetic-test");
        v.claim_instance_binding(
            &InstanceBinding {
                binding_version: 1,
                genesis_id: "1".repeat(32),
                vault_id: observed.vault_id,
                namespace_digest: ContentDigest::parse(observed.namespace_digest).unwrap(),
                administrator_commitment: digest.clone(),
                preparation_digest: digest.clone(),
                activation_intent_digest: digest.clone(),
                artifact_set_digest: digest,
                profile: vp_product_control::FRESH_TLS_RUNTIME_PROFILE.into(),
            },
            deadline(),
        )
        .unwrap();
        (d, v)
    }
    fn snapshot(path: &Path) -> Vec<(String, Vec<u8>, u64, u64)> {
        let mut xs: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_str().unwrap().to_owned(),
                    fs::read(e.path()).unwrap(),
                    e.metadata().unwrap().dev(),
                    e.metadata().unwrap().ino(),
                )
            })
            .collect();
        xs.sort();
        xs
    }
    #[test]
    fn tls_exact_roundtrip_reopen_and_irreversible_retirement() {
        let (d, v) = fixture();
        let r = record("chain", 6, 7);
        let id = r.reference.clone();
        v.put(r, deadline()).unwrap();
        assert_eq!(v.read(&id, deadline()).unwrap().unwrap().version, 7);
        assert!(v.put(record("chain", 6, 8), deadline()).is_err());
        assert!(v.retire(&id, 2, 7, deadline()).is_err());
        v.retire(&id, 6, 7, deadline()).unwrap();
        assert_eq!(v.tombstone(&id, deadline()).unwrap().kind, 6);
        assert!(v.read(&id, deadline()).is_err());
        drop(v);
        let v =
            TlsSecretStore::open(d.path(), ns(), key(), identity(d.path()), deadline()).unwrap();
        assert_eq!(v.tombstone(&id, deadline()).unwrap().version, 7);
        assert!(v.put(record("chain", 6, 7), deadline()).is_err());
    }
    #[test]
    fn old_profiles_refuse_kind6_without_staging_cleanup() {
        let (d, v) = fixture();
        v.put(record("chain", 6, 1), deadline()).unwrap();
        drop(v);
        fs::write(d.path().join(PENDING), b"synthetic-staging").unwrap();
        fs::set_permissions(d.path().join(PENDING), fs::Permissions::from_mode(0o600)).unwrap();
        let before = snapshot(d.path());
        assert!(DurableSecretStore::open(d.path(), ns(), key(), deadline()).is_err());
        assert!(DurableSecretStore::open_fresh_profile(
            d.path(),
            ns(),
            key(),
            identity(d.path()),
            deadline()
        )
        .is_err());
        assert!(crate::inspect_vault_read_only(d.path(), ns(), key(), deadline()).is_err());
        assert!(
            TlsSecretStore::open(d.path(), ns(), key(), identity(d.path()), deadline()).is_err()
        );
        assert_eq!(snapshot(d.path()), before);
    }
    #[test]
    fn old_profiles_reject_clean_kind6_and_new_generic_put() {
        let (d, v) = fixture();
        v.put(record("chain", 6, 1), deadline()).unwrap();
        drop(v);
        let before = snapshot(d.path());
        assert!(matches!(
            DurableSecretStore::open_fresh_profile(
                d.path(),
                ns(),
                key(),
                identity(d.path()),
                deadline()
            ),
            Err(VaultError::UnsupportedVersion | VaultError::MetadataMismatch)
        ));
        assert!(matches!(
            crate::inspect_vault_read_only(d.path(), ns(), key(), deadline()),
            Err(VaultError::UnsupportedVersion | VaultError::MetadataMismatch)
        ));
        assert_eq!(snapshot(d.path()), before);
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let old =
            DurableSecretStore::initialize(d.path(), ns(), key(), Limits::default(), deadline())
                .unwrap();
        let before = snapshot(d.path());
        assert!(matches!(
            old.put(
                &SecretRef::new("x").unwrap(),
                SecretKind::CertificateChain,
                1,
                SecretBytes::new(vec![1]),
                deadline()
            ),
            Err(VaultError::UnsupportedVersion | VaultError::MetadataMismatch)
        ));
        assert_eq!(snapshot(d.path()), before);
    }
    #[test]
    fn wrong_identity_and_reserved_kinds_do_not_write() {
        let (d, v) = fixture();
        let before = snapshot(d.path());
        for kind in [0, 1, 3, 4, 5, 7] {
            assert!(v.put(record("wrong", kind, 1), deadline()).is_err());
        }
        assert!(v
            .put(record("vp-instance-binding-v1", 2, 1), deadline())
            .is_err());
        assert_eq!(snapshot(d.path()), before);
        drop(v);
        let mut id = identity(d.path());
        id.inode += 1;
        assert!(TlsSecretStore::open(d.path(), ns(), key(), id, deadline()).is_err());
        assert_eq!(snapshot(d.path()), before);
    }
    #[test]
    fn write_faults_preserve_uncertainty_and_never_clean_staging() {
        for point in 1..=4 {
            let (d, v) = fixture();
            v.inner.inject_fault(point);
            assert!(v.put(record("chain", 6, 1), deadline()).is_err());
            assert!(v
                .read(&SecretRef::new("chain").unwrap(), deadline())
                .is_err());
            drop(v);
            let before = snapshot(d.path());
            let opened =
                TlsSecretStore::open(d.path(), ns(), key(), identity(d.path()), deadline());
            if point <= 2 {
                assert!(opened.is_err());
            } else {
                let v = opened.unwrap();
                assert!(v
                    .read(&SecretRef::new("chain").unwrap(), deadline())
                    .unwrap()
                    .is_some());
                assert!(v.put(record("chain", 6, 1), deadline()).is_err());
            }
            assert_eq!(snapshot(d.path()), before);
        }
    }
    #[test]
    fn authenticated_read_and_tombstone_refuse_tamper() {
        let (d, v) = fixture();
        let r = record("chain", 6, 1);
        let id = r.reference.clone();
        v.put(r, deadline()).unwrap();
        v.retire(&id, 6, 1, deadline()).unwrap();
        let path = d.path().join(filename(&id, TOMBSTONE));
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(v.tombstone(&id, deadline()).is_err());
    }
    #[test]
    fn credential_port_is_bound_kind_restricted_and_irreversible() {
        let (d, v) = fixture();
        let id = SecretRef::new("password-port").unwrap();
        v.put_credential(
            &id,
            3,
            SecretBytes::new(b"synthetic-password".to_vec()),
            deadline(),
        )
        .unwrap();
        assert_eq!(v.get_credential(&id, deadline()).unwrap().version, 3);
        assert!(v
            .put_credential(&id, 4, SecretBytes::new(vec![1]), deadline())
            .is_err());
        let before = snapshot(d.path());
        assert!(v.retire_credential(&id, 2, deadline()).is_err());
        assert_eq!(before, snapshot(d.path()));
        v.put(record("chain-other", 6, 1), deadline()).unwrap();
        let other = SecretRef::new("chain-other").unwrap();
        assert!(v.get_credential(&other, deadline()).is_err());
        assert!(v.retire_credential(&other, 1, deadline()).is_err());
        v.retire_credential(&id, 3, deadline()).unwrap();
        v.retire_credential(&id, 3, deadline()).unwrap();
        assert!(matches!(
            v.get_credential(&id, deadline()),
            Err(VaultError::Retired)
        ));
        drop(v);
        let v =
            TlsSecretStore::open(d.path(), ns(), key(), identity(d.path()), deadline()).unwrap();
        assert!(matches!(
            v.get_credential(&id, deadline()),
            Err(VaultError::Retired)
        ));
        assert!(v
            .put_credential(&id, 4, SecretBytes::new(vec![1]), deadline())
            .is_err());
    }
    #[test]
    fn password_manager_validates_exact_bytes_and_never_downgrades_retired_to_absent() {
        use vp_product_control::SecretManager;
        use vp_product_domain::NodeCredentialKind;
        let (d, v) = fixture();
        let vault = std::sync::Arc::new(v);
        let before = snapshot(d.path());
        let manager = TlsPasswordSecretManager::new(vault.clone());
        let kind = NodeCredentialKind::Password {};
        assert_eq!(manager.supported_kinds(), vec![kind.clone()]);
        let generated = manager.generate_credential(&kind, deadline()).unwrap();
        assert_eq!(generated.bytes.expose().len(), 64);
        assert!(generated.bytes.expose().iter().all(u8::is_ascii_hexdigit));
        assert_eq!(before, snapshot(d.path()));
        let id = generated.reference;
        assert!(manager
            .load_credential(&id, &kind, None, deadline())
            .unwrap()
            .is_none());
        manager
            .put_credential(&id, &kind, 1, generated.bytes, deadline())
            .unwrap();
        assert!(manager
            .load_credential(&id, &kind, Some(2), deadline())
            .is_err());
        assert!(manager
            .load_credential(&id, &NodeCredentialKind::Uuid {}, Some(1), deadline())
            .is_err());
        assert_eq!(
            manager
                .load_credential(&id, &kind, Some(1), deadline())
                .unwrap()
                .unwrap()
                .expose()
                .len(),
            64
        );
        let before = snapshot(d.path());
        for bytes in [vec![], vec![0], vec![255], vec![b'x'; 4097]] {
            assert!(manager
                .put_credential(
                    &SecretRef::new("bad-password").unwrap(),
                    &kind,
                    1,
                    SecretBytes::new(bytes),
                    deadline()
                )
                .is_err());
        }
        assert!(manager
            .put_credential(
                &SecretRef::new("vp-instance-binding-v1").unwrap(),
                &kind,
                1,
                SecretBytes::new(vec![b'x']),
                deadline()
            )
            .is_err());
        assert!(manager.generate_credential(&kind, Instant::now()).is_err());
        assert!(manager.generate_publication_token(deadline()).is_err());
        assert!(!manager.verify_publication_token(&ContentDigest::bytes(b"test"), b"test"));
        assert_eq!(before, snapshot(d.path()));
        manager.retire_credential(&id, 1, deadline()).unwrap();
        assert!(matches!(
            manager.load_credential(&id, &kind, None, deadline()),
            Err(ControlError::RecoveryRequired)
        ));
    }
    #[cfg(feature = "experimental-public")]
    #[test]
    fn experimental_manager_binds_uuid_and_ss_types_inside_vault() {
        use vp_product_control::SecretManager;
        use vp_product_domain::{NodeCredentialKind, ShadowsocksCipher};
        let (_d, vault) = fixture();
        let vault = std::sync::Arc::new(vault);
        let manager = TlsExperimentalSecretManager::new(vault.clone());
        let legacy = TlsPasswordSecretManager::new(vault.clone());
        let uuid = NodeCredentialKind::Uuid {};
        let ss = NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm };
        for kind in [uuid.clone(), ss.clone()] {
            let generated = manager.generate_credential(&kind, deadline()).unwrap();
            let id = generated.reference;
            let expected = generated.bytes.expose().to_vec();
            manager.put_credential(&id, &kind, 1, generated.bytes, deadline()).unwrap();
            let stored = vault.get_credential(&id, deadline()).unwrap();
            assert_ne!(stored.bytes.expose(), expected.as_slice());
            assert_eq!(manager.load_credential(&id, &kind, Some(1), deadline()).unwrap().unwrap().expose(), expected.as_slice());
            let wrong = if kind == uuid { &ss } else { &uuid };
            assert!(manager.load_credential(&id, wrong, Some(1), deadline()).is_err());
            assert!(manager.load_credential(&id, &kind, Some(2), deadline()).is_err());
            assert!(legacy.load_credential(&id, &NodeCredentialKind::Password {}, Some(1), deadline()).is_err());
            manager.retire_credential(&id, 1, deadline()).unwrap();
            assert!(manager.load_credential(&id, &kind, None, deadline()).is_err());
        }
        assert!(manager.generate_credential(&NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes256Gcm }, deadline()).is_err());
        assert!(manager.generate_credential(&uuid, Instant::now()).is_err());
    }
    #[test]
    fn credential_port_and_manager_refuse_unclaimed_vault_before_writes() {
        use vp_product_control::SecretManager;
        let d = empty_root();
        let v = std::sync::Arc::new(
            TlsSecretStore::initialize_bound(
                d.path(),
                ns(),
                key(),
                Limits::default(),
                identity(d.path()),
                deadline(),
            )
            .unwrap(),
        );
        let before = snapshot(d.path());
        let id = SecretRef::new("unclaimed-password").unwrap();
        assert!(v
            .put_credential(&id, 1, SecretBytes::new(vec![b'x']), deadline())
            .is_err());
        assert!(v.get_credential(&id, deadline()).is_err());
        assert!(v.retire_credential(&id, 1, deadline()).is_err());
        let manager = TlsPasswordSecretManager::new(v);
        assert!(manager
            .generate_credential(
                &vp_product_domain::NodeCredentialKind::Password {},
                deadline()
            )
            .is_err());
        assert_eq!(before, snapshot(d.path()));
    }
    #[test]
    fn credential_write_faults_keep_uncertainty_and_ref_reserved() {
        for point in 1..=4 {
            let (d, v) = fixture();
            let id = SecretRef::new("fault-password").unwrap();
            v.inner.inject_fault(point);
            assert!(v
                .put_credential(&id, 1, SecretBytes::new(vec![b'x']), deadline())
                .is_err());
            assert!(matches!(
                v.get_credential(&id, deadline()),
                Err(VaultError::RecoveryRequired)
            ));
            drop(v);
            let before = snapshot(d.path());
            let opened =
                TlsSecretStore::open(d.path(), ns(), key(), identity(d.path()), deadline());
            if point <= 2 {
                assert!(opened.is_err());
            } else {
                let v = opened.unwrap();
                assert_eq!(v.get_credential(&id, deadline()).unwrap().version, 1);
                assert!(v
                    .put_credential(&id, 1, SecretBytes::new(vec![b'x']), deadline())
                    .is_err());
            }
            assert_eq!(before, snapshot(d.path()));
        }
    }
    fn binding_for(v: &DurableSecretStore, profile: &str) -> InstanceBinding {
        let observed = v.inspect_read_only(deadline()).unwrap();
        let d = ContentDigest::bytes(b"synthetic-profile-gate");
        InstanceBinding {
            binding_version: 1,
            genesis_id: "7".repeat(32),
            vault_id: observed.vault_id,
            namespace_digest: ContentDigest::parse(observed.namespace_digest).unwrap(),
            administrator_commitment: d.clone(),
            preparation_digest: d.clone(),
            activation_intent_digest: d.clone(),
            artifact_set_digest: d,
            profile: profile.into(),
        }
    }
    fn empty_root() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    #[test]
    fn profile_claim_gate_is_closed_before_writes() {
        for profile in [
            vp_product_control::FRESH_ADMIN_PROFILE,
            vp_product_control::FRESH_RUNTIME_PROFILE,
            vp_product_control::FRESH_TLS_RUNTIME_PROFILE,
            "unknown",
        ] {
            let d = empty_root();
            let old = DurableSecretStore::initialize(
                d.path(),
                ns(),
                key(),
                Limits::default(),
                deadline(),
            )
            .unwrap();
            let b = binding_for(&old, profile);
            let before = snapshot(d.path());
            let result = old.claim_instance_binding(&b, deadline());
            if [
                vp_product_control::FRESH_ADMIN_PROFILE,
                vp_product_control::FRESH_RUNTIME_PROFILE,
            ]
            .contains(&profile)
            {
                result.unwrap();
            } else {
                assert!(result.is_err());
                assert_eq!(snapshot(d.path()), before);
            }
            let d = empty_root();
            let tls = TlsSecretStore::initialize_bound(
                d.path(),
                ns(),
                key(),
                Limits::default(),
                identity(d.path()),
                deadline(),
            )
            .unwrap();
            let b = binding_for(&tls.inner, profile);
            let before = snapshot(d.path());
            let result = tls.claim_instance_binding(&b, deadline());
            if profile == vp_product_control::FRESH_TLS_RUNTIME_PROFILE {
                result.unwrap();
            } else {
                assert!(result.is_err());
                assert_eq!(snapshot(d.path()), before);
            }
        }
    }
    #[test]
    fn tls_open_rejects_legacy_binding_without_kind6_and_preserves_bytes() {
        for profile in [
            vp_product_control::FRESH_ADMIN_PROFILE,
            vp_product_control::FRESH_RUNTIME_PROFILE,
        ] {
            let d = empty_root();
            let old = DurableSecretStore::initialize(
                d.path(),
                ns(),
                key(),
                Limits::default(),
                deadline(),
            )
            .unwrap();
            let b = binding_for(&old, profile);
            old.claim_instance_binding(&b, deadline()).unwrap();
            drop(old);
            let before = snapshot(d.path());
            assert!(
                TlsSecretStore::open(d.path(), ns(), key(), identity(d.path()), deadline())
                    .is_err()
            );
            assert!(TlsSecretStore::open_manifest_only(
                d.path(),
                ns(),
                key(),
                identity(d.path()),
                deadline()
            )
            .is_err());
            assert!(TlsSecretStore::open_bound(
                d.path(),
                ns(),
                key(),
                identity(d.path()),
                &b,
                deadline()
            )
            .is_err());
            let mut fake_tls = b.clone();
            fake_tls.profile = vp_product_control::FRESH_TLS_RUNTIME_PROFILE.into();
            assert!(TlsSecretStore::open_bound(
                d.path(),
                ns(),
                key(),
                identity(d.path()),
                &fake_tls,
                deadline()
            )
            .is_err());
            assert_eq!(snapshot(d.path()), before);
            let inspection =
                crate::inspect_vault_read_only(d.path(), ns(), key(), deadline()).unwrap();
            assert_eq!(inspection.receipt().vault_id, b.vault_id);
            drop(inspection);
            assert_eq!(snapshot(d.path()), before);
            let old = DurableSecretStore::open_fresh_profile(
                d.path(),
                ns(),
                key(),
                identity(d.path()),
                deadline(),
            )
            .unwrap();
            assert!(old.instance_binding(deadline()).unwrap() == b);
        }
    }
    #[test]
    fn tls_bound_without_kind6_refuses_old_readers_and_checks_exact_pair() {
        let (d, v) = fixture();
        let b = v.inner.instance_binding(deadline()).unwrap();
        drop(v);
        let before = snapshot(d.path());
        assert!(DurableSecretStore::open(d.path(), ns(), key(), deadline()).is_err());
        assert!(DurableSecretStore::open_fresh_profile(
            d.path(),
            ns(),
            key(),
            identity(d.path()),
            deadline()
        )
        .is_err());
        assert!(crate::inspect_vault_read_only(d.path(), ns(), key(), deadline()).is_err());
        assert!(TlsSecretStore::open_manifest_only(
            d.path(),
            ns(),
            key(),
            identity(d.path()),
            deadline()
        )
        .is_err());
        let v =
            TlsSecretStore::open_bound(d.path(), ns(), key(), identity(d.path()), &b, deadline())
                .unwrap();
        assert!(v.inner.instance_binding(deadline()).unwrap() == b);
        drop(v);
        let mut wrong = b.clone();
        wrong.artifact_set_digest = ContentDigest::bytes(b"other-artifact");
        assert!(TlsSecretStore::open_bound(
            d.path(),
            ns(),
            key(),
            identity(d.path()),
            &wrong,
            deadline()
        )
        .is_err());
        wrong = b.clone();
        wrong.genesis_id = "9".repeat(32);
        assert!(TlsSecretStore::open_bound(
            d.path(),
            ns(),
            key(),
            identity(d.path()),
            &wrong,
            deadline()
        )
        .is_err());
        assert_eq!(snapshot(d.path()), before);
    }
    #[test]
    fn manifest_only_open_is_nonrepairing_and_cannot_reopen_bound_state() {
        let d = empty_root();
        let old =
            DurableSecretStore::initialize(d.path(), ns(), key(), Limits::default(), deadline())
                .unwrap();
        drop(old);
        let before = snapshot(d.path());
        assert!(
            TlsSecretStore::open(d.path(), ns(), key(), identity(d.path()), deadline()).is_err()
        );
        let v = TlsSecretStore::open_manifest_only(
            d.path(),
            ns(),
            key(),
            identity(d.path()),
            deadline(),
        )
        .unwrap();
        assert_eq!(snapshot(d.path()), before);
        let b = binding_for(&v.inner, vp_product_control::FRESH_TLS_RUNTIME_PROFILE);
        v.claim_instance_binding(&b, deadline()).unwrap();
        drop(v);
        assert!(TlsSecretStore::open_manifest_only(
            d.path(),
            ns(),
            key(),
            identity(d.path()),
            deadline()
        )
        .is_err());
        let d = empty_root();
        let old =
            DurableSecretStore::initialize(d.path(), ns(), key(), Limits::default(), deadline())
                .unwrap();
        drop(old);
        fs::write(d.path().join(PENDING), b"synthetic-partial").unwrap();
        fs::set_permissions(d.path().join(PENDING), fs::Permissions::from_mode(0o600)).unwrap();
        let before = snapshot(d.path());
        assert!(TlsSecretStore::open_manifest_only(
            d.path(),
            ns(),
            key(),
            identity(d.path()),
            deadline()
        )
        .is_err());
        assert_eq!(snapshot(d.path()), before);
    }
    #[test]
    fn legacy_repair_refuses_tls_kind5_only_before_staging_cleanup() {
        let (d, v) = fixture();
        // Exactly manifest + authenticated TLS kind 5; no kind 6 exists.
        assert_eq!(snapshot(d.path()).len(), 2);
        drop(v);
        fs::write(d.path().join(PENDING), b"synthetic-incomplete-write").unwrap();
        fs::set_permissions(d.path().join(PENDING), fs::Permissions::from_mode(0o600)).unwrap();
        let before = snapshot(d.path());
        assert!(DurableSecretStore::open(d.path(), ns(), key(), deadline()).is_err());
        assert_eq!(snapshot(d.path()), before);
        assert!(d.path().join(PENDING).is_file());
    }
    #[test]
    fn material_credential_bridge_is_read_only_and_kind_restricted() {
        use vp_product_control::TlsMaterialVault;
        let (d, v) = fixture();
        let id = SecretRef::new("synthetic-credential").unwrap();
        v.inner
            .put(
                &id,
                SecretKind::Credential,
                7,
                SecretBytes::new(b"synthetic-password".to_vec()),
                deadline(),
            )
            .unwrap();
        let before = snapshot(d.path());
        let raw = v
            .read_credential_material(&id, deadline())
            .unwrap()
            .unwrap();
        assert_eq!(raw.reference, id);
        assert_eq!((raw.kind, raw.version), (1, 7));
        assert_eq!(raw.bytes.expose(), b"synthetic-password");
        assert!(v.read_tls_material(&id, deadline()).is_err());
        assert!(v
            .read_credential_material(&SecretRef::new("absent").unwrap(), deadline())
            .unwrap()
            .is_none());
        assert_eq!(snapshot(d.path()), before);
        v.put(record("chain", 6, 1), deadline()).unwrap();
        assert!(v
            .read_credential_material(&SecretRef::new("chain").unwrap(), deadline())
            .is_err());
        v.inner
            .retire(&id, SecretKind::Credential, 7, deadline())
            .unwrap();
        assert!(v.read_credential_material(&id, deadline()).is_err());
    }
}
