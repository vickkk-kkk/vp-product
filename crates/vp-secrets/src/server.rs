use crate::{
    crypto::{Crypto, Decoded, MANIFEST, MAX_FILE_BYTES, RECORD, TOMBSTONE},
    filesystem::{Directory, MANIFEST_NAME, PENDING},
    types::within,
    Limits, MasterKey, Namespace, SecretKind, SecretRecord, VaultError,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Mutex, MutexGuard, TryLockError},
    time::Instant,
};
use vp_product_control::ControlError;
use vp_product_domain::{SecretBytes, SecretRef};
use vp_product_runtime_executor::ImmutableSecretStore;

const INSTANCE_BINDING_REF: &str = "secret:vp-instance-binding-v1";

#[derive(Clone, Copy)]
struct Entry {
    kind: SecretKind,
    version: u64,
    digest: [u8; 32],
    retired: bool,
    tombstone_size: u64,
}
struct State {
    entries: BTreeMap<SecretRef, Entry>,
    total_bytes: u64,
    retirement_reserve: u64,
    poisoned: bool,
}

/// Expected identity of an existing vault directory, captured by the caller.
/// This is a target binding, not an authorization capability or recovery proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultDirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}

/// A locked, dirfd-anchored Linux server vault. Share one instance through Arc.
/// Creating a directory or provisioning a master key remains the caller's job.
/// Secrets are never logged, serialized into DTOs, or used as filenames.
pub struct DurableSecretStore {
    directory: Directory,
    crypto: Crypto,
    limits: Limits,
    state: Mutex<State>,
}
impl DurableSecretStore {
    /// Explicit first provisioning into an EXISTING empty owner-private root.
    /// Never call initialize as fallback after open fails. No key is generated.
    pub fn initialize(
        root: impl AsRef<Path>,
        namespace: Namespace,
        key: MasterKey,
        limits: Limits,
        deadline: Instant,
    ) -> Result<Self, VaultError> {
        Self::initialize_with_identity(root.as_ref(), namespace, key, limits, None, deadline)
    }
    /// Initialize only the exact directory observed by the caller. Identity is
    /// checked on the acquired, locked descriptor before entropy or any writes.
    /// All later accesses remain relative to that descriptor even if renamed.
    pub fn initialize_bound(
        root: impl AsRef<Path>,
        namespace: Namespace,
        key: MasterKey,
        limits: Limits,
        expected: VaultDirectoryIdentity,
        deadline: Instant,
    ) -> Result<Self, VaultError> {
        Self::initialize_with_identity(
            root.as_ref(),
            namespace,
            key,
            limits,
            Some(expected),
            deadline,
        )
    }
    fn initialize_with_identity(
        root: &Path,
        namespace: Namespace,
        key: MasterKey,
        limits: Limits,
        expected: Option<VaultDirectoryIdentity>,
        deadline: Instant,
    ) -> Result<Self, VaultError> {
        within(deadline)?;
        let limits = limits.validate()?;
        let directory = Directory::open(root, deadline)?;
        if let Some(expected) = expected {
            directory.require_identity(expected)?;
        }
        let names = directory.names(3, deadline)?;
        if names.iter().any(|name| name == MANIFEST_NAME) {
            return Err(VaultError::AlreadyExists);
        }
        if !names.is_empty() {
            return Err(VaultError::RecoveryRequired);
        }
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| VaultError::StorageUnavailable)?;
        let crypto = Crypto::new(key, namespace, id);
        let manifest = crypto.seal(MANIFEST, None, 0, None, &limits.encode())?;
        directory.free_space(manifest.len() as u64, limits.min_free_bytes)?;
        directory
            .publish(MANIFEST_NAME, &manifest, deadline)
            .map_err(|_| VaultError::RecoveryRequired)?;
        Ok(Self {
            directory,
            crypto,
            limits,
            state: Mutex::new(State {
                entries: BTreeMap::new(),
                total_bytes: manifest.len() as u64,
                retirement_reserve: 0,
                poisoned: false,
            }),
        })
    }
    /// Authenticate the manifest and every committed record before serving.
    /// Incomplete bounded staging files are discarded ONLY after authentication.
    /// Wrong keys, unknown formats, orphan tombstones and foreign files fail closed.
    pub fn open(
        root: impl AsRef<Path>,
        namespace: Namespace,
        key: MasterKey,
        deadline: Instant,
    ) -> Result<Self, VaultError> {
        Self::open_profile_inner(root.as_ref(), namespace, key, None, true, false, deadline)
    }
    /// Explicit paired fresh-profile reopen. Never repairs staging and verifies
    /// the actual locked directory before reading or changing vault bytes.
    pub fn open_fresh_profile(
        root: impl AsRef<Path>,
        namespace: Namespace,
        key: MasterKey,
        expected: VaultDirectoryIdentity,
        deadline: Instant,
    ) -> Result<Self, VaultError> {
        Self::open_profile_inner(
            root.as_ref(),
            namespace,
            key,
            Some(expected),
            false,
            false,
            deadline,
        )
    }
    fn open_profile_inner(
        root: &Path,
        namespace: Namespace,
        key: MasterKey,
        expected: Option<VaultDirectoryIdentity>,
        repair_staging: bool,
        tls_profile: bool,
        deadline: Instant,
    ) -> Result<Self, VaultError> {
        let directory = Directory::open(root, deadline)?;
        if let Some(expected) = expected {
            directory.require_identity(expected)?;
        }
        let manifest = directory.read(MANIFEST_NAME, MAX_FILE_BYTES, deadline)?;
        let crypto = Crypto::new(key, namespace, Crypto::id_from_manifest(&manifest)?);
        #[cfg(feature = "private-tls")]
        let crypto = {
            let mut crypto = crypto;
            if tls_profile {
                crypto.enable_tls_profile();
            }
            crypto
        };
        #[cfg(not(feature = "private-tls"))]
        if tls_profile {
            return Err(VaultError::UnsupportedVersion);
        }
        let decoded = crypto.open(&manifest)?;
        if decoded.class != MANIFEST {
            return Err(VaultError::Integrity);
        }
        let limits = Limits::decode(decoded.bytes.expose())?;
        let mut state = State {
            entries: BTreeMap::new(),
            total_bytes: manifest.len() as u64,
            retirement_reserve: 0,
            poisoned: false,
        };
        let mut tombstones = Vec::new();
        let names = directory.names(limits.max_records as usize * 2 + 2, deadline)?;
        for name in names {
            within(deadline)?;
            if name == PENDING && !repair_staging {
                return Err(VaultError::RecoveryRequired);
            }
            if name == MANIFEST_NAME || name == PENDING {
                continue;
            }
            let class = if name.ends_with(".record") {
                RECORD
            } else if name.ends_with(".retired") {
                TOMBSTONE
            } else {
                return Err(VaultError::Integrity);
            };
            let encoded = directory.read(&name, MAX_FILE_BYTES, deadline)?;
            let decoded = crypto.open(&encoded)?;
            let (reference, kind, version) = record_metadata(&decoded, class)?;
            // Legacy open must never adopt a freshly paired vault or repair its
            // staging merely because this library recognizes the new kind.
            if kind == SecretKind::InstanceBinding {
                if repair_staging {
                    return Err(VaultError::MetadataMismatch);
                }
                crypto.validate_instance_binding_record(&decoded)?;
            }
            if filename(reference, class) != name {
                return Err(VaultError::Integrity);
            }
            state.total_bytes = state
                .total_bytes
                .checked_add(encoded.len() as u64)
                .ok_or(VaultError::LimitExceeded)?;
            if state.total_bytes > limits.max_total_bytes {
                return Err(VaultError::LimitExceeded);
            }
            if class == TOMBSTONE {
                if !decoded.bytes.expose().is_empty() {
                    return Err(VaultError::Integrity);
                }
                tombstones.push((reference.clone(), kind, version));
            } else {
                if decoded.bytes.expose().is_empty()
                    || decoded.bytes.expose().len() > limits.max_secret_bytes as usize
                {
                    return Err(VaultError::Integrity);
                }
                let tombstone_size = encoded.len() as u64 - decoded.bytes.expose().len() as u64;
                let entry = Entry {
                    kind,
                    version,
                    digest: Sha256::digest(&encoded).into(),
                    retired: false,
                    tombstone_size,
                };
                if state.entries.insert(reference.clone(), entry).is_some()
                    || state.entries.len() > limits.max_records as usize
                {
                    return Err(VaultError::Integrity);
                }
                state.retirement_reserve += tombstone_size;
            }
        }
        for (reference, kind, version) in tombstones {
            let entry = state
                .entries
                .get_mut(&reference)
                .ok_or(VaultError::Integrity)?;
            if entry.kind != kind || entry.version != version || entry.retired {
                return Err(VaultError::Integrity);
            }
            entry.retired = true;
            state.retirement_reserve -= entry.tombstone_size;
        }
        if state.total_bytes + state.retirement_reserve > limits.max_total_bytes {
            return Err(VaultError::LimitExceeded);
        }
        if repair_staging {
            directory.recover_staging(MAX_FILE_BYTES, deadline)?;
        }
        within(deadline)?;
        Ok(Self {
            directory,
            crypto,
            limits,
            state: Mutex::new(state),
        })
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    /// Read-only authenticated observation while this instance retains the vault
    /// lock. Unlike `open`, this never cleans staging or repairs durable state.
    /// It is not a monotonic revocation authority or permission to restore data.
    pub fn inspect_read_only(
        &self,
        deadline: Instant,
    ) -> Result<crate::VaultInspectionReceipt, VaultError> {
        let _state = self.lock(deadline)?;
        crate::inspection::inspect_locked_directory(&self.directory, &self.crypto, deadline)
    }
    /// Fresh genesis preflight under the retained vault lock. No staging repair
    /// or writes; repeated by the claim's in-memory freshness guard.
    pub fn require_manifest_only(&self, deadline: Instant) -> Result<(), VaultError> {
        let state = self.lock(deadline)?;
        if !state.entries.is_empty()
            || self.directory.names_no_atime(2, deadline)? != [MANIFEST_NAME.to_owned()]
        {
            return Err(VaultError::RecoveryRequired);
        }
        crate::inspection::inspect_locked_directory(&self.directory, &self.crypto, deadline)?;
        Ok(())
    }
    /// Permanently reserves this exact ref. Existing refs ALWAYS fail, even if
    /// bytes match or the record was retired. A timeout is not permission to reuse.
    pub fn put(
        &self,
        reference: &SecretRef,
        kind: SecretKind,
        version: u64,
        secret: SecretBytes,
        deadline: Instant,
    ) -> Result<(), VaultError> {
        if kind == SecretKind::InstanceBinding || reference.as_str() == INSTANCE_BINDING_REF {
            return Err(VaultError::InvalidInput);
        }
        self.put_record(reference, kind, version, secret, false, deadline)
    }
    fn put_record(
        &self,
        reference: &SecretRef,
        kind: SecretKind,
        version: u64,
        secret: SecretBytes,
        require_fresh: bool,
        deadline: Instant,
    ) -> Result<(), VaultError> {
        let mut state = self.lock(deadline)?;
        if require_fresh && !state.entries.is_empty() {
            return Err(VaultError::AlreadyExists);
        }
        if state.entries.contains_key(reference) {
            return Err(VaultError::AlreadyExists);
        }
        if version == 0
            || secret.expose().is_empty()
            || secret.expose().len() > self.limits.max_secret_bytes as usize
        {
            return Err(VaultError::InvalidInput);
        }
        if state.entries.len() >= self.limits.max_records as usize {
            return Err(VaultError::LimitExceeded);
        }
        let encoded = self.crypto.seal(
            RECORD,
            Some(kind),
            version,
            Some(reference),
            secret.expose(),
        )?;
        let tombstone_size = encoded.len() as u64 - secret.expose().len() as u64;
        if state.total_bytes + state.retirement_reserve + encoded.len() as u64 + tombstone_size
            > self.limits.max_total_bytes
        {
            return Err(VaultError::LimitExceeded);
        }
        self.directory
            .free_space(encoded.len() as u64, self.limits.min_free_bytes)?;
        self.publish(&mut state, &filename(reference, RECORD), &encoded, deadline)?;
        state.total_bytes += encoded.len() as u64;
        state.retirement_reserve += tombstone_size;
        state.entries.insert(
            reference.clone(),
            Entry {
                kind,
                version,
                digest: Sha256::digest(&encoded).into(),
                retired: false,
                tombstone_size,
            },
        );
        Ok(())
    }
    /// No aliases, latest-version lookup, retired fallback or plaintext cache.
    pub fn get(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<SecretRecord, VaultError> {
        if reference.as_str() == INSTANCE_BINDING_REF {
            return Err(VaultError::InvalidInput);
        }
        let record = self.get_record(reference, deadline)?;
        if record.kind == SecretKind::InstanceBinding {
            return Err(VaultError::InvalidInput);
        }
        Ok(record)
    }
    fn get_record(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<SecretRecord, VaultError> {
        let state = self.lock(deadline)?;
        let entry = state.entries.get(reference).ok_or(VaultError::NotFound)?;
        if entry.retired {
            return Err(VaultError::Retired);
        }
        let decoded = self.read_record(reference, entry, deadline)?;
        within(deadline)?;
        Ok(SecretRecord {
            kind: entry.kind,
            version: entry.version,
            bytes: decoded.bytes,
        })
    }
    /// Consumers that know a kind/version must require both explicitly.
    pub fn get_exact(
        &self,
        reference: &SecretRef,
        kind: SecretKind,
        version: u64,
        deadline: Instant,
    ) -> Result<SecretBytes, VaultError> {
        let record = self.get(reference, deadline)?;
        if record.kind != kind || record.version != version {
            return Err(VaultError::MetadataMismatch);
        }
        Ok(record.bytes)
    }
    /// Irreversible logical revocation; encrypted historical bytes remain.
    /// Call only after control commits rotation AND no rollback/rejection probe
    /// needs the old secret. This vault cannot decide operation/revision reachability.
    /// Repeated retire is idempotent only for the exact original kind/version.
    pub fn retire(
        &self,
        reference: &SecretRef,
        kind: SecretKind,
        version: u64,
        deadline: Instant,
    ) -> Result<(), VaultError> {
        if kind == SecretKind::InstanceBinding || reference.as_str() == INSTANCE_BINDING_REF {
            return Err(VaultError::InvalidInput);
        }
        let mut state = self.lock(deadline)?;
        let entry = *state.entries.get(reference).ok_or(VaultError::NotFound)?;
        if entry.kind != kind || entry.version != version {
            return Err(VaultError::MetadataMismatch);
        }
        if entry.retired {
            return Ok(());
        }
        self.read_record(reference, &entry, deadline)?;
        let encoded = self
            .crypto
            .seal(TOMBSTONE, Some(kind), version, Some(reference), &[])?;
        self.directory
            .free_space(encoded.len() as u64, self.limits.min_free_bytes)?;
        self.publish(
            &mut state,
            &filename(reference, TOMBSTONE),
            &encoded,
            deadline,
        )?;
        state.total_bytes += encoded.len() as u64;
        state.retirement_reserve -= entry.tombstone_size;
        state
            .entries
            .get_mut(reference)
            .ok_or(VaultError::Integrity)?
            .retired = true;
        Ok(())
    }
    /// One immutable authenticated genesis claim in a manifest-only vault.
    /// This record is not a runtime credential and cannot be retired generically.
    pub fn claim_instance_binding(
        &self,
        binding: &vp_product_control::InstanceBinding,
        deadline: Instant,
    ) -> Result<(), VaultError> {
        self.crypto.validate_instance_profile(binding)?;
        let observed = self.inspect_read_only(deadline)?;
        if binding.vault_id != observed.vault_id
            || binding.namespace_digest.as_str() != observed.namespace_digest
        {
            return Err(VaultError::MetadataMismatch);
        }
        let reference =
            SecretRef::new("vp-instance-binding-v1").map_err(|_| VaultError::InvalidInput)?;
        let bytes = serde_json::to_vec(binding).map_err(|_| VaultError::InvalidInput)?;
        if bytes.len() > 4096 {
            return Err(VaultError::LimitExceeded);
        }
        self.put_record(
            &reference,
            SecretKind::InstanceBinding,
            1,
            SecretBytes::new(bytes),
            true,
            deadline,
        )
    }
    pub fn instance_binding(
        &self,
        deadline: Instant,
    ) -> Result<vp_product_control::InstanceBinding, VaultError> {
        let reference =
            SecretRef::new("vp-instance-binding-v1").map_err(|_| VaultError::InvalidInput)?;
        let record = self.get_record(&reference, deadline)?;
        if record.kind != SecretKind::InstanceBinding
            || record.version != 1
            || record.bytes.expose().len() > 4096
        {
            return Err(VaultError::MetadataMismatch);
        }
        let binding: vp_product_control::InstanceBinding =
            serde_json::from_slice(record.bytes.expose()).map_err(|_| VaultError::Integrity)?;
        self.crypto.validate_instance_profile(&binding)?;
        let observed = self.inspect_read_only(deadline)?;
        if binding.vault_id != observed.vault_id
            || binding.namespace_digest.as_str() != observed.namespace_digest
        {
            return Err(VaultError::MetadataMismatch);
        }
        Ok(binding)
    }
    fn lock(&self, deadline: Instant) -> Result<MutexGuard<'_, State>, VaultError> {
        within(deadline)?;
        let state = self.state.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => VaultError::Busy,
            TryLockError::Poisoned(_) => VaultError::RecoveryRequired,
        })?;
        if state.poisoned {
            return Err(VaultError::RecoveryRequired);
        }
        self.directory.check()?;
        within(deadline)?;
        Ok(state)
    }
    fn read_record(
        &self,
        reference: &SecretRef,
        entry: &Entry,
        deadline: Instant,
    ) -> Result<Decoded, VaultError> {
        let encoded = self
            .directory
            .read(&filename(reference, RECORD), MAX_FILE_BYTES, deadline)
            .map_err(|e| {
                if e == VaultError::NotFound {
                    VaultError::Integrity
                } else {
                    e
                }
            })?;
        if <[u8; 32]>::from(Sha256::digest(&encoded)) != entry.digest {
            return Err(VaultError::Integrity);
        }
        let decoded = self.crypto.open(&encoded)?;
        let (actual_ref, kind, version) = record_metadata(&decoded, RECORD)?;
        if actual_ref != reference || kind != entry.kind || version != entry.version {
            return Err(VaultError::Integrity);
        }
        Ok(decoded)
    }
    fn publish(
        &self,
        state: &mut State,
        name: &str,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), VaultError> {
        // Set before the first possible filesystem mutation; reopen is mandatory
        // after any uncertain failure, including an expired post-fsync deadline.
        state.poisoned = true;
        self.directory
            .publish(name, bytes, deadline)
            .map_err(|_| VaultError::RecoveryRequired)?;
        state.poisoned = false;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn inject_fault(&self, point: u8) {
        self.directory
            .fault
            .store(point, std::sync::atomic::Ordering::SeqCst);
    }
}
fn filename(reference: &SecretRef, class: u8) -> String {
    format!(
        "{:x}.{}",
        Sha256::digest(reference.as_str().as_bytes()),
        if class == RECORD { "record" } else { "retired" }
    )
}
fn record_metadata(
    decoded: &Decoded,
    class: u8,
) -> Result<(&SecretRef, SecretKind, u64), VaultError> {
    if decoded.class != class || decoded.version == 0 {
        return Err(VaultError::Integrity);
    }
    let reference = decoded.reference.as_ref().ok_or(VaultError::Integrity)?;
    let kind = decoded.kind.ok_or(VaultError::Integrity)?;
    let reserved = reference.as_str() == INSTANCE_BINDING_REF;
    if reserved != (kind == SecretKind::InstanceBinding)
        || (reserved && (class != RECORD || decoded.version != 1))
    {
        return Err(VaultError::Integrity);
    }
    Ok((reference, kind, decoded.version))
}
impl ImmutableSecretStore for DurableSecretStore {
    fn validate_immutable(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<(), ControlError> {
        let record = self.get(reference, deadline).map_err(control_error)?;
        if record.kind != SecretKind::Credential {
            return Err(ControlError::InvalidConfiguration);
        }
        within(deadline).map_err(control_error)
    }
    fn resolve_immutable(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<SecretBytes, ControlError> {
        let record = self.get(reference, deadline).map_err(control_error)?;
        if record.kind != SecretKind::Credential {
            return Err(ControlError::InvalidConfiguration);
        }
        within(deadline).map_err(control_error)?;
        Ok(record.bytes)
    }
}
fn control_error(error: VaultError) -> ControlError {
    match error {
        VaultError::InvalidInput | VaultError::MetadataMismatch | VaultError::LimitExceeded => {
            ControlError::InvalidRequest
        }
        VaultError::PermissionDenied => ControlError::PermissionDenied,
        VaultError::Busy | VaultError::DeadlineExceeded => ControlError::ExecutorUnavailable,
        VaultError::NotFound | VaultError::Retired => ControlError::NotFound,
        VaultError::AlreadyExists => ControlError::ResourceConflict,
        VaultError::Integrity | VaultError::UnsupportedVersion => ControlError::CorruptState,
        VaultError::StorageUnavailable => ControlError::StorageUnavailable,
        VaultError::RecoveryRequired => ControlError::RecoveryRequired,
    }
}

#[cfg(feature = "private-tls")]
mod tls;
#[cfg(feature = "private-tls")]
pub use tls::TlsSecretStore;
