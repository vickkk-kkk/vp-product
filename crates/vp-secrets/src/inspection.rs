//! Authenticated, strictly non-repairing vault inspection. Do not call the normal
//! `open` path here: it intentionally removes incomplete staging and fsyncs.
use crate::{
    crypto::{Crypto, MANIFEST, MAX_FILE_BYTES, RECORD, TOMBSTONE},
    filesystem::{Directory, MANIFEST_NAME, PENDING},
    types::within,
    Limits, MasterKey, Namespace, SecretKind, VaultError,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, time::Instant};
use vp_product_domain::SecretRef;

/// Only non-secret observations. Digests cover ciphertext/public metadata, never
/// a master key or plaintext credential. No list of refs or guessed validity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultInspectionReceipt {
    pub format_version: u16,
    pub vault_id: String,
    pub namespace_digest: String,
    pub manifest_digest: String,
    pub inventory_digest: String,
}
/// Retains the same exclusive directory flock used by the ordinary vault.
/// The caller may inspect control state while this value remains alive; dropping
/// it ends the observation's exclusion, not an authorization to restore a backup.
pub struct VaultInspection {
    _directory: Directory,
    receipt: VaultInspectionReceipt,
}
impl VaultInspection {
    pub fn receipt(&self) -> &VaultInspectionReceipt {
        &self.receipt
    }
}
pub fn inspect_vault_read_only(
    root: impl AsRef<Path>,
    namespace: Namespace,
    key: MasterKey,
    deadline: Instant,
) -> Result<VaultInspection, VaultError> {
    inspect_vault_with_identity(root.as_ref(), namespace, key, None, deadline)
}
/// Bind a composed read-only observation to a directory already admitted by its
/// caller. Identity is checked on the actual opened descriptor before reads.
pub fn inspect_vault_read_only_at_identity(
    root: impl AsRef<Path>,
    namespace: Namespace,
    key: MasterKey,
    expected: (u64, u64),
    deadline: Instant,
) -> Result<VaultInspection, VaultError> {
    inspect_vault_with_identity(root.as_ref(), namespace, key, Some(expected), deadline)
}
fn inspect_vault_with_identity(
    root: &Path,
    namespace: Namespace,
    key: MasterKey,
    expected: Option<(u64, u64)>,
    deadline: Instant,
) -> Result<VaultInspection, VaultError> {
    let directory = Directory::open(root, deadline)?;
    if let Some(expected) = expected {
        if directory.opened_identity()? != expected {
            return Err(VaultError::MetadataMismatch);
        }
    }
    let manifest = directory.read_no_atime(MANIFEST_NAME, MAX_FILE_BYTES, deadline)?;
    let crypto = Crypto::new(key, namespace, Crypto::id_from_manifest(&manifest)?);
    let receipt = inspect_locked_directory(&directory, &crypto, deadline)?;
    Ok(VaultInspection {
        _directory: directory,
        receipt,
    })
}
pub(crate) fn inspect_locked_directory(
    directory: &Directory,
    crypto: &Crypto,
    deadline: Instant,
) -> Result<VaultInspectionReceipt, VaultError> {
    within(deadline)?;
    let manifest = directory.read_no_atime(MANIFEST_NAME, MAX_FILE_BYTES, deadline)?;
    let decoded = crypto.open(&manifest)?;
    if decoded.class != MANIFEST {
        return Err(VaultError::Integrity);
    }
    let limits = Limits::decode(decoded.bytes.expose())?;
    let names = directory.names_no_atime(limits.max_records as usize * 2 + 2, deadline)?;
    if names.iter().any(|name| name == PENDING) {
        return Err(VaultError::RecoveryRequired);
    }
    let mut entries: BTreeMap<SecretRef, (SecretKind, u64, u64)> = BTreeMap::new();
    let mut tombstones = BTreeMap::new();
    let mut total_bytes = manifest.len() as u64;
    let mut retirement_reserve = 0u64;
    let mut inventory = Sha256::new();
    inventory.update(b"vp.vault.ciphertext-inventory.v1\0");
    inventory.update(Sha256::digest(&manifest));
    for name in names {
        within(deadline)?;
        if name == MANIFEST_NAME {
            continue;
        }
        let class = if name.ends_with(".record") {
            RECORD
        } else if name.ends_with(".retired") {
            TOMBSTONE
        } else {
            return Err(VaultError::Integrity);
        };
        let encoded = directory.read_no_atime(&name, MAX_FILE_BYTES, deadline)?;
        let decoded = crypto.open(&encoded)?;
        if decoded.class != class || decoded.version == 0 {
            return Err(VaultError::Integrity);
        }
        if decoded.kind == Some(SecretKind::InstanceBinding) {
            crypto.validate_instance_binding_record(&decoded)?;
        }
        let reference = decoded.reference.ok_or(VaultError::Integrity)?;
        let kind = decoded.kind.ok_or(VaultError::Integrity)?;
        let expected_name = format!(
            "{:x}.{}",
            Sha256::digest(reference.as_str().as_bytes()),
            if class == RECORD { "record" } else { "retired" }
        );
        if name != expected_name {
            return Err(VaultError::Integrity);
        }
        total_bytes = total_bytes
            .checked_add(encoded.len() as u64)
            .filter(|total| *total <= limits.max_total_bytes)
            .ok_or(VaultError::LimitExceeded)?;
        if class == RECORD {
            if decoded.bytes.expose().is_empty()
                || decoded.bytes.expose().len() > limits.max_secret_bytes as usize
            {
                return Err(VaultError::Integrity);
            }
            let overhead = encoded.len() as u64 - decoded.bytes.expose().len() as u64;
            retirement_reserve = retirement_reserve
                .checked_add(overhead)
                .ok_or(VaultError::LimitExceeded)?;
            if entries
                .insert(reference, (kind, decoded.version, overhead))
                .is_some()
                || entries.len() > limits.max_records as usize
            {
                return Err(VaultError::Integrity);
            }
        } else if !decoded.bytes.expose().is_empty()
            || tombstones
                .insert(reference, (kind, decoded.version))
                .is_some()
        {
            return Err(VaultError::Integrity);
        }
        inventory.update((name.len() as u64).to_be_bytes());
        inventory.update(name.as_bytes());
        inventory.update((encoded.len() as u64).to_be_bytes());
        inventory.update(Sha256::digest(&encoded));
    }
    for (reference, (kind, version)) in tombstones {
        let (record_kind, record_version, overhead) =
            entries.get(&reference).ok_or(VaultError::Integrity)?;
        if kind != *record_kind || version != *record_version {
            return Err(VaultError::Integrity);
        }
        retirement_reserve = retirement_reserve
            .checked_sub(*overhead)
            .ok_or(VaultError::Integrity)?;
    }
    if total_bytes
        .checked_add(retirement_reserve)
        .is_none_or(|total| total > limits.max_total_bytes)
    {
        return Err(VaultError::LimitExceeded);
    }
    let mut namespace = Sha256::new();
    namespace.update(b"vp.vault.namespace.v1\0");
    namespace.update(crypto.namespace().0.as_bytes());
    within(deadline)?;
    Ok(VaultInspectionReceipt {
        format_version: 1,
        vault_id: crypto.id.iter().map(|byte| format!("{byte:02x}")).collect(),
        namespace_digest: format!("{:x}", namespace.finalize()),
        manifest_digest: format!("{:x}", Sha256::digest(&manifest)),
        inventory_digest: format!("{:x}", inventory.finalize()),
    })
}

#[cfg(test)]
#[path = "inspection_tests.rs"]
mod tests;
