//! Explicit password-only adapter for shared control credential transactions.
//! Construction performs no entropy, writes or publication-token provisioning.
use super::TlsSecretStore;
use crate::VaultError;
use std::{sync::Arc, time::Instant};
use vp_product_control::{ContentDigest, ControlError, GeneratedCredential, SecretManager};
use vp_product_domain::{NodeCredentialKind, SecretBytes, SecretRef};
use zeroize::Zeroizing;

pub struct TlsPasswordSecretManager {
    vault: Arc<TlsSecretStore>,
}
impl TlsPasswordSecretManager {
    pub fn new(vault: Arc<TlsSecretStore>) -> Self {
        Self { vault }
    }
    fn ready(&self, deadline: Instant) -> Result<(), ControlError> {
        within(deadline)?;
        self.vault
            .inner
            .instance_binding(deadline)
            .map_err(map)?
            .validate_tls_profile()?;
        within(deadline)
    }
}
fn within(deadline: Instant) -> Result<(), ControlError> {
    if Instant::now() >= deadline {
        Err(ControlError::ExecutorFailed)
    } else {
        Ok(())
    }
}
fn supported(kind: &NodeCredentialKind) -> Result<(), ControlError> {
    if matches!(kind, NodeCredentialKind::Password {}) {
        Ok(())
    } else {
        Err(ControlError::ExecutorUnavailable)
    }
}
fn validate_password(bytes: &[u8]) -> Result<(), ControlError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ControlError::InvalidConfiguration)?;
    if text.is_empty() || text.len() > 4096 || text.contains('\0') {
        return Err(ControlError::InvalidConfiguration);
    }
    Ok(())
}
fn map(error: VaultError) -> ControlError {
    match error {
        VaultError::PermissionDenied => ControlError::PermissionDenied,
        VaultError::NotFound => ControlError::NotFound,
        VaultError::AlreadyExists => ControlError::ResourceConflict,
        VaultError::InvalidInput | VaultError::MetadataMismatch | VaultError::LimitExceeded => {
            ControlError::InvalidConfiguration
        }
        // Retired, corrupt or uncertain records must never look absent to a
        // pending-create recovery operation. Reopen/explicit recovery is required.
        _ => ControlError::RecoveryRequired,
    }
}
fn random_hex<const N: usize>() -> Result<SecretBytes, ControlError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = Zeroizing::new([0u8; N]);
    getrandom::fill(random.as_mut()).map_err(|_| ControlError::ExecutorUnavailable)?;
    let mut output = Zeroizing::new(Vec::with_capacity(N * 2));
    for b in random.iter() {
        output.push(HEX[(b >> 4) as usize]);
        output.push(HEX[(b & 15) as usize]);
    }
    Ok(SecretBytes::new(std::mem::take(&mut *output)))
}
impl SecretManager for TlsPasswordSecretManager {
    fn supported_kinds(&self) -> Vec<NodeCredentialKind> {
        vec![NodeCredentialKind::Password {}]
    }
    fn generate_credential(
        &self,
        kind: &NodeCredentialKind,
        deadline: Instant,
    ) -> Result<GeneratedCredential, ControlError> {
        supported(kind)?;
        self.ready(deadline)?;
        let reference_entropy = random_hex::<16>()?;
        let reference = SecretRef::new(&format!(
            "node-{}",
            std::str::from_utf8(reference_entropy.expose())
                .map_err(|_| ControlError::ExecutorFailed)?
        ))
        .map_err(|_| ControlError::ExecutorFailed)?;
        let bytes = random_hex::<32>()?;
        within(deadline)?;
        Ok(GeneratedCredential { reference, bytes })
    }
    fn put_credential(
        &self,
        reference: &SecretRef,
        kind: &NodeCredentialKind,
        version: u64,
        bytes: SecretBytes,
        deadline: Instant,
    ) -> Result<(), ControlError> {
        supported(kind)?;
        self.ready(deadline)?;
        validate_password(bytes.expose())?;
        self.vault
            .put_credential(reference, version, bytes, deadline)
            .map_err(map)
    }
    fn load_credential(
        &self,
        reference: &SecretRef,
        kind: &NodeCredentialKind,
        version: Option<u64>,
        deadline: Instant,
    ) -> Result<Option<SecretBytes>, ControlError> {
        supported(kind)?;
        self.ready(deadline)?;
        let record = match self.vault.get_credential(reference, deadline) {
            Ok(value) => value,
            Err(VaultError::NotFound) => return Ok(None),
            Err(error) => return Err(map(error)),
        };
        if version.is_some_and(|version| version != record.version) {
            return Err(ControlError::InvalidConfiguration);
        }
        validate_password(record.bytes.expose())?;
        within(deadline)?;
        Ok(Some(record.bytes))
    }
    fn retire_credential(
        &self,
        reference: &SecretRef,
        version: u64,
        deadline: Instant,
    ) -> Result<(), ControlError> {
        self.ready(deadline)?;
        self.vault
            .retire_credential(reference, version, deadline)
            .map_err(map)
    }
    // Publication issuance is intentionally not supplied by this narrow adapter.
    fn generate_publication_token(&self, _: Instant) -> Result<SecretBytes, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn publication_verifier(&self, _: &[u8]) -> Result<ContentDigest, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn verify_publication_token(&self, _: &ContentDigest, _: &[u8]) -> bool {
        false
    }
}

/// Opt-in experimental manager. UUID and SS records are typed inside the
/// authenticated encrypted vault payload; legacy password records stay intact.
#[cfg(feature = "experimental-public")]
pub struct TlsExperimentalSecretManager { base: TlsPasswordSecretManager }
#[cfg(feature = "experimental-public")]
impl TlsExperimentalSecretManager {
    pub fn new(vault: Arc<TlsSecretStore>) -> Self { Self { base: TlsPasswordSecretManager::new(vault) } }
}
#[cfg(feature = "experimental-public")]
fn experimental_kind(kind: &NodeCredentialKind) -> Result<vp_product_domain::experimental_credential_frame::CredentialFrameKind, ControlError> {
    use vp_product_domain::{experimental_credential_frame::CredentialFrameKind as K, ShadowsocksCipher};
    match kind {
        NodeCredentialKind::Uuid {} => Ok(K::Uuid),
        NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm } => Ok(K::ShadowsocksAes128Gcm),
        _ => Err(ControlError::ExecutorUnavailable),
    }
}
#[cfg(feature = "experimental-public")]
fn random_uuid_v4() -> Result<SecretBytes, ControlError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = Zeroizing::new([0u8; 16]);
    getrandom::fill(random.as_mut()).map_err(|_| ControlError::ExecutorUnavailable)?;
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    let mut output = Zeroizing::new(Vec::with_capacity(36));
    for (i, byte) in random.iter().enumerate() {
        if [4, 6, 8, 10].contains(&i) { output.push(b'-'); }
        output.push(HEX[(byte >> 4) as usize]);
        output.push(HEX[(byte & 15) as usize]);
    }
    Ok(SecretBytes::new(std::mem::take(&mut *output)))
}
#[cfg(feature = "experimental-public")]
impl SecretManager for TlsExperimentalSecretManager {
    fn supported_kinds(&self) -> Vec<NodeCredentialKind> {
        vec![NodeCredentialKind::Password {}, NodeCredentialKind::Uuid {}, NodeCredentialKind::Shadowsocks { method: vp_product_domain::ShadowsocksCipher::Aes128Gcm }]
    }
    fn generate_credential(&self, kind: &NodeCredentialKind, deadline: Instant) -> Result<GeneratedCredential, ControlError> {
        if matches!(kind, NodeCredentialKind::Password {}) { return self.base.generate_credential(kind, deadline); }
        let frame_kind = experimental_kind(kind)?;
        self.base.ready(deadline)?;
        let entropy = random_hex::<16>()?;
        let reference = SecretRef::new(&format!("node-{}", std::str::from_utf8(entropy.expose()).map_err(|_| ControlError::ExecutorFailed)?)).map_err(|_| ControlError::ExecutorFailed)?;
        let bytes = match frame_kind {
            vp_product_domain::experimental_credential_frame::CredentialFrameKind::Uuid => random_uuid_v4()?,
            vp_product_domain::experimental_credential_frame::CredentialFrameKind::ShadowsocksAes128Gcm => random_hex::<32>()?,
        };
        within(deadline)?;
        Ok(GeneratedCredential { reference, bytes })
    }
    fn put_credential(&self, reference: &SecretRef, kind: &NodeCredentialKind, version: u64, bytes: SecretBytes, deadline: Instant) -> Result<(), ControlError> {
        if matches!(kind, NodeCredentialKind::Password {}) { return self.base.put_credential(reference, kind, version, bytes, deadline); }
        let kind = experimental_kind(kind)?;
        self.base.ready(deadline)?;
        let frame = vp_product_domain::experimental_credential_frame::encode(kind, bytes.expose()).map_err(|_| ControlError::InvalidConfiguration)?;
        self.base.vault.put_credential(reference, version, frame, deadline).map_err(map)
    }
    fn load_credential(&self, reference: &SecretRef, kind: &NodeCredentialKind, version: Option<u64>, deadline: Instant) -> Result<Option<SecretBytes>, ControlError> {
        if matches!(kind, NodeCredentialKind::Password {}) { return self.base.load_credential(reference, kind, version, deadline); }
        let kind = experimental_kind(kind)?;
        self.base.ready(deadline)?;
        let record = match self.base.vault.get_credential(reference, deadline) {
            Ok(record) => record,
            Err(VaultError::NotFound) => return Ok(None),
            Err(error) => return Err(map(error)),
        };
        if version.is_some_and(|v| v != record.version) { return Err(ControlError::InvalidConfiguration); }
        let value = vp_product_domain::experimental_credential_frame::decode(kind, record.bytes.expose()).map_err(|_| ControlError::InvalidConfiguration)?;
        within(deadline)?;
        Ok(Some(value))
    }
    fn retire_credential(&self, reference: &SecretRef, version: u64, deadline: Instant) -> Result<(), ControlError> { self.base.retire_credential(reference, version, deadline) }
    fn generate_publication_token(&self, deadline: Instant) -> Result<SecretBytes, ControlError> { self.base.generate_publication_token(deadline) }
    fn publication_verifier(&self, bytes: &[u8]) -> Result<ContentDigest, ControlError> { self.base.publication_verifier(bytes) }
    fn verify_publication_token(&self, digest: &ContentDigest, bytes: &[u8]) -> bool { self.base.verify_publication_token(digest, bytes) }
}
