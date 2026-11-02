//! Actual vault/OS-entropy port. Construction creates no credential or token.
//! Only shared control's explicitly confirmed, recoverable actions call generation.
use crate::{probes::parse_uuid, secret_generation};
use std::{sync::Arc, time::Instant};
use subtle::ConstantTimeEq;
use vp_product_control::{ContentDigest, ControlError, GeneratedCredential, SecretManager};
use vp_product_domain::{NodeCredentialKind, SecretBytes, SecretRef};
use vp_product_secrets::{DurableSecretStore, SecretKind, VaultError};
pub struct VaultSecretManager {
    vault: Arc<DurableSecretStore>,
}
impl VaultSecretManager {
    pub fn new(vault: Arc<DurableSecretStore>) -> Self {
        Self { vault }
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
    if matches!(kind, NodeCredentialKind::Uuid {}) {
        Ok(())
    } else {
        Err(ControlError::ExecutorUnavailable)
    }
}
fn map(error: VaultError) -> ControlError {
    match error {
        VaultError::PermissionDenied => ControlError::PermissionDenied,
        VaultError::NotFound => ControlError::NotFound,
        VaultError::AlreadyExists => ControlError::ResourceConflict,
        VaultError::InvalidInput | VaultError::MetadataMismatch => {
            ControlError::InvalidConfiguration
        }
        _ => ControlError::RecoveryRequired,
    }
}
impl SecretManager for VaultSecretManager {
    fn supported_kinds(&self) -> Vec<NodeCredentialKind> {
        vec![NodeCredentialKind::Uuid {}]
    }
    fn generate_credential(
        &self,
        kind: &NodeCredentialKind,
        deadline: Instant,
    ) -> Result<GeneratedCredential, ControlError> {
        within(deadline)?;
        supported(kind)?;
        let material = GeneratedCredential {
            reference: secret_generation::immutable_reference()?,
            bytes: secret_generation::uuid_credential()?,
        };
        within(deadline)?;
        Ok(material)
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
        within(deadline)?;
        parse_uuid(bytes.expose())?;
        self.vault
            .put(reference, SecretKind::Credential, version, bytes, deadline)
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
        within(deadline)?;
        let record = match self.vault.get(reference, deadline) {
            Ok(record) => record,
            Err(VaultError::NotFound) => return Ok(None),
            Err(error) => return Err(map(error)),
        };
        if record.kind != SecretKind::Credential || version.is_some_and(|v| record.version != v) {
            return Err(ControlError::InvalidConfiguration);
        }
        parse_uuid(record.bytes.expose())?;
        within(deadline)?;
        Ok(Some(record.bytes))
    }
    fn retire_credential(
        &self,
        reference: &SecretRef,
        version: u64,
        deadline: Instant,
    ) -> Result<(), ControlError> {
        self.vault
            .retire(reference, SecretKind::Credential, version, deadline)
            .map_err(map)
    }
    fn generate_publication_token(&self, deadline: Instant) -> Result<SecretBytes, ControlError> {
        within(deadline)?;
        let token = secret_generation::subscription_token()?;
        within(deadline)?;
        Ok(token)
    }
    fn publication_verifier(&self, token: &[u8]) -> Result<ContentDigest, ControlError> {
        secret_generation::subscription_verifier(token)
    }
    fn verify_publication_token(&self, verifier: &ContentDigest, token: &[u8]) -> bool {
        secret_generation::subscription_verifier(token)
            .map(|actual| {
                bool::from(
                    actual
                        .as_str()
                        .as_bytes()
                        .ct_eq(verifier.as_str().as_bytes()),
                )
            })
            .unwrap_or(false)
    }
}
