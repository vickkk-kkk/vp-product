//! Typed immutable-material port only. No vault, control transaction, disk cache,
//! certificate issuance or permanent "successful" placeholder implementation.
use super::{protocol_v2, server_v2::ServerInputsV2, Cancellation};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};
use vp_product_compiler::server_v2::{CredentialEncodingV2, ServerRecipeV2, ServerSecurityV2};
use vp_product_domain::{CertificateId, SecretBytes, SecretRef};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterialFailureV2 {
    Unavailable,
    Missing,
    KindMismatch,
    EncodingMismatch,
    InvalidMaterial,
    Limit,
    Timeout,
    Canceled,
}
/// Implementations must enforce immutable reference/version AND requested kind/
/// encoding, read at most max_bytes, and honor deadline/cancel. Returning a public
/// certificate projection is not evidence that its private key was resolved.
pub trait ServerMaterialResolverV2: Send + Sync {
    fn credential(
        &self,
        reference: &SecretRef,
        encoding: CredentialEncodingV2,
        max_bytes: usize,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<SecretBytes, MaterialFailureV2>;
    fn certificate_chain(
        &self,
        reference: &CertificateId,
        max_bytes: usize,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<SecretBytes, MaterialFailureV2>;
    fn private_key(
        &self,
        reference: &SecretRef,
        max_bytes: usize,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<SecretBytes, MaterialFailureV2>;
}
fn check(deadline: Instant, cancel: &Cancellation) -> Result<(), MaterialFailureV2> {
    if cancel.is_canceled() {
        Err(MaterialFailureV2::Canceled)
    } else if Instant::now() >= deadline {
        Err(MaterialFailureV2::Timeout)
    } else {
        Ok(())
    }
}
/// Invoke immediately before host prepare, not at draft/staging time. No result
/// is serializable as a normal DTO or retained as a recovery/rollback artifact.
pub fn resolve_materials_v2(
    recipe: &ServerRecipeV2,
    resolver: &dyn ServerMaterialResolverV2,
    deadline: Instant,
    cancel: &Cancellation,
) -> Result<ServerInputsV2, MaterialFailureV2> {
    check(deadline, cancel)?;
    if recipe.listeners.len() > 128 {
        return Err(MaterialFailureV2::Limit);
    }
    let mut credentials = BTreeMap::new();
    let mut certificates = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for listener in &recipe.listeners {
        check(deadline, cancel)?;
        for credential in &listener.credentials {
            if credentials
                .insert(credential.reference.clone(), credential.encoding)
                .is_some_and(|prior| prior != credential.encoding)
            {
                return Err(MaterialFailureV2::EncodingMismatch);
            }
            if credentials.len() > protocol_v2::MAX_MATERIAL_RECORDS_V2 {
                return Err(MaterialFailureV2::Limit);
            }
        }
        if let ServerSecurityV2::Tls {
            certificate_ref,
            private_key_ref,
            ..
        } = &listener.security
        {
            certificates.insert(certificate_ref.clone());
            keys.insert(private_key_ref.clone());
        }
    }
    if credentials.len() + certificates.len() + keys.len() > protocol_v2::MAX_MATERIAL_RECORDS_V2 {
        return Err(MaterialFailureV2::Limit);
    }
    if credentials.keys().any(|reference| keys.contains(reference)) {
        return Err(MaterialFailureV2::KindMismatch);
    }
    let mut inputs = ServerInputsV2::default();
    for (reference, encoding) in credentials {
        check(deadline, cancel)?;
        let value = resolver.credential(&reference, encoding, 4096, deadline, cancel)?;
        inputs.credentials.insert(reference, value);
        protocol_v2::validate_material_budget(&inputs).map_err(|_| MaterialFailureV2::Limit)?;
    }
    for reference in certificates {
        check(deadline, cancel)?;
        let value = resolver.certificate_chain(
            &reference,
            protocol_v2::MAX_CERTIFICATE_BYTES_V2,
            deadline,
            cancel,
        )?;
        inputs.certificate_chains.insert(reference, value);
        protocol_v2::validate_material_budget(&inputs).map_err(|_| MaterialFailureV2::Limit)?;
    }
    for reference in keys {
        check(deadline, cancel)?;
        let value = resolver.private_key(&reference, 65536, deadline, cancel)?;
        inputs.private_keys.insert(reference, value);
        protocol_v2::validate_material_budget(&inputs).map_err(|_| MaterialFailureV2::Limit)?;
    }
    check(deadline, cancel)?;
    Ok(inputs)
}

#[cfg(test)]
#[path = "material_port_v2_tests.rs"]
mod tests;
