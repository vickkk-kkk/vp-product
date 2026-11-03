//! Separate server-v2 graph only. Not compiled by or selected in the v1 product.
use std::time::Instant;
use vp_product_compiler::server_v2::{CredentialEncodingV2, ServerCompilerV2, ServerProfileV2, ServerRecipeV2};
use vp_product_control::{ContentDigest, ControlError, TlsMaterialAdmission};
use vp_product_core_adapter::managed::{
    material_port_v2::{MaterialFailureV2, ServerMaterialResolverV2},
    Cancellation,
};
use vp_product_domain::{CertificateId, SecretBytes, SecretRef};

/// SHA-256 of canonical serialized recipe bytes, matching the durable artifact store.
/// This computes an identity only; the caller must still validate and approve the plan.
pub fn public_recipe_digest(recipe: &ServerRecipeV2) -> Result<ContentDigest, MaterialFailureV2> {
    if recipe.profile != ServerProfileV2::PublicExperimentalUncertified {
        return Err(MaterialFailureV2::InvalidMaterial);
    }
    let bytes = serde_json::to_vec(recipe).map_err(|_| MaterialFailureV2::InvalidMaterial)?;
    Ok(ContentDigest::bytes(&bytes))
}

/// Resolve an already sealed and currently staging experimental plan. This is a
/// preparation step only: it does not spawn a worker, bind, or claim health.
#[cfg(feature = "experimental-public")]
pub fn resolve_public_stage(
    context: &vp_product_control::RuntimeStageContext<'_>,
    vault: &dyn vp_product_control::TlsMaterialVault,
    policy: &vp_product_control::TlsBackendPolicy,
    compiler: &ServerCompilerV2,
    deadline: Instant,
    cancel: &Cancellation,
) -> Result<(ServerRecipeV2, vp_product_core_adapter::managed::server_v2::ServerInputsV2), ControlError> {
    if context.cancellation().is_canceled() || cancel.is_canceled() {
        return Err(ControlError::Canceled);
    }
    let plan = context.plan();
    plan.verify_integrity()?;
    let recipe = compiler.compile(&plan.body().config, &plan.body().release)
        .map_err(|_| ControlError::InvalidConfiguration)?;
    if recipe.profile != ServerProfileV2::PublicExperimentalUncertified
        || public_recipe_digest(&recipe).map_err(|_| ControlError::InvalidConfiguration)?
            != plan.body().validation.artifact_digest {
        return Err(ControlError::InvalidConfiguration);
    }
    let admission = context.experimental_public_materials(vault, policy, deadline)?;
    let resolver = RegistryMaterialResolverV2::new(admission, &recipe, compiler)
        .map_err(|_| ControlError::InvalidConfiguration)?;
    let inputs = vp_product_core_adapter::managed::material_port_v2::resolve_materials_v2(
        &recipe, &resolver, deadline, cancel,
    ).map_err(|failure| match failure {
        MaterialFailureV2::Canceled => ControlError::Canceled,
        MaterialFailureV2::Timeout => ControlError::PlanExpired,
        _ => ControlError::InvalidConfiguration,
    })?;
    if context.cancellation().is_canceled() { return Err(ControlError::Canceled); }
    Ok((recipe, inputs))
}

pub struct RegistryMaterialResolverV2<'a> {
    admission: TlsMaterialAdmission<'a>,
}
impl<'a> RegistryMaterialResolverV2<'a> {
    /// Recompile rather than trust mutable recipe DTO fields. The compiler is
    /// provisioned by the backend for the exact approved server-v2 release.
    pub fn new(
        admission: TlsMaterialAdmission<'a>,
        recipe: &ServerRecipeV2,
        compiler: &ServerCompilerV2,
    ) -> Result<Self, MaterialFailureV2> {
        // Public target authority must be part of the immutable approved artifact,
        // not merely supplied by a caller constructing a compatible compiler.
        if recipe.profile == ServerProfileV2::PublicExperimentalUncertified {
            let digest = public_recipe_digest(recipe)?;
            if &digest != admission.artifact_digest() { return Err(MaterialFailureV2::InvalidMaterial); }
        }
        if &recipe.source != admission.config()
            || &recipe.release != admission.release()
            || compiler
                .compile(admission.config(), admission.release())
                .map_err(|_| MaterialFailureV2::InvalidMaterial)?
                != *recipe
        {
            return Err(MaterialFailureV2::InvalidMaterial);
        }
        Ok(Self { admission })
    }
}
fn check(d: Instant, c: &Cancellation) -> Result<(), MaterialFailureV2> {
    if c.is_canceled() {
        Err(MaterialFailureV2::Canceled)
    } else if Instant::now() >= d {
        Err(MaterialFailureV2::Timeout)
    } else {
        Ok(())
    }
}
fn map(e: ControlError) -> MaterialFailureV2 {
    match e {
        ControlError::Canceled => MaterialFailureV2::Canceled,
        ControlError::PlanExpired => MaterialFailureV2::Timeout,
        ControlError::NotFound => MaterialFailureV2::Missing,
        _ => MaterialFailureV2::InvalidMaterial,
    }
}
impl ServerMaterialResolverV2 for RegistryMaterialResolverV2<'_> {
    fn credential(
        &self,
        r: &SecretRef,
        e: CredentialEncodingV2,
        n: usize,
        d: Instant,
        c: &Cancellation,
    ) -> Result<SecretBytes, MaterialFailureV2> {
        check(d, c)?;
        let value = match e {
            CredentialEncodingV2::PasswordUtf8V1 {} => self.admission.password_at(r, n, d, &|| c.is_canceled()),
            CredentialEncodingV2::CanonicalUuidTextV1 {} => self.admission.experimental_server_credential_at(r, &vp_product_domain::NodeCredentialKind::Uuid {}, n, d, &|| c.is_canceled()),
            CredentialEncodingV2::ShadowsocksLegacyPasswordUtf8V1 {} => self.admission.experimental_server_credential_at(r, &vp_product_domain::NodeCredentialKind::Shadowsocks { method: vp_product_domain::ShadowsocksCipher::Aes128Gcm }, n, d, &|| c.is_canceled()),
            _ => return Err(MaterialFailureV2::EncodingMismatch),
        }.map_err(map)?;
        check(d, c)?;
        Ok(value)
    }
    fn certificate_chain(
        &self,
        r: &CertificateId,
        n: usize,
        d: Instant,
        c: &Cancellation,
    ) -> Result<SecretBytes, MaterialFailureV2> {
        check(d, c)?;
        let value = self
            .admission
            .certificate_chain_at(r, n, d, &|| c.is_canceled())
            .map_err(map)?;
        check(d, c)?;
        Ok(value)
    }
    fn private_key(
        &self,
        r: &SecretRef,
        n: usize,
        d: Instant,
        c: &Cancellation,
    ) -> Result<SecretBytes, MaterialFailureV2> {
        check(d, c)?;
        let value = self
            .admission
            .private_key_at(r, n, d, &|| c.is_canceled())
            .map_err(map)?;
        check(d, c)?;
        Ok(value)
    }
}

#[cfg(test)]
mod public_recipe_tests {
    use super::*;
    use vp_product_domain::ProductConfig;
    #[test]
    fn public_recipe_digest_changes_with_egress_authority() {
        let release = vp_product_core_adapter::inspect_build().unwrap().build.release;
        let source: ProductConfig = serde_json::from_value(serde_json::json!({
            "schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{
                "schemaVersion":1,"id":"fixture","name":"fixture","enabled":true,
                "bind":{"address":"192.168.1.5","port":19001},
                "protocol":{"kind":"proxy","protocol":{"kind":"trojan"},"users":[{"id":"test-user","credentialRef":"secret:test-password","enabled":true}]},
                "transport":{"kind":"tcp"},"security":{"kind":"tls","certificateRef":"test-certificate","privateKeyRef":"secret:test-key","alpn":[]},"requirements":[]
            }]
        })).unwrap();
        let compiler = ServerCompilerV2::for_public_experiment(release.clone(), vec!["8.8.8.8:443".parse().unwrap()]).unwrap();
        let recipe = compiler.compile(&source, &release).unwrap();
        let original = public_recipe_digest(&recipe).unwrap();
        let mut tampered = recipe.clone();
        tampered.public_targets = Some(vec!["1.1.1.1:443".parse().unwrap()]);
        assert_ne!(original, public_recipe_digest(&tampered).unwrap());
        assert!(compiler.verify_recipe(&tampered).is_err());
        tampered.profile = ServerProfileV2::LoopbackDevelopmentUncertified;
        assert!(public_recipe_digest(&tampered).is_err());
    }
}
