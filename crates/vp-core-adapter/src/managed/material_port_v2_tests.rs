#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::managed::v2_test_support::recipe;
use std::{sync::Mutex, time::Duration};
#[derive(Default)]
struct FixtureResolver {
    calls: Mutex<Vec<(String, usize)>>,
    failure: Option<MaterialFailureV2>,
    oversized: bool,
    cancel_on_read: bool,
}
impl FixtureResolver {
    fn value(
        &self,
        kind: &str,
        max: usize,
        cancel: &Cancellation,
    ) -> Result<SecretBytes, MaterialFailureV2> {
        self.calls.lock().unwrap().push((kind.to_owned(), max));
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        if self.cancel_on_read {
            cancel.cancel();
        }
        Ok(SecretBytes::new(if self.oversized {
            vec![1; max + 1]
        } else {
            vec![1]
        }))
    }
}
impl ServerMaterialResolverV2 for FixtureResolver {
    fn credential(
        &self,
        _: &SecretRef,
        encoding: CredentialEncodingV2,
        max: usize,
        _: Instant,
        cancel: &Cancellation,
    ) -> Result<SecretBytes, MaterialFailureV2> {
        assert_eq!(encoding, CredentialEncodingV2::CanonicalUuidTextV1 {});
        self.value("credential", max, cancel)
    }
    fn certificate_chain(
        &self,
        _: &CertificateId,
        max: usize,
        _: Instant,
        cancel: &Cancellation,
    ) -> Result<SecretBytes, MaterialFailureV2> {
        self.value("certificate", max, cancel)
    }
    fn private_key(
        &self,
        _: &SecretRef,
        max: usize,
        _: Instant,
        cancel: &Cancellation,
    ) -> Result<SecretBytes, MaterialFailureV2> {
        self.value("private_key", max, cancel)
    }
}
fn resolve(
    source: &ServerRecipeV2,
    resolver: &FixtureResolver,
) -> Result<ServerInputsV2, MaterialFailureV2> {
    resolve_materials_v2(
        source,
        resolver,
        Instant::now() + Duration::from_secs(1),
        &Cancellation::default(),
    )
}
#[test]
fn resolver_deduplicates_immutable_references_and_keeps_typed_kind_limits() {
    let mut source = recipe(19001);
    source.listeners.push(source.listeners[0].clone());
    source.listeners[0].security = ServerSecurityV2::Tls {
        certificate_ref: CertificateId::new("fixture-cert").unwrap(),
        private_key_ref: SecretRef::new("fixture-key").unwrap(),
        alpn: vec![],
    };
    let resolver = FixtureResolver::default();
    let result = resolve(&source, &resolver).unwrap();
    assert_eq!(result.credentials.len(), 1);
    assert_eq!(result.certificate_chains.len(), 1);
    assert_eq!(result.private_keys.len(), 1);
    assert_eq!(
        *resolver.calls.lock().unwrap(),
        vec![
            ("credential".into(), 4096),
            ("certificate".into(), protocol_v2::MAX_CERTIFICATE_BYTES_V2),
            ("private_key".into(), 65536)
        ]
    );
    assert_eq!(format!("{result:?}"), "ServerInputsV2([REDACTED])");
}
#[test]
fn resolver_kind_and_encoding_aliases_fail_before_material_access() {
    let mut source = recipe(19001);
    let mut other = source.listeners[0].clone();
    other.credentials[0].encoding = CredentialEncodingV2::PasswordUtf8V1 {};
    source.listeners.push(other);
    let resolver = FixtureResolver::default();
    assert_eq!(
        resolve(&source, &resolver).unwrap_err(),
        MaterialFailureV2::EncodingMismatch
    );
    assert!(resolver.calls.lock().unwrap().is_empty());
    source.listeners.pop();
    source.listeners[0].security = ServerSecurityV2::Tls {
        certificate_ref: CertificateId::new("fixture-cert").unwrap(),
        private_key_ref: source.listeners[0].credentials[0].reference.clone(),
        alpn: vec![],
    };
    assert_eq!(
        resolve(&source, &resolver).unwrap_err(),
        MaterialFailureV2::KindMismatch
    );
    assert!(resolver.calls.lock().unwrap().is_empty());
}
#[test]
fn resolver_unavailable_oversize_and_provider_cancellation_are_not_success() {
    let source = recipe(19001);
    for failure in [
        MaterialFailureV2::Unavailable,
        MaterialFailureV2::Missing,
        MaterialFailureV2::KindMismatch,
        MaterialFailureV2::EncodingMismatch,
    ] {
        let resolver = FixtureResolver {
            failure: Some(failure),
            ..Default::default()
        };
        assert_eq!(resolve(&source, &resolver).unwrap_err(), failure);
    }
    let resolver = FixtureResolver {
        oversized: true,
        ..Default::default()
    };
    assert_eq!(
        resolve(&source, &resolver).unwrap_err(),
        MaterialFailureV2::Limit
    );
    let resolver = FixtureResolver {
        cancel_on_read: true,
        ..Default::default()
    };
    assert_eq!(
        resolve(&source, &resolver).unwrap_err(),
        MaterialFailureV2::Canceled
    );
}
#[test]
fn resolver_pre_canceled_expired_and_oversize_reference_sets_do_not_access_material() {
    let mut source = recipe(19001);
    let resolver = FixtureResolver::default();
    let cancel = Cancellation::default();
    cancel.cancel();
    assert_eq!(
        resolve_materials_v2(
            &source,
            &resolver,
            Instant::now() + Duration::from_secs(1),
            &cancel
        )
        .unwrap_err(),
        MaterialFailureV2::Canceled
    );
    assert_eq!(
        resolve_materials_v2(&source, &resolver, Instant::now(), &Cancellation::default())
            .unwrap_err(),
        MaterialFailureV2::Timeout
    );
    source.listeners = vec![source.listeners[0].clone(); 129];
    assert_eq!(
        resolve(&source, &resolver).unwrap_err(),
        MaterialFailureV2::Limit
    );
    assert!(resolver.calls.lock().unwrap().is_empty());
}
