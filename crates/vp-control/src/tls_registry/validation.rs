//! Exact same parsed leaf supplies metadata and cryptographic verification.
//! No public trust/revocation/issuance or complete SAN inventory claim.
#[path = "pair.rs"]
mod pair;
#[path = "validity.rs"]
mod validity;
use super::{service::TlsBackendPolicy, PublicFacts};
use crate::{CancellationToken, ContentDigest, ControlError};
use rustls::pki_types::UnixTime;
use std::time::{Duration, Instant};
use vp_product_domain::SecretBytes;

pub(super) fn verify(
    chain: &SecretBytes,
    key: &SecretBytes,
    policy: &TlsBackendPolicy,
    now_ms: u64,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<PublicFacts, ControlError> {
    verify_checked(chain, key, policy, now_ms, deadline, &|| {
        cancel.is_canceled()
    })
}
pub(super) fn verify_checked(
    chain: &SecretBytes,
    key: &SecretBytes,
    policy: &TlsBackendPolicy,
    now_ms: u64,
    deadline: Instant,
    canceled: &dyn Fn() -> bool,
) -> Result<PublicFacts, ControlError> {
    verify_internal(chain, key, policy, now_ms, deadline, canceled, false)
        .map(|(facts, _)| facts)
}

/// Ephemeral public path identity, never persisted authority or worker-supplied proof.
/// Only actual webpki-selected intermediates are represented; provisioned anchor
/// expiry and self-signature are deliberately not checked.
#[allow(dead_code)] // Pure source slice: context-owned bridge is not yet wired.
pub(super) struct SelectedPathProjection {
    pub(super) chain_digest: ContentDigest,
    pub(super) leaf_digest: ContentDigest,
    pub(super) selected_certificate_digests: Vec<ContentDigest>,
    pub(super) selected_anchor_digest: ContentDigest,
    pub(super) policy_fingerprint: String,
}

/// Protocol3-only projection. Existing verify_checked accepts exactly its prior
/// certificate profile; this opt-in additionally requires selected intermediates
/// to fit the strict metadata decoder (including explicit X.509 v3 version).
#[allow(dead_code)] // Pure source slice: context-owned bridge is not yet wired.
pub(super) fn verify_checked_with_path(
    chain: &SecretBytes,
    key: &SecretBytes,
    policy: &TlsBackendPolicy,
    now_ms: u64,
    deadline: Instant,
    canceled: &dyn Fn() -> bool,
) -> Result<(PublicFacts, SelectedPathProjection), ControlError> {
    let (facts, selected) = verify_internal(chain, key, policy, now_ms, deadline, canceled, true)?;
    Ok((facts, selected.ok_or(ControlError::InvalidConfiguration)?))
}

#[allow(clippy::too_many_arguments)]
fn verify_internal(
    chain: &SecretBytes,
    key: &SecretBytes,
    policy: &TlsBackendPolicy,
    now_ms: u64,
    deadline: Instant,
    canceled: &dyn Fn() -> bool,
    project_path: bool,
) -> Result<(PublicFacts, Option<SelectedPathProjection>), ControlError> {
    let check = || {
        if canceled() {
            Err(ControlError::Canceled)
        } else if Instant::now() >= deadline {
            Err(ControlError::PlanExpired)
        } else {
            Ok(())
        }
    };
    check()?;
    if project_path && (chain.expose().len() > 65536 || key.expose().len() > 65536) {
        return Err(ControlError::InvalidConfiguration);
    }
    pair::validate_pair(chain, key, deadline, &canceled).map_err(|e| match e {
        pair::Failure::Canceled => ControlError::Canceled,
        pair::Failure::Timeout => ControlError::PlanExpired,
        _ => ControlError::InvalidConfiguration,
    })?;
    let certificates = rustls_pemfile::certs(&mut &chain.expose()[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ControlError::InvalidConfiguration)?;
    if project_path && certificates.len() > 128 {
        return Err(ControlError::InvalidConfiguration);
    }
    let leaf = certificates
        .first()
        .ok_or(ControlError::InvalidConfiguration)?;
    let parsed =
        webpki::EndEntityCert::try_from(leaf).map_err(|_| ControlError::InvalidConfiguration)?;
    let interval =
        validity::extract_validity(&parsed, deadline, &canceled).map_err(|e| match e {
            validity::Failure::Canceled => ControlError::Canceled,
            validity::Failure::Timeout => ControlError::PlanExpired,
            _ => ControlError::InvalidConfiguration,
        })?;
    let anchors = policy
        .anchors
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ControlError::InvalidConfiguration)?;
    let provider = rustls::crypto::ring::default_provider();
    // Server usage if EKU exists; no requirement that EKU exists. One usable path,
    // not proof every unused intermediate was validated or that order is canonical.
    let verified_path = parsed
        .verify_for_usage(
            provider.signature_verification_algorithms.all,
            &anchors,
            &certificates[1..],
            UnixTime::since_unix_epoch(Duration::from_secs(now_ms / 1000)),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|_| ControlError::InvalidConfiguration)?;
    check()?;
    parsed
        .verify_is_valid_for_subject_name(&policy.name)
        .map_err(|_| ControlError::InvalidConfiguration)?;
    let dns = parsed
        .valid_dns_names()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if dns.len() > 128
        || dns.iter().map(String::len).sum::<usize>() > 8192
        || dns.iter().any(|n| n.len() > 253)
    {
        return Err(ControlError::InvalidConfiguration);
    }
    let spki = parsed.subject_public_key_info();
    if spki.len() > 16384 {
        return Err(ControlError::InvalidConfiguration);
    }
    let mut canonical = Vec::new();
    let mut size = 0u32;
    for cert in &certificates {
        let len = u32::try_from(cert.len()).map_err(|_| ControlError::InvalidConfiguration)?;
        size = size
            .checked_add(len)
            .ok_or(ControlError::InvalidConfiguration)?;
        canonical.extend_from_slice(&len.to_be_bytes());
        canonical.extend_from_slice(cert.as_ref());
    }
    let facts = PublicFacts {
        chain_digest: ContentDigest::bytes(&canonical),
        chain_size: size,
        leaf_digest: ContentDigest::bytes(parsed.der().as_ref()),
        spki_digest: ContentDigest::bytes(spki.as_ref()),
        not_before: interval.not_before_unix_seconds,
        not_after: interval.not_after_unix_seconds,
        policy: policy.fingerprint.clone(),
        display_dns_names: dns,
    };
    facts.validate()?;
    check()?;
    let selected = if project_path {
        let mut digests = vec![ContentDigest::bytes(verified_path.end_entity().der().as_ref())];
        for certificate in verified_path.intermediate_certificates() {
            check()?;
            if digests.len() >= 8 { return Err(ControlError::InvalidConfiguration); }
            vp_product_x509_validity::decode_certificate_validity_der(certificate.der().as_ref())
                .map_err(|_| ControlError::InvalidConfiguration)?;
            let digest = ContentDigest::bytes(certificate.der().as_ref());
            if digests.contains(&digest) { return Err(ControlError::InvalidConfiguration); }
            digests.push(digest);
        }
        // VerifiedPath borrows one of this exact anchor slice. Resolve by object
        // identity rather than guessing from issuer/subject or supplied chain order.
        let anchor_index = anchors.iter().position(|anchor| std::ptr::eq(anchor, verified_path.anchor()))
            .ok_or(ControlError::InvalidConfiguration)?;
        Some(SelectedPathProjection {
            chain_digest: facts.chain_digest.clone(),
            leaf_digest: facts.leaf_digest.clone(),
            selected_certificate_digests: digests,
            selected_anchor_digest: ContentDigest::bytes(policy.anchors[anchor_index].as_ref()),
            policy_fingerprint: policy.fingerprint.clone(),
        })
    } else { None };
    check()?;
    Ok((facts, selected))
}

#[cfg(test)]
mod selected_path_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
    use base64::Engine as _;

    // rcgen's PEM feature is deliberately not enabled. Encode only synthetic
    // test DER with the already-existing base64 dev dependency.
    fn pem(label: &str, der: &[u8]) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        let mut output = format!("-----BEGIN {label}-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            output.push_str(std::str::from_utf8(chunk).unwrap());
            output.push('\n');
        }
        output.push_str(&format!("-----END {label}-----\n"));
        output
    }

    #[test]
    fn actual_path_excludes_unused_certificate_and_expired_anchor_dates() {
        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(vec!["root.invalid".into()]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        root_params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let root = root_params.self_signed(&root_key).unwrap();
        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::new(vec!["intermediate.invalid".into()]).unwrap();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let intermediate = intermediate_params.signed_by(&intermediate_key, &root, &root_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params.signed_by(&leaf_key, &intermediate, &intermediate_key).unwrap();
        let unused_key = KeyPair::generate().unwrap();
        let mut unused_params = CertificateParams::new(vec!["unused.invalid".into()]).unwrap();
        unused_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        unused_params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let unused = unused_params.self_signed(&unused_key).unwrap();
        let chain = SecretBytes::new(format!("{}{}{}", pem("CERTIFICATE", leaf.der().as_ref()), pem("CERTIFICATE", unused.der().as_ref()), pem("CERTIFICATE", intermediate.der().as_ref())).into_bytes());
        let key = SecretBytes::new(pem("PRIVATE KEY", &leaf_key.serialize_der()).into_bytes());
        let policy = TlsBackendPolicy::new("test".into(), vec![root.der().as_ref().to_vec()], "localhost".into()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let (facts, path) = verify_checked_with_path(&chain, &key, &policy, 1717200000000, deadline, &|| false).unwrap();
        let ordinary = verify_checked(&chain, &key, &policy, 1717200000000, deadline, &|| false).unwrap();
        assert!(facts == ordinary);
        assert_eq!(path.chain_digest, facts.chain_digest);
        assert_eq!(path.leaf_digest, facts.leaf_digest);
        assert_eq!(path.policy_fingerprint, policy.fingerprint);
        assert_eq!(path.selected_anchor_digest, ContentDigest::bytes(root.der().as_ref()));
        assert_eq!(path.selected_certificate_digests, vec![ContentDigest::bytes(leaf.der().as_ref()), ContentDigest::bytes(intermediate.der().as_ref())]);
        assert!(matches!(verify_checked_with_path(&chain, &key, &policy, 1717200000000, deadline, &|| true), Err(ControlError::Canceled)));
        assert!(matches!(verify_checked_with_path(&chain, &key, &policy, 1717200000000, Instant::now(), &|| false), Err(ControlError::PlanExpired)));
        let oversized = SecretBytes::new(vec![0; 65537]);
        assert!(matches!(verify_checked_with_path(&oversized, &key, &policy, 1717200000000, deadline, &|| false), Err(ControlError::InvalidConfiguration)));
    }
}
