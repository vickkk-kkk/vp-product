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
    pair::validate_pair(chain, key, deadline, &canceled).map_err(|e| match e {
        pair::Failure::Canceled => ControlError::Canceled,
        pair::Failure::Timeout => ControlError::PlanExpired,
        _ => ControlError::InvalidConfiguration,
    })?;
    let certificates = rustls_pemfile::certs(&mut &chain.expose()[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ControlError::InvalidConfiguration)?;
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
    parsed
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
    Ok(facts)
}
