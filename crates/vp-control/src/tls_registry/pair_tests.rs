#![allow(clippy::unwrap_used)]
use super::*;
use crate::tls_test_pem::TestPem;
use std::time::Duration;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn pair() -> (SecretBytes, SecretBytes) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (
        SecretBytes::new(generated.cert.pem().into_bytes()),
        SecretBytes::new(generated.key_pair.serialize_pem().into_bytes()),
    )
}
#[test]
fn synthetic_pair_and_wrong_pair() {
    let (chain, key) = pair();
    let (_, other_key) = pair();
    assert_eq!(validate_pair(&chain, &key, deadline(), &|| false), Ok(()));
    assert_eq!(
        validate_pair(&chain, &other_key, deadline(), &|| false),
        Err(Failure::Invalid)
    );
}
#[test]
fn strict_pem_rejects_skipped_junk_unknown_blocks_and_extra_keys() {
    let (chain, key) = pair();
    for prefix in [
        b"comment\n".as_slice(),
        b"-----BEGIN UNKNOWN-----\nAA==\n-----END UNKNOWN-----\n",
    ] {
        let bad = SecretBytes::new([prefix, chain.expose()].concat());
        assert!(validate_pair(&bad, &key, deadline(), &|| false).is_err());
    }
    let doubled = SecretBytes::new([key.expose(), key.expose()].concat());
    assert_eq!(
        validate_pair(&chain, &doubled, deadline(), &|| false),
        Err(Failure::Limit)
    );
    let mixed = SecretBytes::new([chain.expose(), key.expose()].concat());
    assert_eq!(
        validate_pair(&mixed, &key, deadline(), &|| false),
        Err(Failure::Invalid)
    );
    let trailing = SecretBytes::new([key.expose(), b"junk"].concat());
    assert_eq!(
        validate_pair(&chain, &trailing, deadline(), &|| false),
        Err(Failure::Invalid)
    );
}
#[test]
fn malformed_empty_oversize_and_chain_count_rejected() {
    let (chain, key) = pair();
    for bytes in [
        vec![],
        vec![b'x'; MAX_BYTES + 1],
        b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----".to_vec(),
        vec![255],
    ] {
        assert!(validate_pair(&SecretBytes::new(bytes), &key, deadline(), &|| false).is_err());
    }
    assert_eq!(
        validate_pair(
            &SecretBytes::new(chain.expose().repeat(9)),
            &key,
            deadline(),
            &|| false
        ),
        Err(Failure::Limit)
    );
}
#[test]
fn malformed_intermediate_and_duplicate_cert_are_rejected() {
    let (chain, key) = pair();
    let malformed = b"\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
    for bytes in [
        [chain.expose(), malformed].concat(),
        chain.expose().repeat(2),
    ] {
        assert_eq!(
            validate_pair(&SecretBytes::new(bytes), &key, deadline(), &|| false),
            Err(Failure::Invalid)
        );
    }
}

fn pkcs8_inner(der: &[u8]) -> Vec<u8> {
    yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            r.next().read_u64()?;
            r.next().read_der()?;
            r.next().read_bytes()
        })
    })
    .unwrap()
}
fn pem_key(label: &str, der: Vec<u8>) -> SecretBytes {
    SecretBytes::new(crate::tls_test_pem::encode(label, &der).into_bytes())
}
#[test]
fn pkcs8_ec_and_sec1_positive_trailing_and_malformed_der() {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = SecretBytes::new(generated.cert.pem().into_bytes());
    let pkcs8 = generated.key_pair.serialize_der();
    let inner = pkcs8_inner(&pkcs8);
    // Standalone SEC1 needs the curve parameter formerly in PKCS#8 AlgorithmId.
    let fields: Vec<Vec<u8>> = yasna::parse_der(&inner, |r| {
        r.read_sequence(|r| {
            let mut xs = Vec::new();
            while let Some(v) = r.read_optional(|r| r.read_der())? {
                xs.push(v);
            }
            Ok(xs)
        })
    })
    .unwrap();
    let sec1 = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&fields[0]);
            w.next().write_der(&fields[1]);
            w.next().write_tagged(yasna::Tag::context(0), |w| {
                w.write_oid(&yasna::models::ObjectIdentifier::from_slice(&[
                    1, 2, 840, 10045, 3, 1, 7,
                ]))
            });
            for f in &fields[2..] {
                w.next().write_der(f);
            }
        })
    });
    for (label, bytes) in [("PRIVATE KEY", pkcs8), ("EC PRIVATE KEY", sec1)] {
        assert!(
            validate_pair(&cert, &pem_key(label, bytes.clone()), deadline(), &|| false).is_ok()
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(validate_pair(&cert, &pem_key(label, trailing), deadline(), &|| false).is_err());
        assert!(validate_pair(
            &cert,
            &pem_key(label, bytes[..bytes.len() - 1].to_vec()),
            deadline(),
            &|| false
        )
        .is_err());
    }
}
#[test]
fn cached_public_test_rsa_pkcs8_and_pkcs1_positive_and_malformed() {
    // Public, deliberately insecure test-only ring fixture. Never deployed or
    // copied as a product credential. Source identity recorded in handoff.
    let der = include_bytes!("../../tests/fixtures/ring-public-rsa/rsa_test_private_key_2048.p8");
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls::pki_types::PrivatePkcs8KeyDer::from(&der[..]),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert = SecretBytes::new(cert.pem().into_bytes());
    for (label, bytes) in [
        ("PRIVATE KEY", der.to_vec()),
        ("RSA PRIVATE KEY", pkcs8_inner(der)),
    ] {
        assert!(
            validate_pair(&cert, &pem_key(label, bytes.clone()), deadline(), &|| false).is_ok()
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(validate_pair(&cert, &pem_key(label, trailing), deadline(), &|| false).is_err());
        assert!(validate_pair(
            &cert,
            &pem_key(label, bytes[..bytes.len() - 1].to_vec()),
            deadline(),
            &|| false
        )
        .is_err());
    }
}
