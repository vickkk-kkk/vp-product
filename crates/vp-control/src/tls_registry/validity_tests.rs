#![allow(clippy::unwrap_used)]
use super::*;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, UnixTime};
use std::time::Duration;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn signed(y1: i32, y2: i32) -> (CertificateDer<'static>, CertificateDer<'static>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(vec!["synthetic-ca.invalid".into()]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf.not_before = rcgen::date_time_ymd(y1, 1, 1);
    leaf.not_after = rcgen::date_time_ymd(y2, 1, 1);
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf.signed_by(&key, &ca, &ca_key).unwrap();
    (leaf.der().clone(), ca.der().clone())
}
fn verify(der: &CertificateDer<'_>, root: &CertificateDer<'_>, at: i64) -> bool {
    if at < 0 {
        return false;
    }
    let parsed = match webpki::EndEntityCert::try_from(der) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let anchor = webpki::anchor_from_trusted_cert(root).unwrap();
    parsed
        .verify_for_usage(
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all,
            &[anchor],
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(at as u64)),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .is_ok()
}
// Test-only DER restructuring; never used by production extraction or to issue
// credentials. Mutated signatures intentionally cease to be cryptographically valid.
fn fields(der: &[u8]) -> Vec<Vec<u8>> {
    yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            let mut fields = Vec::new();
            while let Some(field) = r.read_optional(|r| r.read_der())? {
                assert!(fields.len() < 16);
                fields.push(field);
            }
            Ok(fields)
        })
    })
    .unwrap()
}
fn sequence(fields: &[Vec<u8>]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            for field in fields {
                w.next().write_der(field);
            }
        })
    })
}
fn time_der(tag: Tag, value: &[u8]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_tagged_der(&yasna::models::TaggedDerValue::from_tag_and_bytes(
            tag,
            value.to_vec(),
        ))
    })
}
fn replace_dates(der: &[u8], dates: Vec<Vec<u8>>) -> Vec<u8> {
    let mut outer = fields(der);
    let mut tbs = fields(&outer[0]);
    tbs[4] = sequence(&dates);
    outer[0] = sequence(&tbs);
    sequence(&outer)
}
#[test]
fn exact_signed_utc_generalized_mixed_and_inclusive_endpoints() {
    for (before, after) in [(2024, 2025), (2049, 2050), (2050, 2051), (2051, 2051)] {
        let (der, root) = signed(before, after);
        let parsed = webpki::EndEntityCert::try_from(&der).unwrap();
        let interval = extract_validity(&parsed, deadline(), &|| false).unwrap();
        assert_eq!(
            interval.not_before_unix_seconds,
            rcgen::date_time_ymd(before, 1, 1).unix_timestamp()
        );
        assert_eq!(
            interval.not_after_unix_seconds,
            rcgen::date_time_ymd(after, 1, 1).unix_timestamp()
        );
        assert!(verify(&der, &root, interval.not_before_unix_seconds));
        assert!(verify(&der, &root, interval.not_after_unix_seconds));
        assert!(!verify(&der, &root, interval.not_before_unix_seconds - 1));
        assert!(!verify(&der, &root, interval.not_after_unix_seconds + 1));
    }
}
#[test]
fn utc_century_and_generalized_application_processing() {
    for (tag, bytes, year) in [
        (TAG_UTCTIME, b"500101000000Z".as_slice(), 1950),
        (TAG_UTCTIME, b"491231000000Z", 2049),
        (TAG_UTCTIME, b"000101000000Z", 2000),
        (TAG_GENERALIZEDTIME, b"20240101000000Z", 2024),
    ] {
        let der = time_der(tag, bytes);
        let value = yasna::parse_der(&der, time_field).unwrap();
        let expected = if year == 2049 {
            rcgen::date_time_ymd(2049, 12, 31)
        } else {
            rcgen::date_time_ymd(year, 1, 1)
        };
        assert_eq!(value, expected.unix_timestamp());
    }
}
#[test]
fn malformed_time_profiles_and_calendar_values_rejected() {
    for (tag, bytes) in [
        (TAG_UTCTIME, b"2401010000Z".as_slice()),
        (TAG_UTCTIME, b"240101000000+0000"),
        (TAG_UTCTIME, b"240101000000z"),
        (TAG_UTCTIME, b"240230000000Z"),
        (TAG_UTCTIME, b"240101240000Z"),
        (TAG_UTCTIME, b"240101000060Z"),
        (TAG_UTCTIME, b"2x0101000000Z"),
        (TAG_GENERALIZEDTIME, b"20500101000000.1Z"),
        (TAG_GENERALIZEDTIME, b"20500101000000+0000"),
        (TAG_GENERALIZEDTIME, b"205001010000Z"),
        (TAG_GENERALIZEDTIME, b"20510229000000Z"),
        (TAG_GENERALIZEDTIME, b"00000101000000Z"),
        (TAG_SEQUENCE, b"240101000000Z"),
    ] {
        assert!(yasna::parse_der(&time_der(tag, bytes), time_field).is_err());
    }
}
#[test]
fn malformed_actual_leaf_validity_rejected_by_metadata_and_webpki() {
    let (der, root) = signed(2024, 2025);
    for invalid in [
        b"240230000000Z".as_slice(),
        b"2401010000Z",
        b"240101000060Z",
    ] {
        let changed = CertificateDer::from(replace_dates(
            &der,
            vec![
                time_der(TAG_UTCTIME, invalid),
                time_der(TAG_UTCTIME, b"250101000000Z"),
            ],
        ));
        // webpki parses the leaf shape first, then validates time during path checks.
        let parsed = webpki::EndEntityCert::try_from(&changed).unwrap();
        assert_eq!(
            extract_validity(&parsed, deadline(), &|| false).unwrap_err(),
            Failure::InvalidMetadata
        );
        assert!(!verify(&changed, &root, 1717200000));
    }
}
#[test]
fn reversed_missing_extra_dates_and_unknown_time_tag_rejected() {
    let (der, _) = signed(2024, 2025);
    let before = time_der(TAG_UTCTIME, b"240101000000Z");
    let after = time_der(TAG_UTCTIME, b"250101000000Z");
    for dates in [
        vec![],
        vec![before.clone()],
        vec![before.clone(), after.clone(), after.clone()],
        vec![after.clone(), before],
        vec![
            time_der(yasna::tags::TAG_OCTETSTRING, b"240101000000Z"),
            after,
        ],
    ] {
        assert_eq!(
            decode_der(&replace_dates(&der, dates)).unwrap_err(),
            Failure::InvalidMetadata
        );
    }
}
#[test]
fn strict_v3_and_complete_certificate_tbs_consumption() {
    let (der, _) = signed(2024, 2025);
    for case in 0..7 {
        let mut outer = fields(&der);
        let mut tbs = fields(&outer[0]);
        match case {
            0 => {
                tbs.remove(0);
            }
            1 => {
                tbs[0] =
                    yasna::construct_der(|w| w.write_tagged(Tag::context(0), |w| w.write_u64(1)))
            }
            2 => tbs.push(yasna::construct_der(|w| w.write_null())),
            3 => {
                tbs[1] = yasna::construct_der(|w| w.write_bytes(b"serial"));
            }
            4 => {
                tbs[3] = yasna::construct_der(|w| w.write_bytes(b"issuer"));
            }
            5 => {
                tbs.push(tbs.last().unwrap().clone());
            }
            _ => {
                outer.push(yasna::construct_der(|w| w.write_null()));
            }
        }
        outer[0] = sequence(&tbs);
        assert_eq!(
            decode_der(&sequence(&outer)).unwrap_err(),
            Failure::InvalidMetadata
        );
    }
    let mut trailing = der.as_ref().to_vec();
    trailing.extend_from_slice(&[5, 0]);
    assert_eq!(decode_der(&trailing).unwrap_err(), Failure::InvalidMetadata);
}
#[test]
fn bounded_cancel_deadline_and_truncation() {
    let (der, _) = signed(2024, 2025);
    let parsed = webpki::EndEntityCert::try_from(&der).unwrap();
    assert_eq!(
        extract_validity(&parsed, deadline(), &|| true).unwrap_err(),
        Failure::Canceled
    );
    assert_eq!(
        extract_validity(&parsed, Instant::now(), &|| false).unwrap_err(),
        Failure::Timeout
    );
    let n = std::cell::Cell::new(0);
    assert_eq!(
        extract_validity(&parsed, deadline(), &|| {
            n.set(n.get() + 1);
            n.get() > 1
        })
        .unwrap_err(),
        Failure::Canceled
    );
    assert_eq!(decode_der(&vec![0; 65537]).unwrap_err(), Failure::Limit);
    for length in [1, 2, der.len() / 2, der.len() - 1] {
        assert!(decode_der(&der[..length]).is_err());
    }
}
#[test]
fn indefinite_nonminimal_and_constructed_time_encodings_rejected() {
    for der in [
        b"\x17\x80\0\0".as_slice(),
        b"\x17\x81\x0d240101000000Z",
        b"\x37\x0d240101000000Z",
    ] {
        assert!(yasna::parse_der(der, time_field).is_err());
    }
}
#[test]
fn metadata_is_not_signature_or_trust_evidence() {
    let (der, root) = signed(2024, 2025);
    let mut altered = der.as_ref().to_vec();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    let altered = CertificateDer::from(altered);
    let parsed = webpki::EndEntityCert::try_from(&altered).unwrap();
    assert!(extract_validity(&parsed, deadline(), &|| false).is_ok());
    assert!(!verify(&altered, &root, 1717200000));
}
#[test]
fn generalized_maximum_profile_date_is_finite_metadata_not_no_expiry_flag() {
    let value = yasna::parse_der(
        &time_der(TAG_GENERALIZEDTIME, b"99991231235959Z"),
        time_field,
    )
    .unwrap();
    assert_eq!(value, 253402300799);
}
