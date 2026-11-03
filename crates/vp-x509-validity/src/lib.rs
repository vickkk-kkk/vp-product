//! Strict metadata-only RFC5280 v3-certificate validity decoder.
//! Not signature, path, trust, name, usage or revocation verification.
//! Callers must associate exact DER with separately verified certificate identity.
use yasna::tags::{TAG_GENERALIZEDTIME, TAG_SEQUENCE, TAG_UTCTIME};
use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERReader, PCBit, Tag};

#[derive(Debug, PartialEq, Eq)]
pub enum Failure { InvalidMetadata, Limit }
#[derive(Debug, PartialEq, Eq)]
pub struct Validity {
    pub not_before_unix_seconds: i64,
    pub not_after_unix_seconds: i64,
}
fn invalid() -> ASN1Error {
    ASN1Error::new(ASN1ErrorKind::Invalid)
}
fn sequence_field(reader: BERReader<'_, '_>) -> ASN1Result<()> {
    let field = reader.read_tagged_der()?;
    if field.tag() != TAG_SEQUENCE || field.pcbit() != PCBit::Constructed {
        return Err(invalid());
    }
    Ok(())
}
fn time_field(reader: BERReader<'_, '_>) -> ASN1Result<i64> {
    let der = reader.read_der()?;
    // RFC5280 allows only seconds precision and Z; generic ASN.1 APIs also
    // accept other forms, so enforce this profile before mature date decoding.
    if der.len() > 17 {
        return Err(invalid());
    }
    let field = yasna::parse_der(&der, |r| r.read_tagged_der())?;
    let len = match field.tag() {
        TAG_UTCTIME => 13,
        TAG_GENERALIZEDTIME => 15,
        _ => return Err(invalid()),
    };
    let value = field.value();
    if field.pcbit() != PCBit::Primitive
        || value.len() != len
        || value[len - 1] != b'Z'
        || !value[..len - 1].iter().all(u8::is_ascii_digit)
    {
        return Err(invalid());
    }
    // yasna DER mode checks canonical encoding; time checks actual calendar,
    // hour/minute/second and UTC 1950..2049 century interpretation.
    if field.tag() == TAG_UTCTIME {
        yasna::parse_der(&der, |r| Ok(r.read_utctime()?.datetime().unix_timestamp()))
    } else {
        yasna::parse_der(&der, |r| {
            let date = r.read_generalized_time()?;
            if date.datetime().year() < 1 {
                return Err(invalid());
            }
            Ok(date.datetime().unix_timestamp())
        })
    }
}
/// Fixed Certificate3 fields, TBS7 required fields plus optional extensions only.
/// UID fields are unsupported, matching the upstream webpki parsed-leaf gate.
/// Complete consumption is enforced by yasna parse_der/read_sequence at each
/// navigated level. We do not interpret skipped issuer/subject/SPKI semantics.
pub fn decode_certificate_validity_der(der: &[u8]) -> Result<Validity, Failure> {
    if der.is_empty() || der.len() > 65536 {
        return Err(Failure::Limit);
    }
    yasna::parse_der(der, |outer| {
        outer.read_sequence(|certificate| {
            let validity = certificate.next().read_sequence(|tbs| {
                let version = tbs.next().read_tagged(Tag::context(0), |r| r.read_u64())?;
                if version != 2 {
                    return Err(invalid());
                }
                tbs.next().read_bigint_bytes()?; // Exact INTEGER, calendar extraction does not reinterpret serial.
                sequence_field(tbs.next())?; // signature AlgorithmIdentifier
                sequence_field(tbs.next())?; // issuer Name
                let validity = tbs.next().read_sequence(|dates| {
                    let before = time_field(dates.next())?;
                    let after = time_field(dates.next())?;
                    if before > after {
                        return Err(invalid());
                    }
                    Ok(Validity {
                        not_before_unix_seconds: before,
                        not_after_unix_seconds: after,
                    })
                })?;
                sequence_field(tbs.next())?; // subject Name
                sequence_field(tbs.next())?; // SubjectPublicKeyInfo
                tbs.read_optional(|r| r.read_tagged(Tag::context(3), sequence_field))?;
                Ok(validity)
            })?;
            sequence_field(certificate.next())?; // signature AlgorithmIdentifier
            certificate.next().read_bitvec_bytes()?;
            Ok(validity)
        })
    })
    .map_err(|_| Failure::InvalidMetadata)
}

/// Metadata-only single ASN.1 time value, used by wrapper regression tests.
#[doc(hidden)]
pub fn decode_time_der(der: &[u8]) -> Result<i64, Failure> {
    if der.len() > 17 { return Err(Failure::InvalidMetadata); }
    yasna::parse_der(der, time_field).map_err(|_| Failure::InvalidMetadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_and_bounded_metadata() {
        assert_eq!(decode_certificate_validity_der(&[]), Err(Failure::Limit));
        assert_eq!(decode_certificate_validity_der(&vec![0; 65537]), Err(Failure::Limit));
        assert_eq!(decode_certificate_validity_der(&[0, 0]), Err(Failure::InvalidMetadata));
    }
    #[test]
    fn exact_time_grammar() {
        assert_eq!(decode_time_der(b"\x17\x0d240101000000Z"), Ok(1704067200));
        assert!(decode_time_der(b"\x17\x0d240230000000Z").is_err());
        assert!(decode_time_der(b"\x17\x0d240101000060Z").is_err());
        assert!(decode_time_der(b"\x17\x81\x0d240101000000Z").is_err());
    }
}
