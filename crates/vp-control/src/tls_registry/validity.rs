//! Metadata-only wrapper; cryptographic verification remains webpki's job.
use std::time::Instant;
pub(crate) use vp_product_x509_validity::Validity;
#[cfg(test)]
use yasna::tags::{TAG_GENERALIZEDTIME, TAG_SEQUENCE, TAG_UTCTIME};
#[cfg(test)]
use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERReader, Tag};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure { InvalidMetadata, Limit, Canceled, Timeout }
fn decode_der(der: &[u8]) -> Result<Validity, Failure> {
    vp_product_x509_validity::decode_certificate_validity_der(der).map_err(|e| match e {
        vp_product_x509_validity::Failure::InvalidMetadata => Failure::InvalidMetadata,
        vp_product_x509_validity::Failure::Limit => Failure::Limit,
    })
}
#[cfg(test)]
fn time_field(reader: BERReader<'_, '_>) -> ASN1Result<i64> {
    let der = reader.read_der()?;
    vp_product_x509_validity::decode_time_der(&der)
        .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))
}
/// No raw/caller timestamp input. Borrowed parsed leaf fixes the exact DER.
/// A valid result only describes an inclusive interval; never use it instead of
/// fresh webpki validation with authorized roots/name/usage/time at activation.
pub(crate) fn extract_validity(
    leaf: &webpki::EndEntityCert<'_>,
    deadline: Instant,
    canceled: &impl Fn() -> bool,
) -> Result<Validity, Failure> {
    let check = || {
        if canceled() {
            Err(Failure::Canceled)
        } else if Instant::now() >= deadline {
            Err(Failure::Timeout)
        } else {
            Ok(())
        }
    };
    check()?;
    let result = decode_der(leaf.der().as_ref());
    check()?;
    result
}

#[cfg(test)]
#[path = "validity_tests.rs"]
mod tests;
