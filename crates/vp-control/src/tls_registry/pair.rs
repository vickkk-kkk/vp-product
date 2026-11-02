use std::time::Instant;
use vp_product_domain::SecretBytes;
const MAX_BYTES: usize = 65536;
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Invalid,
    Limit,
    Canceled,
    Timeout,
}
fn check(deadline: Instant, canceled: &impl Fn() -> bool) -> Result<(), Failure> {
    if canceled() {
        Err(Failure::Canceled)
    } else if Instant::now() >= deadline {
        Err(Failure::Timeout)
    } else {
        Ok(())
    }
}
/// Reject parser-skipped comments, unrelated PEM objects, extra keys, junk,
/// encrypted keys and non-ASCII encodings before allocating decoded buffers.
/// Supported key labels are PKCS#8, PKCS#1 RSA and SEC1 EC, exactly one object.
fn blocks<'a>(
    input: &'a [u8],
    labels: &[&str],
    max_count: usize,
) -> Result<Vec<&'a [u8]>, Failure> {
    if input.is_empty() {
        return Err(Failure::Invalid);
    }
    if input.len() > MAX_BYTES {
        return Err(Failure::Limit);
    }
    let text = std::str::from_utf8(input).map_err(|_| Failure::Invalid)?;
    let mut remaining = text;
    let mut result = Vec::new();
    while !remaining
        .trim_matches(|c: char| c.is_ascii_whitespace())
        .is_empty()
    {
        remaining = remaining.trim_start_matches(|c: char| c.is_ascii_whitespace());
        let label = labels
            .iter()
            .find(|label| remaining.starts_with(&format!("-----BEGIN {label}-----")))
            .ok_or(Failure::Invalid)?;
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let end_at = remaining.find(&end).ok_or(Failure::Invalid)?;
        let body = &remaining[begin.len()..end_at];
        if !body.starts_with('\n') && !body.starts_with("\r\n") {
            return Err(Failure::Invalid);
        }
        if !body.ends_with('\n')
            || body.trim().is_empty()
            || !body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=\r\n".contains(&b))
        {
            return Err(Failure::Invalid);
        }
        let length = end_at + end.len();
        result.push(&remaining.as_bytes()[..length]);
        if result.len() > max_count {
            return Err(Failure::Limit);
        }
        remaining = &remaining[length..];
    }
    if result.is_empty() {
        return Err(Failure::Invalid);
    }
    Ok(result)
}

/// Strict bounded PEM and crypto leaf/private-key match only. Does NOT establish
/// chain trust, SAN/name constraints, certificate dates, EKU, revocation or import
/// authority. No output is cached or serialized; errors contain no input material.
pub(crate) fn validate_pair(
    chain: &SecretBytes,
    key: &SecretBytes,
    deadline: Instant,
    canceled: &impl Fn() -> bool,
) -> Result<(), Failure> {
    check(deadline, canceled)?;
    let certificate_blocks = blocks(chain.expose(), &["CERTIFICATE"], 8)?;
    let key_blocks = blocks(
        key.expose(),
        &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"],
        1,
    )?;
    let mut certs = Vec::new();
    for block in certificate_blocks {
        check(deadline, canceled)?;
        match rustls_pemfile::read_one(&mut &block[..]).map_err(|_| Failure::Invalid)? {
            Some(rustls_pemfile::Item::X509Certificate(cert)) => {
                rustls::server::ParsedCertificate::try_from(&cert).map_err(|_| Failure::Invalid)?;
                if certs.contains(&cert) {
                    return Err(Failure::Invalid);
                }
                certs.push(cert);
            }
            _ => return Err(Failure::Invalid),
        }
    }
    let private_key = rustls_pemfile::private_key(&mut &key_blocks[0][..])
        .map_err(|_| Failure::Invalid)?
        .ok_or(Failure::Invalid)?;
    check(deadline, canceled)?;
    let result = rustls::sign::CertifiedKey::from_der(
        certs,
        private_key,
        &rustls::crypto::ring::default_provider(),
    )
    // from_der permits unknown consistency; this boundary explicitly does not.
    .and_then(|identity| identity.keys_match())
    .map_err(|_| Failure::Invalid);
    check(deadline, canceled)?;
    result
}

#[cfg(test)]
#[path = "pair_tests.rs"]
mod tests;
