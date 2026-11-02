//! Internal OS entropy helpers. Never invoked at startup and never persist/log.
//! Only the confirmed shared-control action resolves generated material to vault.
use vp_product_control::{ContentDigest, ControlError};
use vp_product_domain::{SecretBytes, SecretRef};
use zeroize::Zeroizing;
const HEX: &[u8; 16] = b"0123456789abcdef";
const TOKEN_PREFIX: &[u8] = b"vps1_";
const TOKEN_DOMAIN: &[u8] = b"vp.subscription-access-token.v1\0";
fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, ControlError> {
    let mut bytes = Zeroizing::new([0; N]);
    getrandom::fill(bytes.as_mut()).map_err(|_| ControlError::ExecutorUnavailable)?;
    Ok(bytes)
}
fn append_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize]);
        out.push(HEX[(byte & 15) as usize]);
    }
}
pub(crate) fn uuid_credential() -> Result<SecretBytes, ControlError> {
    let mut bytes = random::<16>()?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let mut out = Zeroizing::new(Vec::with_capacity(36));
    for (index, byte) in bytes.iter().enumerate() {
        if [4, 6, 8, 10].contains(&index) {
            out.push(b'-');
        }
        append_hex(&mut out, &[*byte]);
    }
    Ok(SecretBytes::new(std::mem::take(&mut *out)))
}
pub(crate) fn immutable_reference() -> Result<SecretRef, ControlError> {
    let mut opaque = Vec::with_capacity(37);
    opaque.extend_from_slice(b"node-");
    append_hex(&mut opaque, random::<16>()?.as_ref());
    let opaque = String::from_utf8(opaque).map_err(|_| ControlError::ExecutorFailed)?;
    SecretRef::new(&opaque).map_err(|_| ControlError::ExecutorFailed)
}
pub(crate) fn subscription_token() -> Result<SecretBytes, ControlError> {
    let mut out = Zeroizing::new(Vec::with_capacity(69));
    out.extend_from_slice(TOKEN_PREFIX);
    append_hex(&mut out, random::<32>()?.as_ref());
    Ok(SecretBytes::new(std::mem::take(&mut *out)))
}
pub(crate) fn subscription_verifier(token: &[u8]) -> Result<ContentDigest, ControlError> {
    if token.len() != 69
        || !token.starts_with(TOKEN_PREFIX)
        || !token[5..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(ControlError::PermissionDenied);
    }
    let mut input = Zeroizing::new(Vec::with_capacity(TOKEN_DOMAIN.len() + token.len()));
    input.extend_from_slice(TOKEN_DOMAIN);
    input.extend_from_slice(token);
    Ok(ContentDigest::bytes(&input))
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn uuid_is_v4_canonical_and_temporary_secret_is_redacted() {
        let value = uuid_credential().unwrap();
        assert_eq!(value.expose().len(), 36);
        assert_eq!(value.expose()[14], b'4');
        assert!(b"89ab".contains(&value.expose()[19]));
        assert!(immutable_reference()
            .unwrap()
            .as_str()
            .starts_with("secret:node-"));
    }
    #[test]
    fn token_has_independent_namespace_and_exact_domain_verifier() {
        let a = subscription_token().unwrap();
        let b = subscription_token().unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_ne!(
            subscription_verifier(a.expose()).unwrap(),
            subscription_verifier(b.expose()).unwrap()
        );
        assert!(subscription_verifier(uuid_credential().unwrap().expose()).is_err());
    }
}
