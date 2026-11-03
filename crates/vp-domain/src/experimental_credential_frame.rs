//! Experimental typed credential envelope inside an encrypted vault record.
//! The envelope is not an authorization grant; registry metadata and a sealed
//! plan must also be verified. Legacy password records are unchanged.
use crate::SecretBytes;
use zeroize::Zeroizing;

const MAGIC: &[u8; 6] = b"VPCR\0\x01";
const MAX_PAYLOAD: usize = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialFrameKind { Uuid, ShadowsocksAes128Gcm }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidCredentialFrame;
impl CredentialFrameKind {
    fn tag(self) -> u8 { match self { Self::Uuid => 1, Self::ShadowsocksAes128Gcm => 2 } }
}
fn valid(kind: CredentialFrameKind, bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else { return false };
    if text.is_empty() || text.len() > MAX_PAYLOAD || text.contains('\0') { return false; }
    match kind {
        CredentialFrameKind::Uuid => text.len() == 36 && text.bytes().enumerate().all(|(i,b)| {
            if [8,13,18,23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() && !b.is_ascii_uppercase() }
        }),
        CredentialFrameKind::ShadowsocksAes128Gcm => true,
    }
}
pub fn encode(kind: CredentialFrameKind, bytes: &[u8]) -> Result<SecretBytes, InvalidCredentialFrame> {
    if !valid(kind, bytes) { return Err(InvalidCredentialFrame); }
    let len = u16::try_from(bytes.len()).map_err(|_| InvalidCredentialFrame)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(9 + bytes.len()));
    frame.extend_from_slice(MAGIC);
    frame.push(kind.tag());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(bytes);
    Ok(SecretBytes::new(std::mem::take(&mut *frame)))
}
pub fn decode(kind: CredentialFrameKind, frame: &[u8]) -> Result<SecretBytes, InvalidCredentialFrame> {
    if frame.len() < 9 || &frame[..6] != MAGIC || frame[6] != kind.tag() { return Err(InvalidCredentialFrame); }
    let len = u16::from_be_bytes([frame[7], frame[8]]) as usize;
    if len > MAX_PAYLOAD || frame.len() != 9 + len || !valid(kind, &frame[9..]) { return Err(InvalidCredentialFrame); }
    Ok(SecretBytes::new(frame[9..].to_vec()))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn typed_roundtrip_and_cross_kind_denial() {
        let uuid = b"12345678-1234-1234-1234-123456789abc";
        let frame = encode(CredentialFrameKind::Uuid, uuid).unwrap();
        assert_eq!(decode(CredentialFrameKind::Uuid, frame.expose()).unwrap().expose(), uuid);
        assert!(decode(CredentialFrameKind::ShadowsocksAes128Gcm, frame.expose()).is_err());
        let password = encode(CredentialFrameKind::ShadowsocksAes128Gcm, b"test-password").unwrap();
        assert_eq!(decode(CredentialFrameKind::ShadowsocksAes128Gcm, password.expose()).unwrap().expose(), b"test-password");
        assert!(decode(CredentialFrameKind::Uuid, password.expose()).is_err());
    }
    #[test] fn malformed_and_oversize_fail_closed() {
        assert!(encode(CredentialFrameKind::Uuid, b"12345678-1234-1234-1234-123456789ABc").is_err());
        assert!(encode(CredentialFrameKind::ShadowsocksAes128Gcm, b"bad\0password").is_err());
        assert!(encode(CredentialFrameKind::ShadowsocksAes128Gcm, &vec![b'a';4097]).is_err());
        let frame = encode(CredentialFrameKind::Uuid, b"12345678-1234-1234-1234-123456789abc").unwrap();
        let mut trailing = frame.expose().to_vec(); trailing.push(0);
        assert!(decode(CredentialFrameKind::Uuid, &trailing).is_err());
        assert!(decode(CredentialFrameKind::Uuid, &frame.expose()[..8]).is_err());
    }
}
