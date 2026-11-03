//! Proposed strict tuple material boundary. Not wired into live v1 or v2 IPC.
//! Raw single-value v1 UUID/password credentials are never tried as tuple JSON.
use serde::{Deserialize, Deserializer};
use vp_product_domain::SecretBytes;
use zeroize::Zeroizing;

/// No Serialize, Clone or plaintext Debug. Even partially decoded JSON fields
/// are zeroized on rejection, including duplicate/unknown-field parse errors.
/// This is best effort; parser/allocator copies and process compromise are not covered.
pub struct ProtectedText(Zeroizing<String>);
impl ProtectedText {
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}
impl std::fmt::Debug for ProtectedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProtectedText([REDACTED])")
    }
}
impl<'de> Deserialize<'de> for ProtectedText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTuplePayload;
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SocksWireV1 {
    schema_version: u16,
    pub username: ProtectedText,
    pub password: ProtectedText,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TuicWireV1 {
    schema_version: u16,
    pub uuid: ProtectedText,
    pub password: ProtectedText,
}
// Validated return values intentionally do not implement Deserialize.
#[derive(Debug)]
pub struct SocksUsernamePasswordJsonV1 {
    pub username: ProtectedText,
    pub password: ProtectedText,
}
#[derive(Debug)]
pub struct TuicUuidPasswordJsonV1 {
    pub uuid: ProtectedText,
    pub password: ProtectedText,
}
fn decode<T: serde::de::DeserializeOwned>(secret: &SecretBytes) -> Result<T, InvalidTuplePayload> {
    if secret.expose().is_empty() || secret.expose().len() > 4096 {
        return Err(InvalidTuplePayload);
    }
    // Never propagate serde_json::Error: it may echo attacker-supplied values.
    serde_json::from_slice(secret.expose()).map_err(|_| InvalidTuplePayload)
}
pub fn decode_socks(
    secret: &SecretBytes,
) -> Result<SocksUsernamePasswordJsonV1, InvalidTuplePayload> {
    let payload: SocksWireV1 = decode(secret)?;
    if payload.schema_version != 1
        || !(1..=255).contains(&payload.username.expose().len())
        || !(1..=255).contains(&payload.password.expose().len())
    {
        return Err(InvalidTuplePayload);
    }
    Ok(SocksUsernamePasswordJsonV1 {
        username: payload.username,
        password: payload.password,
    })
}
pub fn decode_tuic(secret: &SecretBytes) -> Result<TuicUuidPasswordJsonV1, InvalidTuplePayload> {
    let payload: TuicWireV1 = decode(secret)?;
    let value = payload.uuid.expose();
    let canonical = value.len() == 36
        && value.bytes().enumerate().all(|(index, b)| {
            if [8, 13, 18, 23].contains(&index) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        });
    if payload.schema_version != 1
        || !canonical
        || !(1..=1024).contains(&payload.password.expose().len())
    {
        return Err(InvalidTuplePayload);
    }
    Ok(TuicUuidPasswordJsonV1 {
        uuid: payload.uuid,
        password: payload.password,
    })
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    fn input(s: &str) -> SecretBytes {
        SecretBytes::new(s.as_bytes().to_vec())
    }
    #[test]
    fn tuple_json_has_explicit_kind_version_and_no_delimiter_inference() {
        let socks =
            input(r#"{"schemaVersion":1,"username":"test:user","password":"test:password"}"#);
        let tuple = decode_socks(&socks).unwrap();
        assert_eq!(tuple.username.expose(), "test:user");
        assert_eq!(tuple.password.expose(), "test:password");
        assert!(decode_tuic(&socks).is_err());
        let tuic = input(
            r#"{"schemaVersion":1,"uuid":"12345678-1234-1234-1234-123456789abc","password":"test:password"}"#,
        );
        assert!(decode_tuic(&tuic).is_ok());
        assert!(decode_socks(&tuic).is_err());
        assert!(decode_socks(&input("test:user:password")).is_err());
        assert!(decode_tuic(&input("12345678-1234-1234-1234-123456789abc")).is_err());
        assert!(!format!("{tuple:?}").contains("test:user"));
        assert!(!format!("{tuple:?}").contains("test:password"));
    }
    #[test]
    fn duplicate_unknown_wrong_version_and_unbounded_fields_are_rejected() {
        for payload in [
            r#"{"schemaVersion":1,"schemaVersion":1,"username":"u","password":"p"}"#,
            r#"{"schemaVersion":1,"username":"u","password":"p","privateKey":"not-allowed"}"#,
            r#"{"schemaVersion":2,"username":"u","password":"p"}"#,
            r#"{"schemaVersion":1,"username":"","password":"p"}"#,
            r#"{"schemaVersion":1,"username":"u","username":"v","password":"p"}"#,
            r#"{"schemaVersion":1,"username":"u","password":"p","password":"q"}"#,
        ] {
            assert_eq!(
                decode_socks(&input(payload)).unwrap_err(),
                InvalidTuplePayload
            );
        }
        assert!(decode_socks(&input(&" ".repeat(4097))).is_err());
        let too_long =
            serde_json::json!({"schemaVersion":1,"username":"é".repeat(128),"password":"fixture"});
        assert!(decode_socks(&input(&too_long.to_string())).is_err());
        assert!(decode_tuic(&input(
            r#"{"schemaVersion":1,"uuid":"12345678-1234-1234-1234-123456789ABC","password":"p"}"#
        ))
        .is_err());
    }
}
