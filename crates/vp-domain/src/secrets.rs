use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

/// A vault lookup identifier, never a credential or a filesystem path.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretRef(String);
impl SecretRef {
    pub fn new(opaque_id: &str) -> Result<Self, String> {
        if !opaque_id.is_empty()
            && opaque_id.len() <= 128
            && opaque_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            Ok(Self(format!("secret:{opaque_id}")))
        } else {
            Err("invalid secret reference".into())
        }
    }
    /// Use for vault lookup, not diagnostic logging.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for SecretRef {
    type Error = String;
    fn try_from(value: String) -> Result<Self, String> {
        value
            .strip_prefix("secret:")
            .ok_or_else(|| "invalid secret reference".into())
            .and_then(Self::new)
    }
}
impl From<SecretRef> for String {
    fn from(value: SecretRef) -> Self {
        value.0
    }
}
impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretRef([REDACTED])")
    }
}
impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Intentionally neither Serialize nor Clone. Explicit exposure is required at
/// the vault/compiler boundary. Zeroization is best effort, not a claim against
/// process compromise, allocator copies, aborts or swap.
/// ```compile_fail
/// use vp_product_domain::SecretBytes;
/// let secret = SecretBytes::new(vec![1, 2, 3]);
/// let _ = serde_json::to_string(&secret); // Deliberately no Serialize impl.
/// ```
pub struct SecretBytes(Zeroizing<Vec<u8>>);
impl SecretBytes {
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

/// Redacts the entire untrusted value rather than attempting fragile URL/token
/// regexes. Diagnostic code must explicitly select safe structured metadata.
pub fn redact_untrusted(_value: &str) -> &'static str {
    "[REDACTED]"
}

impl JsonSchema for SecretRef {
    fn schema_name() -> String {
        "SecretRef".into()
    }
    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        crate::ids::bounded_string_schema("^secret:[A-Za-z0-9_-]{1,128}$")
    }
}
