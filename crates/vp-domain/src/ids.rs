use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Opaque identifiers deliberately exclude paths, URLs, whitespace and secrets.
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

macro_rules! opaque_id {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl JsonSchema for $name {
            fn schema_name() -> String { stringify!($name).into() }
            fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
                bounded_string_schema("^[A-Za-z0-9_-]{1,128}$")
            }
        }
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, String> {
                let value = value.into();
                if valid_id(&value) { Ok(Self(value)) } else { Err(concat!("invalid ", stringify!($name)).into()) }
            }
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl TryFrom<String> for $name {
            type Error = String;
            fn try_from(value: String) -> Result<Self, Self::Error> { Self::new(value) }
        }
        impl From<$name> for String { fn from(value: $name) -> Self { value.0 } }
        impl FromStr for $name {
            type Err = String;
            fn from_str(value: &str) -> Result<Self, Self::Err> { Self::new(value) }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }
    )+};
}
opaque_id!(
    NodeId,
    ListenerId,
    SourceId,
    UserId,
    RequestId,
    OperationId,
    DraftId,
    PlanId,
    CertificateId,
    DiagnosticId,
    EvidenceId,
    IdempotencyKey,
    ReleaseId,
    CredentialId,
    PublicationId
);

/// Revision and sequence values are restricted to exact JSON/JavaScript integers.
pub const MAX_WIRE_COUNTER: u64 = 9_007_199_254_740_991;
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
#[serde(try_from = "u64", into = "u64")]
pub struct Revision(u64);
impl Revision {
    pub const ZERO: Self = Self(0);
    pub fn new(value: u64) -> Result<Self, String> {
        if value <= MAX_WIRE_COUNTER {
            Ok(Self(value))
        } else {
            Err("revision exceeds safe wire range".into())
        }
    }
    pub fn get(self) -> u64 {
        self.0
    }
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).and_then(|v| Self::new(v).ok())
    }
}
impl TryFrom<u64> for Revision {
    type Error = String;
    fn try_from(value: u64) -> Result<Self, String> {
        Self::new(value)
    }
}
impl From<Revision> for u64 {
    fn from(value: Revision) -> Self {
        value.0
    }
}
impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Schemars derives cannot infer custom TryFrom validation. Encode it explicitly
/// so a named ID definition is as strict as its references in the reviewed API.
pub(crate) fn bounded_string_schema(pattern: &str) -> schemars::schema::Schema {
    schemars::schema::SchemaObject {
        instance_type: Some(schemars::schema::InstanceType::String.into()),
        string: Some(Box::new(schemars::schema::StringValidation {
            pattern: Some(pattern.into()),
            ..Default::default()
        })),
        ..Default::default()
    }
    .into()
}
impl JsonSchema for Revision {
    fn schema_name() -> String {
        "Revision".into()
    }
    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Integer.into()),
            number: Some(Box::new(schemars::schema::NumberValidation {
                minimum: Some(0.0),
                maximum: Some(MAX_WIRE_COUNTER as f64),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}
