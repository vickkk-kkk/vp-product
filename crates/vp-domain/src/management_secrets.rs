//! Strict management credential/publication metadata. Actual secret generation,
//! vault mutation and publication authorization belong to shared control ports.
use crate::*;
use schemars::{
    schema::{InstanceType, Schema, SchemaObject},
    JsonSchema,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Only an explicit true value can be constructed/deserialized. Callers still
/// validate confirmation at the business boundary before any entropy or write.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "bool", into = "bool")]
pub struct ExplicitConfirmation(bool);
impl TryFrom<bool> for ExplicitConfirmation {
    type Error = &'static str;
    fn try_from(value: bool) -> Result<Self, Self::Error> {
        if value {
            Ok(Self(true))
        } else {
            Err("explicit confirmation required")
        }
    }
}
impl From<ExplicitConfirmation> for bool {
    fn from(value: ExplicitConfirmation) -> Self {
        value.0
    }
}
impl ExplicitConfirmation {
    pub fn is_confirmed(self) -> bool {
        self.0
    }
}
impl JsonSchema for ExplicitConfirmation {
    fn schema_name() -> String {
        "ExplicitConfirmation".into()
    }
    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> Schema {
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::Boolean.into()),
            const_value: Some(serde_json::Value::Bool(true)),
            ..Default::default()
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeCredentialKind {
    Uuid {},
    Password {},
    Shadowsocks { method: ShadowsocksCipher },
    UsernamePassword {},
    UuidPassword {},
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    Available,
    Retired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum CredentialDisplayKey {
    #[serde(rename = "credential.managed")]
    Managed,
    #[serde(rename = "credential.retired")]
    Retired,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSummary {
    pub schema_version: u16,
    pub id: CredentialId,
    pub revision: Revision,
    pub secret_ref: SecretRef,
    pub kind: NodeCredentialKind,
    pub created_at: u64,
    pub state: CredentialState,
    pub display_key: CredentialDisplayKey,
}
impl CredentialSummary {
    pub fn validate(&self) -> Result<(), ProductError> {
        if self.schema_version != 1
            || self.revision == Revision::ZERO
            || self.created_at > MAX_WIRE_COUNTER
            || (self.state == CredentialState::Available)
                != (self.display_key == CredentialDisplayKey::Managed)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialInventory {
    pub schema_version: u16,
    #[schemars(length(max = 11))]
    pub supported_kinds: Vec<NodeCredentialKind>,
    #[schemars(length(max = 128))]
    pub credentials: Vec<CredentialSummary>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialCreatePayload {
    pub kind: NodeCredentialKind,
    pub confirm_generate: ExplicitConfirmation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRetirePayload {
    pub confirm_retire: ExplicitConfirmation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationSource {
    pub listener_id: ListenerId,
    pub user_id: UserId,
    pub endpoint: Endpoint,
    pub client_security: ClientSecurity,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicationTokenState {
    NotIssued,
    Active,
    Revoked,
    Expired,
}
fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationTokenStatus {
    pub state: PublicationTokenState,
    pub version: Revision,
    #[serde(deserialize_with = "required_nullable")]
    pub issued_at: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub expires_at: Option<u64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicationFormat {
    UriList,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationSummary {
    pub schema_version: u16,
    pub id: PublicationId,
    pub revision: Revision,
    #[schemars(length(min = 1, max = 128))]
    pub name: String,
    pub enabled: bool,
    pub format: PublicationFormat,
    pub source_revision: Revision,
    #[schemars(length(min = 1, max = 32))]
    pub sources: Vec<PublicationSource>,
    pub created_at: u64,
    pub updated_at: u64,
    pub token: PublicationTokenStatus,
    #[serde(deserialize_with = "required_nullable")]
    pub last_successful_read_at: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationCreatePayload {
    #[schemars(length(min = 1, max = 128))]
    pub name: String,
    pub enabled: bool,
    pub format: PublicationFormat,
    #[schemars(length(min = 1, max = 32))]
    pub sources: Vec<PublicationSource>,
    pub confirm_publish_connection_secrets: ExplicitConfirmation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationReplacePayload {
    #[schemars(length(min = 1, max = 128))]
    pub name: String,
    pub enabled: bool,
    pub format: PublicationFormat,
    pub source_revision: Revision,
    #[schemars(length(min = 1, max = 32))]
    pub sources: Vec<PublicationSource>,
    pub confirm_publish_connection_secrets: ExplicitConfirmation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationIssuePayload {
    #[schemars(range(min = 300, max = 2592000))]
    pub expires_in_seconds: u32,
    pub confirm_issue_secret_url: ExplicitConfirmation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationRevokePayload {
    pub confirm_revoke_access: ExplicitConfirmation,
}

/// Only the deliberately sensitive response wrapper can serialize its content.
/// No Debug, Clone or Deserialize; never put this in stored state/audit/receipts.
/// ```compile_fail
/// use vp_product_domain::SensitiveResponseText;
/// let secret = SensitiveResponseText::new("fixture".into()).unwrap();
/// println!("{secret:?}");
/// ```
/// ```compile_fail
/// use vp_product_domain::SensitiveResponseText;
/// let secret = SensitiveResponseText::new("fixture".into()).unwrap();
/// let duplicate = secret.clone();
/// ```
pub struct SensitiveResponseText(Zeroizing<String>);
impl SensitiveResponseText {
    pub fn new(value: String) -> Result<Self, ProductError> {
        let value = Zeroizing::new(value);
        if value.is_empty() || value.len() > 8192 {
            return Err(invalid());
        }
        Ok(Self(value))
    }
}
impl Serialize for SensitiveResponseText {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl JsonSchema for SensitiveResponseText {
    fn schema_name() -> String {
        "SensitiveResponseText".into()
    }
    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> Schema {
        let mut object = SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(Box::new(schemars::schema::StringValidation {
                min_length: Some(1),
                max_length: Some(8192),
                ..Default::default()
            })),
            ..Default::default()
        };
        object
            .extensions
            .insert("x-sensitive".into(), serde_json::Value::Bool(true));
        Schema::Object(object)
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationIssuedSecret {
    pub publication: PublicationSummary,
    pub subscription_url: SensitiveResponseText,
    pub display_once: ExplicitConfirmation,
}
fn invalid() -> ProductError {
    ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Validate)
}
pub fn validate_publication_sources(
    name: &str,
    sources: &[PublicationSource],
) -> Result<(), ProductError> {
    if name.trim().is_empty()
        || name.chars().count() > 128
        || name.chars().any(char::is_control)
        || sources.is_empty()
        || sources.len() > 32
    {
        return Err(invalid());
    }
    let mut seen = std::collections::BTreeSet::new();
    for source in sources {
        source.endpoint.validate()?;
        if !seen.insert((&source.listener_id, &source.user_id)) {
            return Err(invalid());
        }
    }
    Ok(())
}
impl PublicationSummary {
    pub fn validate(&self) -> Result<(), ProductError> {
        validate_publication_sources(&self.name, &self.sources)?;
        if self.schema_version != 1
            || self.revision == Revision::ZERO
            || self.source_revision == Revision::ZERO
            || self.created_at > self.updated_at
            || self.updated_at > MAX_WIRE_COUNTER
            || self
                .last_successful_read_at
                .is_some_and(|t| t > MAX_WIRE_COUNTER)
        {
            return Err(invalid());
        }
        match self.token.state {
            PublicationTokenState::NotIssued
                if self.token.version == Revision::ZERO
                    && self.token.issued_at.is_none()
                    && self.token.expires_at.is_none() => {}
            PublicationTokenState::Active
            | PublicationTokenState::Expired
            | PublicationTokenState::Revoked
                if self.token.version != Revision::ZERO
                    && self
                        .token
                        .issued_at
                        .zip(self.token.expires_at)
                        .is_some_and(|(a, b)| a < b && b <= MAX_WIRE_COUNTER) => {}
            _ => return Err(invalid()),
        }
        if !self.enabled && self.token.state == PublicationTokenState::Active {
            return Err(invalid());
        }
        Ok(())
    }
}
