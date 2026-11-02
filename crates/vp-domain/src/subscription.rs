use crate::{
    ClientSecurity, Endpoint, ErrorCode, ErrorStage, NodeId, NodeProfile, ProductError, Protocol,
    Revision, SecretRef, SourceId, Transport, SCHEMA_VERSION,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionFormat {
    UriList,
    Base64UriList,
    VpNodes,
    ClashNodes,
    SingBoxOutbounds,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubscriptionSource {
    pub schema_version: u16,
    pub id: SourceId,
    pub name: String,
    pub url_ref: SecretRef,
    pub format: SubscriptionFormat,
    pub refresh_interval_seconds: Option<u32>,
    /// Private network access is not implied by adding any URL.
    pub allow_private_network: bool,
}
impl SubscriptionSource {
    pub fn validate(&self) -> Result<(), ProductError> {
        if self.schema_version != SCHEMA_VERSION
            || self.name.trim().is_empty()
            || self.name.len() > 512
            || self.refresh_interval_seconds.is_some_and(|v| v < 300)
        {
            return Err(
                ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Validate)
                    .at("subscription"),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubscriptionStatus {
    pub source_id: SourceId,
    pub revision: Revision,
    pub last_attempt_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub last_error: Option<ProductError>,
    pub node_count: u32,
}
/// Safe pre-vault import preview. No connection secret or allocated vault ID.
/// Reusing Protocol preserves its typed parameters; custom serde rejects the
/// sole reference-bearing variant field rather than leaking an obfuscation ref.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportNodePreview {
    pub name: String,
    pub endpoint: Endpoint,
    #[serde(
        serialize_with = "serialize_preview_protocol",
        deserialize_with = "deserialize_preview_protocol"
    )]
    #[schemars(with = "PreviewProtocolSchema")]
    pub protocol: Protocol,
    pub transport: Transport,
    pub security: ClientSecurity,
    pub has_obfuscation: bool,
}
impl ImportNodePreview {
    pub fn validate(&self) -> Result<(), ProductError> {
        if preview_protocol_has_reference(&self.protocol) {
            Err(
                ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Validate)
                    .at("preview.protocol"),
            )
        } else {
            Ok(())
        }
    }
}
fn preview_protocol_has_reference(protocol: &Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Hysteria2 {
            obfuscation_ref: Some(_)
        }
    )
}
fn serialize_preview_protocol<S: serde::Serializer>(
    protocol: &Protocol,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if preview_protocol_has_reference(protocol) {
        return Err(<S::Error as serde::ser::Error>::custom(
            "preview protocol cannot contain a secret reference",
        ));
    }
    protocol.serialize(serializer)
}
fn deserialize_preview_protocol<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Protocol, D::Error> {
    let protocol = Protocol::deserialize(deserializer)?;
    if preview_protocol_has_reference(&protocol) {
        return Err(<D::Error as serde::de::Error>::custom(
            "preview protocol cannot contain a secret reference",
        ));
    }
    Ok(protocol)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImportDisposition {
    Accepted,
    NeedsReview,
    Rejected,
    Duplicate,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportEntry {
    pub index: u32,
    pub disposition: ImportDisposition,
    /// Present before vault binding; node is only present after real binding.
    pub preview: Option<ImportNodePreview>,
    pub node: Option<NodeProfile>,
    pub duplicate_of: Option<NodeId>,
    pub diagnostics: Vec<ProductError>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportReport {
    pub schema_version: u16,
    pub entries: Vec<ImportEntry>,
    pub diagnostics: Vec<ProductError>,
    pub has_unimported_fields: bool,
}

// Custom serde excludes obfuscation vault references from preview payloads.
// Reflect that exact restriction in generated schema instead of advertising the
// broader persistent-node Protocol.
struct PreviewProtocolSchema;
impl JsonSchema for PreviewProtocolSchema {
    fn schema_name() -> String {
        "PreviewProtocol".into()
    }
    fn json_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema = Protocol::json_schema(generator).into_object();
        if let Some(variants) = schema.subschemas.as_mut().and_then(|s| s.one_of.as_mut()) {
            for variant in variants {
                if let schemars::schema::Schema::Object(object) = variant {
                    if let Some(fields) = object.object.as_mut() {
                        if let Some(reference) = fields.properties.get_mut("obfuscationRef") {
                            *reference =
                                schemars::schema::Schema::Object(schemars::schema::SchemaObject {
                                    instance_type: Some(
                                        schemars::schema::InstanceType::Null.into(),
                                    ),
                                    ..Default::default()
                                });
                        }
                    }
                }
            }
        }
        schema.into()
    }
}
