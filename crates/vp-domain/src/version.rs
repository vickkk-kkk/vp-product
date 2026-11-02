use crate::{ErrorCode, ErrorStage, ProductError, ReleaseId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 1;
pub const API_MAJOR: u16 = 1;
pub const ABI_MAJOR: u16 = 1;
pub const ABI_MINOR: u16 = 1;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionPair {
    pub major: u16,
    pub minor: u16,
}
impl VersionPair {
    /// Minor additions are compatible only when the provider satisfies caller's minimum.
    pub fn accepts(self, provider: Self) -> bool {
        self.major == provider.major && provider.minor >= self.minor
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityRange {
    pub minimum: u16,
    pub maximum: u16,
}
impl CompatibilityRange {
    pub fn contains(self, version: u16) -> bool {
        self.minimum <= version && version <= self.maximum
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocumentAccess {
    ReadWrite,
    ReadOnly,
    Incompatible,
}
/// Do not decode/save a newer document through an older DTO: read-only consumers
/// retain original bytes and show metadata, not a lossy deserialize/reserialize.
pub fn document_access(
    schema: u16,
    minimum_reader: u16,
    reader: u16,
    writable: CompatibilityRange,
) -> DocumentAccess {
    if schema == 0
        || minimum_reader == 0
        || reader == 0
        || writable.minimum > writable.maximum
        || minimum_reader > schema
        || reader < minimum_reader
    {
        DocumentAccess::Incompatible
    } else if schema <= reader && writable.contains(schema) {
        DocumentAccess::ReadWrite
    } else {
        DocumentAccess::ReadOnly
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub release_id: ReleaseId,
    pub product_version: String,
    pub adapter_version: String,
    pub core_commit: String,
    /// None means no verified patchset identity, never "clean" or certified.
    pub patchset_hash: Option<String>,
    pub build_target: String,
    pub toolchain: String,
    pub schema_read: CompatibilityRange,
    pub schema_write: CompatibilityRange,
    pub abi: VersionPair,
    pub api: VersionPair,
    pub evidence_manifest_hash: Option<String>,
}
impl ReleaseIdentity {
    pub fn validate(&self) -> Result<(), ProductError> {
        let valid_hex =
            |s: &str, n: usize| s.len() == n && s.bytes().all(|c| c.is_ascii_hexdigit());
        if !valid_hex(&self.core_commit, 40)
            || self
                .patchset_hash
                .as_ref()
                .is_some_and(|v| !valid_hex(v, 64))
            || self
                .evidence_manifest_hash
                .as_ref()
                .is_some_and(|v| !valid_hex(v, 64))
            || self.schema_read.minimum == 0
            || self.schema_write.minimum == 0
            || self.schema_read.minimum > self.schema_read.maximum
            || self.schema_write.minimum > self.schema_write.maximum
            || self.schema_write.minimum < self.schema_read.minimum
            || self.schema_write.maximum > self.schema_read.maximum
        {
            return Err(ProductError::new(
                ErrorCode::UpgradeIncompatible,
                ErrorStage::Validate,
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildInfo {
    pub schema_version: u16,
    pub release: ReleaseIdentity,
    pub required_features: Vec<String>,
    pub development: bool,
}
