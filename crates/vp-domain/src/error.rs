use crate::{CapabilityKey, DiagnosticId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    ConfigUnknownField,
    ConfigInvalid,
    ConfigUnsupported,
    InputTooLarge,
    InvalidUtf8,
    CapabilityUncertified,
    CapabilityUnavailable,
    AuthRequired,
    AuthFailed,
    PermissionDenied,
    RevisionConflict,
    IdempotencyConflict,
    PlanExpired,
    ConfirmationRequired,
    ListenerBindFailed,
    TlsTrustFailed,
    SecretNotFound,
    SecretResultUnavailable,
    ImportUnsupported,
    ExportLossy,
    UpgradeIncompatible,
    SignatureInvalid,
    RollbackFailed,
    RecoveryRequired,
    OperationNotCancelable,
    OperationCanceled,
    AbiIncompatible,
    HookRequired,
    QueueFull,
    Timeout,
    Closed,
    Internal,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorStage {
    Decode,
    Validate,
    Authenticate,
    Plan,
    Apply,
    Start,
    Verify,
    Stop,
    Recover,
    Upgrade,
    Export,
}

/// Structured arguments only; never put raw IO errors, URIs or credentials here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SafeArg {
    Count(u32),
    Flag(bool),
    Code(SafeCode),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SafeCode(String);
impl TryFrom<String> for SafeCode {
    type Error = String;
    fn try_from(value: String) -> Result<Self, String> {
        if !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            Ok(Self(value))
        } else {
            Err("invalid public code".into())
        }
    }
}
impl From<SafeCode> for String {
    fn from(value: SafeCode) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductError {
    pub code: ErrorCode,
    pub message_key: SafeCode,
    #[serde(default)]
    pub safe_args: BTreeMap<String, SafeArg>,
    pub field_path: Option<String>,
    pub retryable: bool,
    pub stage: ErrorStage,
    pub capability_key: Option<CapabilityKey>,
    pub remediation: Option<Remediation>,
    pub diagnostic_id: Option<DiagnosticId>,
}
impl ProductError {
    pub fn new(code: ErrorCode, stage: ErrorStage) -> Self {
        Self {
            code,
            message_key: SafeCode("error.action_failed".into()),
            safe_args: BTreeMap::new(),
            field_path: None,
            retryable: false,
            stage,
            capability_key: None,
            remediation: None,
            diagnostic_id: None,
        }
    }
    pub fn at(mut self, path: impl Into<String>) -> Self {
        self.field_path = Some(path.into());
        self
    }
}
impl std::fmt::Display for ProductError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} ({:?})", self.code, self.stage)
    }
}
impl std::error::Error for ProductError {}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Remediation {
    Reauthenticate,
    ReloadSnapshot,
    ReviewFields,
    GrantPermission,
    Retry,
    UpdateProduct,
    RestoreBackup,
    ContactSupport,
}

impl JsonSchema for SafeCode {
    fn schema_name() -> String {
        "SafeCode".into()
    }
    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        crate::ids::bounded_string_schema("^[A-Za-z0-9._-]{1,128}$")
    }
}
