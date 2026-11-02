use crate::{
    ErrorCode, ErrorStage, IdempotencyKey, OperationId, ProductError, RequestId, Revision,
    SCHEMA_VERSION,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommandMethod {
    Snapshot,
    Capabilities,
    Validate,
    Connect,
    Disconnect,
    ApplyRouteSnapshot,
    DraftCreate,
    DraftReplace,
    DraftDelete,
    ListenerCreate,
    ListenerReplace,
    ListenerDelete,
    PlanCreate,
    PlanApply,
    OperationCancel,
    ImportPreview,
    Export,
    DiagnosticPreview,
    UpdatePlan,
    CredentialCreate,
    CredentialRetire,
    PublicationCreate,
    PublicationReplace,
    PublicationTokenIssue,
    PublicationTokenRevoke,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandEnvelope<T> {
    pub schema_version: u16,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
    pub expected_revision: Option<Revision>,
    pub method: CommandMethod,
    pub payload: T,
}
impl<T> CommandEnvelope<T> {
    /// Dispatch must additionally decode T for this exact method. Mutations
    /// require CAS and idempotency; a retry is not permission for a new action.
    pub fn validate_metadata(&self) -> Result<(), ProductError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ProductError::new(
                ErrorCode::UpgradeIncompatible,
                ErrorStage::Decode,
            ));
        }
        let mutating = matches!(
            self.method,
            CommandMethod::Connect
                | CommandMethod::Disconnect
                | CommandMethod::ApplyRouteSnapshot
                | CommandMethod::DraftCreate
                | CommandMethod::DraftReplace
                | CommandMethod::DraftDelete
                | CommandMethod::ListenerCreate
                | CommandMethod::ListenerReplace
                | CommandMethod::ListenerDelete
                | CommandMethod::PlanCreate
                | CommandMethod::PlanApply
                | CommandMethod::OperationCancel
                | CommandMethod::CredentialCreate
                | CommandMethod::CredentialRetire
                | CommandMethod::PublicationCreate
                | CommandMethod::PublicationReplace
                | CommandMethod::PublicationTokenIssue
                | CommandMethod::PublicationTokenRevoke
        );
        if mutating && (self.idempotency_key.is_none() || self.expected_revision.is_none()) {
            return Err(ProductError::new(
                ErrorCode::ConfigInvalid,
                ErrorStage::Validate,
            ));
        }
        Ok(())
    }
}
/// Exactly one of result or error is present on the wire, enforced by this union.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ResultEnvelope<T> {
    Success(SuccessEnvelope<T>),
    Failure(FailureEnvelope),
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuccessEnvelope<T> {
    pub schema_version: u16,
    pub request_id: RequestId,
    pub operation_id: Option<OperationId>,
    pub result: T,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureEnvelope {
    pub schema_version: u16,
    pub request_id: RequestId,
    pub operation_id: Option<OperationId>,
    pub error: ProductError,
}
