use crate::{OperationId, PlanId, ProductError, Revision, SafeCode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Queued,
    Running,
    AwaitingConfirmation,
    Succeeded,
    Failed,
    Canceled,
    RollingBack,
    RolledBack,
    RecoveryRequired,
}
impl OperationStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Canceled
                | Self::RolledBack
                | Self::RecoveryRequired
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationStage {
    Validate,
    Stage,
    StopOld,
    StartNew,
    Verify,
    Commit,
    Rollback,
    Recover,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationSummary {
    pub id: OperationId,
    pub plan_id: Option<PlanId>,
    pub status: OperationStatus,
    pub stage: OperationStage,
    pub cancellable: bool,
    pub completed_steps: u32,
    pub total_steps: u32,
    pub base_revision: Revision,
    pub target_revision: Option<Revision>,
    pub error: Option<ProductError>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeImpact {
    NoRuntimeChange,
    RouteHotSwap,
    ControlledRestart,
    PrivilegedSystemChange,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeSummary {
    pub resource_id: String,
    pub action: ChangeAction,
    pub message_key: SafeCode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeAction {
    Create,
    Update,
    Delete,
}
/// Projection of a durable immutable plan; this DTO cannot authorize application.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangePlanSummary {
    pub id: PlanId,
    pub plan_hash: String,
    pub base_revision: Revision,
    pub expires_at: u64,
    pub changes: Vec<ChangeSummary>,
    pub impact: ChangeImpact,
    pub required_permissions: Vec<SafeCode>,
    pub recovery_available: bool,
    pub recovery_description_key: SafeCode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DraftSummary {
    pub id: crate::DraftId,
    pub revision: Revision,
    pub base_revision: Revision,
    pub config: crate::ProductConfig,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagementSnapshot {
    pub schema_version: u16,
    pub desired_revision: Revision,
    pub observed_revision: Option<Revision>,
    pub listeners: Vec<crate::ListenerObservation>,
    pub operations: Vec<OperationSummary>,
}
