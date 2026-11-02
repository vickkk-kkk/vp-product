use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use vp_product_domain::{
    IdempotencyKey, OperationId, PlanId, ProductConfig, ReleaseIdentity, Revision, UserId,
};

/// No raw OS/compiler messages or secrets cross the control-plane error boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlError {
    #[error("revision conflict")]
    RevisionConflict {
        expected: Revision,
        actual: Revision,
    },
    #[error("idempotency key was already used for different content")]
    IdempotencyConflict,
    #[error("plan expired or clock moved before its creation")]
    PlanExpired,
    #[error("confirmation does not match the immutable plan")]
    ConfirmationMismatch,
    #[error("permission denied")]
    PermissionDenied,
    #[error("requested object was not found")]
    NotFound,
    #[error("configuration validation failed")]
    InvalidConfiguration,
    #[error("invalid request")]
    InvalidRequest,
    #[error("runtime executor is unavailable")]
    ExecutorUnavailable,
    #[error("external resource drift or ownership conflict")]
    ResourceConflict,
    #[error("runtime verification failed")]
    HealthFailed,
    #[error("operation was canceled")]
    Canceled,
    #[error("the operation passed its cancellation boundary")]
    CannotCancel,
    #[error("recovery is required before further changes")]
    RecoveryRequired,
    #[error("durable storage is unavailable; operation outcome may require recovery")]
    StorageUnavailable,
    #[error("stored state failed its integrity check")]
    CorruptState,
    #[error("executor action failed")]
    ExecutorFailed,
    #[error("publication cannot preserve all connection fields")]
    ExportLossy,
    #[error("sensitive result was already issued; explicit new rotation required")]
    SecretResultUnavailable,
    #[error("counter exhausted")]
    CounterExhausted,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContentDigest(String);
impl ContentDigest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ControlError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            Ok(Self(value))
        } else {
            Err(ControlError::InvalidRequest)
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }
    pub fn of<T: Serialize>(domain: &str, value: &T) -> Result<Self, ControlError> {
        let value = serde_json::to_value(value).map_err(|_| ControlError::InvalidRequest)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(domain.as_bytes());
        bytes.push(0);
        canonical_json(&value, &mut bytes)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ControlError::InvalidRequest);
        }
        Ok(Self::bytes(&bytes))
    }
}
impl fmt::Debug for ContentDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ContentDigest").field(&self.0).finish()
    }
}
impl TryFrom<String> for ContentDigest {
    type Error = ControlError;
    fn try_from(v: String) -> Result<Self, Self::Error> {
        Self::parse(v)
    }
}
impl From<ContentDigest> for String {
    fn from(v: ContentDigest) -> Self {
        v.0
    }
}

const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
/// Stable object-key ordering independent of serde_json's preserve_order feature.
/// Domain schema v1 contains integers, not floating point values. This is a
/// versioned product encoding, not a claim to implement RFC 8785.
fn canonical_json(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), ControlError> {
    match value {
        serde_json::Value::Object(map) => {
            out.push(b'{');
            let keys: BTreeSet<_> = map.keys().collect();
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).map_err(|_| ControlError::InvalidRequest)?;
                out.push(b':');
                canonical_json(&map[key], out)?;
            }
            out.push(b'}');
        }
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_json(item, out)?;
            }
            out.push(b']');
        }
        _ => serde_json::to_writer(&mut *out, value).map_err(|_| ControlError::InvalidRequest)?,
    }
    if out.len() > MAX_CONFIG_BYTES {
        return Err(ControlError::InvalidRequest);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Service,
    Firewall,
    Sysctl,
    Certificate,
    EdgeConfig,
    Network,
    ReleaseSlot,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceChange {
    /// Opaque identifier resolved through an owned-resource registry, never a path or shell string.
    pub id: String,
    pub kind: ResourceKind,
    pub expected: Option<ContentDigest>,
    pub desired: Option<ContentDigest>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceObservation {
    pub id: String,
    pub owner: Option<String>,
    pub fingerprint: Option<ContentDigest>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartImpact {
    ControlledRestart,
    RouteOnly,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthenticationProbe {
    pub listener_id: String,
    pub user_id: String,
    /// Hash of an immutable vault reference, never a password hash. The vault
    /// must create a new reference on rotation; in-place replacement is forbidden.
    pub credential_ref_digest: ContentDigest,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", content = "object", rename_all = "snake_case")]
pub enum HealthCheck {
    Process,
    ListenerBound(String),
    AuthenticationAccepted(AuthenticationProbe),
    InvalidAuthenticationRejected(String),
    SecurityIdentity(String),
    RetiredAuthenticationRejected(AuthenticationProbe),
    RetiredListenerReleased(String),
    Forwarding(String),
    Dns(String),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Passed,
    Failed,
    NotChecked,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CheckResult {
    pub check: HealthCheck,
    pub outcome: CheckOutcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeHealth {
    pub revision: Revision,
    pub operation_id: OperationId,
    pub config_digest: ContentDigest,
    pub release_digest: ContentDigest,
    pub generation: u64,
    pub checked_at_ms: u64,
    pub checks: Vec<CheckResult>,
    /// May be NotChecked when probes were not authorized. Never translated to Passed.
    pub external_connectivity: CheckOutcome,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeActivation {
    pub revision: Revision,
    pub operation_id: OperationId,
    pub config_digest: ContentDigest,
    pub release_digest: ContentDigest,
    pub generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ValidationReceipt {
    pub config_digest: ContentDigest,
    pub release_digest: ContentDigest,
    pub artifact_digest: ContentDigest,
    pub impact: RestartImpact,
    pub required_health: BTreeSet<HealthCheck>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanBody {
    pub schema_version: u16,
    pub id: PlanId,
    pub principal: UserId,
    pub base_revision: Revision,
    pub target_revision: Revision,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub config: ProductConfig,
    pub release: ReleaseIdentity,
    pub validation: ValidationReceipt,
    pub resources: Vec<ResourceChange>,
}
/// Fields are private: callers can inspect but cannot modify a validated plan.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangePlan {
    body: PlanBody,
    hash: ContentDigest,
}
impl ChangePlan {
    pub(crate) fn seal(body: PlanBody) -> Result<Self, ControlError> {
        let hash = ContentDigest::of("vp.change-plan.v1", &body)?;
        Ok(Self { body, hash })
    }
    pub fn body(&self) -> &PlanBody {
        &self.body
    }
    pub fn hash(&self) -> &ContentDigest {
        &self.hash
    }
    pub fn verify_integrity(&self) -> Result<(), ControlError> {
        if self.hash != ContentDigest::of("vp.change-plan.v1", &self.body)?
            || self.body.validation.config_digest
                != ContentDigest::of("vp.product-config.v1", &self.body.config)?
            || self.body.validation.release_digest
                != ContentDigest::of("vp.release-identity.v1", &self.body.release)?
            || self.body.base_revision.next() != Some(self.body.target_revision)
            || self.body.expires_at_ms <= self.body.created_at_ms
            || self.body.schema_version != 1
        {
            return Err(ControlError::CorruptState);
        }
        Ok(())
    }
}
impl fmt::Debug for ChangePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangePlan")
            .field("id", &self.body.id)
            .field("hash", &self.hash)
            .field("base_revision", &self.body.base_revision)
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
pub struct PlanRequest {
    pub principal: UserId,
    pub expected_revision: Revision,
    pub config: ProductConfig,
    pub release: ReleaseIdentity,
    pub resources: Vec<ResourceChange>,
    pub ttl_ms: u64,
}
impl fmt::Debug for PlanRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlanRequest")
            .field("expected_revision", &self.expected_revision)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApplyRequest {
    pub principal: UserId,
    pub plan_id: PlanId,
    pub confirmed_hash: ContentDigest,
    pub expected_revision: Revision,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Staging,
    Snapshotting,
    ApplyingResources,
    Activating,
    Verifying,
    Committing,
    Committed,
    Canceling,
    Canceled,
    RollingBack,
    RolledBack,
    Failed,
    RecoveryRequired,
}
impl OperationState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Canceled | Self::RolledBack | Self::Failed
        )
    }
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::Queued | Self::Staging | Self::Snapshotting)
    }
    pub fn may_have_mutated_resources(&self) -> bool {
        !matches!(
            self,
            Self::Queued | Self::Staging | Self::Snapshotting | Self::Failed | Self::Canceled
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceSnapshot {
    /// Executor-created durable snapshot ID; secret bytes remain in the vault.
    pub id: String,
    pub resources: Vec<ResourceObservation>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Operation {
    pub id: OperationId,
    pub plan_id: PlanId,
    pub principal: UserId,
    pub state: OperationState,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub snapshot: Option<ResourceSnapshot>,
    pub failure: Option<ControlError>,
    pub health: Option<RuntimeHealth>,
    pub activation: Option<RuntimeActivation>,
    pub cancel_requested: bool,
    /// Durable first-host-mutation intent, retained through compensation failures.
    pub mutation_started: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RevisionRecord {
    pub revision: Revision,
    pub config: ProductConfig,
    pub release: ReleaseIdentity,
    pub config_digest: ContentDigest,
    pub release_digest: ContentDigest,
    pub artifact_digest: ContentDigest,
    pub operation_id: OperationId,
}
impl fmt::Debug for RevisionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevisionRecord")
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdempotencyRecord {
    pub principal: UserId,
    pub method: String,
    pub key: IdempotencyKey,
    pub request_digest: ContentDigest,
    pub operation_id: OperationId,
}
/// Persistence-only model. Never return this object from an API or diagnostics.
/// Contains private configuration, not credential bytes. Read APIs must project
/// an explicitly authorized view. Retention must not remove live idempotency keys.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StoredState {
    pub secrets: crate::SecretState,
    #[serde(default)]
    pub cancel_idempotency: Vec<crate::CancelIdempotencyRecord>,
    #[serde(default)]
    pub drafts: BTreeMap<vp_product_domain::DraftId, crate::DraftRecord>,
    #[serde(default)]
    pub draft_idempotency: Vec<crate::DraftIdempotencyRecord>,
    #[serde(default)]
    pub plan_idempotency: Vec<crate::PlanIdempotencyRecord>,
    pub schema_version: u16,
    pub version: u64,
    pub next_id: u64,
    pub active_revision: Revision,
    pub revisions: Vec<RevisionRecord>,
    pub plans: BTreeMap<PlanId, ChangePlan>,
    pub operations: BTreeMap<OperationId, Operation>,
    pub idempotency: Vec<IdempotencyRecord>,
}
impl Default for StoredState {
    fn default() -> Self {
        Self {
            schema_version: 2,
            secrets: crate::SecretState::default(),
            drafts: BTreeMap::new(),
            cancel_idempotency: Vec::new(),
            draft_idempotency: Vec::new(),
            plan_idempotency: Vec::new(),
            version: 0,
            next_id: 1,
            active_revision: Revision::ZERO,
            revisions: Vec::new(),
            plans: BTreeMap::new(),
            operations: BTreeMap::new(),
            idempotency: Vec::new(),
        }
    }
}
impl StoredState {
    pub fn active(&self) -> Option<&RevisionRecord> {
        self.revisions
            .iter()
            .find(|r| r.revision == self.active_revision)
    }
    pub fn needs_recovery(&self) -> bool {
        self.secrets.needs_recovery()
            || self
                .operations
                .values()
                .any(|op| !op.state.is_terminal() && op.state != OperationState::Queued)
    }
    pub fn verify_integrity(&self) -> Result<(), ControlError> {
        crate::drafts::verify_drafts(self)?;
        self.secrets.verify_integrity()?;
        if self.schema_version != 2
            || (self.active_revision != Revision::ZERO && self.active().is_none())
        {
            return Err(ControlError::CorruptState);
        }
        for (id, plan) in &self.plans {
            plan.verify_integrity()?;
            if id != &plan.body().id {
                return Err(ControlError::CorruptState);
            }
        }
        for (id, op) in &self.operations {
            if id != &op.id || !self.plans.contains_key(&op.plan_id) {
                return Err(ControlError::CorruptState);
            }
            if op.mutation_started && op.snapshot.is_none() {
                return Err(ControlError::CorruptState);
            }
            if op.state == OperationState::Committed
                && (op.health.is_none()
                    || op.activation.is_none()
                    || !self.revisions.iter().any(|r| r.operation_id == op.id))
            {
                return Err(ControlError::CorruptState);
            }
        }
        let mut seen_revisions = BTreeSet::new();
        for revision in &self.revisions {
            if !seen_revisions.insert(revision.revision)
                || revision.revision == Revision::ZERO
                || revision.config_digest
                    != ContentDigest::of("vp.product-config.v1", &revision.config)?
                || revision.release_digest
                    != ContentDigest::of("vp.release-identity.v1", &revision.release)?
                || !self
                    .operations
                    .get(&revision.operation_id)
                    .is_some_and(|op| op.state == OperationState::Committed)
            {
                return Err(ControlError::CorruptState);
            }
        }
        let mut seen_keys = BTreeSet::new();
        for entry in &self.idempotency {
            if !self.operations.contains_key(&entry.operation_id)
                || !seen_keys.insert((&entry.principal, &entry.method, &entry.key))
            {
                return Err(ControlError::CorruptState);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct JournalEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<crate::SecurityAuditEvent>,
    pub sequence: u64,
    pub at_ms: u64,
    pub operation_id: Option<OperationId>,
    pub state: Option<OperationState>,
}
/// Does not claim persisted health is the current runtime state after a restart.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ControlSnapshot {
    pub active_revision: Revision,
    pub desired_revision: Revision,
    pub observed_revision: Option<Revision>,
    pub recovery_required: bool,
    pub operations: Vec<Operation>,
}
