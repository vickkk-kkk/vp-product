use std::{collections::BTreeSet, time::Instant};
use vp_product_compiler::ExecutionRecipe;
use vp_product_control::{CheckOutcome, ControlError, HealthCheck};
use vp_product_domain::{SecretBytes, SecretRef};

/// Versioned immutable references only. This is not a mutable key/value vault.
/// Implementations MUST enforce the supplied deadline; transient unavailability
/// must not become a missing credential or an anonymous listener. Secret bytes
/// are never persisted by this crate. Rotation creates a new reference.
pub trait ImmutableSecretStore: Send + Sync {
    fn validate_immutable(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<(), ControlError>;
    fn resolve_immutable(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<SecretBytes, ControlError>;
}
pub struct UnavailableSecretStore;
impl ImmutableSecretStore for UnavailableSecretStore {
    fn validate_immutable(&self, _: &SecretRef, _: Instant) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn resolve_immutable(&self, _: &SecretRef, _: Instant) -> Result<SecretBytes, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
}
/// Each check is an active network oracle, not a translation of a worker
/// snapshot into success. Targets must be explicitly allowed loopback endpoints.
/// Accepted/retired auth receives exactly that immutable reference's bytes.
/// Implementations must check invalid/retired credentials did NOT forward, not
/// merely that the client saw a connection reset. They must obey the deadline.
/// A development probe implementation does not certify a protocol capability.
pub trait ActiveProbe: Send + Sync {
    fn available(
        &self,
        current: &ExecutionRecipe,
        previous: Option<&ExecutionRecipe>,
        required: &BTreeSet<HealthCheck>,
    ) -> Result<(), ControlError>;
    fn check(
        &self,
        request: ProbeRequest<'_>,
        deadline: Instant,
    ) -> Result<CheckOutcome, ControlError>;
    /// Prove all these listener endpoints released. Used together with actual
    /// process identity/liveness evidence, never as a substitute for process exit.
    fn stopped(&self, recipe: &ExecutionRecipe, deadline: Instant) -> Result<(), ControlError>;
}
pub struct ProbeRequest<'a> {
    pub check: &'a HealthCheck,
    pub current: &'a ExecutionRecipe,
    pub previous: Option<&'a ExecutionRecipe>,
    pub generation: u64,
    pub credential: Option<&'a SecretBytes>,
}
pub struct UnavailableProbe;
impl ActiveProbe for UnavailableProbe {
    fn available(
        &self,
        _: &ExecutionRecipe,
        _: Option<&ExecutionRecipe>,
        _: &BTreeSet<HealthCheck>,
    ) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn check(&self, _: ProbeRequest<'_>, _: Instant) -> Result<CheckOutcome, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn stopped(&self, _: &ExecutionRecipe, _: Instant) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
}

/// Real empty-resource executor: explicitly refuses every host action. A
/// loopback-only plan has no route/firewall/service state to capture or mutate.
/// The empty snapshot is persisted by ControlService, not invented host evidence.
pub struct NoHostChanges;
impl vp_product_control::SystemExecutor for NoHostChanges {
    fn inspect(
        &self,
        resources: &[vp_product_control::ResourceChange],
    ) -> Result<Vec<vp_product_control::ResourceObservation>, ControlError> {
        if !resources.is_empty() {
            return Err(ControlError::PermissionDenied);
        }
        Ok(Vec::new())
    }
    fn capture(
        &self,
        operation: &vp_product_domain::OperationId,
        resources: &[vp_product_control::ResourceChange],
    ) -> Result<vp_product_control::ResourceSnapshot, ControlError> {
        self.inspect(resources)?;
        Ok(vp_product_control::ResourceSnapshot {
            id: operation.as_str().to_owned(),
            resources: Vec::new(),
        })
    }
    fn apply(
        &self,
        operation: &vp_product_domain::OperationId,
        plan: &vp_product_control::ChangePlan,
        snapshot: &vp_product_control::ResourceSnapshot,
    ) -> Result<(), ControlError> {
        plan.verify_integrity()?;
        self.inspect(&plan.body().resources)?;
        if snapshot.id != operation.as_str() || !snapshot.resources.is_empty() {
            return Err(ControlError::ResourceConflict);
        }
        Ok(())
    }
    fn restore(
        &self,
        operation: &vp_product_domain::OperationId,
        plan: &vp_product_control::ChangePlan,
        snapshot: &vp_product_control::ResourceSnapshot,
    ) -> Result<(), ControlError> {
        self.apply(operation, plan, snapshot)
    }
}
