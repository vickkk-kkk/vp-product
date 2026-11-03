//! Ephemeral contexts for activation and compensation, never persisted authority.
use crate::*;
use vp_product_domain::{OperationId, ProductConfig};

fn uses_tls(config: &ProductConfig) -> bool {
    config
        .listeners
        .iter()
        .any(|l| l.enabled && matches!(l.security, vp_product_domain::ServerSecurity::Tls { .. }))
}
fn verify_phase(
    lease: &dyn WriterLease,
    id: &OperationId,
    plan: &ChangePlan,
    phase: OperationState,
) -> Result<(), ControlError> {
    let state = lease.state();
    state.verify_integrity()?;
    let op = state.operations.get(id).ok_or(ControlError::NotFound)?;
    let stored = state
        .plans
        .get(&op.plan_id)
        .ok_or(ControlError::CorruptState)?;
    plan.verify_integrity()?;
    if op.state != phase
        || !op.mutation_started
        || op.snapshot.is_none()
        || op.plan_id != plan.body().id
        || op.principal != plan.body().principal
        || stored.hash() != plan.hash()
        || state.active_revision != plan.body().base_revision
    {
        return Err(ControlError::ResourceConflict);
    }
    Ok(())
}
fn verify_previous(
    state: &StoredState,
    previous: Option<&RevisionRecord>,
) -> Result<(), ControlError> {
    match (state.active(), previous) {
        (None, None) if state.active_revision == vp_product_domain::Revision::ZERO => Ok(()),
        (Some(actual), Some(expected))
            if ContentDigest::of("vp.context-previous.v1", actual)?
                == ContentDigest::of("vp.context-previous.v1", expected)? =>
        {
            Ok(())
        }
        _ => Err(ControlError::ResourceConflict),
    }
}
#[cfg(feature = "private-tls")]
fn aggregate(lease: &dyn WriterLease) -> Result<&TlsControlEnvelope, ControlError> {
    let aggregate = lease
        .tls_aggregate()
        .ok_or(ControlError::ExecutorUnavailable)?;
    if aggregate.state().version != lease.state().version
        || ContentDigest::of("vp.stage-state.v1", aggregate.state())?
            != ContentDigest::of("vp.stage-state.v1", lease.state())?
    {
        return Err(ControlError::ResourceConflict);
    }
    Ok(aggregate)
}

/// Created only after the durable Activating checkpoint, under the same writer.
/// ```compile_fail
/// use vp_product_control::*;
/// use vp_product_domain::OperationId;
/// fn forge(w: &dyn WriterLease, id: &OperationId, p: &ChangePlan, c: &dyn Clock, x: &CancellationToken) {
///     let _ = RuntimeActivationContext::from_activating(w, id, p, None, c, x);
/// }
/// ```
pub struct RuntimeActivationContext<'a> {
    lease: &'a dyn WriterLease,
    operation: &'a OperationId,
    plan: &'a ChangePlan,
    previous: Option<&'a RevisionRecord>,
    cancel: &'a CancellationToken,
    #[cfg(feature = "private-tls")]
    clock: &'a dyn Clock,
    #[cfg(feature = "private-tls")]
    deadline: std::time::Instant,
}
impl<'a> RuntimeActivationContext<'a> {
    pub(crate) fn from_activating(
        lease: &'a dyn WriterLease,
        operation: &'a OperationId,
        plan: &'a ChangePlan,
        previous: Option<&'a RevisionRecord>,
        clock: &'a dyn Clock,
        cancel: &'a CancellationToken,
    ) -> Result<Self, ControlError> {
        verify_phase(lease, operation, plan, OperationState::Activating)?;
        verify_previous(lease.state(), previous)?;
        #[cfg(not(feature = "private-tls"))]
        let _ = clock;
        Ok(Self {
            lease,
            operation,
            plan,
            previous,
            cancel,
            #[cfg(feature = "private-tls")]
            clock,
            #[cfg(feature = "private-tls")]
            deadline: std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(10))
                .ok_or(ControlError::PlanExpired)?,
        })
    }
    /// The runtime journal may inspect the exact existing writer, never mutate
    /// control state or acquire a second writer through this borrowed handle.
    #[cfg(feature = "experimental-public")]
    pub fn runtime_journal_writer(&self) -> &dyn WriterLease { self.lease }
    pub fn operation(&self) -> &OperationId {
        self.operation
    }
    pub fn plan(&self) -> &ChangePlan {
        self.plan
    }
    pub fn previous(&self) -> Option<&RevisionRecord> {
        self.previous
    }
    pub fn cancellation(&self) -> &CancellationToken {
        self.cancel
    }
    pub fn aggregate_version(&self) -> u64 {
        self.lease.state().version
    }
    pub fn requires_tls_materials(&self) -> bool {
        uses_tls(&self.plan.body().config)
    }
    /// Re-read and verify material at activation, not cached Staging admission.
    /// ```compile_fail
    /// use vp_product_control::*;
    /// fn escape(c: &RuntimeActivationContext<'_>, v: &dyn TlsMaterialVault, p: &TlsBackendPolicy) -> TlsMaterialAdmission<'static> {
    ///     c.tls_materials(v, p, std::time::Instant::now()).unwrap()
    /// }
    /// ```
    #[cfg(feature = "private-tls")]
    pub fn tls_materials<'b>(
        &'b self,
        vault: &'b dyn TlsMaterialVault,
        policy: &'b TlsBackendPolicy,
        deadline: std::time::Instant,
    ) -> Result<TlsMaterialAdmission<'b>, ControlError> {
        TlsMaterialAdmission::for_activation(
            aggregate(self.lease)?,
            vault,
            policy,
            self.clock,
            self.aggregate_version(),
            self.operation,
            deadline.min(self.deadline),
            self.cancel,
        )
    }
    /// Experimental public material access follows the sealed activating plan.
    #[cfg(feature = "experimental-public")]
    pub fn experimental_public_materials<'b>(&'b self, vault: &'b dyn TlsMaterialVault, policy: &'b TlsBackendPolicy, deadline: std::time::Instant) -> Result<TlsMaterialAdmission<'b>, ControlError> {
        TlsMaterialAdmission::for_public_activation(aggregate(self.lease)?, vault, policy, self.clock,
            self.aggregate_version(), self.operation, deadline.min(self.deadline), self.cancel,
            &self.plan.body().validation.artifact_digest)
    }
}

/// A read-only verification view after the activation receipt was durably
/// recorded. It is not itself evidence that a listener forwards traffic.
#[cfg(feature = "experimental-public")]
pub struct RuntimeVerificationContext<'a> {
    lease: &'a dyn WriterLease, operation: &'a OperationId, plan: &'a ChangePlan,
    activation: &'a RuntimeActivation, clock: &'a dyn Clock,
    deadline: std::time::Instant, cancel: &'a CancellationToken,
}
#[cfg(feature = "experimental-public")]
impl<'a> RuntimeVerificationContext<'a> {
    pub(crate) fn from_verifying(lease: &'a dyn WriterLease, operation: &'a OperationId, plan: &'a ChangePlan, clock: &'a dyn Clock, cancel: &'a CancellationToken) -> Result<Self, ControlError> {
        verify_phase(lease, operation, plan, OperationState::Verifying)?;
        let activation = lease.state().operations.get(operation).and_then(|op| op.activation.as_ref()).ok_or(ControlError::CorruptState)?;
        if activation.operation_id != *operation || activation.revision != plan.body().target_revision
            || activation.config_digest != plan.body().validation.config_digest
            || activation.release_digest != plan.body().validation.release_digest || activation.generation == 0 {
            return Err(ControlError::CorruptState);
        }
        Ok(Self { lease, operation, plan, activation, clock, deadline: std::time::Instant::now().checked_add(std::time::Duration::from_secs(10)).ok_or(ControlError::PlanExpired)?, cancel })
    }
    pub fn operation(&self) -> &OperationId { self.operation }
    pub fn plan(&self) -> &ChangePlan { self.plan }
    pub fn activation(&self) -> &RuntimeActivation { self.activation }
    pub fn now_ms(&self) -> Result<u64, ControlError> { self.clock.now_ms() }
    pub fn runtime_journal_writer(&self) -> &dyn WriterLease { self.lease }
    pub fn experimental_public_materials<'b>(&'b self, vault: &'b dyn TlsMaterialVault, policy: &'b TlsBackendPolicy, deadline: std::time::Instant) -> Result<TlsMaterialAdmission<'b>, ControlError> {
        TlsMaterialAdmission::for_public_verification(aggregate(self.lease)?, vault, policy, self.clock,
            self.lease.state().version, self.operation, deadline.min(self.deadline), self.cancel,
            &self.plan.body().validation.artifact_digest)
    }
}

/// Current-state compensation authority. It never inherits an expired apply
/// deadline or canceled apply token; material checks still have a bounded budget.
/// ```compile_fail
/// use vp_product_control::*;
/// use vp_product_domain::OperationId;
/// fn forge(w: &dyn WriterLease, id: &OperationId, p: &ChangePlan, c: &dyn Clock) {
///     let _ = RuntimeRestoreContext::from_rolling_back(w, id, p, None, c);
/// }
/// ```
pub struct RuntimeRestoreContext<'a> {
    lease: &'a dyn WriterLease,
    operation: &'a OperationId,
    plan: &'a ChangePlan,
    previous: Option<&'a RevisionRecord>,
    #[cfg(feature = "private-tls")]
    clock: &'a dyn Clock,
    #[cfg(feature = "private-tls")]
    deadline: std::time::Instant,
    #[cfg(feature = "private-tls")]
    recovery_cancel: CancellationToken,
}
impl<'a> RuntimeRestoreContext<'a> {
    pub(crate) fn from_rolling_back(
        lease: &'a dyn WriterLease,
        operation: &'a OperationId,
        plan: &'a ChangePlan,
        previous: Option<&'a RevisionRecord>,
        clock: &'a dyn Clock,
    ) -> Result<Self, ControlError> {
        verify_phase(lease, operation, plan, OperationState::RollingBack)?;
        verify_previous(lease.state(), previous)?;
        #[cfg(not(feature = "private-tls"))]
        let _ = clock;
        Ok(Self {
            lease,
            operation,
            plan,
            previous,
            #[cfg(feature = "private-tls")]
            clock,
            #[cfg(feature = "private-tls")]
            deadline: std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(10))
                .ok_or(ControlError::PlanExpired)?,
            #[cfg(feature = "private-tls")]
            recovery_cancel: CancellationToken::default(),
        })
    }
    /// The runtime journal may inspect the exact existing writer, never mutate
    /// control state or acquire a second writer through this borrowed handle.
    #[cfg(feature = "experimental-public")]
    pub fn runtime_journal_writer(&self) -> &dyn WriterLease { self.lease }
    pub fn operation(&self) -> &OperationId {
        self.operation
    }
    pub fn plan(&self) -> &ChangePlan { self.plan }
    pub fn previous(&self) -> Option<&RevisionRecord> {
        self.previous
    }
    pub fn aggregate_version(&self) -> u64 {
        self.lease.state().version
    }
    pub fn requires_tls_materials(&self) -> bool {
        uses_tls(&self.plan.body().config) || self.previous.is_some_and(|p| uses_tls(&p.config))
    }
    /// No previous revision represents the stopped state, not invented materials.
    /// ```compile_fail
    /// use vp_product_control::*;
    /// fn escape(c: &RuntimeRestoreContext<'_>, v: &dyn TlsMaterialVault, p: &TlsBackendPolicy) -> TlsMaterialAdmission<'static> {
    ///     c.tls_materials(v, p, std::time::Instant::now()).unwrap()
    /// }
    /// ```
    #[cfg(feature = "private-tls")]
    pub fn tls_materials<'b>(
        &'b self,
        vault: &'b dyn TlsMaterialVault,
        policy: &'b TlsBackendPolicy,
        deadline: std::time::Instant,
    ) -> Result<TlsMaterialAdmission<'b>, ControlError> {
        let previous = self.previous.ok_or(ControlError::NotFound)?;
        TlsMaterialAdmission::for_restoration(
            aggregate(self.lease)?,
            vault,
            policy,
            self.clock,
            self.aggregate_version(),
            self.operation,
            previous,
            deadline.min(self.deadline),
            &self.recovery_cancel,
        )
    }
    /// Experimental rollback revalidates the previous committed artifact, not
    /// the failed candidate. A fresh worker is required for its process floor.
    #[cfg(feature = "experimental-public")]
    pub fn experimental_public_materials<'b>(&'b self, vault: &'b dyn TlsMaterialVault, policy: &'b TlsBackendPolicy, deadline: std::time::Instant) -> Result<TlsMaterialAdmission<'b>, ControlError> {
        let previous = self.previous.ok_or(ControlError::NotFound)?;
        TlsMaterialAdmission::for_public_restoration(aggregate(self.lease)?, vault, policy, self.clock,
            self.aggregate_version(), self.operation, previous, deadline.min(self.deadline),
            &self.recovery_cancel, &previous.artifact_digest)
    }
}
