use crate::*;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use vp_product_domain::{OperationId, ProductConfig, ReleaseIdentity};

/// A clock is injectable for expiry/clock-regression tests. Wall-clock failures
/// fail closed; a restored plan from the future is never applied.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> Result<u64, ControlError>;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> Result<u64, ControlError> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ControlError::PlanExpired)?
            .as_millis();
        u64::try_from(millis).map_err(|_| ControlError::CounterExhausted)
    }
}
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);
impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_canceled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// The lease serializes *all* control writes across both threads and processes.
/// Each persist is a separate durable transaction: never wrap external actions
/// inside one uncommitted SQL transaction. Storage errors must not be retried
/// blindly: the last commit may have reached disk.
pub trait WriterLease {
    /// Borrow the exact current aggregate under this same writer, never reacquire.
    #[cfg(feature = "private-tls")]
    fn tls_aggregate(&self) -> Option<&TlsControlEnvelope> {
        None
    }
    fn state(&self) -> &StoredState;
    fn persist(&mut self, next: StoredState, event: JournalEvent) -> Result<(), ControlError>;
}
pub trait ControlStore: Send + Sync {
    fn read(&self) -> Result<StoredState, ControlError>;
    fn writer(&self) -> Result<Box<dyn WriterLease + '_>, ControlError>;
}

/// Trusted planning view: current aggregate, authenticated principal and exact
/// draft. Read-only material checks grant no apply or worker authority.
#[cfg(feature = "experimental-public")]
pub struct RuntimePlanContext<'a> { lease: &'a dyn WriterLease, request: &'a PlanRequest, clock: &'a dyn Clock }
#[cfg(feature = "experimental-public")]
impl<'a> RuntimePlanContext<'a> {
    pub(crate) fn new(lease: &'a dyn WriterLease, request: &'a PlanRequest, clock: &'a dyn Clock) -> Self { Self { lease, request, clock } }
    pub fn config(&self) -> &ProductConfig { &self.request.config }
    pub fn release(&self) -> &ReleaseIdentity { &self.request.release }
    pub fn previous(&self) -> Option<&RevisionRecord> { self.lease.state().active() }
    pub fn validate_public_materials(&self, vault: &dyn TlsMaterialVault, policy: &TlsBackendPolicy, artifact: &ContentDigest, deadline: std::time::Instant) -> Result<(), ControlError> {
        let aggregate = self.lease.tls_aggregate().ok_or(ControlError::ExecutorUnavailable)?;
        if aggregate.state().version != self.lease.state().version
            || ContentDigest::of("vp.plan-state.v1", aggregate.state())? != ContentDigest::of("vp.plan-state.v1", self.lease.state())? {
            return Err(ControlError::ResourceConflict);
        }
        TlsMaterialAdmission::validate_public_draft(aggregate, vault, policy, self.clock, &self.request.principal, &self.request.config, &self.request.release, artifact, deadline)
    }
}

/// Read-only view of the already-held writer immediately before staging a
/// queued operation. It permits a trusted runtime to reconcile its own terminal
/// journal. This view supplies no mutable control writer or launch authority.
#[cfg(feature = "experimental-public")]
pub struct RuntimePreStageContext<'a> { lease: &'a dyn WriterLease, operation: &'a OperationId, plan: &'a ChangePlan }
#[cfg(feature = "experimental-public")]
impl<'a> RuntimePreStageContext<'a> {
    pub(crate) fn from_queued(lease: &'a dyn WriterLease, operation: &'a OperationId, plan: &'a ChangePlan) -> Result<Self, ControlError> {
        let op = lease.state().operations.get(operation).ok_or(ControlError::NotFound)?;
        let stored = lease.state().plans.get(&op.plan_id).ok_or(ControlError::CorruptState)?;
        plan.verify_integrity()?; stored.verify_integrity()?;
        if op.state != OperationState::Queued || op.cancel_requested || op.mutation_started
            || op.plan_id != plan.body().id || op.principal != plan.body().principal
            || stored.hash() != plan.hash() || plan.body().base_revision != lease.state().active_revision {
            return Err(ControlError::ResourceConflict);
        }
        Ok(Self { lease, operation, plan })
    }
    pub fn operation(&self) -> &OperationId { self.operation }
    pub fn plan(&self) -> &ChangePlan { self.plan }
    pub fn runtime_journal_writer(&self) -> &dyn WriterLease { self.lease }
}

/// Read-only writer context for cancelling a candidate before host mutation.
#[cfg(feature = "experimental-public")]
pub struct RuntimeCleanupContext<'a> { lease: &'a dyn WriterLease, operation: &'a OperationId }
#[cfg(feature = "experimental-public")]
impl<'a> RuntimeCleanupContext<'a> {
    pub(crate) fn from_canceling(lease: &'a dyn WriterLease, operation: &'a OperationId) -> Result<Self, ControlError> {
        let op = lease.state().operations.get(operation).ok_or(ControlError::NotFound)?;
        let plan = lease.state().plans.get(&op.plan_id).ok_or(ControlError::CorruptState)?;
        plan.verify_integrity()?;
        if op.state != OperationState::Canceling || op.mutation_started || op.principal != plan.body().principal
            || plan.body().base_revision != lease.state().active_revision { return Err(ControlError::ResourceConflict); }
        Ok(Self { lease, operation })
    }
    pub fn operation(&self) -> &OperationId { self.operation }
    pub fn runtime_journal_writer(&self) -> &dyn WriterLease { self.lease }
}

/// Ephemeral staging authority created only by ControlService after its durable
/// Staging checkpoint. No serialization, clone, mutable writer or lock acquisition.
/// Backend ports remain trusted; this is not an external request DTO.
///
/// ```compile_fail
/// use vp_product_control::*;
/// use vp_product_domain::OperationId;
/// fn forge(w: &dyn WriterLease, id: &OperationId, p: &ChangePlan,
///          c: &dyn Clock, cancel: &CancellationToken) {
///     let _ = RuntimeStageContext::from_staging(w, id, p, c, cancel);
/// }
/// ```
pub struct RuntimeStageContext<'a> {
    lease: &'a dyn WriterLease,
    operation: &'a OperationId,
    plan: &'a ChangePlan,
    #[cfg(feature = "private-tls")]
    clock: &'a dyn Clock,
    cancel: &'a CancellationToken,
    #[cfg(feature = "private-tls")]
    material_deadline: std::time::Instant,
}
impl<'a> RuntimeStageContext<'a> {
    pub(crate) fn from_staging(
        lease: &'a dyn WriterLease,
        operation: &'a OperationId,
        plan: &'a ChangePlan,
        clock: &'a dyn Clock,
        cancel: &'a CancellationToken,
    ) -> Result<Self, ControlError> {
        let op = lease
            .state()
            .operations
            .get(operation)
            .ok_or(ControlError::NotFound)?;
        let stored = lease
            .state()
            .plans
            .get(&op.plan_id)
            .ok_or(ControlError::CorruptState)?;
        plan.verify_integrity()?;
        stored.verify_integrity()?;
        if op.state != OperationState::Staging
            || op.cancel_requested
            || op.mutation_started
            || op.plan_id != plan.body().id
            || op.principal != plan.body().principal
            || stored.hash() != plan.hash()
            || plan.body().base_revision != lease.state().active_revision
        {
            return Err(ControlError::ResourceConflict);
        }
        #[cfg(not(feature = "private-tls"))]
        let _ = clock;
        Ok(Self {
            lease,
            operation,
            plan,
            cancel,
            #[cfg(feature = "private-tls")]
            clock,
            #[cfg(feature = "private-tls")]
            material_deadline: std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(10))
                .ok_or(ControlError::PlanExpired)?,
        })
    }
    /// Borrow the already-held writer read-only for trusted runtime journal
    /// pairing. It cannot be retained beyond this staging context.
    #[cfg(feature = "experimental-public")]
    pub fn runtime_journal_writer(&self) -> &dyn WriterLease { self.lease }
    pub fn operation(&self) -> &OperationId {
        self.operation
    }
    pub fn plan(&self) -> &ChangePlan {
        self.plan
    }
    pub fn cancellation(&self) -> &CancellationToken {
        self.cancel
    }
    pub fn aggregate_version(&self) -> u64 {
        self.lease.state().version
    }
    pub fn requires_tls_materials(&self) -> bool {
        self.plan.body().config.listeners.iter().any(|l| {
            l.enabled && matches!(l.security, vp_product_domain::ServerSecurity::Tls { .. })
        })
    }
    /// The backend supplies trusted policy/vault ports, not a caller proof.
    /// Returned admission cannot outlive this context or the leased aggregate.
    ///
    /// ```compile_fail
    /// use vp_product_control::*;
    /// fn escape(c: &RuntimeStageContext<'_>, v: &dyn TlsMaterialVault,
    ///           p: &TlsBackendPolicy) -> TlsMaterialAdmission<'static> {
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
        let aggregate = self
            .lease
            .tls_aggregate()
            .ok_or(ControlError::ExecutorUnavailable)?;
        // Store implementations must expose their current snapshot, not a cached view.
        if aggregate.state().version != self.lease.state().version
            || ContentDigest::of("vp.stage-state.v1", aggregate.state())?
                != ContentDigest::of("vp.stage-state.v1", self.lease.state())?
        {
            return Err(ControlError::ResourceConflict);
        }
        TlsMaterialAdmission::for_aggregate(
            aggregate,
            vault,
            policy,
            self.clock,
            self.aggregate_version(),
            self.operation,
            deadline.min(self.material_deadline),
            self.cancel,
        )
    }
    /// Experimental material admission derived from the actual sealed stage
    /// context. It is not available in default builds and grants no listener.
    #[cfg(feature = "experimental-public")]
    pub fn experimental_public_materials<'b>(
        &'b self, vault: &'b dyn TlsMaterialVault, policy: &'b TlsBackendPolicy,
        deadline: std::time::Instant,
    ) -> Result<TlsMaterialAdmission<'b>, ControlError> {
        let aggregate = self.lease.tls_aggregate().ok_or(ControlError::ExecutorUnavailable)?;
        if aggregate.state().version != self.lease.state().version
            || ContentDigest::of("vp.stage-state.v1", aggregate.state())? != ContentDigest::of("vp.stage-state.v1", self.lease.state())? {
            return Err(ControlError::ResourceConflict);
        }
        TlsMaterialAdmission::for_public_aggregate(aggregate, vault, policy, self.clock,
            self.aggregate_version(), self.operation, deadline.min(self.material_deadline),
            self.cancel, &self.plan.body().validation.artifact_digest)
    }
}

/// Every mutating method must be idempotent by operation ID. Before returning
/// stage/capture success, referenced recovery material must be durable. No
/// arbitrary executable/path/URL is accepted by this interface. Secret material
/// may only be resolved inside the protected executor/vault boundary.
/// Vault references must be immutable/versioned: rotation creates a new reference,
/// and validation refuses mutable references. Every executor call must have an
/// implementation-level deadline; no method may wait forever while holding the writer.
pub trait RuntimeExecutor: Send + Sync {
    #[cfg(feature = "experimental-public")]
    fn validate_with_context(&self, context: RuntimePlanContext<'_>) -> Result<ValidationReceipt, ControlError> { self.validate(context.config(), context.release(), context.previous()) }
    /// Complete only terminal runtime-journal reconciliation before this
    /// operation enters staging. Default leaves legacy behavior unchanged.
    #[cfg(feature = "experimental-public")]
    fn reconcile_before_stage(&self, _: RuntimePreStageContext<'_>) -> Result<(), ControlError> { Ok(()) }
    /// Cancel only this operation's staged runtime under the existing writer.
    #[cfg(feature = "experimental-public")]
    fn discard_with_context(&self, context: RuntimeCleanupContext<'_>) -> Result<(), ControlError> { self.discard_stage(context.operation()) }
    fn activate_with_context(
        &self,
        context: RuntimeActivationContext<'_>,
    ) -> Result<RuntimeActivation, ControlError> {
        if context.requires_tls_materials() {
            return Err(ControlError::ExecutorUnavailable);
        }
        self.activate(context.operation(), context.plan(), context.previous())
    }
    fn restore_previous_with_context(
        &self,
        context: RuntimeRestoreContext<'_>,
    ) -> Result<(), ControlError> {
        if context.requires_tls_materials() {
            return Err(ControlError::ExecutorUnavailable);
        }
        self.restore_previous(context.operation(), context.previous())
    }

    /// Called under the existing global writer. A TLS executor must explicitly
    /// implement this method; the legacy path cannot silently ignore admission.
    fn stage_with_context(&self, context: RuntimeStageContext<'_>) -> Result<(), ControlError> {
        if context.requires_tls_materials() {
            return Err(ControlError::ExecutorUnavailable);
        }
        self.stage(context.operation(), context.plan(), context.cancellation())
    }

    /// Fresh read-only observation of this exact committed configuration and
    /// owned generation. Must not launch/reconcile or promote persisted health.
    /// Default remains unavailable for adapters without genuine active probes.
    fn observe_committed(&self, _: &RevisionRecord) -> Result<RuntimeHealth, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }

    /// Pure compile/adapter validation. Must validate exact pinned release,
    /// capabilities, secret references, certificate match and change semantics.
    fn validate(
        &self,
        config: &ProductConfig,
        release: &ReleaseIdentity,
        previous: Option<&RevisionRecord>,
    ) -> Result<ValidationReceipt, ControlError>;
    fn stage(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
        cancel: &CancellationToken,
    ) -> Result<(), ControlError>;
    /// Controlled restart by default, not upstream router-only reload.
    fn activate(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
        previous: Option<&RevisionRecord>,
    ) -> Result<RuntimeActivation, ControlError>;
    /// Must observe the real process/listeners/authentication and match generation.
    #[cfg(feature = "experimental-public")]
    fn verify_with_context(&self, context: RuntimeVerificationContext<'_>) -> Result<RuntimeHealth, ControlError> { self.verify(context.operation(), context.plan()) }
    fn verify(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
    ) -> Result<RuntimeHealth, ControlError>;
    /// Stop only this operation's candidate generation. A retry after restoring
    /// the previous generation must never stop that previous/other generation.
    #[cfg(feature = "experimental-public")]
    fn stop_candidate_with_context(&self, context: RuntimeRestoreContext<'_>) -> Result<(), ControlError> { self.stop_candidate(context.operation(), context.plan()) }
    fn stop_candidate(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
    ) -> Result<(), ControlError>;
    /// None restores the pre-install stopped state, not an invented ready worker.
    fn restore_previous(
        &self,
        operation: &OperationId,
        previous: Option<&RevisionRecord>,
    ) -> Result<(), ControlError>;
    /// Independently verify old runtime (or absence) before rollback is complete.
    fn verify_previous(
        &self,
        operation: &OperationId,
        previous: Option<&RevisionRecord>,
    ) -> Result<(), ControlError>;
    fn discard_stage(&self, operation: &OperationId) -> Result<(), ControlError>;
}

pub trait SystemExecutor: Send + Sync {
    /// Read-only. Exactly one observation per requested resource, including absent ones.
    fn inspect(
        &self,
        resources: &[ResourceChange],
    ) -> Result<Vec<ResourceObservation>, ControlError>;
    fn capture(
        &self,
        operation: &OperationId,
        resources: &[ResourceChange],
    ) -> Result<ResourceSnapshot, ControlError>;
    /// Helper must independently verify authorization, immutable plan hash,
    /// freshness, resource ownership and compare-before-write, not trust a daemon.
    fn apply(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
        snapshot: &ResourceSnapshot,
    ) -> Result<(), ControlError>;
    /// Compare-and-restore only VP-owned resources. External drift is an error.
    fn restore(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
        snapshot: &ResourceSnapshot,
    ) -> Result<(), ControlError>;
}

/// Production composition must replace these with real adapters. They cannot
/// turn empty/missing evidence into an applied or healthy result.
pub struct UnavailableRuntime;
impl RuntimeExecutor for UnavailableRuntime {
    fn validate(
        &self,
        _: &ProductConfig,
        _: &ReleaseIdentity,
        _: Option<&RevisionRecord>,
    ) -> Result<ValidationReceipt, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn stage(
        &self,
        _: &OperationId,
        _: &ChangePlan,
        _: &CancellationToken,
    ) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn activate(
        &self,
        _: &OperationId,
        _: &ChangePlan,
        _: Option<&RevisionRecord>,
    ) -> Result<RuntimeActivation, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn verify(&self, _: &OperationId, _: &ChangePlan) -> Result<RuntimeHealth, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn stop_candidate(&self, _: &OperationId, _: &ChangePlan) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn restore_previous(
        &self,
        _: &OperationId,
        _: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn verify_previous(
        &self,
        _: &OperationId,
        _: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn discard_stage(&self, _: &OperationId) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
}
pub struct UnavailableSystem;
impl SystemExecutor for UnavailableSystem {
    fn inspect(&self, _: &[ResourceChange]) -> Result<Vec<ResourceObservation>, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn capture(
        &self,
        _: &OperationId,
        _: &[ResourceChange],
    ) -> Result<ResourceSnapshot, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn apply(
        &self,
        _: &OperationId,
        _: &ChangePlan,
        _: &ResourceSnapshot,
    ) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn restore(
        &self,
        _: &OperationId,
        _: &ChangePlan,
        _: &ResourceSnapshot,
    ) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
}
