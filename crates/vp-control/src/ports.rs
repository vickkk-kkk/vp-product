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
    fn state(&self) -> &StoredState;
    fn persist(&mut self, next: StoredState, event: JournalEvent) -> Result<(), ControlError>;
}
pub trait ControlStore: Send + Sync {
    fn read(&self) -> Result<StoredState, ControlError>;
    fn writer(&self) -> Result<Box<dyn WriterLease + '_>, ControlError>;
}

/// Every mutating method must be idempotent by operation ID. Before returning
/// stage/capture success, referenced recovery material must be durable. No
/// arbitrary executable/path/URL is accepted by this interface. Secret material
/// may only be resolved inside the protected executor/vault boundary.
/// Vault references must be immutable/versioned: rotation creates a new reference,
/// and validation refuses mutable references. Every executor call must have an
/// implementation-level deadline; no method may wait forever while holding the writer.
pub trait RuntimeExecutor: Send + Sync {
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
    fn verify(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
    ) -> Result<RuntimeHealth, ControlError>;
    /// Stop only this operation's candidate generation. A retry after restoring
    /// the previous generation must never stop that previous/other generation.
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
