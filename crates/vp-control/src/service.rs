use crate::*;
use std::{collections::BTreeSet, sync::Arc};
use vp_product_domain::{
    ListenerUser, OperationId, PlanId, ProductConfig, Revision, ServerProtocol, ServerSecurity,
    UserId,
};

const METHOD: &str = "plans.apply.v1";
const MAX_TTL_MS: u64 = 15 * 60 * 1000;
const MAX_HEALTH_AGE_MS: u64 = 30_000;
const OWNER: &str = "vp-product";

pub struct ControlService {
    pub(crate) store: Arc<dyn ControlStore>,
    pub(crate) runtime: Arc<dyn RuntimeExecutor>,
    pub(crate) system: Arc<dyn SystemExecutor>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) secret_manager: Arc<dyn SecretManager>,
}
impl ControlService {
    pub fn new(
        store: Arc<dyn ControlStore>,
        runtime: Arc<dyn RuntimeExecutor>,
        system: Arc<dyn SystemExecutor>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            runtime,
            system,
            clock,
            secret_manager: Arc::new(UnavailableSecretManager),
        }
    }

    pub fn with_secret_manager(mut self, manager: Arc<dyn SecretManager>) -> Self {
        self.secret_manager = manager;
        self
    }

    /// No runtime/system mutation. Validation and read-only resource inspection
    /// must succeed before an immutable plan is saved.
    pub fn plan(&self, request: PlanRequest) -> Result<ChangePlan, ControlError> {
        let mut lease = self.store.writer()?;
        self.plan_locked(request, &mut *lease)
    }

    pub(crate) fn plan_locked(
        &self,
        request: PlanRequest,
        lease: &mut dyn WriterLease,
    ) -> Result<ChangePlan, ControlError> {
        request
            .config
            .validate()
            .map_err(|_| ControlError::InvalidConfiguration)?;
        request
            .release
            .validate()
            .map_err(|_| ControlError::InvalidConfiguration)?;
        if request.ttl_ms == 0 || request.ttl_ms > MAX_TTL_MS {
            return Err(ControlError::InvalidRequest);
        }
        validate_resources(&request.resources)?;
        lease.state().verify_integrity()?;
        if lease.state().needs_recovery() {
            return Err(ControlError::RecoveryRequired);
        }
        check_revision(request.expected_revision, lease.state().active_revision)?;
        #[cfg(feature = "experimental-public")]
        let validation = self.runtime.validate_with_context(RuntimePlanContext::new(&*lease, &request, &*self.clock))?;
        #[cfg(not(feature = "experimental-public"))]
        let validation = self.runtime.validate(&request.config, &request.release, lease.state().active())?;
        if validation.config_digest != ContentDigest::of("vp.product-config.v1", &request.config)?
            || validation.release_digest
                != ContentDigest::of("vp.release-identity.v1", &request.release)?
        {
            return Err(ControlError::InvalidConfiguration);
        }
        validate_health_requirements(&request, &validation, lease.state().active())?;
        check_observations(
            &request.resources,
            &self.system.inspect(&request.resources)?,
            ObservationMode::Before,
        )?;
        let now = self.clock.now_ms()?;
        let mut next = lease.state().clone();
        let id = PlanId::new(format!("plan-{}", take_id(&mut next)?))
            .map_err(|_| ControlError::CounterExhausted)?;
        let plan = ChangePlan::seal(PlanBody {
            schema_version: 1,
            id: id.clone(),
            principal: request.principal,
            base_revision: request.expected_revision,
            target_revision: request
                .expected_revision
                .next()
                .ok_or(ControlError::CounterExhausted)?,
            created_at_ms: now,
            expires_at_ms: now
                .checked_add(request.ttl_ms)
                .ok_or(ControlError::CounterExhausted)?,
            config: request.config,
            release: request.release,
            validation,
            resources: request.resources,
        })?;
        next.plans.insert(id, plan.clone());
        checkpoint(lease, next, now, None, None)?;
        Ok(plan)
    }

    /// Persists a queued operation before returning. An API can return 202 and
    /// enqueue `run` in its owned worker. Request/connection lifetime is irrelevant.
    /// Authn/RBAC/CSRF belong to the API; principal must come from a verified session.
    pub fn submit(&self, request: ApplyRequest) -> Result<Operation, ControlError> {
        let mut lease = self.store.writer()?;
        lease.state().verify_integrity()?;
        let request_digest = ContentDigest::of("vp.apply-request.v1", &request)?;
        if let Some(prior) = lease.state().idempotency.iter().find(|entry| {
            entry.principal == request.principal
                && entry.method == METHOD
                && entry.key == request.idempotency_key
        }) {
            if prior.request_digest != request_digest {
                return Err(ControlError::IdempotencyConflict);
            }
            return lease
                .state()
                .operations
                .get(&prior.operation_id)
                .cloned()
                .ok_or(ControlError::CorruptState);
        }
        if lease.state().needs_recovery() {
            return Err(ControlError::RecoveryRequired);
        }
        let plan = lease
            .state()
            .plans
            .get(&request.plan_id)
            .ok_or(ControlError::NotFound)?;
        plan.verify_integrity()?;
        if plan.body().principal != request.principal {
            return Err(ControlError::PermissionDenied);
        }
        if plan.hash() != &request.confirmed_hash {
            return Err(ControlError::ConfirmationMismatch);
        }
        check_revision(request.expected_revision, plan.body().base_revision)?;
        check_revision(request.expected_revision, lease.state().active_revision)?;
        let now = self.clock.now_ms()?;
        check_fresh(plan, now)?;
        // Applying one plan with another key must not duplicate its side effects.
        if let Some(existing) = lease
            .state()
            .operations
            .values()
            .find(|op| op.plan_id == request.plan_id)
        {
            let existing = existing.clone();
            let mut next = lease.state().clone();
            next.idempotency.push(IdempotencyRecord {
                principal: request.principal,
                method: METHOD.into(),
                key: request.idempotency_key,
                request_digest,
                operation_id: existing.id.clone(),
            });
            checkpoint(&mut *lease, next, now, None, None)?;
            return Ok(existing);
        }
        let mut next = lease.state().clone();
        let id = OperationId::new(format!("operation-{}", take_id(&mut next)?))
            .map_err(|_| ControlError::CounterExhausted)?;
        let operation = Operation {
            id: id.clone(),
            plan_id: request.plan_id,
            principal: request.principal.clone(),
            state: OperationState::Queued,
            created_at_ms: now,
            updated_at_ms: now,
            snapshot: None,
            failure: None,
            health: None,
            activation: None,
            cancel_requested: false,
            mutation_started: false,
        };
        next.idempotency.push(IdempotencyRecord {
            principal: request.principal,
            method: METHOD.into(),
            key: request.idempotency_key,
            request_digest,
            operation_id: id.clone(),
        });
        next.operations.insert(id.clone(), operation.clone());
        checkpoint(
            &mut *lease,
            next,
            now,
            Some(id),
            Some(OperationState::Queued),
        )?;
        Ok(operation)
    }

    /// Runs under the global writer lease. A caller-owned token allows prompt
    /// cancellation while stage/capture are executing, without a second writer.
    /// After ApplyingResources, cancellation is too late; finish or compensate.
    pub fn run(
        &self,
        id: &OperationId,
        cancel: &CancellationToken,
    ) -> Result<Operation, ControlError> {
        let mut lease = self.store.writer()?;
        lease.state().verify_integrity()?;
        let op = lease
            .state()
            .operations
            .get(id)
            .cloned()
            .ok_or(ControlError::NotFound)?;
        if op.state.is_terminal() {
            return Ok(op);
        }
        if op.state != OperationState::Queued || lease.state().needs_recovery() {
            return Err(ControlError::RecoveryRequired);
        }
        let plan = lease
            .state()
            .plans
            .get(&op.plan_id)
            .cloned()
            .ok_or(ControlError::CorruptState)?;
        let previous = lease.state().active().cloned();
        let now = self.clock.now_ms()?;
        let preflight = check_revision(plan.body().base_revision, lease.state().active_revision)
            .and_then(|_| check_fresh(&plan, now))
            .and_then(|_| {
                check_observations(
                    &plan.body().resources,
                    &self.system.inspect(&plan.body().resources)?,
                    ObservationMode::Before,
                )
            });
        if let Err(error) = preflight {
            return self.finish(&mut *lease, id, OperationState::Failed, Some(error));
        }
        if cancel.is_canceled() || op.cancel_requested {
            return self.finish(
                &mut *lease,
                id,
                OperationState::Canceled,
                Some(ControlError::Canceled),
            );
        }
        #[cfg(feature = "experimental-public")]
        if let Err(error) = RuntimePreStageContext::from_queued(&*lease, id, &plan)
            .and_then(|context| self.runtime.reconcile_before_stage(context)) {
            return self.finish(&mut *lease, id, OperationState::RecoveryRequired, Some(error));
        }
        self.transition(&mut *lease, id, OperationState::Staging, None)?;
        let staged = RuntimeStageContext::from_staging(&*lease, id, &plan, &*self.clock, cancel)
            .and_then(|context| self.runtime.stage_with_context(context));
        if let Err(error) = staged {
            return self.cleanup_staging(&mut *lease, id, error);
        }
        if cancel.is_canceled() {
            return self.cleanup_staging(&mut *lease, id, ControlError::Canceled);
        }
        self.transition(&mut *lease, id, OperationState::Snapshotting, None)?;
        let snapshot = match self.system.capture(id, &plan.body().resources) {
            Ok(snapshot) => snapshot,
            Err(error) => return self.cleanup_staging(&mut *lease, id, error),
        };
        if validate_resource_id(&snapshot.id).is_err()
            || check_observations(
                &plan.body().resources,
                &snapshot.resources,
                ObservationMode::Before,
            )
            .is_err()
        {
            return self.cleanup_staging(&mut *lease, id, ControlError::ResourceConflict);
        }
        let mut next = lease.state().clone();
        next.operations
            .get_mut(id)
            .ok_or(ControlError::CorruptState)?
            .snapshot = Some(snapshot.clone());
        checkpoint(
            &mut *lease,
            next,
            self.clock.now_ms()?,
            Some(id.clone()),
            Some(OperationState::Snapshotting),
        )?;
        if cancel.is_canceled() {
            return self.cleanup_staging(&mut *lease, id, ControlError::Canceled);
        }
        // Confirmation freshness is checked again immediately before the first
        // host mutation. The helper also checks at its own privilege boundary.
        if let Err(error) = check_fresh(&plan, self.clock.now_ms()?) {
            return self.cleanup_staging(&mut *lease, id, error);
        }
        self.transition(&mut *lease, id, OperationState::ApplyingResources, None)?;
        if let Err(error) = self.system.apply(id, &plan, &snapshot) {
            return self.rollback(&mut *lease, id, &plan, previous.as_ref(), error);
        }
        self.transition(&mut *lease, id, OperationState::Activating, None)?;
        let activation = match RuntimeActivationContext::from_activating(
            &*lease,
            id,
            &plan,
            previous.as_ref(),
            &*self.clock,
            cancel,
        )
        .and_then(|context| self.runtime.activate_with_context(context))
        .and_then(|activation| {
            if activation.operation_id != *id
                || activation.revision != plan.body().target_revision
                || activation.generation == 0
                || activation.config_digest != plan.body().validation.config_digest
                || activation.release_digest != plan.body().validation.release_digest
            {
                return Err(ControlError::HealthFailed);
            }
            Ok(activation)
        }) {
            Ok(activation) => activation,
            Err(error) => return self.rollback(&mut *lease, id, &plan, previous.as_ref(), error),
        };
        let mut next = lease.state().clone();
        next.operations
            .get_mut(id)
            .ok_or(ControlError::CorruptState)?
            .activation = Some(activation.clone());
        checkpoint(
            &mut *lease,
            next,
            self.clock.now_ms()?,
            Some(id.clone()),
            Some(OperationState::Activating),
        )?;
        self.transition(&mut *lease, id, OperationState::Verifying, None)?;
        #[cfg(feature = "experimental-public")]
        let observed_health = RuntimeVerificationContext::from_verifying(&*lease, id, &plan, &*self.clock, cancel)
            .and_then(|context| self.runtime.verify_with_context(context));
        #[cfg(not(feature = "experimental-public"))]
        let observed_health = self.runtime.verify(id, &plan);
        let health = match observed_health.and_then(|health| {
            verify_health(&plan, id, &activation, &health, self.clock.now_ms()?)?;
            check_observations(
                &plan.body().resources,
                &self.system.inspect(&plan.body().resources)?,
                ObservationMode::After,
            )?;
            Ok(health)
        }) {
            Ok(health) => health,
            Err(error) => return self.rollback(&mut *lease, id, &plan, previous.as_ref(), error),
        };
        // No applied/active revision changes before all exact-generation checks pass.
        self.transition(&mut *lease, id, OperationState::Committing, None)?;
        let mut next = lease.state().clone();
        check_revision(plan.body().base_revision, next.active_revision)?;
        next.revisions.push(RevisionRecord {
            revision: plan.body().target_revision,
            config: plan.body().config.clone(),
            release: plan.body().release.clone(),
            config_digest: plan.body().validation.config_digest.clone(),
            release_digest: plan.body().validation.release_digest.clone(),
            artifact_digest: plan.body().validation.artifact_digest.clone(),
            operation_id: id.clone(),
        });
        next.active_revision = plan.body().target_revision;
        let op = next
            .operations
            .get_mut(id)
            .ok_or(ControlError::CorruptState)?;
        op.state = OperationState::Committed;
        op.health = Some(health);
        op.updated_at_ms = self.clock.now_ms()?;
        let result = op.clone();
        // Revision + operation + idempotency result become durable atomically.
        checkpoint(
            &mut *lease,
            next,
            self.clock.now_ms()?,
            Some(id.clone()),
            Some(OperationState::Committed),
        )?;
        Ok(result)
    }

    /// Only queued work can be canceled by another durable control command.
    /// In-flight requests use the run token and receive current can_cancel state.
    pub fn cancel_queued(
        &self,
        id: &OperationId,
        principal: &UserId,
    ) -> Result<Operation, ControlError> {
        let mut lease = self.store.writer()?;
        let op = lease
            .state()
            .operations
            .get(id)
            .cloned()
            .ok_or(ControlError::NotFound)?;
        if &op.principal != principal {
            return Err(ControlError::PermissionDenied);
        }
        if op.state == OperationState::Canceled {
            return Ok(op);
        }
        if op.state != OperationState::Queued {
            return Err(ControlError::CannotCancel);
        }
        self.finish(
            &mut *lease,
            id,
            OperationState::Canceled,
            Some(ControlError::Canceled),
        )
    }

    /// Startup recovery is conservative: unfinished operations never auto-commit
    /// from stale health. Queued operations are canceled (confirmation does not
    /// authorize executing unexpectedly after a daemon restart); staged work is
    /// discarded; a crossed mutation boundary restores the full old combination.
    /// RecoveryRequired stays nonterminal and blocks new plans/applies until a
    /// later explicitly invoked recovery succeeds. No unbounded internal retry.
    pub fn recover(&self) -> Result<Vec<Operation>, ControlError> {
        let mut lease = self.store.writer()?;
        lease.state().verify_integrity()?;
        self.recover_secret_intents(&mut *lease)?;
        let pending: Vec<_> = lease
            .state()
            .operations
            .values()
            .filter(|op| !op.state.is_terminal())
            .cloned()
            .collect();
        let mut results = Vec::new();
        for op in pending {
            let plan = lease
                .state()
                .plans
                .get(&op.plan_id)
                .cloned()
                .ok_or(ControlError::CorruptState)?;
            if op.state == OperationState::Queued {
                results.push(self.finish(
                    &mut *lease,
                    &op.id,
                    OperationState::Canceled,
                    Some(ControlError::Canceled),
                )?);
                continue;
            }
            if lease.state().active_revision != plan.body().base_revision {
                // A committed revision with nonterminal operation is forbidden by
                // the store's atomic contract: do not guess which half is true.
                results.push(self.finish(
                    &mut *lease,
                    &op.id,
                    OperationState::RecoveryRequired,
                    Some(ControlError::CorruptState),
                )?);
                continue;
            }
            let previous = lease
                .state()
                .revisions
                .iter()
                .find(|r| r.revision == plan.body().base_revision)
                .cloned();
            if plan.body().base_revision != Revision::ZERO && previous.is_none() {
                return Err(ControlError::CorruptState);
            }
            let result = match op.state {
                OperationState::RecoveryRequired if !op.mutation_started => {
                    self.cleanup_staging(&mut *lease, &op.id, ControlError::Canceled)?
                }
                OperationState::Queued => self.finish(
                    &mut *lease,
                    &op.id,
                    OperationState::Canceled,
                    Some(ControlError::Canceled),
                )?,
                OperationState::Staging
                | OperationState::Snapshotting
                | OperationState::Canceling => {
                    self.cleanup_staging(&mut *lease, &op.id, ControlError::Canceled)?
                }
                _ => self.rollback(
                    &mut *lease,
                    &op.id,
                    &plan,
                    previous.as_ref(),
                    op.failure.unwrap_or(ControlError::RecoveryRequired),
                )?,
            };
            results.push(result);
        }
        Ok(results)
    }

    pub fn operation(
        &self,
        id: &OperationId,
        principal: &UserId,
    ) -> Result<Operation, ControlError> {
        let state = self.store.read()?;
        let operation = state.operations.get(id).ok_or(ControlError::NotFound)?;
        if &operation.principal != principal {
            return Err(ControlError::PermissionDenied);
        }
        Ok(operation.clone())
    }
    pub fn snapshot(&self, principal: &UserId) -> Result<ControlSnapshot, ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        let desired = state
            .operations
            .values()
            .filter(|op| !op.state.is_terminal())
            .filter_map(|op| {
                state
                    .plans
                    .get(&op.plan_id)
                    .map(|p| p.body().target_revision)
            })
            .max()
            .unwrap_or(state.active_revision);
        Ok(ControlSnapshot {
            active_revision: state.active_revision,
            desired_revision: desired,
            // A separate live runtime observation API must supply observedRevision.
            // Never use a journaled health receipt as current process evidence.
            observed_revision: None,
            // In-flight staging/verifying is progress, not a recovery failure.
            // Composition must run startup recovery before serving requests.
            recovery_required: state
                .operations
                .values()
                .any(|op| op.state == OperationState::RecoveryRequired),
            operations: state
                .operations
                .values()
                .filter(|op| &op.principal == principal)
                .cloned()
                .collect(),
        })
    }

    fn transition(
        &self,
        lease: &mut dyn WriterLease,
        id: &OperationId,
        target: OperationState,
        failure: Option<ControlError>,
    ) -> Result<(), ControlError> {
        let mut next = lease.state().clone();
        let op = next
            .operations
            .get_mut(id)
            .ok_or(ControlError::CorruptState)?;
        if !valid_transition(&op.state, &target) {
            return Err(ControlError::CorruptState);
        }
        op.state = target.clone();
        if target == OperationState::ApplyingResources {
            op.mutation_started = true;
        }
        op.updated_at_ms = self.clock.now_ms()?;
        if failure.is_some() {
            op.failure = failure;
        }
        if target == OperationState::Canceled || target == OperationState::Canceling {
            op.cancel_requested = true;
        }
        checkpoint(
            lease,
            next,
            self.clock.now_ms()?,
            Some(id.clone()),
            Some(target),
        )
    }
    fn finish(
        &self,
        lease: &mut dyn WriterLease,
        id: &OperationId,
        state: OperationState,
        failure: Option<ControlError>,
    ) -> Result<Operation, ControlError> {
        self.transition(lease, id, state, failure)?;
        lease
            .state()
            .operations
            .get(id)
            .cloned()
            .ok_or(ControlError::CorruptState)
    }
    fn cleanup_staging(
        &self,
        lease: &mut dyn WriterLease,
        id: &OperationId,
        error: ControlError,
    ) -> Result<Operation, ControlError> {
        self.transition(lease, id, OperationState::Canceling, Some(error.clone()))?;
        #[cfg(feature = "experimental-public")]
        let discarded = RuntimeCleanupContext::from_canceling(&*lease, id)
            .and_then(|context| self.runtime.discard_with_context(context));
        #[cfg(not(feature = "experimental-public"))]
        let discarded = self.runtime.discard_stage(id);
        if discarded.is_err() {
            return self.finish(
                lease,
                id,
                OperationState::RecoveryRequired,
                Some(ControlError::ExecutorFailed),
            );
        }
        let target = if error == ControlError::Canceled {
            OperationState::Canceled
        } else {
            OperationState::Failed
        };
        self.finish(lease, id, target, Some(error))
    }
    fn rollback(
        &self,
        lease: &mut dyn WriterLease,
        id: &OperationId,
        plan: &ChangePlan,
        previous: Option<&RevisionRecord>,
        cause: ControlError,
    ) -> Result<Operation, ControlError> {
        self.transition(lease, id, OperationState::RollingBack, Some(cause.clone()))?;
        let snapshot = lease
            .state()
            .operations
            .get(id)
            .and_then(|op| op.snapshot.clone());
        let result = (|| {
            let snapshot = snapshot.ok_or(ControlError::CorruptState)?;
            // Stop the new runtime before reversing host resources. If external
            // drift occurred, stop here; do not restore unrelated machine state.
            #[cfg(feature = "experimental-public")]
            {
                let context = RuntimeRestoreContext::from_rolling_back(&*lease, id, plan, previous, &*self.clock)?;
                self.runtime.stop_candidate_with_context(context)?;
            }
            #[cfg(not(feature = "experimental-public"))]
            self.runtime.stop_candidate(id, plan)?;
            check_observations(
                &plan.body().resources,
                &self.system.inspect(&plan.body().resources)?,
                ObservationMode::Recoverable,
            )?;
            self.system.restore(id, plan, &snapshot)?;
            check_observations(
                &plan.body().resources,
                &self.system.inspect(&plan.body().resources)?,
                ObservationMode::Before,
            )?;
            let context = RuntimeRestoreContext::from_rolling_back(
                &*lease,
                id,
                plan,
                previous,
                &*self.clock,
            )?;
            self.runtime.restore_previous_with_context(context)?;
            self.runtime.verify_previous(id, previous)?;
            self.runtime.discard_stage(id)?;
            Ok::<(), ControlError>(())
        })();
        match result {
            Ok(()) => self.finish(lease, id, OperationState::RolledBack, Some(cause)),
            Err(error) => self.finish(lease, id, OperationState::RecoveryRequired, Some(error)),
        }
    }
}

pub(crate) fn checkpoint(
    lease: &mut dyn WriterLease,
    mut next: StoredState,
    now: u64,
    operation: Option<OperationId>,
    state: Option<OperationState>,
) -> Result<(), ControlError> {
    next.version = lease
        .state()
        .version
        .checked_add(1)
        .ok_or(ControlError::CounterExhausted)?;
    let event = JournalEvent {
        security: None,
        sequence: next.version,
        at_ms: now,
        operation_id: operation,
        state,
    };
    lease.persist(next, event)
}
pub(crate) fn take_id(state: &mut StoredState) -> Result<u64, ControlError> {
    let id = state.next_id;
    state.next_id = state
        .next_id
        .checked_add(1)
        .ok_or(ControlError::CounterExhausted)?;
    Ok(id)
}
pub(crate) fn check_revision(expected: Revision, actual: Revision) -> Result<(), ControlError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ControlError::RevisionConflict { expected, actual })
    }
}
fn check_fresh(plan: &ChangePlan, now: u64) -> Result<(), ControlError> {
    if now < plan.body().created_at_ms || now >= plan.body().expires_at_ms {
        Err(ControlError::PlanExpired)
    } else {
        Ok(())
    }
}
fn validate_resource_id(id: &str) -> Result<(), ControlError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        Err(ControlError::InvalidRequest)
    } else {
        Ok(())
    }
}
fn validate_resources(resources: &[ResourceChange]) -> Result<(), ControlError> {
    let mut ids = BTreeSet::new();
    if resources.len() > 1024 {
        return Err(ControlError::InvalidRequest);
    }
    for change in resources {
        validate_resource_id(&change.id)?;
        if !ids.insert(&change.id) || change.expected == change.desired {
            return Err(ControlError::InvalidRequest);
        }
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum ObservationMode {
    Before,
    After,
    Recoverable,
}
fn check_observations(
    changes: &[ResourceChange],
    observations: &[ResourceObservation],
    mode: ObservationMode,
) -> Result<(), ControlError> {
    if observations.len() != changes.len() {
        return Err(ControlError::ResourceConflict);
    }
    let mut seen = BTreeSet::new();
    for observation in observations {
        if !seen.insert(&observation.id) {
            return Err(ControlError::ResourceConflict);
        }
        let change = changes
            .iter()
            .find(|r| r.id == observation.id)
            .ok_or(ControlError::ResourceConflict)?;
        let valid_owner = match (&observation.fingerprint, &observation.owner) {
            (None, None) => true,
            (Some(_), Some(owner)) => owner == OWNER,
            _ => false,
        };
        let valid_value = match mode {
            ObservationMode::Before => observation.fingerprint == change.expected,
            ObservationMode::After => observation.fingerprint == change.desired,
            ObservationMode::Recoverable => {
                observation.fingerprint == change.expected
                    || observation.fingerprint == change.desired
            }
        };
        if !valid_owner || !valid_value {
            return Err(ControlError::ResourceConflict);
        }
    }
    Ok(())
}
pub(crate) fn validate_health_requirements(
    request: &PlanRequest,
    receipt: &ValidationReceipt,
    previous: Option<&RevisionRecord>,
) -> Result<(), ControlError> {
    for check in &receipt.required_health {
        match check {
            HealthCheck::Process => (),
            HealthCheck::ListenerBound(id)
            | HealthCheck::SecurityIdentity(id)
            | HealthCheck::InvalidAuthenticationRejected(id)
            | HealthCheck::RetiredListenerReleased(id)
            | HealthCheck::Forwarding(id)
            | HealthCheck::Dns(id) => validate_resource_id(id)?,
            HealthCheck::AuthenticationAccepted(probe)
            | HealthCheck::RetiredAuthenticationRejected(probe) => {
                validate_resource_id(&probe.listener_id)?;
                validate_resource_id(&probe.user_id)?;
            }
        }
    }
    if previous.is_some_and(|p| p.config.listeners != request.config.listeners)
        && receipt.impact != RestartImpact::ControlledRestart
    {
        return Err(ControlError::InvalidConfiguration);
    }
    if !request.resources.is_empty() && receipt.impact != RestartImpact::ControlledRestart {
        return Err(ControlError::InvalidConfiguration);
    }
    let required = minimum_health_checks(&request.config, previous)?;
    if !required.is_subset(&receipt.required_health) {
        return Err(ControlError::InvalidConfiguration);
    }
    Ok(())
}

/// Pure minimum probe requirements shared with real validator adapters. A probe
/// target must be explicitly approved; inability to run required checks blocks
/// applying the plan rather than silently dropping the forwarding/auth oracle.
pub fn minimum_health_checks(
    config: &ProductConfig,
    previous: Option<&RevisionRecord>,
) -> Result<BTreeSet<HealthCheck>, ControlError> {
    let mut required = BTreeSet::from([HealthCheck::Process]);
    for listener in config.listeners.iter().filter(|l| l.enabled) {
        let id = listener.id.as_str().to_owned();
        required.insert(HealthCheck::ListenerBound(id.clone()));
        required.insert(HealthCheck::Forwarding(id.clone()));
        if !matches!(&listener.security, ServerSecurity::None {}) {
            required.insert(HealthCheck::SecurityIdentity(id.clone()));
        }
        // Direct has no credential oracle, and must demonstrate forwarding to an
        // explicitly approved target. Proxy listeners must test both auth paths.
        if let ServerProtocol::Proxy { users, .. } = &listener.protocol {
            for user in users.iter().filter(|u| u.enabled) {
                required.insert(HealthCheck::AuthenticationAccepted(auth_probe(&id, user)?));
            }
            required.insert(HealthCheck::InvalidAuthenticationRejected(id));
        } else {
            required.insert(HealthCheck::Forwarding(id));
        }
    }
    if let Some(previous) = previous {
        for old in previous.config.listeners.iter().filter(|l| l.enabled) {
            let new = config
                .listeners
                .iter()
                .find(|l| l.id == old.id && l.enabled);
            if new.map(|l| &l.bind) != Some(&old.bind) {
                required.insert(HealthCheck::RetiredListenerReleased(
                    old.id.as_str().to_owned(),
                ));
            }
            if let ServerProtocol::Proxy {
                users: old_users, ..
            } = &old.protocol
            {
                let retained_users = match new.map(|l| &l.protocol) {
                    Some(ServerProtocol::Proxy { users, .. }) => users.as_slice(),
                    _ => &[],
                };
                for user in old_users.iter().filter(|u| u.enabled) {
                    // A password may intentionally remain valid for another
                    // enabled user. Reorder/rename/add-user must not demand
                    // rejection of credentials that the new plan still allows.
                    if !retained_users
                        .iter()
                        .any(|u| u.enabled && u.credential_ref == user.credential_ref)
                    {
                        required.insert(HealthCheck::RetiredAuthenticationRejected(auth_probe(
                            old.id.as_str(),
                            user,
                        )?));
                    }
                }
            }
        }
    }
    Ok(required)
}
fn auth_probe(listener: &str, user: &ListenerUser) -> Result<AuthenticationProbe, ControlError> {
    Ok(AuthenticationProbe {
        listener_id: listener.to_owned(),
        user_id: user.id.as_str().to_owned(),
        credential_ref_digest: ContentDigest::of(
            "vp.credential-reference.v1",
            &user.credential_ref,
        )?,
    })
}
fn verify_health(
    plan: &ChangePlan,
    id: &OperationId,
    activation: &RuntimeActivation,
    health: &RuntimeHealth,
    now: u64,
) -> Result<(), ControlError> {
    if &health.operation_id != id
        || health.revision != plan.body().target_revision
        || health.config_digest != plan.body().validation.config_digest
        || health.release_digest != plan.body().validation.release_digest
        || health.generation != activation.generation
        || health.checked_at_ms > now
        || now - health.checked_at_ms > MAX_HEALTH_AGE_MS
    {
        return Err(ControlError::HealthFailed);
    }
    let mut seen = BTreeSet::new();
    for result in &health.checks {
        if !seen.insert(&result.check)
            || !plan
                .body()
                .validation
                .required_health
                .contains(&result.check)
        {
            return Err(ControlError::HealthFailed);
        }
    }
    for required in &plan.body().validation.required_health {
        if !health
            .checks
            .iter()
            .any(|r| &r.check == required && r.outcome == CheckOutcome::Passed)
        {
            return Err(ControlError::HealthFailed);
        }
    }
    Ok(())
}
fn valid_transition(from: &OperationState, to: &OperationState) -> bool {
    use OperationState::*;
    match (from, to) {
        (Queued, Staging | Canceled | Failed)
        | (Staging, Snapshotting | Canceling)
        | (Snapshotting, ApplyingResources | Canceling)
        | (ApplyingResources, Activating | RollingBack)
        | (Activating, Verifying | RollingBack)
        | (Verifying, Committing | RollingBack)
        | (Committing, Committed | RollingBack)
        | (Canceling, Canceled | Failed | RecoveryRequired)
        | (RollingBack, RolledBack | RecoveryRequired)
        | (RecoveryRequired, RollingBack | Canceling | RecoveryRequired) => true,
        // Recovery may revisit an idempotent compensating action after a crash.
        (RollingBack, RollingBack) | (Canceling, Canceling) => true,
        (_, RecoveryRequired) if !from.is_terminal() => true,
        _ => false,
    }
}
