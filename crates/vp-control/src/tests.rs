#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Unit-test executors are deliberately local to cfg(test). Their invented
//! observations exercise orchestration only, not protocol/runtime acceptance.
use super::*;
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
};
use vp_product_domain::{
    CompatibilityRange, IdempotencyKey, OperationId, ProductConfig, ReleaseId, ReleaseIdentity,
    Revision, UserId, VersionPair,
};

#[derive(Default)]
struct MemoryStore {
    writer: Mutex<()>,
    state: Mutex<StoredState>,
    journal: Mutex<Vec<JournalEvent>>,
}
impl MemoryStore {
    fn recovered(state: StoredState) -> Self {
        Self {
            writer: Mutex::new(()),
            state: Mutex::new(state),
            journal: Mutex::new(Vec::new()),
        }
    }
}
struct MemoryWriter<'a> {
    store: &'a MemoryStore,
    _guard: MutexGuard<'a, ()>,
    state: StoredState,
}
impl ControlStore for MemoryStore {
    fn read(&self) -> Result<StoredState, ControlError> {
        Ok(self.state.lock().unwrap().clone())
    }
    fn writer(&self) -> Result<Box<dyn WriterLease + '_>, ControlError> {
        let guard = self.writer.lock().unwrap();
        let state = self.read()?;
        Ok(Box::new(MemoryWriter {
            store: self,
            _guard: guard,
            state,
        }))
    }
}
impl WriterLease for MemoryWriter<'_> {
    fn state(&self) -> &StoredState {
        &self.state
    }
    fn persist(&mut self, next: StoredState, event: JournalEvent) -> Result<(), ControlError> {
        next.verify_integrity()?;
        assert_eq!(next.version, self.state.version + 1);
        assert_eq!(event.sequence, next.version);
        *self.store.state.lock().unwrap() = next.clone();
        self.store.journal.lock().unwrap().push(event);
        self.state = next;
        Ok(())
    }
}
struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now_ms(&self) -> Result<u64, ControlError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
struct TestRuntime {
    stages: AtomicUsize,
    activations: AtomicUsize,
    restores: AtomicUsize,
    fail_health: AtomicBool,
    fail_restore: AtomicBool,
    panic_activate: AtomicBool,
    wrong_generation: AtomicBool,
    stage_cancel: Mutex<Option<CancellationToken>>,
    activate_cancel: Mutex<Option<CancellationToken>>,
}
impl Default for TestRuntime {
    fn default() -> Self {
        Self {
            stages: AtomicUsize::new(0),
            activations: AtomicUsize::new(0),
            restores: AtomicUsize::new(0),
            fail_health: AtomicBool::new(false),
            fail_restore: AtomicBool::new(false),
            panic_activate: AtomicBool::new(false),
            wrong_generation: AtomicBool::new(false),
            stage_cancel: Mutex::new(None),
            activate_cancel: Mutex::new(None),
        }
    }
}
impl RuntimeExecutor for TestRuntime {
    fn validate(
        &self,
        config: &ProductConfig,
        release: &ReleaseIdentity,
        _: Option<&RevisionRecord>,
    ) -> Result<ValidationReceipt, ControlError> {
        Ok(ValidationReceipt {
            config_digest: ContentDigest::of("vp.product-config.v1", config)?,
            release_digest: ContentDigest::of("vp.release-identity.v1", release)?,
            artifact_digest: ContentDigest::bytes(b"test-only-compiled-reference"),
            impact: RestartImpact::ControlledRestart,
            required_health: BTreeSet::from([HealthCheck::Process]),
        })
    }
    fn stage(
        &self,
        _: &OperationId,
        _: &ChangePlan,
        _: &CancellationToken,
    ) -> Result<(), ControlError> {
        self.stages.fetch_add(1, Ordering::SeqCst);
        if let Some(token) = &*self.stage_cancel.lock().unwrap() {
            token.cancel();
        }
        Ok(())
    }
    fn activate(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
        _: Option<&RevisionRecord>,
    ) -> Result<RuntimeActivation, ControlError> {
        self.activations.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.panic_activate.load(Ordering::SeqCst),
            "test-only simulated process crash"
        );
        if let Some(token) = &*self.activate_cancel.lock().unwrap() {
            token.cancel();
        }
        Ok(RuntimeActivation {
            operation_id: operation.clone(),
            revision: plan.body().target_revision,
            config_digest: plan.body().validation.config_digest.clone(),
            release_digest: plan.body().validation.release_digest.clone(),
            generation: 1,
        })
    }
    fn verify(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
    ) -> Result<RuntimeHealth, ControlError> {
        Ok(RuntimeHealth {
            revision: plan.body().target_revision,
            operation_id: operation.clone(),
            config_digest: plan.body().validation.config_digest.clone(),
            release_digest: plan.body().validation.release_digest.clone(),
            generation: if self.wrong_generation.load(Ordering::SeqCst) {
                0
            } else {
                1
            },
            checked_at_ms: 1000,
            checks: vec![CheckResult {
                check: HealthCheck::Process,
                outcome: if self.fail_health.load(Ordering::SeqCst) {
                    CheckOutcome::Failed
                } else {
                    CheckOutcome::Passed
                },
            }],
            external_connectivity: CheckOutcome::NotChecked,
        })
    }
    fn stop_candidate(&self, _: &OperationId, _: &ChangePlan) -> Result<(), ControlError> {
        Ok(())
    }
    fn restore_previous(
        &self,
        _: &OperationId,
        _: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        self.restores.fetch_add(1, Ordering::SeqCst);
        if self.fail_restore.load(Ordering::SeqCst) {
            Err(ControlError::ExecutorFailed)
        } else {
            Ok(())
        }
    }
    fn verify_previous(
        &self,
        _: &OperationId,
        _: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        Ok(())
    }
    fn discard_stage(&self, _: &OperationId) -> Result<(), ControlError> {
        Ok(())
    }
}
#[derive(Default)]
struct TestSystem {
    resource: Mutex<Option<ContentDigest>>,
    applies: AtomicUsize,
    restores: AtomicUsize,
    foreign_drift: AtomicBool,
}
impl SystemExecutor for TestSystem {
    fn inspect(
        &self,
        changes: &[ResourceChange],
    ) -> Result<Vec<ResourceObservation>, ControlError> {
        Ok(changes
            .iter()
            .map(|r| {
                let fingerprint = self.resource.lock().unwrap().clone();
                ResourceObservation {
                    id: r.id.clone(),
                    owner: fingerprint.as_ref().map(|_| {
                        if self.foreign_drift.load(Ordering::SeqCst)
                            && self.applies.load(Ordering::SeqCst) > 0
                        {
                            "foreign-application".into()
                        } else {
                            "vp-product".into()
                        }
                    }),
                    fingerprint,
                }
            })
            .collect())
    }
    fn capture(
        &self,
        _: &OperationId,
        resources: &[ResourceChange],
    ) -> Result<ResourceSnapshot, ControlError> {
        Ok(ResourceSnapshot {
            id: "test-snapshot".into(),
            resources: self.inspect(resources)?,
        })
    }
    fn apply(
        &self,
        _: &OperationId,
        plan: &ChangePlan,
        _: &ResourceSnapshot,
    ) -> Result<(), ControlError> {
        self.applies.fetch_add(1, Ordering::SeqCst);
        if let Some(change) = plan.body().resources.first() {
            *self.resource.lock().unwrap() = change.desired.clone();
        }
        Ok(())
    }
    fn restore(
        &self,
        _: &OperationId,
        plan: &ChangePlan,
        _: &ResourceSnapshot,
    ) -> Result<(), ControlError> {
        self.restores.fetch_add(1, Ordering::SeqCst);
        if let Some(change) = plan.body().resources.first() {
            *self.resource.lock().unwrap() = change.expected.clone();
        }
        Ok(())
    }
}
struct Fixture {
    service: Arc<ControlService>,
    store: Arc<MemoryStore>,
    runtime: Arc<TestRuntime>,
    system: Arc<TestSystem>,
    clock: Arc<TestClock>,
}
impl Fixture {
    fn new() -> Self {
        let store = Arc::new(MemoryStore::default());
        let runtime = Arc::new(TestRuntime::default());
        let system = Arc::new(TestSystem::default());
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let service = Arc::new(ControlService::new(
            store.clone(),
            runtime.clone(),
            system.clone(),
            clock.clone(),
        ));
        Self {
            service,
            store,
            runtime,
            system,
            clock,
        }
    }
    fn plan(&self) -> ChangePlan {
        self.service.plan(plan_request()).unwrap()
    }
}
fn principal() -> UserId {
    UserId::new("test-admin").unwrap()
}
fn release() -> ReleaseIdentity {
    ReleaseIdentity {
        release_id: ReleaseId::new("test-release").unwrap(),
        product_version: "test-only".into(),
        adapter_version: "test-only".into(),
        core_commit: "a".repeat(40),
        patchset_hash: Some("b".repeat(64)),
        build_target: "unit-test".into(),
        toolchain: "unit-test".into(),
        schema_read: CompatibilityRange {
            minimum: 1,
            maximum: 1,
        },
        schema_write: CompatibilityRange {
            minimum: 1,
            maximum: 1,
        },
        abi: VersionPair { major: 1, minor: 0 },
        api: VersionPair { major: 1, minor: 0 },
        evidence_manifest_hash: None,
    }
}
fn plan_request() -> PlanRequest {
    PlanRequest {
        principal: principal(),
        expected_revision: Revision::ZERO,
        config: ProductConfig {
            schema_version: 1,
            minimum_reader_version: 1,
            nodes: vec![],
            listeners: vec![],
            subscriptions: vec![],
        },
        release: release(),
        resources: vec![],
        ttl_ms: 60_000,
    }
}
fn apply_request(plan: &ChangePlan, key: &str) -> ApplyRequest {
    ApplyRequest {
        principal: principal(),
        plan_id: plan.body().id.clone(),
        confirmed_hash: plan.hash().clone(),
        expected_revision: plan.body().base_revision,
        idempotency_key: IdempotencyKey::new(key).unwrap(),
    }
}
fn resource_request() -> PlanRequest {
    let mut request = plan_request();
    request.resources = vec![ResourceChange {
        id: "owned-firewall".into(),
        kind: ResourceKind::Firewall,
        expected: None,
        desired: Some(ContentDigest::bytes(b"new-owned-state")),
    }];
    request
}

#[test]
fn idempotency_returns_same_operation_even_after_expiry_and_commit() {
    let f = Fixture::new();
    let plan = f.plan();
    let request = apply_request(&plan, "same-key");
    let op = f.service.submit(request.clone()).unwrap();
    let finished = f
        .service
        .run(&op.id, &CancellationToken::default())
        .unwrap();
    assert_eq!(finished.state, OperationState::Committed);
    f.clock.0.store(90_000, Ordering::SeqCst);
    let repeated = f.service.submit(request).unwrap();
    assert_eq!(repeated.id, op.id);
    assert_eq!(repeated.state, OperationState::Committed);
    assert_eq!(f.runtime.activations.load(Ordering::SeqCst), 1);
}
#[test]
fn same_key_different_content_is_a_conflict_and_scoped_by_principal() {
    let f = Fixture::new();
    let plan = f.plan();
    let request = apply_request(&plan, "reused");
    f.service.submit(request.clone()).unwrap();
    let mut changed = request.clone();
    changed.confirmed_hash = ContentDigest::bytes(b"changed");
    assert!(matches!(
        f.service.submit(changed),
        Err(ControlError::IdempotencyConflict)
    ));
    let mut other = request;
    other.principal = UserId::new("different-admin").unwrap();
    assert!(matches!(
        f.service.submit(other),
        Err(ControlError::PermissionDenied)
    ));
}
#[test]
fn exact_confirmation_and_expiry_fail_before_mutation() {
    let f = Fixture::new();
    let plan = f.plan();
    let mut request = apply_request(&plan, "wrong-hash");
    request.confirmed_hash = ContentDigest::bytes(b"wrong");
    assert!(matches!(
        f.service.submit(request),
        Err(ControlError::ConfirmationMismatch)
    ));
    f.clock.0.store(plan.body().expires_at_ms, Ordering::SeqCst);
    assert!(matches!(
        f.service.submit(apply_request(&plan, "expired")),
        Err(ControlError::PlanExpired)
    ));
    assert_eq!(f.runtime.stages.load(Ordering::SeqCst), 0);
}
#[test]
fn queued_plan_is_rechecked_when_worker_eventually_runs() {
    let f = Fixture::new();
    let plan = f.plan();
    let op = f.service.submit(apply_request(&plan, "queued")).unwrap();
    f.clock.0.store(plan.body().expires_at_ms, Ordering::SeqCst);
    let result = f
        .service
        .run(&op.id, &CancellationToken::default())
        .unwrap();
    assert_eq!(result.state, OperationState::Failed);
    assert_eq!(result.failure, Some(ControlError::PlanExpired));
    assert_eq!(f.system.applies.load(Ordering::SeqCst), 0);
}
#[test]
fn concurrent_expected_revision_allows_only_one_commit() {
    let f = Fixture::new();
    let a = f.plan();
    let b = f.plan();
    let a = f.service.submit(apply_request(&a, "one")).unwrap();
    let b = f.service.submit(apply_request(&b, "two")).unwrap();
    let first = f.service.clone();
    let second = f.service.clone();
    let ta = std::thread::spawn(move || first.run(&a.id, &CancellationToken::default()).unwrap());
    let tb = std::thread::spawn(move || second.run(&b.id, &CancellationToken::default()).unwrap());
    let results = [ta.join().unwrap(), tb.join().unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|op| op.state == OperationState::Committed)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|op| matches!(op.failure, Some(ControlError::RevisionConflict { .. })))
            .count(),
        1
    );
    assert_eq!(f.store.read().unwrap().active_revision.get(), 1);
    assert_eq!(f.runtime.activations.load(Ordering::SeqCst), 1);
}
#[test]
fn cancel_before_boundary_discards_stage_without_host_changes() {
    let f = Fixture::new();
    let plan = f.plan();
    let op = f.service.submit(apply_request(&plan, "cancel")).unwrap();
    let token = CancellationToken::default();
    *f.runtime.stage_cancel.lock().unwrap() = Some(token.clone());
    let result = f.service.run(&op.id, &token).unwrap();
    assert_eq!(result.state, OperationState::Canceled);
    assert_eq!(f.system.applies.load(Ordering::SeqCst), 0);
    assert_eq!(f.store.read().unwrap().active_revision, Revision::ZERO);
}
#[test]
fn cancel_after_boundary_does_not_abandon_a_half_applied_machine() {
    let f = Fixture::new();
    let plan = f.plan();
    let op = f
        .service
        .submit(apply_request(&plan, "late-cancel"))
        .unwrap();
    let token = CancellationToken::default();
    *f.runtime.activate_cancel.lock().unwrap() = Some(token.clone());
    let result = f.service.run(&op.id, &token).unwrap();
    assert!(token.is_canceled());
    assert_eq!(result.state, OperationState::Committed);
    assert!(matches!(
        f.service.cancel_queued(&op.id, &principal()),
        Err(ControlError::CannotCancel)
    ));
}
#[test]
fn failed_health_restores_owned_resources_and_does_not_advance_revision() {
    let f = Fixture::new();
    let plan = f.service.plan(resource_request()).unwrap();
    f.runtime.fail_health.store(true, Ordering::SeqCst);
    let op = f.service.submit(apply_request(&plan, "rollback")).unwrap();
    let result = f
        .service
        .run(&op.id, &CancellationToken::default())
        .unwrap();
    assert_eq!(result.state, OperationState::RolledBack);
    assert_eq!(f.store.read().unwrap().active_revision, Revision::ZERO);
    assert!(f.system.resource.lock().unwrap().is_none());
    assert_eq!(f.system.restores.load(Ordering::SeqCst), 1);
}
#[test]
fn stale_or_missing_real_generation_cannot_commit() {
    let f = Fixture::new();
    let plan = f.plan();
    f.runtime.wrong_generation.store(true, Ordering::SeqCst);
    let op = f
        .service
        .submit(apply_request(&plan, "invalid-health"))
        .unwrap();
    let result = f
        .service
        .run(&op.id, &CancellationToken::default())
        .unwrap();
    assert_eq!(result.state, OperationState::RolledBack);
    assert_eq!(result.failure, Some(ControlError::HealthFailed));
}
#[test]
fn foreign_resource_drift_is_never_overwritten_during_rollback() {
    let f = Fixture::new();
    let plan = f.service.plan(resource_request()).unwrap();
    f.system.foreign_drift.store(true, Ordering::SeqCst);
    let op = f.service.submit(apply_request(&plan, "drift")).unwrap();
    let result = f
        .service
        .run(&op.id, &CancellationToken::default())
        .unwrap();
    assert_eq!(result.state, OperationState::RecoveryRequired);
    assert_eq!(f.system.restores.load(Ordering::SeqCst), 0);
    assert!(matches!(
        f.service.plan(plan_request()),
        Err(ControlError::RecoveryRequired)
    ));
    assert_eq!(f.store.read().unwrap().active_revision, Revision::ZERO);
}
#[test]
fn crash_after_durable_mutation_intent_recovers_full_previous_state() {
    let f = Fixture::new();
    let plan = f.service.plan(resource_request()).unwrap();
    f.runtime.panic_activate.store(true, Ordering::SeqCst);
    let op = f.service.submit(apply_request(&plan, "crash")).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.service.run(&op.id, &CancellationToken::default())
    }));
    assert!(result.is_err());
    let durable = f.store.read().unwrap();
    assert_eq!(durable.operations[&op.id].state, OperationState::Activating);
    assert!(durable.operations[&op.id].mutation_started);
    f.runtime.panic_activate.store(false, Ordering::SeqCst);
    let reopened = Arc::new(MemoryStore::recovered(durable));
    let recovered = ControlService::new(
        reopened.clone(),
        f.runtime.clone(),
        f.system.clone(),
        f.clock.clone(),
    );
    assert_eq!(
        recovered.recover().unwrap()[0].state,
        OperationState::RolledBack
    );
    assert!(f.system.resource.lock().unwrap().is_none());
    assert_eq!(reopened.read().unwrap().active_revision, Revision::ZERO);
}
#[test]
fn failed_recovery_blocks_new_writes_until_explicit_retry_succeeds() {
    let f = Fixture::new();
    let plan = f.plan();
    f.runtime.fail_health.store(true, Ordering::SeqCst);
    f.runtime.fail_restore.store(true, Ordering::SeqCst);
    let op = f
        .service
        .submit(apply_request(&plan, "restore-failure"))
        .unwrap();
    assert_eq!(
        f.service
            .run(&op.id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::RecoveryRequired
    );
    let blocked = f.service.management_view(&principal()).unwrap();
    assert!(blocked.observed.is_none());
    assert_eq!(
        blocked.observation_error,
        Some(ControlError::RecoveryRequired)
    );
    f.runtime.fail_restore.store(false, Ordering::SeqCst);
    assert_eq!(
        f.service.recover().unwrap()[0].state,
        OperationState::RolledBack
    );
    assert!(f.service.plan(plan_request()).is_ok());
}
#[test]
fn startup_never_unexpectedly_executes_queued_confirmation() {
    let f = Fixture::new();
    let plan = f.plan();
    f.service
        .submit(apply_request(&plan, "queued-restart"))
        .unwrap();
    assert_eq!(
        f.service.recover().unwrap()[0].state,
        OperationState::Canceled
    );
    assert_eq!(f.runtime.activations.load(Ordering::SeqCst), 0);
}
#[test]
fn persisted_receipts_are_not_reported_as_live_observed_health() {
    let f = Fixture::new();
    let plan = f.plan();
    let op = f.service.submit(apply_request(&plan, "snapshot")).unwrap();
    f.service
        .run(&op.id, &CancellationToken::default())
        .unwrap();
    let snapshot = f.service.snapshot(&principal()).unwrap();
    assert_eq!(snapshot.active_revision.get(), 1);
    assert_eq!(snapshot.observed_revision, None);
    let view = f.service.management_view(&principal()).unwrap();
    assert!(view.observed.is_none());
    assert_eq!(
        view.observation_error,
        Some(ControlError::ExecutorUnavailable)
    );
    assert_eq!(
        snapshot.operations[0]
            .health
            .as_ref()
            .unwrap()
            .external_connectivity,
        CheckOutcome::NotChecked
    );
}
#[test]
fn production_missing_executor_returns_unavailable_not_fake_ready() {
    let service = ControlService::new(
        Arc::new(MemoryStore::default()),
        Arc::new(UnavailableRuntime),
        Arc::new(UnavailableSystem),
        Arc::new(TestClock(AtomicU64::new(1000))),
    );
    assert!(matches!(
        service.plan(plan_request()),
        Err(ControlError::ExecutorUnavailable)
    ));
}
#[test]
fn plan_and_errors_do_not_print_configuration_or_untrusted_diagnostics() {
    let f = Fixture::new();
    let mut request = plan_request();
    request.release.product_version = "fixture-private-value".into();
    let plan = f.service.plan(request).unwrap();
    assert!(!format!("{plan:?}").contains("fixture-private-value"));
    assert!(!ControlError::ExecutorFailed
        .to_string()
        .contains("fixture-private-value"));
    let journal = serde_json::to_string(&*f.store.journal.lock().unwrap()).unwrap();
    assert!(!journal.contains("fixture-private-value"));
}
#[test]
fn tampered_persisted_plan_fails_integrity_check() {
    let f = Fixture::new();
    let plan = f.plan();
    let mut wire = serde_json::to_value(&plan).unwrap();
    wire["body"]["expiresAtMs"] = serde_json::json!(999999);
    let tampered: ChangePlan = serde_json::from_value(wire).unwrap();
    assert!(matches!(
        tampered.verify_integrity(),
        Err(ControlError::CorruptState)
    ));
}
#[test]
fn canonical_digest_is_order_independent_and_sha256_is_standard() {
    assert_eq!(
        ContentDigest::bytes(b"abc").as_str(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let a: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":{"z":3,"y":4}}"#).unwrap();
    let b: serde_json::Value = serde_json::from_str(r#"{"a":{"y":4,"z":3},"b":2}"#).unwrap();
    assert_eq!(
        ContentDigest::of("test", &a).unwrap(),
        ContentDigest::of("test", &b).unwrap()
    );
    assert_ne!(
        ContentDigest::of("other-domain", &a).unwrap(),
        ContentDigest::of("test", &a).unwrap()
    );
}
#[test]
fn a_queued_losing_revision_is_canceled_during_recovery_not_rolled_back() {
    let f = Fixture::new();
    let first = f.plan();
    let second = f.plan();
    let a = f.service.submit(apply_request(&first, "winner")).unwrap();
    let b = f
        .service
        .submit(apply_request(&second, "queued-loser"))
        .unwrap();
    f.service.run(&a.id, &CancellationToken::default()).unwrap();
    let recovered = f.service.recover().unwrap();
    assert_eq!(recovered[0].id, b.id);
    assert_eq!(recovered[0].state, OperationState::Canceled);
    assert_eq!(f.store.read().unwrap().active_revision.get(), 1);
    assert_eq!(f.runtime.restores.load(Ordering::SeqCst), 0);
}
#[test]
fn clock_before_plan_creation_is_rejected() {
    let f = Fixture::new();
    let plan = f.plan();
    f.clock.0.store(999, Ordering::SeqCst);
    assert!(matches!(
        f.service.submit(apply_request(&plan, "clock-rollback")),
        Err(ControlError::PlanExpired)
    ));
}
#[test]
fn recovery_after_pre_mutation_cleanup_failure_does_not_touch_host_resources() {
    let f = Fixture::new();
    let plan = f.plan();
    let op = f
        .service
        .submit(apply_request(&plan, "staged-recovery"))
        .unwrap();
    // Model the durable state left by a failed cleanup without executing a host.
    let mut durable = f.store.read().unwrap();
    durable.operations.get_mut(&op.id).unwrap().state = OperationState::RecoveryRequired;
    let reopened = Arc::new(MemoryStore::recovered(durable));
    let recovered = ControlService::new(
        reopened,
        f.runtime.clone(),
        f.system.clone(),
        f.clock.clone(),
    );
    assert_eq!(
        recovered.recover().unwrap()[0].state,
        OperationState::Canceled
    );
    assert_eq!(f.system.restores.load(Ordering::SeqCst), 0);
    assert_eq!(f.runtime.restores.load(Ordering::SeqCst), 0);
}
fn listener_config(users: &[(&str, &str)]) -> ProductConfig {
    use vp_product_domain::{
        BindAddress, ListenerId, ListenerUser, Protocol, SecretRef, ServerListener, ServerProtocol,
        ServerSecurity, Transport,
    };
    let mut config = plan_request().config;
    config.listeners.push(ServerListener {
        schema_version: 1,
        id: ListenerId::new("listener-one").unwrap(),
        name: "fixture".into(),
        enabled: true,
        bind: BindAddress {
            address: "127.0.0.1".parse().unwrap(),
            port: 9000,
        },
        protocol: ServerProtocol::Proxy {
            protocol: Protocol::Socks5 {},
            users: users
                .iter()
                .map(|(id, secret)| ListenerUser {
                    id: UserId::new(*id).unwrap(),
                    credential_ref: SecretRef::new(secret).unwrap(),
                    enabled: true,
                })
                .collect(),
        },
        transport: Transport::Tcp {},
        security: ServerSecurity::None {},
        requirements: vec![],
    });
    config
}
fn prior_record(config: ProductConfig) -> RevisionRecord {
    RevisionRecord {
        revision: Revision::new(1).unwrap(),
        config_digest: ContentDigest::of("vp.product-config.v1", &config).unwrap(),
        config,
        release: release(),
        release_digest: ContentDigest::of("vp.release-identity.v1", &release()).unwrap(),
        artifact_digest: ContentDigest::bytes(b"prior"),
        operation_id: OperationId::new("prior-operation").unwrap(),
    }
}
#[test]
fn adding_or_reordering_users_does_not_retire_still_authorized_credentials() {
    let previous = prior_record(listener_config(&[("alice", "alice-v1")]));
    let added = listener_config(&[("bob", "bob-v1"), ("alice", "alice-v1")]);
    let checks = minimum_health_checks(&added, Some(&previous)).unwrap();
    assert_eq!(
        checks
            .iter()
            .filter(|c| matches!(c, HealthCheck::AuthenticationAccepted(_)))
            .count(),
        2
    );
    assert!(!checks
        .iter()
        .any(|c| matches!(c, HealthCheck::RetiredAuthenticationRejected(_))));
    let reordered = prior_record(listener_config(&[("alice", "alice-v1"), ("bob", "bob-v1")]));
    let checks = minimum_health_checks(&added, Some(&reordered)).unwrap();
    assert!(!checks
        .iter()
        .any(|c| matches!(c, HealthCheck::RetiredAuthenticationRejected(_))));
}
#[test]
fn removed_and_rotated_credentials_have_individually_identified_negative_probes() {
    let previous = prior_record(listener_config(&[("alice", "alice-v1"), ("bob", "bob-v1")]));
    let changed = listener_config(&[("alice", "alice-v2")]);
    let checks = minimum_health_checks(&changed, Some(&previous)).unwrap();
    let retired: Vec<_> = checks
        .iter()
        .filter_map(|c| {
            if let HealthCheck::RetiredAuthenticationRejected(probe) = c {
                Some(probe)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(retired.len(), 2);
    assert!(retired.iter().any(|probe| probe.user_id == "alice"));
    assert!(retired.iter().any(|probe| probe.user_id == "bob"));
    assert_ne!(
        retired[0].credential_ref_digest,
        retired[1].credential_ref_digest
    );
}
#[test]
fn preexisting_resource_drift_rejects_plan_without_a_write() {
    let f = Fixture::new();
    *f.system.resource.lock().unwrap() =
        Some(ContentDigest::bytes(b"someone-elses-existing-state"));
    assert!(matches!(
        f.service.plan(resource_request()),
        Err(ControlError::ResourceConflict)
    ));
    assert_eq!(f.system.applies.load(Ordering::SeqCst), 0);
    assert_eq!(f.runtime.stages.load(Ordering::SeqCst), 0);
}
#[test]
fn resource_deletion_failure_restores_the_exact_previous_fingerprint() {
    let f = Fixture::new();
    let old = ContentDigest::bytes(b"old-owned-rule");
    *f.system.resource.lock().unwrap() = Some(old.clone());
    let mut request = resource_request();
    request.resources[0].expected = Some(old.clone());
    request.resources[0].desired = None;
    let plan = f.service.plan(request).unwrap();
    f.runtime.fail_health.store(true, Ordering::SeqCst);
    let op = f
        .service
        .submit(apply_request(&plan, "delete-rollback"))
        .unwrap();
    assert_eq!(
        f.service
            .run(&op.id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::RolledBack
    );
    assert_eq!(*f.system.resource.lock().unwrap(), Some(old));
    assert_eq!(f.store.read().unwrap().active_revision, Revision::ZERO);
}

fn draft_request(key: &str) -> DraftRequest {
    DraftRequest {
        principal: principal(),
        draft_id: None,
        expected_revision: Revision::ZERO,
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        mutation: DraftMutation::Create(plan_request().config),
    }
}
#[test]
fn durable_draft_cas_scoped_idempotency_and_no_runtime_mutation() {
    let f = Fixture::new();
    let request = draft_request("draft-key");
    let created = f.service.edit_draft(request.clone()).unwrap().unwrap();
    assert_eq!(
        created,
        f.service.edit_draft(request.clone()).unwrap().unwrap()
    );
    let mut conflict = request;
    conflict.expected_revision = Revision::new(1).unwrap();
    assert_eq!(
        f.service.edit_draft(conflict).unwrap_err(),
        ControlError::IdempotencyConflict
    );
    let mut edit = draft_request("edit-key");
    edit.draft_id = Some(created.id.clone());
    edit.mutation = DraftMutation::Replace(created.config.clone());
    assert!(matches!(
        f.service.edit_draft(edit.clone()),
        Err(ControlError::RevisionConflict { .. })
    ));
    edit.expected_revision = created.revision;
    let updated = f.service.edit_draft(edit.clone()).unwrap().unwrap();
    assert_eq!(updated.revision.get(), 2);
    assert_eq!(f.service.edit_draft(edit).unwrap().unwrap(), updated);
    assert_eq!(f.service.active_config().unwrap().0, Revision::ZERO);
    assert_eq!(f.runtime.activations.load(Ordering::SeqCst), 0);
    assert_eq!(f.system.applies.load(Ordering::SeqCst), 0);
    assert!(matches!(
        f.service.draft(&created.id, &UserId::new("other").unwrap()),
        Err(ControlError::NotFound)
    ));
    let mut delete = draft_request("delete-key");
    delete.draft_id = Some(created.id.clone());
    delete.expected_revision = updated.revision;
    delete.mutation = DraftMutation::Delete {};
    assert!(f.service.edit_draft(delete.clone()).unwrap().is_none());
    assert!(f.service.edit_draft(delete).unwrap().is_none());
    assert!(f.service.drafts(&principal()).unwrap().is_empty());
}
#[test]
fn draft_plan_retry_is_atomic_and_independent_of_subsequent_edits() {
    let f = Fixture::new();
    let draft = f
        .service
        .edit_draft(draft_request("draft-key"))
        .unwrap()
        .unwrap();
    let before = f.store.read().unwrap().version;
    let key = IdempotencyKey::new("plan-key").unwrap();
    let plan = f
        .service
        .plan_draft(
            &draft.id,
            &principal(),
            Revision::ZERO,
            key.clone(),
            release(),
        )
        .unwrap();
    let state = f.store.read().unwrap();
    assert_eq!(state.version, before + 1);
    assert_eq!(state.plan_idempotency.len(), 1);
    assert_eq!(state.plans.len(), 1);
    f.clock.0.store(999_999, Ordering::SeqCst);
    let replay = f
        .service
        .plan_draft(&draft.id, &principal(), Revision::ZERO, key, release())
        .unwrap();
    assert_eq!(plan.hash(), replay.hash());
    assert_eq!(f.store.read().unwrap().version, before + 1);
}
#[test]
fn unavailable_validation_does_not_create_plan_or_change_revision() {
    let f = Fixture::new();
    let service = ControlService::new(
        f.store.clone(),
        Arc::new(UnavailableRuntime),
        Arc::new(UnavailableSystem),
        f.clock,
    );
    let draft = service
        .edit_draft(draft_request("create"))
        .unwrap()
        .unwrap();
    assert!(matches!(
        service.validate_draft(&draft.id, &principal(), draft.revision, &release()),
        Err(ControlError::ExecutorUnavailable)
    ));
    assert!(matches!(
        service.plan_draft(
            &draft.id,
            &principal(),
            Revision::ZERO,
            IdempotencyKey::new("plan").unwrap(),
            release()
        ),
        Err(ControlError::ExecutorUnavailable)
    ));
    let state = f.store.read().unwrap();
    assert!(state.plans.is_empty());
    assert!(state.plan_idempotency.is_empty());
    assert!(state.operations.is_empty());
    assert_eq!(state.active_revision, Revision::ZERO);
}

#[test]
fn queued_http_cancellation_is_atomic_scoped_and_durable() {
    let f = Fixture::new();
    let plan = f.plan();
    let op = f.service.submit(apply_request(&plan, "submit")).unwrap();
    let request = CancelRequest {
        principal: principal(),
        operation_id: op.id.clone(),
        expected_revision: Revision::ZERO,
        idempotency_key: IdempotencyKey::new("cancel-key").unwrap(),
    };
    let before = f.store.read().unwrap().version;
    let canceled = f.service.cancel_request(request.clone()).unwrap();
    assert_eq!(canceled.0.state, OperationState::Canceled);
    assert_eq!(f.store.read().unwrap().version, before + 1);
    assert_eq!(
        f.service.cancel_request(request.clone()).unwrap().0.id,
        op.id
    );
    assert_eq!(f.store.read().unwrap().version, before + 1);
    let mut different = request;
    different.expected_revision = Revision::new(1).unwrap();
    assert_eq!(
        f.service.cancel_request(different).unwrap_err(),
        ControlError::IdempotencyConflict
    );
    assert_eq!(
        f.service
            .run(&op.id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::Canceled
    );
    assert_eq!(f.runtime.activations.load(Ordering::SeqCst), 0);
}

#[test]
fn fresh_observation_requires_exact_identity_generation_time_and_all_checks() {
    let f = Fixture::new();
    let plan = f.plan();
    let op = f
        .service
        .submit(apply_request(&plan, "observation"))
        .unwrap();
    let op = f
        .service
        .run(&op.id, &CancellationToken::default())
        .unwrap();
    let record = f.store.read().unwrap().active().unwrap().clone();
    let health = op.health.unwrap();
    assert!(crate::drafts::validate_observation(&record, &health, 1000).is_ok());
    let mut bad = health.clone();
    bad.generation = 0;
    assert!(crate::drafts::validate_observation(&record, &bad, 1000).is_err());
    let mut bad = health.clone();
    bad.config_digest = ContentDigest::bytes(b"wrong config");
    assert!(crate::drafts::validate_observation(&record, &bad, 1000).is_err());
    let mut bad = health.clone();
    bad.revision = Revision::ZERO;
    assert!(crate::drafts::validate_observation(&record, &bad, 1000).is_err());
    let mut bad = health.clone();
    bad.checks.clear();
    assert!(crate::drafts::validate_observation(&record, &bad, 1000).is_err());
    let mut bad = health.clone();
    bad.checks.push(bad.checks[0].clone());
    assert!(crate::drafts::validate_observation(&record, &bad, 1000).is_err());
    let mut bad = health.clone();
    bad.checks[0].outcome = CheckOutcome::Failed;
    assert!(crate::drafts::validate_observation(&record, &bad, 1000).is_err());
    let mut bad = health.clone();
    bad.release_digest = ContentDigest::bytes(b"wrong release");
    assert!(crate::drafts::validate_observation(&record, &bad, 1000).is_err());
    assert!(crate::drafts::validate_observation(&record, &health, 999).is_err());
    assert!(crate::drafts::validate_observation(&record, &health, 31_001).is_err());
}

#[path = "managed_secret_tests.rs"]
mod managed_secret_tests;

#[path = "stage_context_tests.rs"]
mod stage_context_tests;

#[path = "runtime_context_tests.rs"]
mod runtime_context_tests;
