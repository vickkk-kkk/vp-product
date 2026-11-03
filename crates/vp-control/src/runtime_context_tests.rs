//! Synthetic orchestration only. No real runtime, vault or traffic acceptance.
use super::*;
#[derive(Default)]
struct CountingStore {
    inner: MemoryStore,
    writers: AtomicUsize,
}
impl ControlStore for CountingStore {
    fn read(&self) -> Result<StoredState, ControlError> {
        self.inner.read()
    }
    fn writer(&self) -> Result<Box<dyn WriterLease + '_>, ControlError> {
        self.writers.fetch_add(1, Ordering::SeqCst);
        self.inner.writer()
    }
}
struct ContextRuntime {
    inner: TestRuntime,
    store: Arc<CountingStore>,
    before: AtomicUsize,
    observed: Mutex<Vec<u64>>,
    activations: Mutex<Vec<u64>>,
    restorations: Mutex<Vec<u64>>,
    fail_activate: AtomicBool,
    fail_restore: AtomicBool,
    fail: AtomicBool,
    cancel: AtomicBool,
    fail_discard: AtomicBool,
    discards: AtomicUsize,
}
impl ContextRuntime {
    fn new(store: Arc<CountingStore>) -> Self {
        Self {
            inner: TestRuntime::default(),
            store,
            before: AtomicUsize::new(0),
            observed: Mutex::new(vec![]),
            activations: Mutex::new(vec![]),
            restorations: Mutex::new(vec![]),
            fail_activate: AtomicBool::new(false),
            fail_restore: AtomicBool::new(false),
            fail: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            fail_discard: AtomicBool::new(false),
            discards: AtomicUsize::new(0),
        }
    }
}
impl RuntimeExecutor for ContextRuntime {
    fn validate(
        &self,
        c: &ProductConfig,
        r: &ReleaseIdentity,
        p: Option<&RevisionRecord>,
    ) -> Result<ValidationReceipt, ControlError> {
        self.inner.validate(c, r, p)
    }
    fn stage(
        &self,
        _: &OperationId,
        _: &ChangePlan,
        _: &CancellationToken,
    ) -> Result<(), ControlError> {
        panic!("context-free stage must not be called")
    }
    fn stage_with_context(&self, c: RuntimeStageContext<'_>) -> Result<(), ControlError> {
        assert_eq!(
            self.store.writers.load(Ordering::SeqCst),
            self.before.load(Ordering::SeqCst) + 1
        );
        assert!(self.store.inner.writer.try_lock().is_err());
        assert_eq!(
            c.plan().body().id,
            self.store.read()?.operations[c.operation()].plan_id
        );
        self.observed.lock().unwrap().push(c.aggregate_version());
        if self.cancel.load(Ordering::SeqCst) {
            c.cancellation().cancel();
        }
        if self.fail.load(Ordering::SeqCst) {
            Err(ControlError::ExecutorFailed)
        } else {
            Ok(())
        }
    }
    fn activate_with_context(
        &self,
        c: RuntimeActivationContext<'_>,
    ) -> Result<RuntimeActivation, ControlError> {
        assert_eq!(
            self.store.writers.load(Ordering::SeqCst),
            self.before.load(Ordering::SeqCst) + 1
        );
        assert!(self.store.inner.writer.try_lock().is_err());
        assert_eq!(
            self.store.read()?.operations[c.operation()].state,
            OperationState::Activating
        );
        self.activations.lock().unwrap().push(c.aggregate_version());
        if self.fail_activate.load(Ordering::SeqCst) {
            return Err(ControlError::ExecutorFailed);
        }
        self.inner.activate(c.operation(), c.plan(), c.previous())
    }
    fn restore_previous_with_context(
        &self,
        c: RuntimeRestoreContext<'_>,
    ) -> Result<(), ControlError> {
        assert_eq!(
            self.store.writers.load(Ordering::SeqCst),
            self.before.load(Ordering::SeqCst) + 1
        );
        assert!(self.store.inner.writer.try_lock().is_err());
        assert_eq!(
            self.store.read()?.operations[c.operation()].state,
            OperationState::RollingBack
        );
        self.restorations
            .lock()
            .unwrap()
            .push(c.aggregate_version());
        if self.fail_restore.load(Ordering::SeqCst) {
            return Err(ControlError::ExecutorFailed);
        }
        self.inner.restore_previous(c.operation(), c.previous())
    }
    fn activate(
        &self,
        o: &OperationId,
        p: &ChangePlan,
        r: Option<&RevisionRecord>,
    ) -> Result<RuntimeActivation, ControlError> {
        self.inner.activate(o, p, r)
    }
    fn verify(&self, o: &OperationId, p: &ChangePlan) -> Result<RuntimeHealth, ControlError> {
        self.inner.verify(o, p)
    }
    fn stop_candidate(&self, o: &OperationId, p: &ChangePlan) -> Result<(), ControlError> {
        self.inner.stop_candidate(o, p)
    }
    fn restore_previous(
        &self,
        o: &OperationId,
        r: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        self.inner.restore_previous(o, r)
    }
    fn verify_previous(
        &self,
        o: &OperationId,
        r: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        self.inner.verify_previous(o, r)
    }
    fn discard_stage(&self, _: &OperationId) -> Result<(), ControlError> {
        self.discards.fetch_add(1, Ordering::SeqCst);
        if self.fail_discard.load(Ordering::SeqCst) {
            Err(ControlError::ExecutorFailed)
        } else {
            Ok(())
        }
    }
}
fn setup() -> (
    ControlService,
    Arc<CountingStore>,
    Arc<ContextRuntime>,
    Arc<TestSystem>,
    OperationId,
) {
    let store = Arc::new(CountingStore::default());
    let runtime = Arc::new(ContextRuntime::new(store.clone()));
    let system = Arc::new(TestSystem::default());
    let service = ControlService::new(
        store.clone(),
        runtime.clone(),
        system.clone(),
        Arc::new(TestClock(AtomicU64::new(1000))),
    );
    let plan = service.plan(plan_request()).unwrap();
    let op = service.submit(apply_request(&plan, "context")).unwrap();
    runtime
        .before
        .store(store.writers.load(Ordering::SeqCst), Ordering::SeqCst);
    (service, store, runtime, system, op.id)
}
#[test]
fn activation_context_uses_later_checkpoint_and_one_writer() {
    let (service, store, runtime, _, id) = setup();
    assert_eq!(
        service
            .run(&id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::Committed
    );
    assert!(runtime.activations.lock().unwrap()[0] > runtime.observed.lock().unwrap()[0]);
    assert_eq!(
        store.writers.load(Ordering::SeqCst),
        runtime.before.load(Ordering::SeqCst) + 1
    );
}
#[test]
fn activation_failure_uses_fresh_rollback_context() {
    let (service, _, runtime, _, id) = setup();
    runtime.fail_activate.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .run(&id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::RolledBack
    );
    assert!(runtime.restorations.lock().unwrap()[0] > runtime.activations.lock().unwrap()[0]);
}
#[test]
fn restoration_failure_remains_recovery_required_then_recovers() {
    let (service, store, runtime, _, id) = setup();
    runtime.inner.fail_health.store(true, Ordering::SeqCst);
    runtime.fail_restore.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .run(&id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::RecoveryRequired
    );
    runtime
        .before
        .store(store.writers.load(Ordering::SeqCst), Ordering::SeqCst);
    runtime.fail_restore.store(false, Ordering::SeqCst);
    assert_eq!(
        service.recover().unwrap()[0].state,
        OperationState::RolledBack
    );
    assert_eq!(runtime.restorations.lock().unwrap().len(), 2);
    assert_eq!(
        runtime.observed.lock().unwrap().len(),
        1,
        "recovery never restages"
    );
}
#[test]
fn activation_and_restore_reject_wrong_phase_and_forged_previous() {
    let f = Fixture::new();
    let plan = f.plan();
    let op = f.service.submit(apply_request(&plan, "phase")).unwrap();
    let cancel = CancellationToken::default();
    let mut state = f.store.read().unwrap();
    assert!(RuntimeActivationContext::from_activating(
        &*f.store.writer().unwrap(),
        &op.id,
        &plan,
        None,
        &*f.clock,
        &cancel
    )
    .is_err());
    let operation = state.operations.get_mut(&op.id).unwrap();
    operation.state = OperationState::Activating;
    operation.mutation_started = true;
    operation.snapshot = Some(ResourceSnapshot {
        id: "snapshot".into(),
        resources: vec![],
    });
    let store = MemoryStore::recovered(state.clone());
    let lease = store.writer().unwrap();
    assert!(RuntimeActivationContext::from_activating(
        &*lease, &op.id, &plan, None, &*f.clock, &cancel
    )
    .is_ok());
    assert!(
        RuntimeRestoreContext::from_rolling_back(&*lease, &op.id, &plan, None, &*f.clock).is_err()
    );
    let fake = RevisionRecord {
        revision: Revision::ZERO.next().unwrap(),
        config: plan.body().config.clone(),
        release: plan.body().release.clone(),
        config_digest: plan.body().validation.config_digest.clone(),
        release_digest: plan.body().validation.release_digest.clone(),
        artifact_digest: plan.body().validation.artifact_digest.clone(),
        operation_id: op.id.clone(),
    };
    assert!(RuntimeActivationContext::from_activating(
        &*lease,
        &op.id,
        &plan,
        Some(&fake),
        &*f.clock,
        &cancel
    )
    .is_err());
    state.operations.get_mut(&op.id).unwrap().state = OperationState::RollingBack;
    let store = MemoryStore::recovered(state);
    let lease = store.writer().unwrap();
    assert!(
        RuntimeRestoreContext::from_rolling_back(&*lease, &op.id, &plan, None, &*f.clock).is_ok()
    );
    assert!(RuntimeRestoreContext::from_rolling_back(
        &*lease,
        &op.id,
        &plan,
        Some(&fake),
        &*f.clock
    )
    .is_err());
}
#[test]
fn default_activation_and_restoration_refuse_tls_without_legacy_calls() {
    let f = Fixture::new();
    let original = f.plan();
    let op = f
        .service
        .submit(apply_request(&original, "tls-context"))
        .unwrap();
    let mut body = original.body().clone();
    body.config = listener_config(&[("user", "credential")]);
    body.config.listeners[0].security = vp_product_domain::ServerSecurity::Tls {
        certificate_ref: vp_product_domain::CertificateId::new("cert").unwrap(),
        private_key_ref: vp_product_domain::SecretRef::new("key").unwrap(),
        alpn: vec![],
    };
    body.validation.config_digest =
        ContentDigest::of("vp.product-config.v1", &body.config).unwrap();
    let plan = ChangePlan::seal(body).unwrap();
    let mut state = f.store.read().unwrap();
    state.plans.insert(plan.body().id.clone(), plan.clone());
    let operation = state.operations.get_mut(&op.id).unwrap();
    operation.state = OperationState::Activating;
    operation.mutation_started = true;
    operation.snapshot = Some(ResourceSnapshot {
        id: "snapshot".into(),
        resources: vec![],
    });
    let cancel = CancellationToken::default();
    let store = MemoryStore::recovered(state.clone());
    let lease = store.writer().unwrap();
    let ctx =
        RuntimeActivationContext::from_activating(&*lease, &op.id, &plan, None, &*f.clock, &cancel)
            .unwrap();
    assert!(matches!(
        f.runtime.activate_with_context(ctx),
        Err(ControlError::ExecutorUnavailable)
    ));
    assert_eq!(f.runtime.activations.load(Ordering::SeqCst), 0);
    state.operations.get_mut(&op.id).unwrap().state = OperationState::RollingBack;
    let store = MemoryStore::recovered(state);
    let lease = store.writer().unwrap();
    let ctx =
        RuntimeRestoreContext::from_rolling_back(&*lease, &op.id, &plan, None, &*f.clock).unwrap();
    assert_eq!(
        f.runtime.restore_previous_with_context(ctx),
        Err(ControlError::ExecutorUnavailable)
    );
    assert_eq!(f.runtime.restores.load(Ordering::SeqCst), 0);
}
