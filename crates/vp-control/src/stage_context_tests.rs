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
fn context_observes_post_staging_version_with_one_existing_writer() {
    let (service, store, runtime, _, id) = setup();
    let queued = store.read().unwrap().version;
    assert_eq!(
        service
            .run(&id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::Committed
    );
    assert_eq!(*runtime.observed.lock().unwrap(), vec![queued + 1]);
    assert_eq!(
        store.writers.load(Ordering::SeqCst),
        runtime.before.load(Ordering::SeqCst) + 1
    );
}
#[test]
fn context_stage_error_discards_without_host_mutation() {
    let (service, _, runtime, system, id) = setup();
    runtime.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .run(&id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::Failed
    );
    assert_eq!(runtime.discards.load(Ordering::SeqCst), 1);
    assert_eq!(system.applies.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.inner.activations.load(Ordering::SeqCst), 0);
}
#[test]
fn context_cancellation_discards_without_activation() {
    let (service, _, runtime, system, id) = setup();
    runtime.cancel.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .run(&id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::Canceled
    );
    assert_eq!(runtime.discards.load(Ordering::SeqCst), 1);
    assert_eq!(system.applies.load(Ordering::SeqCst), 0);
}
#[test]
fn context_failed_discard_is_recovered_without_restaging() {
    let (service, _, runtime, system, id) = setup();
    runtime.fail.store(true, Ordering::SeqCst);
    runtime.fail_discard.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .run(&id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::RecoveryRequired
    );
    runtime.fail_discard.store(false, Ordering::SeqCst);
    assert_eq!(
        service.recover().unwrap()[0].state,
        OperationState::Canceled
    );
    assert_eq!(runtime.observed.lock().unwrap().len(), 1);
    assert_eq!(runtime.discards.load(Ordering::SeqCst), 2);
    assert_eq!(system.restores.load(Ordering::SeqCst), 0);
}
#[test]
fn recovery_of_durable_staging_discards_and_never_calls_stage_context() {
    let (service, store, runtime, system, id) = setup();
    store
        .inner
        .state
        .lock()
        .unwrap()
        .operations
        .get_mut(&id)
        .unwrap()
        .state = OperationState::Staging;
    assert_eq!(
        service.recover().unwrap()[0].state,
        OperationState::Canceled
    );
    assert!(runtime.observed.lock().unwrap().is_empty());
    assert_eq!(runtime.discards.load(Ordering::SeqCst), 1);
    assert_eq!(system.applies.load(Ordering::SeqCst), 0);
}
#[test]
fn context_preserves_ordinary_health_rollback() {
    let (service, _, runtime, _, id) = setup();
    runtime.inner.fail_health.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .run(&id, &CancellationToken::default())
            .unwrap()
            .state,
        OperationState::RolledBack
    );
    assert_eq!(runtime.inner.restores.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.discards.load(Ordering::SeqCst), 1);
}
#[test]
fn context_rejects_wrong_phase_plan_and_principal() {
    let f = Fixture::new();
    let plan = f.plan();
    let op = f.service.submit(apply_request(&plan, "forge")).unwrap();
    let cancel = CancellationToken::default();
    let mut lease = f.store.writer().unwrap();
    assert!(RuntimeStageContext::from_staging(&*lease, &op.id, &plan, &*f.clock, &cancel).is_err());
    let mut state = lease.state().clone();
    state.operations.get_mut(&op.id).unwrap().state = OperationState::Staging;
    checkpoint(
        &mut *lease,
        state,
        1000,
        Some(op.id.clone()),
        Some(OperationState::Staging),
    )
    .unwrap();
    assert!(RuntimeStageContext::from_staging(&*lease, &op.id, &plan, &*f.clock, &cancel).is_ok());
    let mut body = plan.body().clone();
    body.principal = UserId::new("other").unwrap();
    let other = ChangePlan::seal(body).unwrap();
    assert!(
        RuntimeStageContext::from_staging(&*lease, &op.id, &other, &*f.clock, &cancel).is_err()
    );
}
#[test]
fn default_stage_refuses_tls_without_calling_legacy_stage() {
    let f = Fixture::new();
    let original = f.plan();
    let op = f.service.submit(apply_request(&original, "tls")).unwrap();
    // Synthetic persisted staging fixture, not TLS runtime validation.
    let mut body = original.body().clone();
    body.config = listener_config(&[("user", "credential")]);
    body.config.listeners[0].security = vp_product_domain::ServerSecurity::Tls {
        certificate_ref: vp_product_domain::CertificateId::new("certificate").unwrap(),
        private_key_ref: vp_product_domain::SecretRef::new("key").unwrap(),
        alpn: vec![],
    };
    body.validation.config_digest =
        ContentDigest::of("vp.product-config.v1", &body.config).unwrap();
    let plan = ChangePlan::seal(body).unwrap();
    let mut state = f.store.read().unwrap();
    state.plans.insert(plan.body().id.clone(), plan.clone());
    state.operations.get_mut(&op.id).unwrap().state = OperationState::Staging;
    let store = MemoryStore::recovered(state);
    let lease = store.writer().unwrap();
    let cancel = CancellationToken::default();
    let context =
        RuntimeStageContext::from_staging(&*lease, &op.id, &plan, &*f.clock, &cancel).unwrap();
    assert_eq!(
        f.runtime.stage_with_context(context),
        Err(ControlError::ExecutorUnavailable)
    );
    assert_eq!(f.runtime.stages.load(Ordering::SeqCst), 0);
}
