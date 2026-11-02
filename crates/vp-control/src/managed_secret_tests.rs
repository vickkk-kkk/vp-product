//! SOURCE-AUTHORED transaction regressions; execution evidence is separate.
//! All entropy, vault contents, storage failures and runtime observations here
//! are isolated test doubles. No protocol/runtime acceptance is established.
//! The actual v1 manager does NOT generate UsernamePassword/UuidPassword tuples.
use super::*;
use crate::RuntimeHealth;
use std::{collections::BTreeMap, time::Instant};
use vp_product_domain::*;

#[derive(Default)]
struct FaultStore {
    inner: MemoryStore,
    persists: AtomicUsize,
    fail_at: AtomicUsize,
    fail_after_commit: AtomicBool,
}
impl FaultStore {
    fn fail_nth_next(&self, count: usize, after_commit: bool) {
        assert!(count > 0);
        self.fail_after_commit.store(after_commit, Ordering::SeqCst);
        self.fail_at.store(
            self.persists.load(Ordering::SeqCst) + count,
            Ordering::SeqCst,
        );
    }
    fn serialized(&self) -> Vec<u8> {
        serde_json::to_vec(&self.read().unwrap()).unwrap()
    }
}
struct FaultWriter<'a> {
    inner: Box<dyn WriterLease + 'a>,
    store: &'a FaultStore,
}
impl ControlStore for FaultStore {
    fn read(&self) -> Result<StoredState, ControlError> {
        self.inner.read()
    }
    fn writer(&self) -> Result<Box<dyn WriterLease + '_>, ControlError> {
        Ok(Box::new(FaultWriter {
            inner: self.inner.writer()?,
            store: self,
        }))
    }
}
impl WriterLease for FaultWriter<'_> {
    fn state(&self) -> &StoredState {
        self.inner.state()
    }
    fn persist(&mut self, next: StoredState, event: JournalEvent) -> Result<(), ControlError> {
        let call = self.store.persists.fetch_add(1, Ordering::SeqCst) + 1;
        let fail = self.store.fail_at.load(Ordering::SeqCst) == call;
        let after_commit = self.store.fail_after_commit.load(Ordering::SeqCst);
        if fail && !after_commit {
            return Err(ControlError::StorageUnavailable);
        }
        self.inner.persist(next, event)?;
        if fail {
            return Err(ControlError::StorageUnavailable);
        }
        Ok(())
    }
}

struct VaultValue {
    kind: NodeCredentialKind,
    version: u64,
    bytes: SecretBytes,
    retired: bool,
}
#[derive(Default)]
struct MemorySecrets {
    values: Mutex<BTreeMap<SecretRef, VaultValue>>,
    credential_entropy: AtomicUsize,
    token_entropy: AtomicUsize,
    puts: AtomicUsize,
    loads: AtomicUsize,
    retires: AtomicUsize,
    // 1: fail before mutation; 2: mutate successfully, report uncertain failure.
    put_failure: AtomicUsize,
    retire_failure: AtomicUsize,
}
impl MemorySecrets {
    fn current(&self, reference: &SecretRef) -> Option<SecretBytes> {
        self.values
            .lock()
            .unwrap()
            .get(reference)
            .filter(|v| !v.retired)
            .map(|v| SecretBytes::new(v.bytes.expose().to_vec()))
    }
}
impl SecretManager for MemorySecrets {
    fn supported_kinds(&self) -> Vec<NodeCredentialKind> {
        vec![NodeCredentialKind::Uuid {}, NodeCredentialKind::Password {}]
    }
    fn generate_credential(
        &self,
        kind: &NodeCredentialKind,
        _: Instant,
    ) -> Result<GeneratedCredential, ControlError> {
        if !self.supported_kinds().contains(kind) {
            return Err(ControlError::ExecutorUnavailable);
        }
        let n = self.credential_entropy.fetch_add(1, Ordering::SeqCst) + 1;
        // Deliberately deterministic, synthetic and confined to cfg(test).
        let bytes = match kind {
            NodeCredentialKind::Uuid {} => format!("00000000-0000-4000-8000-{n:012x}"),
            NodeCredentialKind::Password {} => format!("synthetic-node-password-{n}"),
            _ => return Err(ControlError::ExecutorUnavailable),
        };
        Ok(GeneratedCredential {
            reference: SecretRef::new(&format!("synthetic-managed-{n}")).unwrap(),
            bytes: SecretBytes::new(bytes.into_bytes()),
        })
    }
    fn put_credential(
        &self,
        reference: &SecretRef,
        kind: &NodeCredentialKind,
        version: u64,
        bytes: SecretBytes,
        _: Instant,
    ) -> Result<(), ControlError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        let failure = self.put_failure.swap(0, Ordering::SeqCst);
        if failure == 1 {
            return Err(ControlError::ExecutorFailed);
        }
        let mut values = self.values.lock().unwrap();
        if values.contains_key(reference) {
            return Err(ControlError::ResourceConflict);
        }
        values.insert(
            reference.clone(),
            VaultValue {
                kind: kind.clone(),
                version,
                bytes,
                retired: false,
            },
        );
        if failure == 2 {
            return Err(ControlError::ExecutorFailed);
        }
        Ok(())
    }
    fn load_credential(
        &self,
        reference: &SecretRef,
        kind: &NodeCredentialKind,
        version: Option<u64>,
        _: Instant,
    ) -> Result<Option<SecretBytes>, ControlError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        let values = self.values.lock().unwrap();
        let Some(value) = values.get(reference) else {
            return Ok(None);
        };
        if &value.kind != kind || version.is_some_and(|v| v != value.version) {
            return Err(ControlError::ResourceConflict);
        }
        if value.retired {
            return Ok(None);
        }
        Ok(Some(SecretBytes::new(value.bytes.expose().to_vec())))
    }
    fn retire_credential(
        &self,
        reference: &SecretRef,
        version: u64,
        _: Instant,
    ) -> Result<(), ControlError> {
        self.retires.fetch_add(1, Ordering::SeqCst);
        let failure = self.retire_failure.swap(0, Ordering::SeqCst);
        if failure == 1 {
            return Err(ControlError::ExecutorFailed);
        }
        let mut values = self.values.lock().unwrap();
        let value = values.get_mut(reference).ok_or(ControlError::NotFound)?;
        if value.version != version {
            return Err(ControlError::ResourceConflict);
        }
        value.retired = true; // Immutable tombstone, including repeated retirement.
        if failure == 2 {
            return Err(ControlError::ExecutorFailed);
        }
        Ok(())
    }
    fn generate_publication_token(&self, _: Instant) -> Result<SecretBytes, ControlError> {
        let n = self.token_entropy.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(SecretBytes::new(
            format!("synthetic-only-token-{n:043x}").into_bytes(),
        ))
    }
    fn publication_verifier(&self, token: &[u8]) -> Result<ContentDigest, ControlError> {
        Ok(ContentDigest::bytes(token))
    }
    fn verify_publication_token(&self, verifier: &ContentDigest, token: &[u8]) -> bool {
        // NOT a production verifier: the actual manager owns domain-separated constant-time verification.
        &ContentDigest::bytes(token) == verifier
    }
}

struct ObservationRuntime {
    inner: TestRuntime,
    clock: Arc<TestClock>,
    fault: AtomicUsize,
    observations: AtomicUsize,
}
impl RuntimeExecutor for ObservationRuntime {
    fn observe_committed(&self, active: &RevisionRecord) -> Result<RuntimeHealth, ControlError> {
        self.observations.fetch_add(1, Ordering::SeqCst);
        let fault = self.fault.load(Ordering::SeqCst);
        if fault == 1 {
            return Err(ControlError::ExecutorUnavailable);
        }
        let mut health = RuntimeHealth {
            revision: active.revision,
            operation_id: active.operation_id.clone(),
            config_digest: active.config_digest.clone(),
            release_digest: active.release_digest.clone(),
            generation: 1,
            checked_at_ms: self.clock.now_ms()?,
            checks: minimum_health_checks(&active.config, None)?
                .into_iter()
                .map(|check| CheckResult {
                    check,
                    outcome: CheckOutcome::Passed,
                })
                .collect(),
            external_connectivity: CheckOutcome::NotChecked,
        };
        match fault {
            2 => health.revision = Revision::ZERO,
            3 => health.config_digest = ContentDigest::bytes(b"test-only-wrong-config"),
            4 => health.release_digest = ContentDigest::bytes(b"test-only-wrong-release"),
            5 => health.operation_id = OperationId::new("test-only-other-operation").unwrap(),
            6 => health.generation = 0,
            7 => health.checked_at_ms += 1,
            8 => health.checks[0].outcome = CheckOutcome::Failed,
            9 => health.checks.push(health.checks[0].clone()),
            10 => health.checks.clear(),
            11 => health.checked_at_ms = 0,
            12 => {
                // Advance virtual wall time while a read-only probe is in flight.
                let now = self.clock.now_ms()? + 300_000;
                self.clock.0.store(now, Ordering::SeqCst);
                health.checked_at_ms = now;
            }
            _ => (),
        }
        Ok(health)
    }
    fn validate(
        &self,
        config: &ProductConfig,
        release: &ReleaseIdentity,
        previous: Option<&RevisionRecord>,
    ) -> Result<ValidationReceipt, ControlError> {
        let mut receipt = self.inner.validate(config, release, previous)?;
        receipt.required_health = minimum_health_checks(config, previous)?;
        Ok(receipt)
    }
    fn stage(
        &self,
        op: &OperationId,
        plan: &ChangePlan,
        cancel: &CancellationToken,
    ) -> Result<(), ControlError> {
        self.inner.stage(op, plan, cancel)
    }
    fn activate(
        &self,
        op: &OperationId,
        plan: &ChangePlan,
        previous: Option<&RevisionRecord>,
    ) -> Result<RuntimeActivation, ControlError> {
        self.inner.activate(op, plan, previous)
    }
    fn verify(&self, op: &OperationId, plan: &ChangePlan) -> Result<RuntimeHealth, ControlError> {
        let mut health = self.inner.verify(op, plan)?;
        health.checked_at_ms = self.clock.now_ms()?;
        health.checks = plan
            .body()
            .validation
            .required_health
            .iter()
            .cloned()
            .map(|check| CheckResult {
                check,
                outcome: CheckOutcome::Passed,
            })
            .collect();
        Ok(health)
    }
    fn stop_candidate(&self, op: &OperationId, plan: &ChangePlan) -> Result<(), ControlError> {
        self.inner.stop_candidate(op, plan)
    }
    fn restore_previous(
        &self,
        op: &OperationId,
        previous: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        self.inner.restore_previous(op, previous)
    }
    fn verify_previous(
        &self,
        op: &OperationId,
        previous: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        self.inner.verify_previous(op, previous)
    }
    fn discard_stage(&self, op: &OperationId) -> Result<(), ControlError> {
        self.inner.discard_stage(op)
    }
}

struct SecretFixture {
    service: ControlService,
    store: Arc<FaultStore>,
    manager: Arc<MemorySecrets>,
    runtime: Arc<ObservationRuntime>,
    clock: Arc<TestClock>,
}
impl SecretFixture {
    fn new() -> Self {
        let store = Arc::new(FaultStore::default());
        let manager = Arc::new(MemorySecrets::default());
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let runtime = Arc::new(ObservationRuntime {
            inner: TestRuntime::default(),
            clock: clock.clone(),
            fault: AtomicUsize::new(0),
            observations: AtomicUsize::new(0),
        });
        let service = ControlService::new(
            store.clone(),
            runtime.clone(),
            Arc::new(TestSystem::default()),
            clock.clone(),
        )
        .with_secret_manager(manager.clone());
        Self {
            service,
            store,
            manager,
            runtime,
            clock,
        }
    }
    fn revision(&self) -> Revision {
        self.store.read().unwrap().active_revision
    }
    fn reopened_service(&self) -> ControlService {
        // New service instance over the same test durable-state/vault ports;
        // no secret/result is carried in a service-local recovery cache.
        ControlService::new(
            self.store.clone(),
            self.runtime.clone(),
            Arc::new(TestSystem::default()),
            self.clock.clone(),
        )
        .with_secret_manager(self.manager.clone())
    }
    fn create(&self, key: &str) -> CredentialSummary {
        self.service
            .create_credential(&principal(), self.revision(), idem(key), create_payload())
            .unwrap()
    }
    fn commit(&self, config: ProductConfig, key: &str) -> Revision {
        let mut request = plan_request();
        request.expected_revision = self.revision();
        request.config = config;
        let plan = self.service.plan(request).unwrap();
        let op = self.service.submit(apply_request(&plan, key)).unwrap();
        assert_eq!(
            self.service
                .run(&op.id, &CancellationToken::default())
                .unwrap()
                .state,
            OperationState::Committed
        );
        self.revision()
    }
    fn publish(&self, payload: PublicationCreatePayload, key: &str) -> PublicationSummary {
        self.service
            .create_publication(&principal(), self.revision(), idem(key), payload)
            .unwrap()
    }
    fn issue(&self, publication: &PublicationSummary, key: &str) -> IssuedPublicationToken {
        self.service
            .issue_publication_token(
                &principal(),
                &publication.id,
                publication.revision,
                idem(key),
                issue_payload(),
            )
            .unwrap()
    }
}
fn idem(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value).unwrap()
}
fn confirmed() -> ExplicitConfirmation {
    ExplicitConfirmation::try_from(true).unwrap()
}
fn create_payload() -> CredentialCreatePayload {
    CredentialCreatePayload {
        kind: NodeCredentialKind::Uuid {},
        confirm_generate: confirmed(),
    }
}
fn retire_payload() -> CredentialRetirePayload {
    CredentialRetirePayload {
        confirm_retire: confirmed(),
    }
}
fn issue_payload() -> PublicationIssuePayload {
    PublicationIssuePayload {
        expires_in_seconds: 300,
        confirm_issue_secret_url: confirmed(),
    }
}
fn revoke_payload() -> PublicationRevokePayload {
    PublicationRevokePayload {
        confirm_revoke_access: confirmed(),
    }
}
fn listener(reference: &SecretRef, id: &str, port: u16) -> ServerListener {
    ServerListener {
        schema_version: 1,
        id: ListenerId::new(id).unwrap(),
        name: format!("Synthetic {id}"),
        enabled: true,
        bind: BindAddress {
            address: "127.0.0.1".parse().unwrap(),
            port,
        },
        protocol: ServerProtocol::Proxy {
            protocol: Protocol::Vless { flow: None },
            users: vec![ListenerUser {
                id: UserId::new("synthetic-node-user").unwrap(),
                credential_ref: reference.clone(),
                enabled: true,
            }],
        },
        transport: Transport::Tcp {},
        security: ServerSecurity::None {},
        requirements: vec![],
    }
}
fn config(listeners: Vec<ServerListener>) -> ProductConfig {
    ProductConfig {
        listeners,
        ..plan_request().config
    }
}
fn source(listener: &ServerListener) -> PublicationSource {
    PublicationSource {
        listener_id: listener.id.clone(),
        user_id: UserId::new("synthetic-node-user").unwrap(),
        endpoint: Endpoint {
            host: "publication.example.invalid".into(),
            port: listener.bind.port,
        },
        client_security: ClientSecurity::None {},
    }
}
fn publication_payload(listeners: &[ServerListener]) -> PublicationCreatePayload {
    PublicationCreatePayload {
        name: "Synthetic publication".into(),
        enabled: true,
        format: PublicationFormat::UriList,
        sources: listeners.iter().map(source).collect(),
        confirm_publish_connection_secrets: confirmed(),
    }
}
fn active_fixture() -> (SecretFixture, CredentialSummary, PublicationSummary) {
    let f = SecretFixture::new();
    let credential = f.create("create-node");
    let l = listener(&credential.secret_ref, "synthetic-listener", 23450);
    f.commit(config(vec![l.clone()]), "activate-node");
    let publication = f.publish(publication_payload(&[l]), "create-publication");
    (f, credential, publication)
}
fn fetch(
    f: &SecretFixture,
    id: &PublicationId,
    token: &SecretBytes,
) -> Result<SubscriptionContent, ControlError> {
    f.service
        .fetch_publication(id, SecretBytes::new(token.expose().to_vec()))
}
fn assert_safe_state(f: &SecretFixture, secrets: &[&SecretBytes]) {
    let state = f.store.serialized();
    let journal = serde_json::to_vec(&*f.store.inner.journal.lock().unwrap()).unwrap();
    for secret in secrets {
        assert!(!secret.expose().is_empty());
        assert!(!state
            .windows(secret.expose().len())
            .any(|w| w == secret.expose()));
        assert!(!journal
            .windows(secret.expose().len())
            .any(|w| w == secret.expose()));
    }
    f.store.read().unwrap().verify_integrity().unwrap();
}

#[test]
fn credential_confirmation_revision_and_tuple_capability_fail_before_entropy() {
    assert!(
        serde_json::from_value::<CredentialCreatePayload>(serde_json::json!({
            "kind": {"kind": "uuid"}, "confirmGenerate": false
        }))
        .is_err()
    );
    let f = SecretFixture::new();
    assert!(matches!(
        f.service.create_credential(
            &principal(),
            Revision::new(1).unwrap(),
            idem("stale"),
            create_payload()
        ),
        Err(ControlError::RevisionConflict { .. })
    ));
    for kind in [
        NodeCredentialKind::UsernamePassword {},
        NodeCredentialKind::UuidPassword {},
    ] {
        assert!(matches!(
            f.service.create_credential(
                &principal(),
                Revision::ZERO,
                idem("tuple-unavailable"),
                CredentialCreatePayload {
                    kind,
                    confirm_generate: confirmed()
                }
            ),
            Err(ControlError::ExecutorUnavailable)
        ));
    }
    assert_eq!(f.manager.credential_entropy.load(Ordering::SeqCst), 0);
    assert_eq!(f.store.persists.load(Ordering::SeqCst), 0);
}

#[test]
fn credential_create_retry_is_same_safe_receipt_without_second_entropy_or_vault_write() {
    let f = SecretFixture::new();
    let first = f.create("same-create");
    let before = f.store.serialized();
    let repeated = f
        .service
        .create_credential(
            &principal(),
            Revision::ZERO,
            idem("same-create"),
            create_payload(),
        )
        .unwrap();
    assert_eq!(first, repeated);
    assert_eq!(before, f.store.serialized());
    assert_eq!(f.manager.credential_entropy.load(Ordering::SeqCst), 1);
    assert_eq!(f.manager.puts.load(Ordering::SeqCst), 1);
    let raw = f.manager.current(&first.secret_ref).unwrap();
    assert_safe_state(&f, &[&raw]);
    let receipt = serde_json::to_vec(&first).unwrap();
    assert!(!receipt
        .windows(raw.expose().len())
        .any(|w| w == raw.expose()));
    let mut changed = create_payload();
    changed.kind = NodeCredentialKind::Password {};
    assert!(matches!(
        f.service
            .create_credential(&principal(), Revision::ZERO, idem("same-create"), changed),
        Err(ControlError::IdempotencyConflict)
    ));
    assert_eq!(f.manager.credential_entropy.load(Ordering::SeqCst), 1);
}

#[test]
fn credential_create_scopes_idempotency_and_inventory_to_principal() {
    let f = SecretFixture::new();
    let a = f.create("same-key");
    let other = UserId::new("other-administrator").unwrap();
    let b = f
        .service
        .create_credential(&other, Revision::ZERO, idem("same-key"), create_payload())
        .unwrap();
    assert_ne!(a.id, b.id);
    assert_eq!(
        f.service
            .credential_inventory(&principal())
            .unwrap()
            .credentials,
        vec![a.clone()]
    );
    assert_eq!(
        f.service.credential_inventory(&other).unwrap().credentials,
        vec![b]
    );
    assert!(matches!(
        f.service.retire_credential(
            &other,
            &a.id,
            a.revision,
            idem("steal-retire"),
            retire_payload()
        ),
        Err(ControlError::NotFound)
    ));
    assert_eq!(f.manager.retires.load(Ordering::SeqCst), 0);
}

#[test]
fn create_failed_before_vault_write_recovers_terminal_failure_without_regeneration() {
    let f = SecretFixture::new();
    f.manager.put_failure.store(1, Ordering::SeqCst);
    assert!(matches!(
        f.service.create_credential(
            &principal(),
            Revision::ZERO,
            idem("put-fails"),
            create_payload()
        ),
        Err(ControlError::RecoveryRequired)
    ));
    assert!(f.store.read().unwrap().needs_recovery());
    assert!(f
        .service
        .credential_inventory(&principal())
        .unwrap()
        .credentials
        .is_empty());
    assert!(matches!(
        f.service.create_credential(
            &principal(),
            Revision::ZERO,
            idem("put-fails"),
            create_payload()
        ),
        Err(ControlError::RecoveryRequired)
    ));
    assert!(matches!(
        f.service.plan(plan_request()),
        Err(ControlError::RecoveryRequired)
    ));
    f.reopened_service().recover().unwrap();
    assert!(!f.store.read().unwrap().needs_recovery());
    assert!(matches!(
        f.service.create_credential(
            &principal(),
            Revision::ZERO,
            idem("put-fails"),
            create_payload()
        ),
        Err(ControlError::ExecutorFailed)
    ));
    assert_eq!(f.manager.credential_entropy.load(Ordering::SeqCst), 1);
    assert_eq!(f.manager.puts.load(Ordering::SeqCst), 1);
    assert!(f.manager.values.lock().unwrap().is_empty());
}

#[test]
fn create_uncertain_after_vault_write_recovers_original_ref_and_never_generates_again() {
    let f = SecretFixture::new();
    f.manager.put_failure.store(2, Ordering::SeqCst);
    assert!(matches!(
        f.service.create_credential(
            &principal(),
            Revision::ZERO,
            idem("put-uncertain"),
            create_payload()
        ),
        Err(ControlError::RecoveryRequired)
    ));
    assert!(f
        .service
        .credential_inventory(&principal())
        .unwrap()
        .credentials
        .is_empty());
    f.reopened_service().recover().unwrap();
    let receipt = f
        .service
        .create_credential(
            &principal(),
            Revision::ZERO,
            idem("put-uncertain"),
            create_payload(),
        )
        .unwrap();
    assert_eq!(receipt.state, CredentialState::Available);
    assert!(f.manager.current(&receipt.secret_ref).is_some());
    assert_eq!(f.manager.credential_entropy.load(Ordering::SeqCst), 1);
    assert_eq!(f.manager.puts.load(Ordering::SeqCst), 1);
    let before = f.store.serialized();
    f.reopened_service().recover().unwrap();
    assert_eq!(before, f.store.serialized());
}

#[test]
fn create_terminal_checkpoint_failure_recovers_without_duplicate_vault_write() {
    for after_commit in [false, true] {
        let f = SecretFixture::new();
        f.store.fail_nth_next(2, after_commit);
        assert!(matches!(
            f.service.create_credential(
                &principal(),
                Revision::ZERO,
                idem("finish-uncertain"),
                create_payload()
            ),
            Err(ControlError::StorageUnavailable)
        ));
        f.reopened_service().recover().unwrap();
        let receipt = f
            .service
            .create_credential(
                &principal(),
                Revision::ZERO,
                idem("finish-uncertain"),
                create_payload(),
            )
            .unwrap();
        assert!(f.manager.current(&receipt.secret_ref).is_some());
        assert_eq!(f.manager.credential_entropy.load(Ordering::SeqCst), 1);
        assert_eq!(f.manager.puts.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn uncertain_durable_prepare_never_puts_before_explicit_recovery() {
    let f = SecretFixture::new();
    f.store.fail_nth_next(1, true);
    assert!(matches!(
        f.service.create_credential(
            &principal(),
            Revision::ZERO,
            idem("prepare-uncertain"),
            create_payload()
        ),
        Err(ControlError::StorageUnavailable)
    ));
    assert_eq!(f.manager.puts.load(Ordering::SeqCst), 0);
    assert!(f.store.read().unwrap().needs_recovery());
    f.reopened_service().recover().unwrap();
    assert!(matches!(
        f.service.create_credential(
            &principal(),
            Revision::ZERO,
            idem("prepare-uncertain"),
            create_payload()
        ),
        Err(ControlError::ExecutorFailed)
    ));
    assert_eq!(f.manager.credential_entropy.load(Ordering::SeqCst), 1);
}

#[test]
fn retirement_of_unused_value_is_idempotent_and_never_revives_it() {
    let f = SecretFixture::new();
    let c = f.create("unused");
    let retired = f
        .service
        .retire_credential(
            &principal(),
            &c.id,
            c.revision,
            idem("retire"),
            retire_payload(),
        )
        .unwrap();
    assert_eq!(retired.state, CredentialState::Retired);
    assert_eq!(retired.display_key, CredentialDisplayKey::Retired);
    assert_eq!(retired.revision.get(), c.revision.get() + 1);
    assert!(f.manager.current(&c.secret_ref).is_none());
    let before = f.store.serialized();
    assert_eq!(
        f.service
            .retire_credential(
                &principal(),
                &c.id,
                c.revision,
                idem("retire"),
                retire_payload()
            )
            .unwrap(),
        retired
    );
    f.reopened_service().recover().unwrap();
    assert_eq!(before, f.store.serialized());
    assert_eq!(f.manager.retires.load(Ordering::SeqCst), 1);
    assert!(f.manager.current(&c.secret_ref).is_none());
}

#[test]
fn retirement_rejects_drafts_unapplied_plans_and_historical_revisions() {
    for retained_by in ["draft", "plan", "history"] {
        let f = SecretFixture::new();
        let c = f.create("retained");
        let cfg = config(vec![listener(&c.secret_ref, "retained-listener", 23451)]);
        match retained_by {
            "draft" => {
                f.service
                    .edit_draft(DraftRequest {
                        principal: principal(),
                        draft_id: None,
                        expected_revision: f.revision(),
                        idempotency_key: idem("draft-ref"),
                        mutation: DraftMutation::Create(cfg),
                    })
                    .unwrap();
            }
            "plan" => {
                let mut req = plan_request();
                req.config = cfg;
                f.service.plan(req).unwrap();
            }
            "history" => {
                f.commit(cfg, "initial");
                f.commit(config(vec![]), "remove-listener");
            }
            _ => unreachable!(),
        }
        let before = f.store.serialized();
        assert!(matches!(
            f.service.retire_credential(
                &principal(),
                &c.id,
                c.revision,
                idem("must-retain"),
                retire_payload()
            ),
            Err(ControlError::ResourceConflict)
        ));
        assert_eq!(before, f.store.serialized());
        assert_eq!(f.manager.retires.load(Ordering::SeqCst), 0);
        assert!(f.manager.current(&c.secret_ref).is_some());
    }
}

#[test]
fn retirement_uncertain_before_or_after_vault_tombstone_resumes_no_revival() {
    for failure in [1, 2] {
        let f = SecretFixture::new();
        let c = f.create("retire-uncertain");
        f.manager.retire_failure.store(failure, Ordering::SeqCst);
        assert!(matches!(
            f.service.retire_credential(
                &principal(),
                &c.id,
                c.revision,
                idem("retire-uncertain"),
                retire_payload()
            ),
            Err(ControlError::RecoveryRequired)
        ));
        assert!(f.store.read().unwrap().needs_recovery());
        assert!(matches!(
            f.service.create_credential(
                &principal(),
                f.revision(),
                idem("blocked-until-retire-recovered"),
                create_payload()
            ),
            Err(ControlError::RecoveryRequired)
        ));
        f.reopened_service().recover().unwrap();
        let result = f
            .service
            .retire_credential(
                &principal(),
                &c.id,
                c.revision,
                idem("retire-uncertain"),
                retire_payload(),
            )
            .unwrap();
        assert_eq!(result.state, CredentialState::Retired);
        assert!(f.manager.current(&c.secret_ref).is_none());
        assert_eq!(f.manager.retires.load(Ordering::SeqCst), 2);
        assert_eq!(f.manager.puts.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn retirement_terminal_checkpoint_failure_keeps_tombstone_and_recovers() {
    let f = SecretFixture::new();
    let c = f.create("retire-storage-failure");
    f.store.fail_nth_next(2, false);
    assert!(matches!(
        f.service.retire_credential(
            &principal(),
            &c.id,
            c.revision,
            idem("retire-finish"),
            retire_payload()
        ),
        Err(ControlError::StorageUnavailable)
    ));
    assert!(f.manager.current(&c.secret_ref).is_none());
    f.reopened_service().recover().unwrap();
    assert_eq!(
        f.service
            .credential_inventory(&principal())
            .unwrap()
            .credentials[0]
            .state,
        CredentialState::Retired
    );
    assert!(f.manager.current(&c.secret_ref).is_none());
}

#[test]
fn publication_requires_current_exact_and_fresh_complete_observation() {
    for fault in 1..=11 {
        let f = SecretFixture::new();
        let c = f.create("observer-node");
        let l = listener(&c.secret_ref, "observer-listener", 23452);
        f.commit(config(vec![l.clone()]), "observer-active");
        f.clock.0.store(40_000, Ordering::SeqCst);
        f.runtime.fault.store(fault, Ordering::SeqCst);
        let before = f.store.serialized();
        let result = f.service.create_publication(
            &principal(),
            f.revision(),
            idem("bad-observation"),
            publication_payload(&[l]),
        );
        if fault == 1 {
            assert!(matches!(result, Err(ControlError::ExecutorUnavailable)));
        } else {
            assert!(matches!(result, Err(ControlError::HealthFailed)));
        }
        assert_eq!(before, f.store.serialized());
        assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn publication_does_not_promote_a_draft_or_plan_to_active_configuration() {
    let f = SecretFixture::new();
    let c = f.create("unapplied-node");
    let l = listener(&c.secret_ref, "unapplied-listener", 23453);
    let mut request = plan_request();
    request.config = config(vec![l.clone()]);
    f.service.plan(request).unwrap();
    let before = f.store.serialized();
    assert!(matches!(
        f.service.create_publication(
            &principal(),
            Revision::ZERO,
            idem("not-active"),
            publication_payload(&[l])
        ),
        Err(ControlError::ExecutorUnavailable)
    ));
    assert_eq!(before, f.store.serialized());
    assert_eq!(f.runtime.observations.load(Ordering::SeqCst), 0);
}

#[test]
fn publication_issue_same_key_loses_secret_result_but_never_generates_another_token() {
    let (f, c, p) = active_fixture();
    let issued = f.issue(&p, "issue-once");
    let before = f.store.serialized();
    assert!(matches!(
        f.service.issue_publication_token(
            &principal(),
            &p.id,
            p.revision,
            idem("issue-once"),
            issue_payload()
        ),
        Err(ControlError::SecretResultUnavailable)
    ));
    assert_eq!(before, f.store.serialized());
    assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 1);
    let raw = f.manager.current(&c.secret_ref).unwrap();
    assert_safe_state(&f, &[&raw, &issued.token]);
    let receipt = serde_json::to_vec(&issued.publication).unwrap();
    assert!(!receipt
        .windows(issued.token.expose().len())
        .any(|w| w == issued.token.expose()));
    let mut changed = issue_payload();
    changed.expires_in_seconds = 600;
    assert!(matches!(
        f.service.issue_publication_token(
            &principal(),
            &p.id,
            p.revision,
            idem("issue-once"),
            changed
        ),
        Err(ControlError::IdempotencyConflict)
    ));
    assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 1);
}

#[test]
fn publication_issue_unknown_commit_returns_no_token_and_same_key_cannot_regenerate() {
    let (f, _, p) = active_fixture();
    f.store.fail_nth_next(2, true);
    assert!(matches!(
        f.service.issue_publication_token(
            &principal(),
            &p.id,
            p.revision,
            idem("issue-uncertain"),
            issue_payload()
        ),
        Err(ControlError::StorageUnavailable)
    ));
    assert!(matches!(
        f.service.issue_publication_token(
            &principal(),
            &p.id,
            p.revision,
            idem("issue-uncertain"),
            issue_payload()
        ),
        Err(ControlError::SecretResultUnavailable)
    ));
    assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.service
            .publication(&principal(), &p.id)
            .unwrap()
            .token
            .state,
        PublicationTokenState::Active
    );
}

#[test]
fn publication_rotation_rejects_old_token_and_revoke_does_not_revoke_cached_nodes() {
    let (f, c, p) = active_fixture();
    let first = f.issue(&p, "first-token");
    let cached = fetch(&f, &p.id, &first.token).unwrap();
    let batch = vp_product_import::parse(
        cached.bytes.expose(),
        vp_product_import::ImportFormat::UriList,
    )
    .unwrap();
    assert_eq!(batch.entries.len(), 1);
    assert!(!batch.has_unimported_fields);
    let candidate = batch.entries[0].candidate.as_ref().unwrap();
    let vault_before = f.manager.current(&c.secret_ref).unwrap();
    assert!(candidate.secrets().credential.primary.expose() == vault_before.expose());
    let rotated = f.issue(&first.publication, "rotate-token");
    assert!(first.token.expose() != rotated.token.expose());
    assert!(matches!(
        fetch(&f, &p.id, &first.token),
        Err(ControlError::PermissionDenied)
    ));
    assert!(fetch(&f, &p.id, &rotated.token).is_ok());
    let active_before = f.service.active_config().unwrap();
    let revoked = f
        .service
        .revoke_publication_token(
            &principal(),
            &p.id,
            rotated.publication.revision,
            idem("revoke"),
            revoke_payload(),
        )
        .unwrap();
    assert_eq!(revoked.token.state, PublicationTokenState::Revoked);
    assert!(matches!(
        fetch(&f, &p.id, &rotated.token),
        Err(ControlError::PermissionDenied)
    ));
    assert_eq!(f.service.active_config().unwrap(), active_before);
    let vault_after = f.manager.current(&c.secret_ref).unwrap();
    assert!(vault_before.expose() == vault_after.expose());
    assert!(candidate.secrets().credential.primary.expose() == vault_after.expose());
    assert_eq!(f.manager.retires.load(Ordering::SeqCst), 0);
    // This asserts cache/vault semantics, NOT an actual VPN connection test.
    assert_safe_state(&f, &[&vault_after, &first.token, &rotated.token]);
}

#[test]
fn publication_token_expiry_and_clock_regression_are_fail_closed_before_probe() {
    let (f, _, p) = active_fixture();
    let issued = f.issue(&p, "expiring-token");
    let expiry = issued.publication.token.expires_at.unwrap();
    f.clock.0.store(expiry - 1, Ordering::SeqCst);
    assert!(fetch(&f, &p.id, &issued.token).is_ok());
    for now in [
        expiry,
        expiry + 1,
        issued.publication.token.issued_at.unwrap() - 1,
    ] {
        f.clock.0.store(now, Ordering::SeqCst);
        let before = f.store.serialized();
        let observations = f.runtime.observations.load(Ordering::SeqCst);
        assert!(matches!(
            fetch(&f, &p.id, &issued.token),
            Err(ControlError::PermissionDenied)
        ));
        assert_eq!(f.runtime.observations.load(Ordering::SeqCst), observations);
        assert_eq!(before, f.store.serialized());
    }
    f.clock.0.store(expiry, Ordering::SeqCst);
    assert_eq!(
        f.service
            .publication(&principal(), &p.id)
            .unwrap()
            .token
            .state,
        PublicationTokenState::Expired
    );
    // Expiry projection is read-only; it does not rewrite the token record.
    assert_eq!(
        f.store.read().unwrap().secrets.publications[&p.id]
            .summary
            .token
            .state,
        PublicationTokenState::Active
    );
}

#[test]
fn publication_permissions_and_token_scope_prevent_cross_principal_or_publication_access() {
    let (f, _, p) = active_fixture();
    let other = UserId::new("other-publication-admin").unwrap();
    let issued = f.issue(&p, "owner-token");
    assert!(f.service.publications(&other).unwrap().is_empty());
    assert!(matches!(
        f.service.publication(&other, &p.id),
        Err(ControlError::NotFound)
    ));
    assert!(matches!(
        f.service.issue_publication_token(
            &other,
            &p.id,
            issued.publication.revision,
            idem("owner-token"),
            issue_payload()
        ),
        Err(ControlError::NotFound)
    ));
    assert!(matches!(
        f.service.revoke_publication_token(
            &other,
            &p.id,
            issued.publication.revision,
            idem("cross-revoke"),
            revoke_payload()
        ),
        Err(ControlError::NotFound)
    ));
    let current = f.service.active_config().unwrap().1.unwrap();
    let other_publication = f
        .service
        .create_publication(
            &other,
            f.revision(),
            idem("other-publication"),
            publication_payload(&current.listeners),
        )
        .unwrap();
    assert!(matches!(
        fetch(&f, &other_publication.id, &issued.token),
        Err(ControlError::PermissionDenied)
    ));
    assert!(matches!(
        f.service
            .fetch_publication(&p.id, SecretBytes::new(b"synthetic-wrong-token".to_vec())),
        Err(ControlError::PermissionDenied)
    ));
    assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 1);
}

#[test]
fn pinned_publication_goes_stale_until_explicit_republish_to_current_active_revision() {
    let (f, c, p) = active_fixture();
    let issued = f.issue(&p, "pinned-token");
    let cached = fetch(&f, &p.id, &issued.token).unwrap();
    let mut new_listener = listener(&c.secret_ref, "synthetic-listener", 23450);
    new_listener.name = "Explicitly republished listener".into();
    let current = f.commit(config(vec![new_listener.clone()]), "next-active");
    assert_ne!(current, p.source_revision);
    let before = f.store.serialized();
    assert!(matches!(
        fetch(&f, &p.id, &issued.token),
        Err(ControlError::RevisionConflict { .. })
    ));
    assert_eq!(before, f.store.serialized());
    assert!(!cached.bytes.expose().is_empty()); // Previously fetched list is not replaced on failure.
    let replacement = PublicationReplacePayload {
        name: p.name.clone(),
        enabled: true,
        format: p.format,
        source_revision: current,
        sources: vec![source(&new_listener)],
        confirm_publish_connection_secrets: confirmed(),
    };
    let replaced = f
        .service
        .replace_publication(
            &principal(),
            &p.id,
            issued.publication.revision,
            idem("explicit-republish"),
            replacement,
        )
        .unwrap();
    assert_eq!(replaced.source_revision, current);
    let fresh = fetch(&f, &p.id, &issued.token).unwrap();
    assert_eq!(fresh.source_revision, current);
    assert!(fresh.bytes.expose() != cached.bytes.expose());
}

#[test]
fn publication_fetch_observation_failure_returns_no_content_or_success_audit() {
    let (f, _, p) = active_fixture();
    let issued = f.issue(&p, "fetch-probe-token");
    f.runtime.fault.store(3, Ordering::SeqCst);
    let before = f.store.serialized();
    let events = f.store.inner.journal.lock().unwrap().len();
    assert!(matches!(
        fetch(&f, &p.id, &issued.token),
        Err(ControlError::HealthFailed)
    ));
    assert_eq!(before, f.store.serialized());
    assert_eq!(events, f.store.inner.journal.lock().unwrap().len());
    assert!(f
        .service
        .publication(&principal(), &p.id)
        .unwrap()
        .last_successful_read_at
        .is_none());
}

#[test]
fn publication_fetch_audit_failure_never_returns_partial_content() {
    let (f, _, p) = active_fixture();
    let issued = f.issue(&p, "audit-token");
    let before = f.store.serialized();
    f.store.fail_nth_next(1, false);
    assert!(matches!(
        fetch(&f, &p.id, &issued.token),
        Err(ControlError::StorageUnavailable)
    ));
    assert_eq!(before, f.store.serialized());
    let fetched = fetch(&f, &p.id, &issued.token).unwrap();
    assert!(!fetched.bytes.expose().is_empty());
    let events = f.store.inner.journal.lock().unwrap();
    let audit = events.last().unwrap().security.as_ref().unwrap();
    assert!(matches!(
        audit.action,
        SecurityAuditAction::PublicationFetched
    ));
    assert!(
        matches!(&audit.actor, SecurityAuditActor::PublicationToken { id, version } if id == &p.id && *version == issued.publication.token.version)
    );
}

#[test]
fn unsupported_or_lossy_second_source_rejects_the_entire_publication_atomically() {
    for lossy in [false, true] {
        let f = SecretFixture::new();
        let c = f.create("atomic-source-node");
        let good = listener(&c.secret_ref, "exportable", 23454);
        let mut bad = listener(&c.secret_ref, "not-exportable", 23455);
        if lossy {
            if let ServerProtocol::Proxy { protocol, .. } = &mut bad.protocol {
                *protocol = Protocol::Vmess {
                    cipher: VmessCipher::Auto,
                    alter_id: 1,
                };
            }
        } else {
            bad.transport = Transport::Ws {
                path: "/synthetic".into(),
                host: None,
                early_data: None,
            };
        }
        f.commit(
            config(vec![good.clone(), bad.clone()]),
            "atomic-source-active",
        );
        let before = f.store.serialized();
        let loads = f.manager.loads.load(Ordering::SeqCst);
        let result = f.service.create_publication(
            &principal(),
            f.revision(),
            idem("all-or-none"),
            publication_payload(&[good, bad]),
        );
        if lossy {
            assert!(matches!(result, Err(ControlError::ExportLossy)));
        } else {
            assert!(matches!(result, Err(ControlError::ExecutorUnavailable)));
        }
        assert!(f.manager.loads.load(Ordering::SeqCst) > loads); // First entry was assembled privately.
        assert_eq!(before, f.store.serialized());
        assert!(f.service.publications(&principal()).unwrap().is_empty());
        assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn publication_source_limits_duplicates_and_missing_users_fail_before_any_commit() {
    let (f, _, p) = active_fixture();
    let current = f.service.active_config().unwrap().1.unwrap();
    for count in [0, 2, 33] {
        let mut payload = publication_payload(&current.listeners);
        payload.sources = vec![payload.sources[0].clone(); count];
        let before = f.store.serialized();
        assert!(matches!(
            f.service.create_publication(
                &principal(),
                f.revision(),
                idem("bad-source-count"),
                payload
            ),
            Err(ControlError::InvalidConfiguration)
        ));
        assert_eq!(before, f.store.serialized());
    }
    let mut payload = publication_payload(&current.listeners);
    payload.sources[0].user_id = UserId::new("missing-user").unwrap();
    assert!(matches!(
        f.service.create_publication(
            &principal(),
            f.revision(),
            idem("missing-source-user"),
            payload
        ),
        Err(ControlError::InvalidConfiguration)
    ));
    assert_eq!(f.service.publications(&principal()).unwrap(), vec![p]);
}

#[test]
fn publication_disable_revokes_token_and_reenable_does_not_restore_old_access() {
    let (f, c, p) = active_fixture();
    let issued = f.issue(&p, "disable-token");
    let mut payload = PublicationReplacePayload {
        name: p.name.clone(),
        enabled: false,
        format: p.format,
        source_revision: p.source_revision,
        sources: p.sources.clone(),
        confirm_publish_connection_secrets: confirmed(),
    };
    let disabled = f
        .service
        .replace_publication(
            &principal(),
            &p.id,
            issued.publication.revision,
            idem("disable"),
            payload.clone(),
        )
        .unwrap();
    assert_eq!(disabled.token.state, PublicationTokenState::Revoked);
    assert!(matches!(
        fetch(&f, &p.id, &issued.token),
        Err(ControlError::PermissionDenied)
    ));
    assert!(matches!(
        f.service.issue_publication_token(
            &principal(),
            &p.id,
            disabled.revision,
            idem("disabled-issue"),
            issue_payload()
        ),
        Err(ControlError::PermissionDenied)
    ));
    payload.enabled = true;
    let enabled = f
        .service
        .replace_publication(
            &principal(),
            &p.id,
            disabled.revision,
            idem("reenable"),
            payload,
        )
        .unwrap();
    assert_eq!(enabled.token.state, PublicationTokenState::Revoked);
    assert!(matches!(
        fetch(&f, &p.id, &issued.token),
        Err(ControlError::PermissionDenied)
    ));
    let replacement = f.issue(&enabled, "explicit-new-token");
    assert!(fetch(&f, &p.id, &replacement.token).is_ok());
    assert!(f.manager.current(&c.secret_ref).is_some());
    assert_eq!(f.manager.retires.load(Ordering::SeqCst), 0);
}

#[test]
fn failed_prepare_commit_never_writes_vault_or_advertises_a_credential() {
    let f = SecretFixture::new();
    let before = f.store.serialized();
    f.store.fail_nth_next(1, false);
    assert!(matches!(
        f.service.create_credential(
            &principal(),
            Revision::ZERO,
            idem("prepare-not-committed"),
            create_payload()
        ),
        Err(ControlError::StorageUnavailable)
    ));
    assert_eq!(before, f.store.serialized());
    assert_eq!(f.manager.puts.load(Ordering::SeqCst), 0);
    assert!(f.manager.values.lock().unwrap().is_empty());
    assert!(f
        .service
        .credential_inventory(&principal())
        .unwrap()
        .credentials
        .is_empty());
    f.reopened_service().recover().unwrap();
    assert_eq!(before, f.store.serialized());
}

#[test]
fn new_credential_reference_collision_never_adopts_or_overwrites_existing_vault_data() {
    let f = SecretFixture::new();
    let reference = SecretRef::new("synthetic-managed-1").unwrap();
    f.manager.values.lock().unwrap().insert(
        reference.clone(),
        VaultValue {
            kind: NodeCredentialKind::Uuid {},
            version: 1,
            bytes: SecretBytes::new(b"00000000-0000-4000-8000-000000000099".to_vec()),
            retired: false,
        },
    );
    let original = f.manager.current(&reference).unwrap();
    let before = f.store.serialized();
    assert!(matches!(
        f.service.create_credential(
            &principal(),
            Revision::ZERO,
            idem("collision"),
            create_payload()
        ),
        Err(ControlError::ResourceConflict)
    ));
    assert_eq!(before, f.store.serialized());
    assert_eq!(f.manager.puts.load(Ordering::SeqCst), 0);
    assert!(original.expose() == f.manager.current(&reference).unwrap().expose());
}

#[test]
fn token_expiring_during_probe_never_escapes_as_content_or_success_audit() {
    let (f, _, p) = active_fixture();
    let issued = f.issue(&p, "expires-in-probe");
    f.runtime.fault.store(12, Ordering::SeqCst);
    let before = f.store.serialized();
    let events = f.store.inner.journal.lock().unwrap().len();
    assert!(matches!(
        fetch(&f, &p.id, &issued.token),
        Err(ControlError::PermissionDenied)
    ));
    assert_eq!(before, f.store.serialized());
    assert_eq!(events, f.store.inner.journal.lock().unwrap().len());
}

#[test]
fn publication_and_credential_mutations_enforce_their_own_revision_cas() {
    let (f, c, p) = active_fixture();
    let wrong = Revision::new(999).unwrap();
    let before = f.store.serialized();
    assert!(matches!(
        f.service.retire_credential(
            &principal(),
            &c.id,
            wrong,
            idem("retire-stale"),
            retire_payload()
        ),
        Err(ControlError::RevisionConflict { .. })
    ));
    assert!(matches!(
        f.service.issue_publication_token(
            &principal(),
            &p.id,
            wrong,
            idem("issue-stale"),
            issue_payload()
        ),
        Err(ControlError::RevisionConflict { .. })
    ));
    assert!(matches!(
        f.service.revoke_publication_token(
            &principal(),
            &p.id,
            wrong,
            idem("revoke-stale"),
            revoke_payload()
        ),
        Err(ControlError::RevisionConflict { .. })
    ));
    let replace = PublicationReplacePayload {
        name: p.name.clone(),
        enabled: true,
        format: p.format,
        source_revision: p.source_revision,
        sources: p.sources.clone(),
        confirm_publish_connection_secrets: confirmed(),
    };
    assert!(matches!(
        f.service
            .replace_publication(&principal(), &p.id, wrong, idem("replace-stale"), replace),
        Err(ControlError::RevisionConflict { .. })
    ));
    for expires_in_seconds in [0, 299, 2_592_001, u32::MAX] {
        assert!(matches!(
            f.service.issue_publication_token(
                &principal(),
                &p.id,
                p.revision,
                idem("issue-bad-expiry"),
                PublicationIssuePayload {
                    expires_in_seconds,
                    confirm_issue_secret_url: confirmed()
                }
            ),
            Err(ControlError::InvalidRequest)
        ));
    }
    assert_eq!(before, f.store.serialized());
    assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 0);
    assert_eq!(f.manager.retires.load(Ordering::SeqCst), 0);
}

#[test]
fn disabled_listener_or_user_mapping_is_not_publishable() {
    for disabled_listener in [false, true] {
        let f = SecretFixture::new();
        let c = f.create("disabled-source-node");
        let mut l = listener(&c.secret_ref, "disabled-source", 23456);
        let mut s = source(&l);
        if disabled_listener {
            l.enabled = false;
        } else if let ServerProtocol::Proxy { users, .. } = &mut l.protocol {
            let disabled_id = UserId::new("synthetic-disabled-user").unwrap();
            users.push(ListenerUser {
                id: disabled_id.clone(),
                credential_ref: c.secret_ref.clone(),
                enabled: false,
            });
            s.user_id = disabled_id;
        }
        f.commit(config(vec![l.clone()]), "disabled-source-active");
        let mut payload = publication_payload(&[l]);
        payload.sources = vec![s];
        let before = f.store.serialized();
        assert!(matches!(
            f.service.create_publication(
                &principal(),
                f.revision(),
                idem("disabled-source-publication"),
                payload
            ),
            Err(ControlError::InvalidConfiguration)
        ));
        assert_eq!(before, f.store.serialized());
        assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn invalid_second_vault_credential_rejects_whole_publication_without_metadata_commit() {
    let f = SecretFixture::new();
    let a = f.create("valid-uuid");
    let b = f.create("invalid-uuid");
    // Intentional corruption only inside this test vault, never product storage.
    f.manager
        .values
        .lock()
        .unwrap()
        .get_mut(&b.secret_ref)
        .unwrap()
        .bytes = SecretBytes::new(b"synthetic-malformed-uuid".to_vec());
    let listeners = vec![
        listener(&a.secret_ref, "valid-node", 23457),
        listener(&b.secret_ref, "invalid-node", 23458),
    ];
    f.commit(config(listeners.clone()), "invalid-vault-active");
    let before = f.store.serialized();
    assert!(matches!(
        f.service.create_publication(
            &principal(),
            f.revision(),
            idem("invalid-vault-publication"),
            publication_payload(&listeners)
        ),
        Err(ControlError::InvalidConfiguration)
    ));
    assert_eq!(before, f.store.serialized());
    assert!(f.service.publications(&principal()).unwrap().is_empty());
}

#[test]
fn bounded_credential_inventory_rejects_129th_before_entropy_or_write() {
    let f = SecretFixture::new();
    for n in 0..128 {
        f.create(&format!("bounded-credential-{n}"));
    }
    let before = f.store.serialized();
    let entropy = f.manager.credential_entropy.load(Ordering::SeqCst);
    assert_eq!(
        f.service
            .credential_inventory(&principal())
            .unwrap()
            .credentials
            .len(),
        128
    );
    assert!(matches!(
        f.service.create_credential(
            &principal(),
            f.revision(),
            idem("bounded-credential-overflow"),
            create_payload()
        ),
        Err(ControlError::InvalidRequest)
    ));
    assert_eq!(f.manager.credential_entropy.load(Ordering::SeqCst), entropy);
    assert_eq!(before, f.store.serialized());
}

#[test]
fn bounded_publication_inventory_rejects_17th_before_probe_or_write() {
    let (f, _, p) = active_fixture();
    let current = f.service.active_config().unwrap().1.unwrap();
    for n in 1..16 {
        f.publish(
            publication_payload(&current.listeners),
            &format!("bounded-publication-{n}"),
        );
    }
    let before = f.store.serialized();
    let probes = f.runtime.observations.load(Ordering::SeqCst);
    assert_eq!(f.service.publications(&principal()).unwrap().len(), 16);
    assert!(matches!(
        f.service.create_publication(
            &principal(),
            f.revision(),
            idem("bounded-publication-overflow"),
            publication_payload(&current.listeners)
        ),
        Err(ControlError::InvalidRequest)
    ));
    assert_eq!(f.runtime.observations.load(Ordering::SeqCst), probes);
    assert_eq!(before, f.store.serialized());
    assert_eq!(f.service.publication(&principal(), &p.id).unwrap(), p);
}

#[test]
fn token_issue_reservation_failure_never_generates_entropy_or_changes_access() {
    for after_commit in [false, true] {
        let (f, _, p) = active_fixture();
        f.store.fail_nth_next(1, after_commit);
        assert!(matches!(
            f.service.issue_publication_token(
                &principal(),
                &p.id,
                p.revision,
                idem("reservation-failure"),
                issue_payload()
            ),
            Err(ControlError::StorageUnavailable)
        ));
        assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 0);
        assert_eq!(f.service.publication(&principal(), &p.id).unwrap(), p);
        assert!(!f.store.read().unwrap().needs_recovery());
        if after_commit {
            // Lost acknowledgement of a durable consumed key: never regenerate.
            assert!(matches!(
                f.reopened_service().issue_publication_token(
                    &principal(),
                    &p.id,
                    p.revision,
                    idem("reservation-failure"),
                    issue_payload()
                ),
                Err(ControlError::SecretResultUnavailable)
            ));
            assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 0);
        } else {
            // No reservation and no previous entropy: a retry can generate once.
            assert!(f
                .reopened_service()
                .issue_publication_token(
                    &principal(),
                    &p.id,
                    p.revision,
                    idem("reservation-failure"),
                    issue_payload()
                )
                .is_ok());
            assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn consumed_issue_key_survives_final_commit_failure_and_preserves_old_token() {
    let (f, _, p) = active_fixture();
    let original = f.issue(&p, "original-before-failed-rotation");
    f.store.fail_nth_next(2, false);
    assert!(matches!(
        f.service.issue_publication_token(
            &principal(),
            &p.id,
            original.publication.revision,
            idem("failed-final-rotation"),
            issue_payload()
        ),
        Err(ControlError::StorageUnavailable)
    ));
    assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 2);
    assert_eq!(
        f.service.publication(&principal(), &p.id).unwrap(),
        original.publication
    );
    assert!(!f.store.read().unwrap().needs_recovery());
    assert!(matches!(
        f.reopened_service().issue_publication_token(
            &principal(),
            &p.id,
            original.publication.revision,
            idem("failed-final-rotation"),
            issue_payload()
        ),
        Err(ControlError::SecretResultUnavailable)
    ));
    assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 2);
    assert!(fetch(&f, &p.id, &original.token).is_ok());
    let current = f.service.publication(&principal(), &p.id).unwrap();
    let deliberate_rotation = f.issue(&current, "explicit-rotation-after-unknown");
    assert!(matches!(
        fetch(&f, &p.id, &original.token),
        Err(ControlError::PermissionDenied)
    ));
    assert!(fetch(&f, &p.id, &deliberate_rotation.token).is_ok());
    assert_eq!(f.manager.token_entropy.load(Ordering::SeqCst), 3);
}
