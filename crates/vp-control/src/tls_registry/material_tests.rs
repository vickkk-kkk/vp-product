use super::*;
use crate::{TlsMaterialAdmission, TlsMaterialVault};
use std::sync::Mutex;
use vp_product_domain::*;
impl TlsMaterialVault for Mutex<Vault> {
    fn material_binding(&self, d: Instant) -> Result<InstanceBinding, ControlError> {
        self.lock().unwrap().binding(d)
    }
    fn read_tls_material(
        &self,
        r: &SecretRef,
        d: Instant,
    ) -> Result<Option<TlsRawRecord>, ControlError> {
        self.lock().unwrap().read(r, d)
    }
    fn read_credential_material(
        &self,
        r: &SecretRef,
        d: Instant,
    ) -> Result<Option<TlsRawRecord>, ControlError> {
        self.lock().unwrap().read(r, d)
    }
}
fn staged(m: &Material, c: &Wall) -> (Lease, Mutex<Vault>, OperationId) {
    let mut l = Lease::new();
    let v = Vault::new();
    TlsImportService::new(&m.policy, c)
        .import(
            &mut l,
            &v,
            request(m),
            deadline(),
            &CancellationToken::default(),
        )
        .unwrap();
    let credential = SecretRef::new("password-1").unwrap();
    v.data.borrow_mut().insert(
        credential.as_str().into(),
        (1, 7, b"synthetic-password".to_vec()),
    );
    let principal = UserId::new("administrator").unwrap();
    let id = CredentialId::new("credential-1").unwrap();
    l.e.state.secrets.credentials.insert(
        id.clone(),
        crate::CredentialRecord {
            principal: principal.clone(),
            vault_version: 7,
            summary: CredentialSummary {
                schema_version: 1,
                id,
                revision: Revision::ZERO.next().unwrap(),
                secret_ref: credential.clone(),
                kind: NodeCredentialKind::Password {},
                created_at: 1,
                state: CredentialState::Available,
                display_key: CredentialDisplayKey::Managed,
            },
        },
    );
    let config = ProductConfig {
        schema_version: 1,
        minimum_reader_version: 1,
        nodes: vec![],
        subscriptions: vec![],
        listeners: vec![ServerListener {
            schema_version: 1,
            id: ListenerId::new("trojan-1").unwrap(),
            name: "synthetic".into(),
            enabled: true,
            bind: BindAddress {
                address: "127.0.0.1".parse().unwrap(),
                port: 23456,
            },
            protocol: ServerProtocol::Proxy {
                protocol: Protocol::Trojan {},
                users: vec![ListenerUser {
                    id: UserId::new("user-1").unwrap(),
                    credential_ref: credential,
                    enabled: true,
                }],
            },
            transport: Transport::Tcp {},
            security: ServerSecurity::Tls {
                certificate_ref: CertificateId::new("certificate-1").unwrap(),
                private_key_ref: SecretRef::new("tls-key-import-1").unwrap(),
                alpn: vec![],
            },
            requirements: vec![],
        }],
    };
    config.validate().unwrap();
    let release:ReleaseIdentity=serde_json::from_value(serde_json::json!({"releaseId":"release", "productVersion":"synthetic", "adapterVersion":"synthetic", "coreCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "patchsetHash":null,"buildTarget":"test","toolchain":"test","schemaRead":{"minimum":1,"maximum":1},"schemaWrite":{"minimum":1,"maximum":1},"abi":{"major":1,"minor":0},"api":{"major":1,"minor":0},"evidenceManifestHash":null})).unwrap();
    let pid = PlanId::new("plan-1").unwrap();
    let op = OperationId::new("operation-1").unwrap();
    let now = c.now_ms().unwrap();
    let plan = crate::ChangePlan::seal(crate::PlanBody {
        schema_version: 1,
        id: pid.clone(),
        principal: principal.clone(),
        base_revision: Revision::ZERO,
        target_revision: Revision::ZERO.next().unwrap(),
        created_at_ms: now - 1000,
        expires_at_ms: now + 100000,
        validation: crate::ValidationReceipt {
            config_digest: ContentDigest::of("vp.product-config.v1", &config).unwrap(),
            release_digest: ContentDigest::of("vp.release-identity.v1", &release).unwrap(),
            artifact_digest: ContentDigest::bytes(b"synthetic"),
            impact: crate::RestartImpact::ControlledRestart,
            required_health: BTreeSet::new(),
        },
        config,
        release,
        resources: vec![],
    })
    .unwrap();
    l.e.state.plans.insert(pid.clone(), plan);
    l.e.state.operations.insert(
        op.clone(),
        crate::Operation {
            id: op.clone(),
            plan_id: pid,
            principal,
            state: crate::OperationState::Staging,
            created_at_ms: now,
            updated_at_ms: now,
            snapshot: None,
            failure: None,
            health: None,
            activation: None,
            cancel_requested: false,
            mutation_started: false,
        },
    );
    l.e.validate().unwrap();
    (l, Mutex::new(v), op)
}
fn admit<'a>(
    l: &'a Lease,
    v: &'a Mutex<Vault>,
    m: &'a Material,
    c: &'a Wall,
    op: &OperationId,
    cancel: &'a CancellationToken,
) -> Result<TlsMaterialAdmission<'a>, ControlError> {
    TlsMaterialAdmission::for_staging(
        l,
        v,
        &m.policy,
        c,
        l.e.state.version,
        op,
        deadline(),
        cancel,
    )
}
#[test]
fn material_context_accepts_own_staging_and_reads_exact_plan_material() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    assert!(l.e.require_admission(l.e.state.version).is_err());
    let a = admit(&l, &v, &m, &c, &op, &cancel).unwrap();
    assert_eq!(a.aggregate_version(), 2);
    assert_eq!(
        a.password(&SecretRef::new("password-1").unwrap(), 4096)
            .unwrap()
            .expose(),
        b"synthetic-password"
    );
    assert_eq!(
        a.certificate_chain(&CertificateId::new("certificate-1").unwrap(), 65536)
            .unwrap()
            .expose(),
        m.chain
    );
    assert_eq!(
        a.private_key(&SecretRef::new("tls-key-import-1").unwrap(), 65536)
            .unwrap()
            .expose(),
        m.key
    );
    assert!(a
        .password(&SecretRef::new("unreferenced").unwrap(), 4096)
        .is_err());
    assert!(a
        .password(&SecretRef::new("password-1").unwrap(), 1)
        .is_err());
    assert!(a
        .certificate_chain(&CertificateId::new("certificate-1").unwrap(), 1)
        .is_err());
    assert!(a
        .private_key(&SecretRef::new("tls-key-import-1").unwrap(), 1)
        .is_err());
}
#[test]
fn material_context_denies_stale_cas_wrong_phase_cancel_and_foreign_binding() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (mut l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    assert!(
        TlsMaterialAdmission::for_staging(&l, &v, &m.policy, &c, 1, &op, deadline(), &cancel)
            .is_err()
    );
    for phase in [
        crate::OperationState::Queued,
        crate::OperationState::Activating,
        crate::OperationState::RecoveryRequired,
    ] {
        l.e.state.operations.get_mut(&op).unwrap().state = phase;
        assert!(admit(&l, &v, &m, &c, &op, &cancel).is_err());
    }
    l.e.state.operations.get_mut(&op).unwrap().state = crate::OperationState::Staging;
    l.e.state.operations.get_mut(&op).unwrap().cancel_requested = true;
    assert!(admit(&l, &v, &m, &c, &op, &cancel).is_err());
    l.e.state.operations.get_mut(&op).unwrap().cancel_requested = false;
    v.lock().unwrap().wrong_binding.set(true);
    assert!(admit(&l, &v, &m, &c, &op, &cancel).is_err());
}
#[test]
fn material_context_rechecks_readback_expiry_and_kind_after_admission() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    let a = admit(&l, &v, &m, &c, &op, &cancel).unwrap();
    v.lock().unwrap().wrong_version.set(true);
    assert!(a
        .certificate_chain(&CertificateId::new("certificate-1").unwrap(), 65536)
        .is_err());
    v.lock().unwrap().wrong_version.set(false);
    v.lock()
        .unwrap()
        .data
        .borrow_mut()
        .get_mut("secret:password-1")
        .unwrap()
        .0 = 2;
    assert!(a
        .password(&SecretRef::new("password-1").unwrap(), 4096)
        .is_err());
    c.0.store(
        c.now_ms().unwrap() + 200000,
        std::sync::atomic::Ordering::SeqCst,
    );
    assert!(a
        .private_key(&SecretRef::new("tls-key-import-1").unwrap(), 65536)
        .is_err());
}
#[test]
fn material_context_denies_unavailable_assets_and_retired_credentials() {
    for phase in [
        AssetPhase::PendingImport,
        AssetPhase::PendingRetire,
        AssetPhase::Retired,
        AssetPhase::Aborted,
    ] {
        let m = material(true, 2024, 2026);
        let c = clock();
        let (mut l, v, op) = staged(&m, &c);
        let cancel = CancellationToken::default();
        l.e.certificate_assets
            .get_mut("certificate-1")
            .unwrap()
            .phase = phase;
        assert!(admit(&l, &v, &m, &c, &op, &cancel).is_err());
    }
    let m = material(true, 2024, 2026);
    let c = clock();
    let (mut l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    let credential = l.e.state.secrets.credentials.values_mut().next().unwrap();
    credential.summary.state = CredentialState::Retired;
    credential.summary.display_key = CredentialDisplayKey::Retired;
    assert!(admit(&l, &v, &m, &c, &op, &cancel).is_err());
}
#[test]
fn material_context_rejects_policy_change_and_clock_rollback() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    let different = material(true, 2024, 2026);
    assert!(admit(&l, &v, &different, &c, &op, &cancel).is_err());
    let a = admit(&l, &v, &m, &c, &op, &cancel).unwrap();
    c.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    assert!(a
        .password(&SecretRef::new("password-1").unwrap(), 4096)
        .is_err());
}

#[test]
fn adapter_budget_cancellation_and_shorter_deadline_apply_inside_context() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    let a = admit(&l, &v, &m, &c, &op, &cancel).unwrap();
    let id = CertificateId::new("certificate-1").unwrap();
    assert!(matches!(
        a.certificate_chain_at(&id, 65536, deadline(), &|| true),
        Err(ControlError::Canceled)
    ));
    assert!(matches!(
        a.certificate_chain_at(&id, 65536, Instant::now(), &|| false),
        Err(ControlError::PlanExpired)
    ));
    let key = SecretRef::new("tls-key-import-1").unwrap();
    assert!(matches!(
        a.private_key_at(&key, 65536, deadline(), &|| true),
        Err(ControlError::Canceled)
    ));
    assert!(matches!(
        a.password_at(
            &SecretRef::new("password-1").unwrap(),
            4096,
            deadline(),
            &|| true
        ),
        Err(ControlError::Canceled)
    ));
}

struct ReadClockHook<'a> {
    inner: Mutex<Vault>,
    wall: &'a Wall,
    after_read: std::sync::atomic::AtomicU64,
}
impl TlsMaterialVault for ReadClockHook<'_> {
    fn material_binding(&self, d: Instant) -> Result<InstanceBinding, ControlError> {
        self.inner.material_binding(d)
    }
    fn read_tls_material(
        &self,
        r: &SecretRef,
        d: Instant,
    ) -> Result<Option<TlsRawRecord>, ControlError> {
        let value = self.inner.read_tls_material(r, d)?;
        let next = self.after_read.load(std::sync::atomic::Ordering::SeqCst);
        if next != 0 {
            self.wall.0.store(next, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(value)
    }
    fn read_credential_material(
        &self,
        r: &SecretRef,
        d: Instant,
    ) -> Result<Option<TlsRawRecord>, ControlError> {
        self.inner.read_credential_material(r, d)
    }
}
#[test]
fn expiry_during_vault_reads_is_rejected_even_with_valid_plan() {
    const EXPIRES: u64 = 1_767_225_600_000;
    for offset in [0, 1000] {
        let m = material(true, 2024, 2026);
        let c = Wall(std::sync::atomic::AtomicU64::new(EXPIRES - 1000));
        let (l, v, op) = staged(&m, &c);
        let cancel = CancellationToken::default();
        let hook = ReadClockHook {
            inner: v,
            wall: &c,
            after_read: std::sync::atomic::AtomicU64::new(0),
        };
        let a = TlsMaterialAdmission::for_staging(
            &l,
            &hook,
            &m.policy,
            &c,
            l.e.state.version,
            &op,
            deadline(),
            &cancel,
        )
        .unwrap();
        hook.after_read
            .store(EXPIRES + offset, std::sync::atomic::Ordering::SeqCst);
        let result = a.certificate_chain(&CertificateId::new("certificate-1").unwrap(), 65536);
        assert!(c.now_ms().unwrap() < EXPIRES + 99000);
        assert_eq!(
            result.is_ok(),
            offset == 0,
            "inclusive endpoint accepted, next second rejected"
        );
    }
}
#[test]
fn per_call_clock_rollback_above_initial_admission_floor_is_rejected() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    let baseline = c.now_ms().unwrap();
    let hook = ReadClockHook {
        inner: v,
        wall: &c,
        after_read: std::sync::atomic::AtomicU64::new(0),
    };
    let a = TlsMaterialAdmission::for_staging(
        &l,
        &hook,
        &m.policy,
        &c,
        l.e.state.version,
        &op,
        deadline(),
        &cancel,
    )
    .unwrap();
    c.0.store(baseline + 100, std::sync::atomic::Ordering::SeqCst);
    hook.after_read
        .store(baseline + 50, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        a.certificate_chain(&CertificateId::new("certificate-1").unwrap(), 65536),
        Err(ControlError::PlanExpired)
    ));
}

struct FinalClockHook {
    before: u64,
    after: u64,
    calls: std::sync::atomic::AtomicUsize,
    switch_after: std::sync::atomic::AtomicUsize,
}
impl Clock for FinalClockHook {
    fn now_ms(&self) -> Result<u64, ControlError> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(
            if call >= self.switch_after.load(std::sync::atomic::Ordering::SeqCst) {
                self.after
            } else {
                self.before
            },
        )
    }
}
#[test]
fn expiry_after_crypto_is_rejected_by_final_inclusive_bound() {
    const EXPIRES: u64 = 1_767_225_600_000;
    let m = material(true, 2024, 2026);
    let c = Wall(std::sync::atomic::AtomicU64::new(EXPIRES - 1000));
    let (l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    let time = FinalClockHook {
        before: EXPIRES - 1000,
        after: EXPIRES + 1000,
        calls: std::sync::atomic::AtomicUsize::new(0),
        switch_after: std::sync::atomic::AtomicUsize::new(usize::MAX),
    };
    let a = TlsMaterialAdmission::for_staging(
        &l,
        &v,
        &m.policy,
        &time,
        l.e.state.version,
        &op,
        deadline(),
        &cancel,
    )
    .unwrap();
    time.calls.store(0, std::sync::atomic::Ordering::SeqCst);
    // Three pre-verification checks each observe time before and after binding.
    // The seventh observation occurs only in the post-crypto check.
    time.switch_after
        .store(6, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        a.certificate_chain(&CertificateId::new("certificate-1").unwrap(), 65536),
        Err(ControlError::PlanExpired)
    ));
    assert!(time.calls.load(std::sync::atomic::Ordering::SeqCst) >= 7);
    assert!(time.after < EXPIRES + 99000, "plan remains valid");
}

#[test]
fn entire_verified_path_proof_requires_stable_unix_second() {
    const NOW: u64 = 1_735_689_600_100;
    for advance in [800, 1000] {
        let m = material(true, 2024, 2026);
        let c = Wall(std::sync::atomic::AtomicU64::new(NOW));
        let (l, v, op) = staged(&m, &c);
        let cancel = CancellationToken::default();
        let time = FinalClockHook {
            before: NOW,
            after: NOW + advance,
            calls: std::sync::atomic::AtomicUsize::new(0),
            switch_after: std::sync::atomic::AtomicUsize::new(usize::MAX),
        };
        let a = TlsMaterialAdmission::for_staging(
            &l,
            &v,
            &m.policy,
            &time,
            l.e.state.version,
            &op,
            deadline(),
            &cancel,
        )
        .unwrap();
        time.calls.store(0, std::sync::atomic::Ordering::SeqCst);
        time.switch_after
            .store(6, std::sync::atomic::Ordering::SeqCst);
        let result = a.certificate_chain(&CertificateId::new("certificate-1").unwrap(), 65536);
        assert_eq!(
            result.is_ok(),
            advance == 800,
            "same second proof accepted; next second must be reverified by a fresh attempt"
        );
        assert!(time.after < NOW + 100000, "plan remains valid");
    }
}

// A test-only WriterLease exposes the same currently borrowed aggregate.
impl crate::WriterLease for Lease {
    fn state(&self) -> &crate::StoredState {
        self.e.state()
    }
    fn persist(
        &mut self,
        _: crate::StoredState,
        _: crate::JournalEvent,
    ) -> Result<(), ControlError> {
        panic!("material context must not persist")
    }
    fn tls_aggregate(&self) -> Option<&TlsControlEnvelope> {
        Some(&self.e)
    }
}
#[test]
fn stage_context_constructs_tls_admission_from_existing_writer() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    let plan =
        l.e.state
            .plans
            .get(&l.e.state.operations[&op].plan_id)
            .unwrap();
    let ctx = crate::RuntimeStageContext::from_staging(&l, &op, plan, &c, &cancel).unwrap();
    let a = ctx.tls_materials(&v, &m.policy, deadline()).unwrap();
    assert_eq!(a.aggregate_version(), l.e.state.version);
    assert_eq!(
        a.password(&SecretRef::new("password-1").unwrap(), 4096)
            .unwrap()
            .expose(),
        b"synthetic-password"
    );
}
#[test]
fn stage_context_honors_deadline_and_cancellation_before_material_use() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    let plan =
        l.e.state
            .plans
            .get(&l.e.state.operations[&op].plan_id)
            .unwrap();
    let ctx = crate::RuntimeStageContext::from_staging(&l, &op, plan, &c, &cancel).unwrap();
    assert!(ctx.tls_materials(&v, &m.policy, Instant::now()).is_err());
    cancel.cancel();
    assert!(ctx.tls_materials(&v, &m.policy, deadline()).is_err());
}

#[test]
fn stage_context_refuses_absent_or_inconsistent_tls_view() {
    struct View<'a> {
        e: Option<&'a TlsControlEnvelope>,
        state: crate::StoredState,
    }
    impl crate::WriterLease for View<'_> {
        fn state(&self) -> &crate::StoredState {
            &self.state
        }
        fn persist(
            &mut self,
            _: crate::StoredState,
            _: crate::JournalEvent,
        ) -> Result<(), ControlError> {
            panic!("read only")
        }
        fn tls_aggregate(&self) -> Option<&TlsControlEnvelope> {
            self.e
        }
    }
    let m = material(true, 2024, 2026);
    let c = clock();
    let (l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    let plan =
        l.e.state
            .plans
            .get(&l.e.state.operations[&op].plan_id)
            .unwrap();
    let absent = View {
        e: None,
        state: l.e.state.clone(),
    };
    let ctx = crate::RuntimeStageContext::from_staging(&absent, &op, plan, &c, &cancel).unwrap();
    assert!(matches!(
        ctx.tls_materials(&v, &m.policy, deadline()),
        Err(ControlError::ExecutorUnavailable)
    ));
    let mut wrong = View {
        e: Some(&l.e),
        state: l.e.state.clone(),
    };
    wrong.state.version += 1;
    let ctx = crate::RuntimeStageContext::from_staging(&wrong, &op, plan, &c, &cancel).unwrap();
    assert!(matches!(
        ctx.tls_materials(&v, &m.policy, deadline()),
        Err(ControlError::ResourceConflict)
    ));
    wrong.state.version = l.e.state.version;
    wrong.state.next_id += 1;
    let ctx = crate::RuntimeStageContext::from_staging(&wrong, &op, plan, &c, &cancel).unwrap();
    assert!(matches!(
        ctx.tls_materials(&v, &m.policy, deadline()),
        Err(ControlError::ResourceConflict)
    ));
}

fn mutation_phase(l: &mut Lease, op: &OperationId, phase: crate::OperationState) {
    let operation = l.e.state.operations.get_mut(op).unwrap();
    operation.state = phase;
    operation.mutation_started = true;
    operation.snapshot = Some(crate::ResourceSnapshot {
        id: "synthetic-snapshot".into(),
        resources: vec![],
    });
}
#[test]
fn activation_context_revalidates_current_material_and_expiry() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (mut l, v, op) = staged(&m, &c);
    mutation_phase(&mut l, &op, crate::OperationState::Activating);
    let plan = &l.e.state.plans[&l.e.state.operations[&op].plan_id];
    let cancel = CancellationToken::default();
    let ctx =
        crate::RuntimeActivationContext::from_activating(&l, &op, plan, None, &c, &cancel).unwrap();
    assert!(ctx.tls_materials(&v, &m.policy, deadline()).is_ok());
    v.lock().unwrap().wrong_version.set(true);
    assert!(ctx.tls_materials(&v, &m.policy, deadline()).is_err());
    v.lock().unwrap().wrong_version.set(false);
    c.0.fetch_add(100001, std::sync::atomic::Ordering::SeqCst);
    assert!(ctx.tls_materials(&v, &m.policy, deadline()).is_err());
}
fn restoring_fixture(
    m: &Material,
    c: &Wall,
) -> (Lease, Mutex<Vault>, OperationId, crate::RevisionRecord) {
    let (l, v, old) = staged(m, c);
    restoring_from_staged(l, v, old, c)
}
fn restoring_from_staged(mut l: Lease, v: Mutex<Vault>, old: OperationId, c: &Wall) -> (Lease, Mutex<Vault>, OperationId, crate::RevisionRecord) {
    let old_plan = l.e.state.plans[&l.e.state.operations[&old].plan_id].clone();
    let revision = crate::RevisionRecord {
        revision: old_plan.body().target_revision,
        config: old_plan.body().config.clone(),
        release: old_plan.body().release.clone(),
        config_digest: old_plan.body().validation.config_digest.clone(),
        release_digest: old_plan.body().validation.release_digest.clone(),
        artifact_digest: old_plan.body().validation.artifact_digest.clone(),
        operation_id: old.clone(),
    };
    let activation = crate::RuntimeActivation {
        revision: revision.revision,
        operation_id: old.clone(),
        config_digest: revision.config_digest.clone(),
        release_digest: revision.release_digest.clone(),
        generation: 1,
    };
    let health = crate::RuntimeHealth {
        revision: revision.revision,
        operation_id: old.clone(),
        config_digest: revision.config_digest.clone(),
        release_digest: revision.release_digest.clone(),
        generation: 1,
        checked_at_ms: c.now_ms().unwrap(),
        checks: vec![],
        external_connectivity: crate::CheckOutcome::NotChecked,
    };
    let old_op = l.e.state.operations.get_mut(&old).unwrap();
    old_op.state = crate::OperationState::Committed;
    old_op.activation = Some(activation);
    old_op.health = Some(health);
    l.e.state.active_revision = revision.revision;
    l.e.state.revisions.push(revision.clone());
    let id = OperationId::new("restore-operation").unwrap();
    let mut body = old_plan.body().clone();
    body.id = PlanId::new("restore-plan").unwrap();
    body.principal = UserId::new("different-apply-actor").unwrap();
    body.base_revision = revision.revision;
    body.target_revision = revision.revision.next().unwrap();
    let plan = crate::ChangePlan::seal(body).unwrap();
    let mut operation = l.e.state.operations[&old].clone();
    operation.id = id.clone();
    operation.plan_id = plan.body().id.clone();
    operation.principal = plan.body().principal.clone();
    operation.activation = None;
    operation.health = None;
    operation.cancel_requested = true;
    l.e.state.plans.insert(plan.body().id.clone(), plan);
    l.e.state.operations.insert(id.clone(), operation);
    mutation_phase(&mut l, &id, crate::OperationState::RollingBack);
    l.e.validate().unwrap();
    (l, v, id, revision)
}
#[test]
fn restoration_uses_current_retirement_not_old_apply_expiry_or_actor() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (mut l, v, op, previous) = restoring_fixture(&m, &c);
    c.0.fetch_add(200000, std::sync::atomic::Ordering::SeqCst);
    let plan = &l.e.state.plans[&l.e.state.operations[&op].plan_id];
    let ctx = crate::RuntimeRestoreContext::from_rolling_back(&l, &op, plan, Some(&previous), &c)
        .unwrap();
    assert!(
        ctx.tls_materials(&v, &m.policy, deadline()).is_ok(),
        "canceled and expired apply is not recovery authority"
    );
    let id = l.e.state.secrets.credentials.keys().next().unwrap().clone();
    let summary = &mut l.e.state.secrets.credentials.get_mut(&id).unwrap().summary;
    summary.state = CredentialState::Retired;
    summary.display_key = CredentialDisplayKey::Retired;
    // Keep the synthetic retired record structurally valid so this assertion
    // exercises fresh restoration material admission, not corrupt-state refusal.
    l.e.validate().unwrap();
    let plan = &l.e.state.plans[&l.e.state.operations[&op].plan_id];
    let ctx = crate::RuntimeRestoreContext::from_rolling_back(&l, &op, plan, Some(&previous), &c)
        .unwrap();
    assert!(ctx.tls_materials(&v, &m.policy, deadline()).is_err());
}
#[test]
fn restoration_rejects_noncurrent_previous_and_expired_certificate() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (l, v, op, previous) = restoring_fixture(&m, &c);
    let plan = &l.e.state.plans[&l.e.state.operations[&op].plan_id];
    let mut wrong = previous.clone();
    wrong.artifact_digest = ContentDigest::bytes(b"wrong");
    assert!(
        crate::RuntimeRestoreContext::from_rolling_back(&l, &op, plan, Some(&wrong), &c).is_err()
    );
    let ctx = crate::RuntimeRestoreContext::from_rolling_back(&l, &op, plan, Some(&previous), &c)
        .unwrap();
    c.0.store(1_800_000_000_000, std::sync::atomic::Ordering::SeqCst);
    assert!(ctx.tls_materials(&v, &m.policy, deadline()).is_err());
}

#[test]
fn experimental_typed_credential_read_does_not_widen_trojan_admission() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (l, v, op) = staged(&m, &c);
    let cancel = CancellationToken::default();
    let a = admit(&l, &v, &m, &c, &op, &cancel).unwrap();
    let reference = SecretRef::new("password-1").unwrap();
    assert!(matches!(a.experimental_server_credential_at(&reference, &NodeCredentialKind::Uuid {}, 4096, deadline(), &|| false), Err(ControlError::PermissionDenied)));
    assert!(matches!(a.experimental_server_credential_at(&reference, &NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }, 4096, deadline(), &|| false), Err(ControlError::PermissionDenied)));
    assert!(matches!(a.experimental_server_credential_at(&reference, &NodeCredentialKind::Uuid {}, 4096, deadline(), &|| true), Err(ControlError::Canceled)));
}

#[cfg(feature = "experimental-public")]
#[test]
fn public_material_staging_is_plan_bound_and_typed() {
    for case in 0..3 {
        let m = material(true, 2024, 2026);
        let c = clock();
        let (mut l, v, op) = staged(&m, &c);
        let reference = SecretRef::new("password-1").unwrap();
        let (protocol, kind, secret) = match case {
            0 => (Protocol::Trojan {}, NodeCredentialKind::Password {}, b"synthetic-password".to_vec()),
            1 => (Protocol::Vless { flow: None }, NodeCredentialKind::Uuid {}, b"12345678-1234-1234-1234-123456789abc".to_vec()),
            _ => (Protocol::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }, NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }, b"synthetic-ss-password".to_vec()),
        };
        l.e.state.secrets.credentials.values_mut().next().unwrap().summary.kind = kind.clone();
        let stored = match case {
            1 => vp_product_domain::experimental_credential_frame::encode(vp_product_domain::experimental_credential_frame::CredentialFrameKind::Uuid, &secret).unwrap().expose().to_vec(),
            2 => vp_product_domain::experimental_credential_frame::encode(vp_product_domain::experimental_credential_frame::CredentialFrameKind::ShadowsocksAes128Gcm, &secret).unwrap().expose().to_vec(),
            _ => secret.clone(),
        };
        v.lock().unwrap().data.borrow_mut().insert(reference.as_str().into(), (1, 7, stored.clone()));
        let plan_id = l.e.state.operations.get(&op).unwrap().plan_id.clone();
        let mut body = l.e.state.plans.get(&plan_id).unwrap().body().clone();
        let listener = &mut body.config.listeners[0];
        listener.bind.address = "192.168.1.5".parse().unwrap();
        if let ServerProtocol::Proxy { protocol: p, .. } = &mut listener.protocol { *p = protocol; } else { panic!("proxy fixture"); }
        if case == 1 { listener.transport = Transport::Ws { path: "/test".into(), host: None, early_data: None }; }
        if case == 2 { listener.security = ServerSecurity::None {}; }
        body.validation.config_digest = crate::ContentDigest::of("vp.product-config.v1", &body.config).unwrap();
        let digest = crate::ContentDigest::bytes(b"public-artifact-fixture");
        body.validation.artifact_digest = digest.clone();
        l.e.state.plans.insert(plan_id, crate::ChangePlan::seal(body).unwrap());
        let cancel = CancellationToken::default();
        let wrong = crate::ContentDigest::bytes(b"wrong-artifact");
        assert!(TlsMaterialAdmission::for_public_staging(&l, &v, &m.policy, &c, l.e.state.version, &op, deadline(), &cancel, &wrong).is_err());
        assert!(TlsMaterialAdmission::for_staging(&l, &v, &m.policy, &c, l.e.state.version, &op, deadline(), &cancel).is_err());
        let admission = TlsMaterialAdmission::for_public_staging(&l, &v, &m.policy, &c, l.e.state.version, &op, deadline(), &cancel, &digest).unwrap();
        let bytes = if case == 0 { admission.password_at(&reference, 4096, deadline(), &|| false).unwrap() }
            else { admission.experimental_server_credential_at(&reference, &kind, 4096, deadline(), &|| false).unwrap() };
        assert_eq!(bytes.expose(), secret.as_slice());
        {
            let sealed = l.e.state.plans.get(&l.e.state.operations[&op].plan_id).unwrap();
            let context = crate::RuntimeStageContext::from_staging(&l, &op, sealed, &c, &cancel).unwrap();
            let staged = context.experimental_public_materials(&v, &m.policy, deadline()).unwrap();
            assert_eq!(staged.artifact_digest(), &digest);
            let staged_bytes = if case == 0 { staged.password_at(&reference, 4096, deadline(), &|| false).unwrap() }
                else { staged.experimental_server_credential_at(&reference, &kind, 4096, deadline(), &|| false).unwrap() };
            assert_eq!(staged_bytes.expose(), secret.as_slice());
        }
        if case != 0 {
            let wrong_kind = if case == 1 { NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm } } else { NodeCredentialKind::Uuid {} };
            assert!(admission.experimental_server_credential_at(&reference, &wrong_kind, 4096, deadline(), &|| false).is_err());
        }
        drop(admission);
        if case == 0 {
            mutation_phase(&mut l, &op, crate::OperationState::Activating);
            let plan = &l.e.state.plans[&l.e.state.operations[&op].plan_id];
            let context = crate::RuntimeActivationContext::from_activating(&l, &op, plan, None, &c, &cancel).unwrap();
            let activation = context.experimental_public_materials(&v, &m.policy, deadline()).unwrap();
            assert_eq!(activation.artifact_digest(), &digest);
            assert_eq!(activation.password_at(&reference, 4096, deadline(), &|| false).unwrap().expose(), secret.as_slice());
            mutation_phase(&mut l, &op, crate::OperationState::Verifying);
            let body = l.e.state.plans[&l.e.state.operations[&op].plan_id].body().clone();
            l.e.state.operations.get_mut(&op).unwrap().activation = Some(crate::RuntimeActivation {
                revision: body.target_revision, operation_id: op.clone(), config_digest: body.validation.config_digest.clone(),
                release_digest: body.validation.release_digest.clone(), generation: 1,
            });
            let plan = &l.e.state.plans[&l.e.state.operations[&op].plan_id];
            let verify = crate::RuntimeVerificationContext::from_verifying(&l, &op, plan, &c, &cancel).unwrap();
            let admitted = verify.experimental_public_materials(&v, &m.policy, deadline()).unwrap();
            assert_eq!(admitted.password_at(&reference, 4096, deadline(), &|| false).unwrap().expose(), secret.as_slice());
            l.e.state.operations.get_mut(&op).unwrap().activation.as_mut().unwrap().generation = 0;
            let plan = &l.e.state.plans[&l.e.state.operations[&op].plan_id];
            assert!(crate::RuntimeVerificationContext::from_verifying(&l, &op, plan, &c, &cancel).is_err());
        }
        if case != 0 {
            let malformed = if case == 1 { b"12345678-1234-1234-1234-123456789ABc".to_vec() } else { b"bad\0password".to_vec() };
            v.lock().unwrap().data.borrow_mut().insert(reference.as_str().into(), (1, 7, malformed));
            assert!(matches!(TlsMaterialAdmission::for_public_staging(&l, &v, &m.policy, &c, l.e.state.version, &op, deadline(), &cancel, &digest), Err(ControlError::InvalidConfiguration)));
            let wrong_frame = if case == 1 {
                vp_product_domain::experimental_credential_frame::encode(vp_product_domain::experimental_credential_frame::CredentialFrameKind::ShadowsocksAes128Gcm, &secret).unwrap()
            } else {
                vp_product_domain::experimental_credential_frame::encode(vp_product_domain::experimental_credential_frame::CredentialFrameKind::Uuid, b"12345678-1234-1234-1234-123456789abc").unwrap()
            };
            v.lock().unwrap().data.borrow_mut().insert(reference.as_str().into(), (1, 7, wrong_frame.expose().to_vec()));
            assert!(matches!(TlsMaterialAdmission::for_public_staging(&l, &v, &m.policy, &c, l.e.state.version, &op, deadline(), &cancel, &digest), Err(ControlError::InvalidConfiguration)));
            v.lock().unwrap().data.borrow_mut().insert(reference.as_str().into(), (1, 7, stored.clone()));
            l.e.state.secrets.credentials.values_mut().next().unwrap().summary.kind = NodeCredentialKind::Password {};
            assert!(matches!(TlsMaterialAdmission::for_public_staging(&l, &v, &m.policy, &c, l.e.state.version, &op, deadline(), &cancel, &digest), Err(ControlError::ResourceConflict)));
            if case == 1 {
                l.e.state.secrets.credentials.values_mut().next().unwrap().summary.kind = kind.clone();
                let plan_id = l.e.state.operations.get(&op).unwrap().plan_id.clone();
                let mut body = l.e.state.plans.get(&plan_id).unwrap().body().clone();
                let mut alias = body.config.listeners[0].clone();
                alias.id = ListenerId::new("conflicting-listener").unwrap();
                alias.bind.port += 1;
                alias.transport = Transport::Tcp {};
                if let ServerProtocol::Proxy { protocol, .. } = &mut alias.protocol { *protocol = Protocol::Trojan {}; }
                body.config.listeners.push(alias);
                body.validation.config_digest = crate::ContentDigest::of("vp.product-config.v1", &body.config).unwrap();
                l.e.state.plans.insert(plan_id, crate::ChangePlan::seal(body).unwrap());
                assert!(matches!(TlsMaterialAdmission::for_public_staging(&l, &v, &m.policy, &c, l.e.state.version, &op, deadline(), &cancel, &digest), Err(ControlError::PermissionDenied)));
            }
        }
    }
}

#[cfg(feature = "experimental-public")]
#[test]
fn public_restoration_uses_previous_sealed_artifact_and_current_material() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let (mut l, v, old) = staged(&m, &c);
    let plan_id = l.e.state.operations[&old].plan_id.clone();
    let mut body = l.e.state.plans[&plan_id].body().clone();
    body.config.listeners[0].bind.address = "192.168.1.5".parse().unwrap();
    body.validation.config_digest = crate::ContentDigest::of("vp.product-config.v1", &body.config).unwrap();
    let digest = crate::ContentDigest::bytes(b"previous-public-artifact");
    body.validation.artifact_digest = digest.clone();
    l.e.state.plans.insert(plan_id, crate::ChangePlan::seal(body).unwrap());
    let (l, v, op, previous) = restoring_from_staged(l, v, old, &c);
    let plan = &l.e.state.plans[&l.e.state.operations[&op].plan_id];
    let context = crate::RuntimeRestoreContext::from_rolling_back(&l, &op, plan, Some(&previous), &c).unwrap();
    let admission = context.experimental_public_materials(&v, &m.policy, deadline()).unwrap();
    assert_eq!(admission.artifact_digest(), &digest);
    assert_eq!(admission.password_at(&SecretRef::new("password-1").unwrap(), 4096, deadline(), &|| false).unwrap().expose(), b"synthetic-password");
    drop(admission);
    v.lock().unwrap().wrong_version.set(true);
    assert!(context.experimental_public_materials(&v, &m.policy, deadline()).is_err());
    let mut wrong = previous.clone();
    wrong.artifact_digest = crate::ContentDigest::bytes(b"wrong-previous");
    assert!(crate::RuntimeRestoreContext::from_rolling_back(&l, &op, plan, Some(&wrong), &c).is_err());
}

#[cfg(feature = "experimental-public")]
#[test]
fn committed_restart_material_requires_current_paired_healthy_revision() {
    use crate::{OperationState, ResourceSnapshot, RuntimeActivation, RuntimeHealth, RevisionRecord, CheckOutcome};
    let m = material(true, 2024, 2026);
    let c = clock();
    let (mut lease, vault, op_id) = staged(&m, &c);
    let plan_id = lease.e.state.operations[&op_id].plan_id.clone();
    let mut body = lease.e.state.plans[&plan_id].body().clone();
    body.config.listeners[0].bind.address = "8.8.8.8".parse().unwrap();
    body.validation.config_digest = ContentDigest::of("vp.product-config.v1", &body.config).unwrap();
    body.validation.required_health = crate::minimum_health_checks(&body.config, None).unwrap();
    let plan = crate::ChangePlan::seal(body).unwrap();
    let b = plan.body();
    let revision = RevisionRecord { revision: b.target_revision, config: b.config.clone(), release: b.release.clone(),
        config_digest: b.validation.config_digest.clone(), release_digest: b.validation.release_digest.clone(),
        artifact_digest: b.validation.artifact_digest.clone(), operation_id: op_id.clone() };
    let activation = RuntimeActivation { revision: revision.revision, operation_id: op_id.clone(), config_digest: revision.config_digest.clone(), release_digest: revision.release_digest.clone(), generation: 1 };
    let health = RuntimeHealth { revision: revision.revision, operation_id: op_id.clone(), config_digest: revision.config_digest.clone(), release_digest: revision.release_digest.clone(), generation: 1,
        checked_at_ms: c.now_ms().unwrap(), checks: b.validation.required_health.iter().cloned().map(|check| crate::CheckResult { check, outcome: CheckOutcome::Passed }).collect(), external_connectivity: CheckOutcome::NotChecked };
    let operation = lease.e.state.operations.get_mut(&op_id).unwrap();
    operation.state = OperationState::Committed;
    operation.mutation_started = true;
    operation.snapshot = Some(ResourceSnapshot { id: "synthetic-snapshot".into(), resources: vec![] });
    operation.activation = Some(activation);
    operation.health = Some(health);
    lease.e.state.active_revision = revision.revision;
    lease.e.state.revisions.push(revision.clone());
    lease.e.state.plans.insert(plan_id, plan);
    lease.e.state.verify_integrity().unwrap();
    let cancel = CancellationToken::default();
    let version = lease.e.state.version;
    {
        let admit = |artifact: &ContentDigest, version| TlsMaterialAdmission::for_public_committed_restart(
            &lease, &vault, &m.policy, &c, version, artifact, deadline(), &cancel);
        let accepted = admit(&revision.artifact_digest, version).unwrap();
        assert_eq!(accepted.password(&SecretRef::new("password-1").unwrap(), 4096).unwrap().expose(), b"synthetic-password");
        assert!(admit(&ContentDigest::bytes(b"wrong"), version).is_err());
        assert!(admit(&revision.artifact_digest, version + 1).is_err());
    }
    // Historical plan expiry is not a current certificate validity decision.
    c.0.fetch_add(200_000, std::sync::atomic::Ordering::SeqCst);
    assert!(TlsMaterialAdmission::for_public_committed_restart(&lease, &vault, &m.policy, &c, version, &revision.artifact_digest, deadline(), &cancel).is_ok());
    vault.lock().unwrap().wrong_binding.set(true);
    assert!(TlsMaterialAdmission::for_public_committed_restart(&lease, &vault, &m.policy, &c, version, &revision.artifact_digest, deadline(), &cancel).is_err());
    vault.lock().unwrap().wrong_binding.set(false);
    vault.lock().unwrap().wrong_version.set(true);
    assert!(TlsMaterialAdmission::for_public_committed_restart(&lease, &vault, &m.policy, &c, version, &revision.artifact_digest, deadline(), &cancel).is_err());
    vault.lock().unwrap().wrong_version.set(false);
    lease.e.state.operations.get_mut(&op_id).unwrap().health.as_mut().unwrap().checks[0].outcome = CheckOutcome::Failed;
    assert!(TlsMaterialAdmission::for_public_committed_restart(&lease, &vault, &m.policy, &c, version, &revision.artifact_digest, deadline(), &cancel).is_err());
    lease.e.state.operations.get_mut(&op_id).unwrap().health.as_mut().unwrap().checks[0].outcome = CheckOutcome::Passed;
    lease.e.state.operations.get_mut(&op_id).unwrap().activation.as_mut().unwrap().generation += 1;
    assert!(TlsMaterialAdmission::for_public_committed_restart(&lease, &vault, &m.policy, &c, version, &revision.artifact_digest, deadline(), &cancel).is_err());
    lease.e.state.operations.get_mut(&op_id).unwrap().activation.as_mut().unwrap().generation -= 1;
    cancel.cancel();
    assert!(TlsMaterialAdmission::for_public_committed_restart(&lease, &vault, &m.policy, &c, version, &revision.artifact_digest, deadline(), &cancel).is_err());
}
