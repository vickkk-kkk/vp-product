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
