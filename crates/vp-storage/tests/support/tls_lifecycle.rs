//! Test-only synthetic runtime/secret adapters; REAL control service and SQL store.
//! No listener, real key, protocol acceptance or production vault is involved.
#![allow(clippy::unwrap_used, dead_code)]
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use vp_product_control::RuntimeHealth;
use vp_product_control::*;
use vp_product_domain::*;
use vp_product_storage::{AnchoredControlRoot, TlsSqliteStore};
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
        if self.panic_activate.load(Ordering::SeqCst) {
            std::process::exit(73);
        }
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

fn payload() -> CredentialCreatePayload {
    CredentialCreatePayload {
        kind: NodeCredentialKind::Uuid {},
        confirm_generate: true.try_into().unwrap(),
    }
}
pub fn child(root: AnchoredControlRoot, mode: &str) {
    let reopen = matches!(
        mode,
        "lifecycle-recover" | "lifecycle-credential-recover" | "lifecycle-verify-credential"
    );
    let store = Arc::new(if reopen {
        TlsSqliteStore::open_initialized(root, super::binding()).unwrap()
    } else {
        let store = TlsSqliteStore::create(root, super::binding()).unwrap();
        store.mark_initialized().unwrap();
        store
    });
    let runtime = Arc::new(TestRuntime::default());
    let secrets = Arc::new(MemorySecrets::default());
    let service = ControlService::new(
        store.clone(),
        runtime.clone(),
        Arc::new(TestSystem::default()),
        Arc::new(TestClock(AtomicU64::new(1000))),
    )
    .with_secret_manager(secrets.clone());
    match mode {
        "lifecycle-apply" | "lifecycle-failure" | "lifecycle-crash" => {
            let plan = service.plan(plan_request()).unwrap();
            let operation = service.submit(apply_request(&plan, "apply")).unwrap();
            runtime
                .fail_health
                .store(mode == "lifecycle-failure", Ordering::SeqCst);
            runtime
                .panic_activate
                .store(mode == "lifecycle-crash", Ordering::SeqCst);
            let result = service
                .run(&operation.id, &CancellationToken::default())
                .unwrap();
            if mode == "lifecycle-crash" {
                panic!("crash hook did not exit");
            }
            assert_eq!(
                result.state,
                if mode == "lifecycle-failure" {
                    OperationState::RolledBack
                } else {
                    OperationState::Committed
                }
            );
            let state = store.read().unwrap();
            assert!(!state.needs_recovery());
            assert!(state.version > 5); // Staging, Snapshotting, activation/rollback checkpoints really persisted.
            assert_eq!(
                state.active_revision,
                if mode == "lifecycle-failure" {
                    Revision::ZERO
                } else {
                    plan.body().target_revision
                }
            );
            assert!(service.recover().unwrap().is_empty());
        }
        "lifecycle-recover" => {
            let before = store.read().unwrap();
            assert!(before.needs_recovery());
            let _readable_snapshot = service.snapshot(&principal()).unwrap();
            assert!(store
                .asset_writer()
                .unwrap()
                .aggregate()
                .require_admission(before.version)
                .is_err());
            assert!(service.plan(plan_request()).is_err());
            let results = service.recover().unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].state, OperationState::RolledBack);
            assert!(!store.read().unwrap().needs_recovery());
            assert_eq!(store.read().unwrap().active_revision, Revision::ZERO);
            assert!(service.recover().unwrap().is_empty());
        }
        "lifecycle-credential"
        | "lifecycle-credential-uncertain"
        | "lifecycle-credential-pending" => {
            let failure = match mode {
                "lifecycle-credential-uncertain" => 2,
                "lifecycle-credential-pending" => 1,
                _ => 0,
            };
            secrets.put_failure.store(failure, Ordering::SeqCst);
            let result = service.create_credential(
                &principal(),
                Revision::ZERO,
                IdempotencyKey::new("credential-action").unwrap(),
                payload(),
            );
            if failure == 0 {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.unwrap_err(), ControlError::RecoveryRequired);
                let before = store.read().unwrap();
                assert!(before.needs_recovery());
                assert!(store
                    .asset_writer()
                    .unwrap()
                    .aggregate()
                    .require_admission(before.version)
                    .is_err());
                if failure == 1 {
                    return;
                }
                service.recover().unwrap();
            }
            let state = store.read().unwrap();
            assert!(!state.needs_recovery());
            assert_eq!(state.secrets.credentials.len(), 1);
            assert_eq!(state.version, 2);
            assert_eq!(state.active_revision, Revision::ZERO);
            let retry = service
                .create_credential(
                    &principal(),
                    Revision::ZERO,
                    IdempotencyKey::new("credential-action").unwrap(),
                    payload(),
                )
                .unwrap();
            assert_eq!(retry.state, CredentialState::Available);
            assert_eq!(secrets.credential_entropy.load(Ordering::SeqCst), 1);
            assert_eq!(secrets.puts.load(Ordering::SeqCst), 1);
        }
        "lifecycle-credential-recover" => {
            assert!(store.read().unwrap().needs_recovery());
            let _readable_snapshot = service.snapshot(&principal()).unwrap();
            service.recover().unwrap();
            let state = store.read().unwrap();
            assert!(!state.needs_recovery());
            assert!(state.secrets.credentials.is_empty());
            assert!(matches!(
                state.secrets.actions[0].outcome,
                SecretActionOutcome::Failed(_)
            ));
            assert_eq!(state.version, 2);
            assert_eq!(secrets.credential_entropy.load(Ordering::SeqCst), 0);
        }
        "lifecycle-verify-credential" => {
            let state = store.read().unwrap();
            assert!(!state.needs_recovery());
            assert_eq!(state.secrets.credentials.len(), 1);
            assert!(service.recover().unwrap().is_empty());
        }
        _ => panic!("unknown lifecycle fixture"),
    }
}
