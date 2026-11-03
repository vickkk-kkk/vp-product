//! Synthetic local encrypted-vault and SQLite integration; no worker or network.
#![allow(unused_imports, dead_code, clippy::unwrap_used, clippy::expect_used)]
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use sha2::{Digest, Sha224, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use vp_product_compiler::server_v2::ServerCompilerV2;
use vp_product_control::*;
use vp_product_core_adapter::managed::{
    host_v2::ManagedRuntimeV2, material_port_v2::resolve_materials_v2,
    protocol_v2::WorkerInstanceV2, Cancellation, Failure, VerifiedWorker,
};
use vp_product_domain::*;
use vp_product_secrets::{
    Limits, MasterKey, Namespace, TlsPasswordSecretManager, TlsSecretStore, VaultDirectoryIdentity,
};
use vp_product_server_materials::RegistryMaterialResolverV2;
use vp_product_storage::{BoundDirectory, DirectoryIdentity, TlsSqliteStore};
const WAIT: Duration = Duration::from_secs(10);
const IO_WAIT: Duration = Duration::from_secs(2);
fn deadline() -> Instant {
    Instant::now() + WAIT
}
fn actor() -> UserId {
    UserId::new("wire-test-admin").unwrap()
}
fn now() -> u64 {
    SystemClock.now_ms().unwrap()
}
fn anchor(path: &Path) -> vp_product_storage::AnchoredControlRoot {
    let id = DirectoryIdentity::of(&File::open(path).unwrap()).unwrap();
    BoundDirectory::open(path, id)
        .unwrap()
        .anchor_before_threads()
        .unwrap()
}
fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    const B: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = format!("-----BEGIN {label}-----\n").into_bytes();
    let mut encoded = Vec::new();
    for c in der.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | c.get(2).copied().unwrap_or(0) as u32;
        encoded.extend_from_slice(&[
            B[((n >> 18) & 63) as usize],
            B[((n >> 12) & 63) as usize],
            if c.len() > 1 {
                B[((n >> 6) & 63) as usize]
            } else {
                b'='
            },
            if c.len() > 2 {
                B[(n & 63) as usize]
            } else {
                b'='
            },
        ]);
    }
    for c in encoded.chunks(64) {
        out.extend_from_slice(c);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    out
}
fn materials() -> (SecretBytes, SecretBytes, Vec<u8>) {
    let clock = time::OffsetDateTime::now_utc();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(vec!["fixture-ca.invalid".into()]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.not_before = clock - time::Duration::days(1);
    ca.not_after = clock + time::Duration::days(2);
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf.not_before = clock - time::Duration::hours(1);
    leaf.not_after = clock + time::Duration::hours(2);
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf.signed_by(&key, &ca, &ca_key).unwrap();
    (
        SecretBytes::new(pem("CERTIFICATE", leaf.der().as_ref())),
        SecretBytes::new(pem("PRIVATE KEY", &key.serialize_der())),
        ca.der().to_vec(),
    )
}
fn config(port: u16, credential: &SecretRef) -> ProductConfig {
    serde_json::from_value(serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{
      "schemaVersion":1,"id":"wire-listener","name":"synthetic-wire","enabled":true,"bind":{"address":"127.0.0.1","port":port},
      "protocol":{"kind":"proxy","protocol":{"kind":"trojan"},"users":[{"id":"wire-user","credentialRef":credential,"enabled":true}]},
      "transport":{"kind":"tcp"},"security":{"kind":"tls","certificateRef":"wire-certificate","privateKeyRef":"secret:tls-key-wire-import","alpn":[]},"requirements":[]
    }]})).unwrap()
}
fn journal(state: &StoredState, id: &OperationId, phase: OperationState) -> JournalEvent {
    JournalEvent {
        security: None,
        sequence: state.version,
        at_ms: now(),
        operation_id: Some(id.clone()),
        state: Some(phase),
    }
}
fn synthetic_stage(
    store: &TlsSqliteStore,
    config: ProductConfig,
    release: ReleaseIdentity,
    label: &str,
    artifact: ContentDigest,
) -> OperationId {
    let mut lease = store.asset_writer().unwrap();
    let mut state = lease.state().clone();
    let operation = OperationId::new(format!("synthetic-wire-stage-{label}")).unwrap();
    let plan_id = PlanId::new(format!("synthetic-wire-plan-{label}")).unwrap();
    let at = now();
    let body = PlanBody {
        schema_version: 1,
        id: plan_id.clone(),
        principal: actor(),
        base_revision: state.active_revision,
        target_revision: state.active_revision.next().unwrap(),
        created_at_ms: at,
        expires_at_ms: at + 120_000,
        validation: ValidationReceipt {
            config_digest: ContentDigest::of("vp.product-config.v1", &config).unwrap(),
            release_digest: ContentDigest::of("vp.release-identity.v1", &release).unwrap(),
            artifact_digest: artifact,
            impact: RestartImpact::ControlledRestart,
            required_health: BTreeSet::new(),
        },
        config,
        release,
        resources: vec![],
    };
    // Explicit synthetic persisted fixture, not a ControlService-validated plan.
    let hash = ContentDigest::of("vp.change-plan.v1", &body).unwrap();
    let plan: ChangePlan = serde_json::from_value(serde_json::json!({
        "body": body, "hash": hash
    }))
    .unwrap();
    plan.verify_integrity().unwrap();
    state.plans.insert(plan_id.clone(), plan);
    state.operations.insert(
        operation.clone(),
        Operation {
            id: operation.clone(),
            plan_id,
            principal: actor(),
            state: OperationState::Staging,
            created_at_ms: at,
            updated_at_ms: at,
            snapshot: None,
            failure: None,
            health: None,
            activation: None,
            cancel_requested: false,
            mutation_started: false,
        },
    );
    state.version += 1;
    let event = journal(&state, &operation, OperationState::Staging);
    lease.persist(state, event).unwrap();
    operation
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--case" {
        let case: u8 = args[2].parse().unwrap();
        assert!(case < 3);
        run_case(case);
        return;
    }
    assert_eq!(args.len(), 1);
    // Each case needs a fresh process because the secure directory anchor must
    // be created before any helper threads have ever started in that process.
    for case in 0..3 {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--case").arg(case.to_string()).status().unwrap();
        assert!(status.success(), "case {case} failed");
    }
    println!("PASS: three typed credentials and real control plan/stage admission with temporary vault; intentional failure before host mutation; no runtime or traffic");
}
// Real ControlService plan/submit/stage orchestration with an explicitly failing
// test executor. It resolves material but never launches or mutates a host.
struct StageOnly {
    vault: Arc<TlsSecretStore>, policy: Arc<TlsBackendPolicy>,
    completed: std::sync::atomic::AtomicBool,
}
impl RuntimeExecutor for StageOnly {
    fn validate_with_context(&self, c: RuntimePlanContext<'_>) -> Result<ValidationReceipt, ControlError> {
        let receipt = self.validate(c.config(), c.release(), c.previous())?;
        c.validate_public_materials(self.vault.as_ref(), self.policy.as_ref(), &receipt.artifact_digest, deadline())?;
        Ok(receipt)
    }
    fn validate(&self, c: &ProductConfig, r: &ReleaseIdentity, p: Option<&RevisionRecord>) -> Result<ValidationReceipt, ControlError> {
        let compiler = ServerCompilerV2::for_public_experiment(r.clone(), vec!["8.8.8.8:443".parse().unwrap()]).map_err(|_| ControlError::InvalidConfiguration)?;
        let recipe = compiler.compile(c, r).map_err(|_| ControlError::InvalidConfiguration)?;
        Ok(ValidationReceipt { config_digest: ContentDigest::of("vp.product-config.v1", c)?, release_digest: ContentDigest::of("vp.release-identity.v1", r)?, artifact_digest: vp_product_server_materials::public_recipe_digest(&recipe).map_err(|_| ControlError::InvalidConfiguration)?, impact: RestartImpact::ControlledRestart, required_health: minimum_health_checks(c, p)? })
    }
    fn stage_with_context(&self, c: RuntimeStageContext<'_>) -> Result<(), ControlError> {
        let compiler = ServerCompilerV2::for_public_experiment(c.plan().body().release.clone(), vec!["8.8.8.8:443".parse().unwrap()]).map_err(|_| ControlError::InvalidConfiguration)?;
        let (recipe, inputs) = vp_product_server_materials::resolve_public_stage(&c, self.vault.as_ref(), self.policy.as_ref(), &compiler, deadline(), &Cancellation::default())?;
        vp_product_core_adapter::managed::server_v2::PreparedServerV2::prepare(&recipe, inputs).map_err(|_| ControlError::InvalidConfiguration)?;
        self.completed.store(true, std::sync::atomic::Ordering::SeqCst);
        Err(ControlError::ExecutorFailed) // intentional stop before host changes
    }
    fn stage(&self, _: &OperationId, _: &ChangePlan, _: &CancellationToken) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn activate(&self, _: &OperationId, _: &ChangePlan, _: Option<&RevisionRecord>) -> Result<RuntimeActivation, ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn verify(&self, _: &OperationId, _: &ChangePlan) -> Result<vp_product_control::RuntimeHealth, ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn stop_candidate(&self, _: &OperationId, _: &ChangePlan) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn restore_previous(&self, _: &OperationId, _: Option<&RevisionRecord>) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn verify_previous(&self, _: &OperationId, _: Option<&RevisionRecord>) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn discard_stage(&self, _: &OperationId) -> Result<(), ControlError> { Ok(()) }
}
struct EmptySystem;
impl SystemExecutor for EmptySystem {
    fn inspect(&self, resources: &[ResourceChange]) -> Result<Vec<ResourceObservation>, ControlError> {
        if resources.is_empty() { Ok(vec![]) } else { Err(ControlError::ExecutorUnavailable) }
    }
    fn capture(&self, _: &OperationId, _: &[ResourceChange]) -> Result<ResourceSnapshot, ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn apply(&self, _: &OperationId, _: &ChangePlan, _: &ResourceSnapshot) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn restore(&self, _: &OperationId, _: &ChangePlan, _: &ResourceSnapshot) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
}
fn run_case(case: u8) {
    println!("case={case}");
    use vp_product_core_adapter::managed::material_port_v2::resolve_materials_v2;
    use vp_product_secrets::TlsExperimentalSecretManager;
    use vp_product_server_materials::public_recipe_digest;
    let root = tempfile::tempdir().unwrap();
    let control_path = root.path().join("control");
    let vault_path = root.path().join("vault");
    for p in [&control_path, &vault_path] { fs::create_dir(p).unwrap(); fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap(); }
    let metadata = fs::metadata(&vault_path).unwrap();
    let vault = TlsSecretStore::initialize_bound(&vault_path, Namespace::new("public-material-test").unwrap(), MasterKey::new(SecretBytes::new(vec![61; 32])).unwrap(), Limits::default(), VaultDirectoryIdentity { device: metadata.dev(), inode: metadata.ino() }, deadline()).unwrap();
    let observation = vault.inspect_read_only(deadline()).unwrap();
    let d = ContentDigest::bytes(b"SYNTHETIC-TEST-GENESIS");
    let binding = InstanceBinding { binding_version: 1, genesis_id: "9".repeat(32), vault_id: observation.vault_id, namespace_digest: ContentDigest::parse(observation.namespace_digest).unwrap(), administrator_commitment: d.clone(), preparation_digest: d.clone(), activation_intent_digest: d.clone(), artifact_set_digest: d, profile: FRESH_TLS_RUNTIME_PROFILE.into() };
    vault.claim_instance_binding(&binding, deadline()).unwrap();
    let store = Arc::new(TlsSqliteStore::create(anchor(&control_path), binding).unwrap());
    store.mark_initialized().unwrap();
    let vault = Arc::new(vault);
    let manager = Arc::new(TlsExperimentalSecretManager::new(vault.clone()));
    let control = ControlService::new(store.clone(), Arc::new(UnavailableRuntime), Arc::new(UnavailableSystem), Arc::new(SystemClock)).with_secret_manager(manager.clone());
    let kind = match case { 0 => NodeCredentialKind::Password {}, 1 => NodeCredentialKind::Uuid {}, _ => NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm } };
    let credential = control.create_credential(&actor(), Revision::ZERO, IdempotencyKey::new("public-test-credential").unwrap(), CredentialCreatePayload { kind: kind.clone(), confirm_generate: ExplicitConfirmation::try_from(true).unwrap() }).unwrap();
    let expected = manager.load_credential(&credential.secret_ref, &kind, Some(1), deadline()).unwrap().unwrap();
    let (chain, key, ca) = materials();
    let policy = Arc::new(TlsBackendPolicy::new(actor().as_str().into(), vec![ca], "localhost".into()).unwrap());
    let wall = SystemClock;
    let cancel = CancellationToken::default();
    {
        let mut lease = store.asset_writer().unwrap();
        let version = lease.state().version;
        TlsImportService::new(policy.as_ref(), &wall).import(&mut lease, vault.as_ref(), TlsImportRequest { actor: actor().as_str().into(), expected_version: version, action: "wire-import".into(), idempotency: "wire-import-request".into(), asset: "wire-certificate".into(), confirmed: true, chain, key }, deadline(), &cancel).unwrap();
    }
    let release = vp_product_core_adapter::inspect_build().unwrap().build.release;
    let mut source = config(19001, &credential.secret_ref);
    source.listeners[0].bind.address = "192.168.1.5".parse().unwrap();
    if case == 1 {
        if let ServerProtocol::Proxy { protocol, .. } = &mut source.listeners[0].protocol { *protocol = Protocol::Vless { flow: None }; }
        source.listeners[0].transport = Transport::Ws { path: "/test".into(), host: None, early_data: None };
        if let ServerSecurity::Tls { alpn, .. } = &mut source.listeners[0].security { *alpn = vec!["http/1.1".into()]; }
    } else if case == 2 {
        if let ServerProtocol::Proxy { protocol, .. } = &mut source.listeners[0].protocol { *protocol = Protocol::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }; }
        source.listeners[0].security = ServerSecurity::None {};
    }
    let compiler = ServerCompilerV2::for_public_experiment(release.clone(), vec!["8.8.8.8:443".parse().unwrap()]).unwrap();
    let recipe = compiler.compile(&source, &release).unwrap();
    let digest = public_recipe_digest(&recipe).unwrap();
    let staged = Arc::new(StageOnly { vault: vault.clone(), policy: policy.clone(), completed: std::sync::atomic::AtomicBool::new(false) });
    let real_control = ControlService::new(store.clone(), staged.clone(), Arc::new(EmptySystem), Arc::new(SystemClock));
    let wrong_principal = UserId::new("other-user").unwrap();
    let before = store.read().unwrap();
    assert!(real_control.plan(PlanRequest { principal: wrong_principal, expected_revision: Revision::ZERO, config: source.clone(), release: release.clone(), resources: vec![], ttl_ms: 120_000 }).is_err());
    let after = store.read().unwrap();
    assert_eq!(before.version, after.version);
    assert_eq!(before.plans.len(), after.plans.len());
    assert_eq!(before.operations.len(), after.operations.len());
    let plan = real_control.plan(PlanRequest { principal: actor(), expected_revision: Revision::ZERO, config: source.clone(), release: release.clone(), resources: vec![], ttl_ms: 120_000 }).unwrap();
    assert_eq!(plan.body().validation.artifact_digest, digest);
    let op = real_control.submit(ApplyRequest { principal: actor(), plan_id: plan.body().id.clone(), confirmed_hash: plan.hash().clone(), expected_revision: Revision::ZERO, idempotency_key: IdempotencyKey::new("real-stage-test").unwrap() }).unwrap();
    assert_eq!(real_control.run(&op.id, &CancellationToken::default()).unwrap().state, OperationState::Failed);
    assert!(staged.completed.load(std::sync::atomic::Ordering::SeqCst));
    let op = synthetic_stage(store.as_ref(), source, release.clone(), "public", digest.clone());
    let lease = store.asset_writer().unwrap();
    let version = lease.state().version;
    let admission = TlsMaterialAdmission::for_public_staging(&lease, vault.as_ref(), policy.as_ref(), &wall, version, &op, deadline(), &cancel, &digest).unwrap();
    let resolver = RegistryMaterialResolverV2::new(admission, &recipe, &compiler).unwrap();
    let actual = resolve_materials_v2(&recipe, &resolver, deadline(), &Cancellation::default()).unwrap();
    assert_eq!(actual.credentials.get(&credential.secret_ref).unwrap().expose(), expected.expose());
    let prepared = vp_product_core_adapter::managed::server_v2::PreparedServerV2::prepare(&recipe, actual).unwrap();
    drop(prepared); // preparation only: never bind or activate in this test.
    let other_compiler = ServerCompilerV2::for_public_experiment(release.clone(), vec!["1.1.1.1:443".parse().unwrap()]).unwrap();
    let other_recipe = other_compiler.compile(&recipe.source, &release).unwrap();
    let admission = TlsMaterialAdmission::for_public_staging(&lease, vault.as_ref(), policy.as_ref(), &wall, version, &op, deadline(), &cancel, &digest).unwrap();
    assert!(RegistryMaterialResolverV2::new(admission, &other_recipe, &other_compiler).is_err());
}
