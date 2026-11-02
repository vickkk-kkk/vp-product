//! Local authored wire probes, NOT independent implementation certification.
//! Only ephemeral synthetic UUID fixtures and loopback sockets are used.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, OnceLock,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use vp_product_compiler::{ExecutionRecipe, RecipeProtocol};
use vp_product_control::*;
use vp_product_core_adapter::managed::VerifiedWorker;
use vp_product_domain::*;
use vp_product_runtime_executor::*;
use vp_product_storage::SqliteStore;
const OLD: &str = "00000000-0000-0000-0000-000000000001";
const NEW: &str = "00000000-0000-0000-0000-000000000002";
const MARKER: &[u8; 12] = b"vp-wire-test";
struct SyntheticVault;
impl ImmutableSecretStore for SyntheticVault {
    fn validate_immutable(&self, reference: &SecretRef, _: Instant) -> Result<(), ControlError> {
        match reference.as_str() {
            "secret:unit-old-v1" | "secret:unit-new-v2" => Ok(()),
            _ => Err(ControlError::ExecutorUnavailable),
        }
    }
    fn resolve_immutable(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<SecretBytes, ControlError> {
        self.validate_immutable(reference, deadline)?;
        Ok(SecretBytes::new(
            if reference.as_str() == "secret:unit-old-v1" {
                OLD
            } else {
                NEW
            }
            .as_bytes()
            .to_vec(),
        ))
    }
}
struct Echo {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    payloads: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Echo {
    fn new() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let payloads = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (c, p, s) = (connections.clone(), payloads.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        c.fetch_add(1, Ordering::SeqCst);
                        stream
                            .set_read_timeout(Some(Duration::from_millis(300)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_millis(300)))
                            .unwrap();
                        let mut bytes = [0; 12];
                        if stream.read_exact(&mut bytes).is_ok() && bytes == *MARKER {
                            p.fetch_add(1, Ordering::SeqCst);
                            let _ = stream.write_all(&bytes);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            connections,
            payloads,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
struct LocalVlessProbe {
    echo: Echo,
    fail_new: AtomicBool,
}
impl LocalVlessProbe {
    fn wire(
        &self,
        address: SocketAddr,
        credential: &[u8],
        allow_absent: bool,
    ) -> Result<bool, ControlError> {
        let mut stream = match TcpStream::connect_timeout(&address, Duration::from_millis(500)) {
            Ok(stream) => stream,
            Err(e) if allow_absent && e.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Ok(false)
            }
            Err(_) => return Err(ControlError::HealthFailed),
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let hex: String = std::str::from_utf8(credential)
            .unwrap()
            .chars()
            .filter(|c| *c != '-')
            .collect();
        let mut bytes = vec![0];
        for index in (0..32).step_by(2) {
            bytes.push(u8::from_str_radix(&hex[index..index + 2], 16).unwrap());
        }
        bytes.extend_from_slice(&[0, 1]);
        bytes.extend_from_slice(&self.echo.address.port().to_be_bytes());
        bytes.extend_from_slice(&[1, 127, 0, 0, 1]);
        // Header then payload verifies actual target receives the bytes. A later
        // dedicated upstream regression covers coalesced initial payload.
        stream
            .write_all(&bytes)
            .map_err(|_| ControlError::HealthFailed)?;
        let mut response = [0; 2];
        if stream.read_exact(&mut response).is_err() {
            return Ok(false);
        }
        if response != [0, 0] {
            return Ok(false);
        }
        stream
            .write_all(MARKER)
            .map_err(|_| ControlError::HealthFailed)?;
        let mut echo = [0; 12];
        Ok(stream.read_exact(&mut echo).is_ok() && echo == *MARKER)
    }
    fn rejected(
        &self,
        address: SocketAddr,
        credential: &[u8],
        absent: bool,
    ) -> Result<CheckOutcome, ControlError> {
        let before = self.echo.connections.load(Ordering::SeqCst);
        let forwarded = self.wire(address, credential, absent)?;
        std::thread::sleep(Duration::from_millis(60));
        Ok(
            if !forwarded && self.echo.connections.load(Ordering::SeqCst) == before {
                CheckOutcome::Passed
            } else {
                CheckOutcome::Failed
            },
        )
    }
}
impl ActiveProbe for LocalVlessProbe {
    fn available(
        &self,
        current: &ExecutionRecipe,
        previous: Option<&ExecutionRecipe>,
        _: &BTreeSet<HealthCheck>,
    ) -> Result<(), ControlError> {
        if current
            .listeners
            .iter()
            .chain(previous.into_iter().flat_map(|p| p.listeners.iter()))
            .any(|l| !matches!(l.protocol, RecipeProtocol::Vless {}))
        {
            return Err(ControlError::ExecutorUnavailable);
        }
        Ok(())
    }
    fn check(&self, request: ProbeRequest<'_>, _: Instant) -> Result<CheckOutcome, ControlError> {
        let id = match request.check {
            HealthCheck::ListenerBound(id)
            | HealthCheck::Forwarding(id)
            | HealthCheck::InvalidAuthenticationRejected(id)
            | HealthCheck::RetiredListenerReleased(id) => id,
            HealthCheck::AuthenticationAccepted(auth)
            | HealthCheck::RetiredAuthenticationRejected(auth) => &auth.listener_id,
            _ => return Err(ControlError::ExecutorUnavailable),
        };
        let current = request
            .current
            .listeners
            .iter()
            .find(|l| l.id.as_str() == id);
        let old = request.previous.and_then(|p| {
            p.listeners
                .iter()
                .find(|l| l.id.as_str() == id)
                .map(|l| (p, l))
        });
        let (recipe, listener) = current
            .map(|l| (request.current, l))
            .or(old)
            .ok_or(ControlError::HealthFailed)?;
        let address = SocketAddr::new(recipe.bind_address, listener.port);
        match request.check {
            HealthCheck::ListenerBound(_) => Ok(
                if TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_ok() {
                    CheckOutcome::Passed
                } else {
                    CheckOutcome::Failed
                },
            ),
            HealthCheck::AuthenticationAccepted(_) => {
                let credential = request.credential.unwrap().expose();
                let before = self.echo.payloads.load(Ordering::SeqCst);
                let success = self.wire(address, credential, false)?
                    && self.echo.payloads.load(Ordering::SeqCst) == before + 1;
                Ok(if success {
                    CheckOutcome::Passed
                } else {
                    CheckOutcome::Failed
                })
            }
            HealthCheck::Forwarding(_) => {
                if self.fail_new.load(Ordering::Acquire)
                    && listener.users[0].credential_ref.as_str() == "secret:unit-new-v2"
                {
                    return Ok(CheckOutcome::Failed);
                }
                let credential = SyntheticVault.resolve_immutable(
                    &listener.users[0].credential_ref,
                    Instant::now() + Duration::from_secs(1),
                )?;
                Ok(if self.wire(address, credential.expose(), false)? {
                    CheckOutcome::Passed
                } else {
                    CheckOutcome::Failed
                })
            }
            HealthCheck::InvalidAuthenticationRejected(_) => {
                self.rejected(address, b"ffffffff-ffff-ffff-ffff-ffffffffffff", false)
            }
            HealthCheck::RetiredAuthenticationRejected(_) => self.rejected(
                address,
                request.credential.unwrap().expose(),
                current.is_none(),
            ),
            HealthCheck::RetiredListenerReleased(_) => {
                let (recipe, listener) = old.ok_or(ControlError::HealthFailed)?;
                Ok(
                    if TcpListener::bind(SocketAddr::new(recipe.bind_address, listener.port))
                        .is_ok()
                    {
                        CheckOutcome::Passed
                    } else {
                        CheckOutcome::Failed
                    },
                )
            }
            _ => Err(ControlError::ExecutorUnavailable),
        }
    }
    fn stopped(&self, recipe: &ExecutionRecipe, _: Instant) -> Result<(), ControlError> {
        let mut held = Vec::new();
        for listener in &recipe.listeners {
            held.push(
                TcpListener::bind(SocketAddr::new(recipe.bind_address, listener.port))
                    .map_err(|_| ControlError::HealthFailed)?,
            );
        }
        Ok(())
    }
}
fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn worker_fixture() -> (VerifiedWorker, ContentDigest) {
    static WORKER: OnceLock<(VerifiedWorker, ContentDigest)> = OnceLock::new();
    WORKER.get_or_init(|| {
        let path = std::env::var_os("VP_RUNTIME_TEST_WORKER").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/vp-core-managed-worker"));
        let path = std::fs::canonicalize(path).expect("build vp-core-managed-worker with managed-runtime before this actual-process suite");
        let mut hash = Sha256::new(); let mut file = std::fs::File::open(&path).unwrap(); let mut buffer = [0; 65536]; loop { let n = file.read(&mut buffer).unwrap(); if n == 0 { break; } hash.update(&buffer[..n]); }
        let digest = format!("{:x}", hash.finalize()); (VerifiedWorker::new(path, &digest).unwrap(), ContentDigest::parse(digest).unwrap())
    }).clone()
}
fn release() -> ReleaseIdentity {
    vp_product_core_adapter::inspect_build()
        .unwrap()
        .build
        .release
}
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn config(port: u16, new: bool) -> ProductConfig {
    serde_json::from_value(serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{"schemaVersion":1,"id":"vless-test","name":"local test only","enabled":true,"bind":{"address":"127.0.0.1","port":port},"protocol":{"kind":"proxy","protocol":{"kind":"vless","flow":null},"users":[{"id":"unit-user","credentialRef":if new {"secret:unit-new-v2"} else {"secret:unit-old-v1"},"enabled":true}]},"transport":{"kind":"tcp"},"security":{"kind":"none"},"requirements":[]}]})).unwrap()
}
struct Harness {
    _control_dir: tempfile::TempDir,
    runtime_dir: tempfile::TempDir,
    store: Arc<SqliteStore>,
    runtime: Arc<ManagedExecutor>,
    probe: Arc<LocalVlessProbe>,
    service: ControlService,
}
impl Harness {
    fn new() -> Self {
        Self::with_bound(false)
    }
    fn with_bound(bound: bool) -> Self {
        let control_dir = private_dir();
        let runtime_dir = private_dir();
        let store = Arc::new(SqliteStore::open(control_dir.path()).unwrap());
        let probe = Arc::new(LocalVlessProbe {
            echo: Echo::new(),
            fail_new: AtomicBool::new(false),
        });
        let (worker, digest) = worker_fixture();
        let runtime = Arc::new(if bound {
            let expected = vp_product_storage::DirectoryIdentity::of(
                &std::fs::File::open(runtime_dir.path()).unwrap(),
            )
            .unwrap();
            ManagedExecutor::open_bound(
                vp_product_storage::BoundDirectory::open(runtime_dir.path(), expected).unwrap(),
                vp_product_storage::BoundOpenMode::CreateFresh,
                BoundRuntimeIdentity {
                    genesis: ContentDigest::bytes(b"synthetic-bound-genesis"),
                    release: release(),
                    worker_digest: digest,
                },
                worker,
                Arc::new(SyntheticVault),
                probe.clone(),
                Arc::new(SystemClock),
            )
            .unwrap()
        } else {
            ManagedExecutor::open(
                runtime_dir.path(),
                release(),
                worker,
                digest,
                Arc::new(SyntheticVault),
                probe.clone(),
                Arc::new(SystemClock),
            )
            .unwrap()
        });
        let service = ControlService::new(
            store.clone(),
            runtime.clone(),
            Arc::new(NoHostChanges),
            Arc::new(SystemClock),
        );
        Self {
            _control_dir: control_dir,
            runtime_dir,
            store,
            runtime,
            probe,
            service,
        }
    }
    fn plan(&self, config: ProductConfig) -> ChangePlan {
        self.service
            .plan(PlanRequest {
                principal: UserId::new("test-admin").unwrap(),
                expected_revision: self.store.read().unwrap().active_revision,
                config,
                release: release(),
                resources: Vec::new(),
                ttl_ms: 60_000,
            })
            .unwrap()
    }
    fn submit(&self, plan: &ChangePlan, key: &str) -> Operation {
        self.service
            .submit(ApplyRequest {
                principal: UserId::new("test-admin").unwrap(),
                plan_id: plan.body().id.clone(),
                confirmed_hash: plan.hash().clone(),
                expected_revision: plan.body().base_revision,
                idempotency_key: IdempotencyKey::new(key).unwrap(),
            })
            .unwrap()
    }
    fn apply(&self, config: ProductConfig, key: &str) -> Operation {
        let plan = self.plan(config);
        let op = self.submit(&plan, key);
        self.service
            .run(&op.id, &CancellationToken::default())
            .unwrap()
    }
}
#[test]
fn real_apply_rotation_retires_credentials_and_never_serializes_secrets() {
    let h = Harness::new();
    let port = free_port();
    let first = h.apply(config(port, false), "first");
    assert_eq!(first.state, OperationState::Committed);
    let second = h.apply(config(port, true), "rotation");
    assert_eq!(second.state, OperationState::Committed);
    assert!(
        second.activation.as_ref().unwrap().generation
            > first.activation.as_ref().unwrap().generation
    );
    let health = second.health.unwrap();
    assert!(health.checks.iter().any(|r| matches!(
        r.check,
        HealthCheck::RetiredAuthenticationRejected(_)
    ) && r.outcome == CheckOutcome::Passed));
    assert_eq!(health.external_connectivity, CheckOutcome::NotChecked);
    assert_eq!(
        h.store.read().unwrap().active_revision,
        Revision::new(2).unwrap()
    );
    for entry in std::fs::read_dir(h.runtime_dir.path()).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        for secret in [OLD, NEW] {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "credential bytes persisted"
            );
        }
    }
}
#[test]
fn failed_forwarding_rolls_back_real_runtime_and_old_credentials() {
    let h = Harness::new();
    let port = free_port();
    assert_eq!(
        h.apply(config(port, false), "old").state,
        OperationState::Committed
    );
    h.probe.fail_new.store(true, Ordering::Release);
    let failed = h.apply(config(port, true), "failing");
    assert_eq!(failed.state, OperationState::RolledBack);
    assert_eq!(
        h.store.read().unwrap().active_revision,
        Revision::new(1).unwrap()
    );
    assert!(h
        .probe
        .wire((Ipv4Addr::LOCALHOST, port).into(), OLD.as_bytes(), false)
        .unwrap());
    assert_eq!(
        h.probe
            .rejected((Ipv4Addr::LOCALHOST, port).into(), NEW.as_bytes(), false)
            .unwrap(),
        CheckOutcome::Passed
    );
    let plan = h
        .store
        .read()
        .unwrap()
        .plans
        .get(&failed.plan_id)
        .unwrap()
        .clone();
    h.runtime.stop_candidate(&failed.id, &plan).unwrap();
    assert!(
        h.probe
            .wire((Ipv4Addr::LOCALHOST, port).into(), OLD.as_bytes(), false)
            .unwrap(),
        "late candidate cleanup stopped restored previous generation"
    );
}
#[test]
fn bind_failure_rolls_back_and_initial_failure_restores_stopped_state() {
    let h = Harness::new();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = occupied.local_addr().unwrap().port();
    let failed = h.apply(config(port, false), "bind-fail");
    // The unrelated owner occupying the candidate port prevents proving the
    // pre-install absent listener; recovery must remain unresolved, not fake pass.
    assert_eq!(failed.state, OperationState::RecoveryRequired);
    drop(occupied);
    let recovered = h.service.recover().unwrap();
    assert_eq!(recovered[0].state, OperationState::RolledBack);
    assert_eq!(h.store.read().unwrap().active_revision, Revision::ZERO);
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
}
#[test]
fn missing_vault_or_probe_never_issues_a_validation_receipt() {
    let dir = private_dir();
    let (worker, digest) = worker_fixture();
    let runtime = ManagedExecutor::open(
        dir.path(),
        release(),
        worker,
        digest,
        Arc::new(UnavailableSecretStore),
        Arc::new(UnavailableProbe),
        Arc::new(SystemClock),
    )
    .unwrap();
    assert_eq!(
        runtime
            .validate(&config(free_port(), false), &release(), None)
            .unwrap_err(),
        ControlError::ExecutorUnavailable
    );
}
#[test]
fn lifetime_lock_private_permissions_tamper_and_cancellation_fail_closed() {
    let h = Harness::new();
    let (worker, digest) = worker_fixture();
    assert!(matches!(
        ManagedExecutor::open(
            h.runtime_dir.path(),
            release(),
            worker,
            digest,
            Arc::new(SyntheticVault),
            h.probe.clone(),
            Arc::new(SystemClock)
        ),
        Err(ControlError::RecoveryRequired)
    ));
    let plan = h.plan(config(free_port(), false));
    let operation = OperationId::new("cancel-stage").unwrap();
    let cancel = CancellationToken::default();
    cancel.cancel();
    assert_eq!(
        h.runtime.stage(&operation, &plan, &cancel).unwrap_err(),
        ControlError::Canceled
    );
    h.runtime
        .stage(&operation, &plan, &CancellationToken::default())
        .unwrap();
    h.runtime
        .stage(&operation, &plan, &CancellationToken::default())
        .unwrap();
    std::fs::write(
        h.runtime_dir
            .path()
            .join(plan.body().validation.artifact_digest.as_str()),
        b"tampered",
    )
    .unwrap();
    assert_eq!(
        h.runtime.activate(&operation, &plan, None).unwrap_err(),
        ControlError::CorruptState
    );
    use std::os::unix::fs::PermissionsExt;
    let public = private_dir();
    std::fs::set_permissions(public.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let (worker, digest) = worker_fixture();
    assert!(matches!(
        ManagedExecutor::open(
            public.path(),
            release(),
            worker,
            digest,
            Arc::new(SyntheticVault),
            h.probe.clone(),
            Arc::new(SystemClock)
        ),
        Err(ControlError::PermissionDenied)
    ));
}
#[test]
fn daemon_reopen_never_reuses_generation_or_saved_health() {
    let h = Harness::new();
    let port = free_port();
    let old = h.apply(config(port, false), "one");
    let old_generation = old.activation.unwrap().generation;
    let previous = h.store.read().unwrap().active().unwrap().clone();
    let path = h.runtime_dir.path().to_owned();
    let Harness {
        service,
        runtime,
        runtime_dir,
        probe,
        ..
    } = h;
    drop(service);
    drop(runtime);
    let (worker, digest) = worker_fixture();
    let runtime = ManagedExecutor::open(
        &path,
        release(),
        worker,
        digest,
        Arc::new(SyntheticVault),
        probe.clone(),
        Arc::new(SystemClock),
    )
    .unwrap();
    runtime.reconcile_committed(&previous).unwrap();
    assert!(probe
        .wire((Ipv4Addr::LOCALHOST, port).into(), OLD.as_bytes(), false)
        .unwrap());
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("runtime.journal.json")).unwrap()).unwrap();
    assert!(journal["journal"]["active"]["generation"].as_u64().unwrap() > old_generation);
    drop(runtime);
    drop(runtime_dir);
}

/// Only the test composition injects this host interruption; it delegates every
/// action to the real bridge and never manufactures a successful receipt/probe.
struct InterruptBeforeVerify(Arc<ManagedExecutor>);
impl RuntimeExecutor for InterruptBeforeVerify {
    fn validate(
        &self,
        c: &ProductConfig,
        r: &ReleaseIdentity,
        p: Option<&RevisionRecord>,
    ) -> Result<ValidationReceipt, ControlError> {
        self.0.validate(c, r, p)
    }
    fn stage(
        &self,
        o: &OperationId,
        p: &ChangePlan,
        c: &CancellationToken,
    ) -> Result<(), ControlError> {
        self.0.stage(o, p, c)
    }
    fn activate(
        &self,
        o: &OperationId,
        p: &ChangePlan,
        r: Option<&RevisionRecord>,
    ) -> Result<RuntimeActivation, ControlError> {
        self.0.activate(o, p, r)
    }
    fn verify(
        &self,
        _: &OperationId,
        _: &ChangePlan,
    ) -> Result<vp_product_control::RuntimeHealth, ControlError> {
        panic!("test-only interruption after durable activation, before health")
    }
    fn stop_candidate(&self, o: &OperationId, p: &ChangePlan) -> Result<(), ControlError> {
        self.0.stop_candidate(o, p)
    }
    fn restore_previous(
        &self,
        o: &OperationId,
        r: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        self.0.restore_previous(o, r)
    }
    fn verify_previous(
        &self,
        o: &OperationId,
        r: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        self.0.verify_previous(o, r)
    }
    fn discard_stage(&self, o: &OperationId) -> Result<(), ControlError> {
        self.0.discard_stage(o)
    }
}
#[test]
fn interrupted_control_reopen_recovers_prior_config_without_stale_health_commit() {
    let h = Harness::new();
    let port = free_port();
    assert_eq!(
        h.apply(config(port, false), "first").state,
        OperationState::Committed
    );
    let plan = h.plan(config(port, true));
    let op = h.submit(&plan, "interrupted");
    let interrupted = ControlService::new(
        h.store.clone(),
        Arc::new(InterruptBeforeVerify(h.runtime.clone())),
        Arc::new(NoHostChanges),
        Arc::new(SystemClock),
    );
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || interrupted.run(&op.id, &CancellationToken::default())
    ))
    .is_err());
    drop(interrupted);
    let Harness {
        _control_dir,
        runtime_dir,
        store,
        runtime,
        probe,
        service,
    } = h;
    drop(service);
    drop(runtime);
    drop(store);
    let store = Arc::new(SqliteStore::open(_control_dir.path()).unwrap());
    assert_eq!(
        store.read().unwrap().operations[&op.id].state,
        OperationState::Verifying
    );
    assert_eq!(
        store.read().unwrap().active_revision,
        Revision::new(1).unwrap()
    );
    let (worker, digest) = worker_fixture();
    let runtime = Arc::new(
        ManagedExecutor::open(
            runtime_dir.path(),
            release(),
            worker,
            digest,
            Arc::new(SyntheticVault),
            probe.clone(),
            Arc::new(SystemClock),
        )
        .unwrap(),
    );
    let recovered = ControlService::new(
        store.clone(),
        runtime,
        Arc::new(NoHostChanges),
        Arc::new(SystemClock),
    );
    let result = recovered.recover().unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].state, OperationState::RolledBack);
    assert_eq!(
        store.read().unwrap().active_revision,
        Revision::new(1).unwrap()
    );
    assert!(probe
        .wire((Ipv4Addr::LOCALHOST, port).into(), OLD.as_bytes(), false)
        .unwrap());
    assert_eq!(
        probe
            .rejected((Ipv4Addr::LOCALHOST, port).into(), NEW.as_bytes(), false)
            .unwrap(),
        CheckOutcome::Passed
    );
}

async fn http_request(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: serde_json::Value,
    auth: Option<&(String, String)>,
) -> (
    axum::http::StatusCode,
    axum::http::HeaderMap,
    serde_json::Value,
) {
    use tower::ServiceExt;
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost:9443")
        .header("origin", "https://localhost:9443")
        .header("content-type", "application/json");
    if let Some((cookie, csrf)) = auth {
        request = request.header("cookie", cookie).header("x-vp-csrf", csrf);
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, headers, serde_json::from_slice(&bytes).unwrap())
}
fn http_command(
    method: &str,
    key: &str,
    revision: u64,
    payload: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({"schemaVersion":1,"requestId":"runtime-http-test","idempotencyKey":key,"expectedRevision":revision,"method":method,"payload":payload})
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_http_router_applies_real_worker_instead_of_unavailable_stub() {
    use axum::http::StatusCode;
    use serde_json::{json, Value};
    use vp_product_api::{ApiState, BootstrapCredential, OperationWorker, SecurityPolicy};
    const TOKEN: &str = "synthetic-http-test-token-never-deployed-0123456789";
    let h = Harness::new();
    let control = Arc::new(ControlService::new(
        h.store.clone(),
        h.runtime.clone(),
        Arc::new(NoHostChanges),
        Arc::new(SystemClock),
    ));
    let (worker, handle) = OperationWorker::start(control.clone());
    let router = vp_product_api::router(
        ApiState::new(
            control,
            worker.clone(),
            BootstrapCredential::new("tester", SecretBytes::new(TOKEN.as_bytes().to_vec()))
                .unwrap(),
            SecurityPolicy::new("https://localhost:9443").unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        http_request(&router, "GET", "/api/v1/config", Value::Null, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let login = http_request(
        &router,
        "POST",
        "/api/v1/auth/login",
        json!({"username":"tester","password":TOKEN,"secondFactor":null}),
        None,
    )
    .await;
    assert_eq!(login.0, StatusCode::OK);
    let auth = (
        login.1["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned(),
        login.2["result"]["csrfToken"].as_str().unwrap().to_owned(),
    );
    let port = free_port();
    let draft = http_request(
        &router,
        "POST",
        "/api/v1/drafts",
        http_command(
            "draft_create",
            "http-draft",
            0,
            serde_json::to_value(config(port, false)).unwrap(),
        ),
        Some(&auth),
    )
    .await;
    assert_eq!(draft.0, StatusCode::OK);
    let plan = http_request(
        &router,
        "POST",
        "/api/v1/plans",
        http_command(
            "plan_create",
            "http-plan",
            0,
            json!({"draftId":draft.2["result"]["id"]}),
        ),
        Some(&auth),
    )
    .await;
    assert_eq!(plan.0, StatusCode::OK);
    let apply_path = format!(
        "/api/v1/plans/{}/apply",
        plan.2["result"]["id"].as_str().unwrap()
    );
    let command = http_command(
        "plan_apply",
        "http-apply",
        0,
        json!({"planHash":plan.2["result"]["planHash"],"confirmed":true}),
    );
    let apply = http_request(&router, "POST", &apply_path, command.clone(), Some(&auth)).await;
    assert_eq!(apply.0, StatusCode::ACCEPTED);
    let retry = http_request(&router, "POST", &apply_path, command, Some(&auth)).await;
    assert_eq!(retry.2["operationId"], apply.2["operationId"]);
    let result = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let operation = http_request(
                &router,
                "GET",
                "/api/v1/operations/by-idempotency/http-apply",
                Value::Null,
                Some(&auth),
            )
            .await;
            assert_eq!(operation.0, StatusCode::OK);
            match operation.2["result"]["status"].as_str().unwrap() {
                "queued" | "running" => tokio::time::sleep(Duration::from_millis(20)).await,
                _ => break operation.2,
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(result["result"]["status"], "succeeded");
    let active = http_request(&router, "GET", "/api/v1/config", Value::Null, Some(&auth)).await;
    assert_eq!(active.0, StatusCode::OK);
    assert_eq!(active.2["result"]["revision"], 1);
    assert!(h
        .probe
        .wire((Ipv4Addr::LOCALHOST, port).into(), OLD.as_bytes(), false)
        .unwrap());
    assert_eq!(
        h.probe
            .rejected((Ipv4Addr::LOCALHOST, port).into(), NEW.as_bytes(), false)
            .unwrap(),
        CheckOutcome::Passed
    );
    worker.stop();
    handle.await.unwrap();
}

#[test]
fn bound_runtime_actual_apply_rotation_rename_and_paired_restart() {
    use std::os::unix::fs::PermissionsExt;
    use vp_product_storage::{BoundDirectory, BoundOpenMode, DirectoryIdentity};
    let h = Harness::with_bound(true);
    let before_legacy = std::fs::read_dir(h.runtime_dir.path()).unwrap().count();
    let (old_worker, old_digest) = worker_fixture();
    assert!(ManagedExecutor::open(
        h.runtime_dir.path(),
        release(),
        old_worker,
        old_digest,
        Arc::new(SyntheticVault),
        h.probe.clone(),
        Arc::new(SystemClock)
    )
    .is_err());
    assert_eq!(
        std::fs::read_dir(h.runtime_dir.path()).unwrap().count(),
        before_legacy
    );
    assert!(!h.runtime_dir.path().join("runtime.writer.lock").exists());
    let original = h.runtime_dir.path().to_path_buf();
    let retained = h._control_dir.path().join("retained-runtime");
    std::fs::rename(&original, &retained).unwrap();
    std::fs::create_dir(&original).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
    let port = free_port();
    let first = h.apply(config(port, false), "bound-one");
    assert_eq!(first.state, OperationState::Committed);
    let second = h.apply(config(port, true), "bound-two");
    assert_eq!(second.state, OperationState::Committed);
    assert!(
        second.activation.as_ref().unwrap().generation
            > first.activation.as_ref().unwrap().generation
    );
    assert_eq!(std::fs::read_dir(&original).unwrap().count(), 0);
    let paired = h.store.read().unwrap();
    h.runtime.validate_startup_pair(&paired).unwrap();
    assert!(h
        .runtime
        .validate_startup_pair(&StoredState::default())
        .is_err());
    let mut mismatched = paired.clone();
    mismatched.active_revision = mismatched.revisions[0].revision;
    assert!(h.runtime.validate_startup_pair(&mismatched).is_err());
    let mut pending = paired.clone();
    pending.operations.get_mut(&second.id).unwrap().state = OperationState::Activating;
    assert!(h.runtime.validate_startup_pair(&pending).is_err());
    h.runtime.shutdown().unwrap();
    h.runtime.validate_startup_pair(&paired).unwrap();
    let previous = h.store.read().unwrap().active().unwrap().clone();
    let last_generation = second.activation.unwrap().generation;
    let Harness {
        _control_dir: control_dir,
        runtime_dir,
        store,
        runtime,
        probe,
        service,
    } = h;
    drop(service);
    drop(runtime);
    let expected = DirectoryIdentity::of(&std::fs::File::open(&retained).unwrap()).unwrap();
    let (worker, digest) = worker_fixture();
    let runtime = ManagedExecutor::open_bound(
        BoundDirectory::open(&retained, expected).unwrap(),
        BoundOpenMode::OpenExisting,
        BoundRuntimeIdentity {
            genesis: ContentDigest::bytes(b"synthetic-bound-genesis"),
            release: release(),
            worker_digest: digest,
        },
        worker,
        Arc::new(SyntheticVault),
        probe.clone(),
        Arc::new(SystemClock),
    )
    .unwrap();
    runtime
        .validate_startup_pair(&store.read().unwrap())
        .unwrap();
    runtime.reconcile_committed(&previous).unwrap();
    assert!(probe
        .wire((Ipv4Addr::LOCALHOST, port).into(), NEW.as_bytes(), false)
        .unwrap());
    let journal: serde_json::Value = serde_json::from_slice(
        &std::fs::read(retained.join("journal/runtime.journal.json")).unwrap(),
    )
    .unwrap();
    assert!(journal["journal"]["active"]["generation"].as_u64().unwrap() > last_generation);
    for child in ["journal", "artifacts"] {
        for entry in std::fs::read_dir(retained.join(child)).unwrap() {
            let data = std::fs::read(entry.unwrap().path()).unwrap();
            for secret in [OLD, NEW] {
                assert!(!data.windows(secret.len()).any(|w| w == secret.as_bytes()));
            }
        }
    }
    drop(runtime);
    drop(probe);
    drop(store);
    drop(runtime_dir);
    drop(control_dir);
}
