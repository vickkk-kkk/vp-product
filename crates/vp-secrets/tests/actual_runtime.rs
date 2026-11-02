//! Real encrypted vault + shared control + actual worker composition.
//! The local authored VLESS probe is adapted from runtime-executor test support;
//! it is NOT independent implementation or production probe certification.
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
use vp_product_secrets::{
    DurableSecretStore, Limits, MasterKey, Namespace, SecretKind, VaultError,
};
use vp_product_storage::SqliteStore;
const OLD: &str = "00000000-0000-0000-0000-000000000001";
const NEW: &str = "00000000-0000-0000-0000-000000000002";
const MARKER: &[u8; 12] = b"vp-wire-test";
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
    vault: Arc<DurableSecretStore>,
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
                let credential = self.vault.resolve_immutable(
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
    probe: Arc<LocalVlessProbe>,
    service: ControlService,
}
impl Harness {
    fn new(vault: Arc<DurableSecretStore>) -> Self {
        let control_dir = private_dir();
        let runtime_dir = private_dir();
        let store = Arc::new(SqliteStore::open(control_dir.path()).unwrap());
        let probe = Arc::new(LocalVlessProbe {
            vault: vault.clone(),
            echo: Echo::new(),
            fail_new: AtomicBool::new(false),
        });
        let (worker, digest) = worker_fixture();
        let runtime = Arc::new(
            ManagedExecutor::open(
                runtime_dir.path(),
                release(),
                worker,
                digest,
                vault,
                probe.clone(),
                Arc::new(SystemClock),
            )
            .unwrap(),
        );
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

fn key() -> MasterKey {
    MasterKey::new(SecretBytes::new(vec![0x35; 32])).unwrap()
}
fn namespace() -> Namespace {
    Namespace::new("synthetic-runtime-integration").unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

#[test]
fn actual_worker_rotation_uses_encrypted_vault_and_reopened_exact_references() {
    let vault_dir = private_dir();
    let vault = Arc::new(
        DurableSecretStore::initialize(
            vault_dir.path(),
            namespace(),
            key(),
            Limits::default(),
            deadline(),
        )
        .unwrap(),
    );
    let old = SecretRef::new("unit-old-v1").unwrap();
    let new = SecretRef::new("unit-new-v2").unwrap();
    vault
        .put(
            &old,
            SecretKind::Credential,
            1,
            SecretBytes::new(OLD.as_bytes().to_vec()),
            deadline(),
        )
        .unwrap();
    vault
        .put(
            &new,
            SecretKind::Credential,
            2,
            SecretBytes::new(NEW.as_bytes().to_vec()),
            deadline(),
        )
        .unwrap();
    let h = Harness::new(vault.clone());
    let port = free_port();
    let first = h.apply(config(port, false), "encrypted-first");
    assert_eq!(first.state, OperationState::Committed);
    let second = h.apply(config(port, true), "encrypted-rotation");
    assert_eq!(second.state, OperationState::Committed);
    assert!(
        second.activation.as_ref().unwrap().generation
            > first.activation.as_ref().unwrap().generation
    );
    let health = second.health.as_ref().unwrap();
    assert!(health.checks.iter().any(|r| matches!(
        r.check,
        HealthCheck::RetiredAuthenticationRejected(_)
    ) && r.outcome == CheckOutcome::Passed));
    assert_eq!(health.external_connectivity, CheckOutcome::NotChecked);
    assert!(!h
        .probe
        .wire(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            OLD.as_bytes(),
            false
        )
        .unwrap());
    assert!(h
        .probe
        .wire(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            NEW.as_bytes(),
            false
        )
        .unwrap());
    // Rejection probes and rollback retained OLD until rotation committed.
    // Only now perform irreversible vault retirement, not during apply.
    vault
        .retire(&old, SecretKind::Credential, 1, deadline())
        .unwrap();
    assert!(matches!(
        vault.get(&old, deadline()),
        Err(VaultError::Retired)
    ));
    for root in [
        vault_dir.path(),
        h.runtime_dir.path(),
        h._control_dir.path(),
    ] {
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = std::fs::read(path).unwrap();
                for value in [OLD, NEW] {
                    assert!(!bytes.windows(value.len()).any(|w| w == value.as_bytes()));
                }
            }
        }
    }
    drop(h);
    drop(vault);
    let reopened = Arc::new(
        DurableSecretStore::open(vault_dir.path(), namespace(), key(), deadline()).unwrap(),
    );
    assert!(matches!(
        reopened.get(&old, deadline()),
        Err(VaultError::Retired)
    ));
    assert_eq!(
        reopened
            .get_exact(&new, SecretKind::Credential, 2, deadline())
            .unwrap()
            .expose(),
        NEW.as_bytes()
    );
    // A fresh real worker consumes the key-authenticated reopened vault, not
    // credentials cached by the first controller/worker or a synthetic map.
    let resumed = Harness::new(reopened.clone());
    let restarted = resumed.apply(config(free_port(), true), "reopened-vault");
    assert_eq!(restarted.state, OperationState::Committed);
    assert_eq!(
        reopened.put(
            &old,
            SecretKind::Credential,
            3,
            SecretBytes::new(NEW.as_bytes().to_vec()),
            deadline()
        ),
        Err(VaultError::AlreadyExists)
    );
}
