//! Real SQL/vault/import/resolver/worker/wire component journey.
//! Credential provisioning uses ControlService. Staging is explicitly synthetic:
//! this is NOT ControlService::apply, durable v2 recovery, or production admission.
//! Fresh ephemeral test roots only; all listeners are IPv4 loopback.
#![allow(clippy::unwrap_used, clippy::expect_used)]
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
fn verified_worker() -> VerifiedWorker {
    let path = std::env::var("VP_TEST_SERVER_V2_WORKER").expect("reviewed worker path required");
    let expected = std::env::var("VP_TEST_SERVER_V2_SHA256").expect("reviewed worker SHA required");
    assert_eq!(expected.len(), 64);
    assert!(expected.bytes().all(|b| b.is_ascii_hexdigit()));
    // The expected identity is supplied by the external frozen artifact receipt.
    // Do not replace it with a hash computed from whichever file happened to exist.
    VerifiedWorker::for_server_v2(&path, &expected, deadline(), &Cancellation::default()).unwrap()
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
            artifact_digest: ContentDigest::bytes(
                b"EXPLICIT-SYNTHETIC-STAGING-NOT-PRODUCTION-APPLY",
            ),
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
fn mark_fixture_phase(store: &TlsSqliteStore, id: &OperationId, phase: OperationState) {
    let mut lease = store.asset_writer().unwrap();
    let mut state = lease.state().clone();
    let op = state.operations.get_mut(id).unwrap();
    op.state = phase.clone();
    op.updated_at_ms = now();
    state.version += 1;
    let event = journal(&state, id, phase);
    lease.persist(state, event).unwrap();
}
fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), IO_WAIT).unwrap();
    stream.set_read_timeout(Some(IO_WAIT)).unwrap();
    stream.set_write_timeout(Some(IO_WAIT)).unwrap();
    stream
}
fn tls(
    port: u16,
    ca: Option<&[u8]>,
    name: &str,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca) = ca {
        roots
            .add(rustls::pki_types::CertificateDer::from(ca.to_vec()))
            .unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connection = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap(),
    )
    .unwrap();
    rustls::StreamOwned::new(connection, connect(port))
}
fn trojan(password: &[u8], target: u16, payload: &[u8]) -> SecretBytes {
    // Standard Trojan CONNECT header. Never print this password-derived value.
    let mut request = format!("{:x}\r\n", Sha224::digest(password)).into_bytes();
    request.extend_from_slice(&[1, 1, 127, 0, 0, 1]);
    request.extend_from_slice(&target.to_be_bytes());
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(payload);
    SecretBytes::new(request)
}
fn no_target(target: &TcpListener) {
    // Bounded observation, not a claim about all future time.
    let end = Instant::now() + Duration::from_millis(500);
    while Instant::now() < end {
        match target.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Ok(_) => panic!("negative case reached target"),
            Err(_) => panic!("target observation failed"),
        }
    }
}
fn handshake_fails(port: u16, ca: Option<&[u8]>, name: &str) {
    let mut client = tls(port, ca, name);
    let end = Instant::now() + IO_WAIT;
    while client.conn.is_handshaking() {
        assert!(Instant::now() < end, "TLS rejection deadline");
        if client.conn.complete_io(&mut client.sock).is_err() {
            return;
        }
    }
    panic!("invalid trust/name unexpectedly handshook");
}
fn child(path: &Path) {
    // Create/anchor before starting any target threads or worker pumps.
    let control_path = path.join("control");
    let vault_path = path.join("vault");
    for p in [&control_path, &vault_path] {
        fs::create_dir(p).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let metadata = fs::metadata(&vault_path).unwrap();
    let vault = TlsSecretStore::initialize_bound(
        &vault_path,
        Namespace::new("registry-wire-test").unwrap(),
        MasterKey::new(SecretBytes::new(vec![61; 32])).unwrap(),
        Limits::default(),
        VaultDirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        deadline(),
    )
    .unwrap();
    let observation = vault.inspect_read_only(deadline()).unwrap();
    let d = ContentDigest::bytes(b"SYNTHETIC-COMPONENT-GENESIS-NOT-INSTANCE-ADMISSION");
    let binding = InstanceBinding {
        binding_version: 1,
        genesis_id: "9".repeat(32),
        vault_id: observation.vault_id,
        namespace_digest: ContentDigest::parse(observation.namespace_digest).unwrap(),
        administrator_commitment: d.clone(),
        preparation_digest: d.clone(),
        activation_intent_digest: d.clone(),
        artifact_set_digest: d,
        profile: FRESH_TLS_RUNTIME_PROFILE.into(),
    };
    vault.claim_instance_binding(&binding, deadline()).unwrap();
    let store = Arc::new(TlsSqliteStore::create(anchor(&control_path), binding).unwrap());
    store.mark_initialized().unwrap();
    let vault = Arc::new(vault);
    let manager = Arc::new(TlsPasswordSecretManager::new(vault.clone()));
    let control = ControlService::new(
        store.clone(),
        Arc::new(UnavailableRuntime),
        Arc::new(UnavailableSystem),
        Arc::new(SystemClock),
    )
    .with_secret_manager(manager.clone());
    let credential = control
        .create_credential(
            &actor(),
            Revision::ZERO,
            IdempotencyKey::new("wire-password").unwrap(),
            CredentialCreatePayload {
                kind: NodeCredentialKind::Password {},
                confirm_generate: ExplicitConfirmation::try_from(true).unwrap(),
            },
        )
        .unwrap();
    let password = manager
        .load_credential(
            &credential.secret_ref,
            &credential.kind,
            Some(1),
            deadline(),
        )
        .unwrap()
        .unwrap();
    let (chain, key, ca) = materials();
    let policy = TlsBackendPolicy::new(
        actor().as_str().into(),
        vec![ca.clone()],
        "localhost".into(),
    )
    .unwrap();
    let wall = SystemClock;
    let importer = TlsImportService::new(&policy, &wall);
    let cancel = CancellationToken::default();
    {
        let mut lease = store.asset_writer().unwrap();
        let version = lease.state().version;
        importer
            .import(
                &mut lease,
                vault.as_ref(),
                TlsImportRequest {
                    actor: actor().as_str().into(),
                    expected_version: version,
                    action: "wire-import".into(),
                    idempotency: "wire-import-request".into(),
                    asset: "wire-certificate".into(),
                    confirmed: true,
                    chain,
                    key,
                },
                deadline(),
                &cancel,
            )
            .unwrap();
    }
    let worker = verified_worker();
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    let target_port = target.local_addr().unwrap().port();
    let release = vp_product_core_adapter::inspect_build()
        .unwrap()
        .build
        .release;
    let compiler = ServerCompilerV2::for_loopback_server_extensions(release.clone()).unwrap();
    let config = config(port, &credential.secret_ref);
    let recipe = compiler.compile(&config, &release).unwrap();
    let operation = synthetic_stage(&store, config, release, "first");
    let mut runtime = ManagedRuntimeV2::with_generation(
        worker,
        WorkerInstanceV2::new("registry-wire-owned").unwrap(),
        0,
    )
    .unwrap();
    let lease = store.asset_writer().unwrap();
    let version = lease.state().version;
    assert!(TlsMaterialAdmission::for_staging(
        &lease,
        vault.as_ref(),
        &policy,
        &wall,
        version - 1,
        &operation,
        deadline(),
        &cancel
    )
    .is_err());
    let canceled = CancellationToken::default();
    canceled.cancel();
    assert!(TlsMaterialAdmission::for_staging(
        &lease,
        vault.as_ref(),
        &policy,
        &wall,
        version,
        &operation,
        deadline(),
        &canceled
    )
    .is_err());
    assert!(TlsMaterialAdmission::for_staging(
        &lease,
        vault.as_ref(),
        &policy,
        &wall,
        version,
        &operation,
        Instant::now(),
        &cancel
    )
    .is_err());
    assert_eq!(runtime.prepared_generation(), None);
    drop(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap());
    let inputs = {
        let admission = TlsMaterialAdmission::for_staging(
            &lease,
            vault.as_ref(),
            &policy,
            &wall,
            version,
            &operation,
            deadline(),
            &cancel,
        )
        .unwrap();
        let resolver = RegistryMaterialResolverV2::new(admission, &recipe, &compiler).unwrap();
        resolve_materials_v2(&recipe, &resolver, deadline(), &Cancellation::default()).unwrap()
    };
    let mut cooperative_abort = None;
    let prepared = runtime.prepare_with_spawn_observer(
        recipe,
        inputs,
        0,
        WAIT,
        &Cancellation::default(),
        |observed| {
            let (ticks, parent, session, _) =
                process_identity(observed.pid).expect("owned worker identity");
            assert_eq!(parent, std::process::id());
            assert_eq!(session, process_identity(std::process::id()).unwrap().2);
            println!("VP_WIRE_WORKER={}:{}:{}", observed.pid, ticks, port);
            std::io::stdout().flush().unwrap();
            let mut go = [0];
            if std::io::stdin().read_exact(&mut go).is_err() || go != [1] {
                cooperative_abort = Some((observed.pid, ticks));
                return Err(Failure::Canceled);
            }
            Ok(())
        },
    );
    if let Some((pid, ticks)) = cooperative_abort {
        assert!(prepared.is_err());
        // Observer error drops/reaps the actual retained ProcessV2 before return.
        assert!(process_identity(pid).is_none_or(|(current, _, _, _)| current != ticks));
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
        println!("VP_WIRE_ABORT_REAPED={pid}:{ticks}");
        return;
    }
    let process = prepared.unwrap();
    assert_eq!(runtime.prepared_generation(), Some(process.generation));
    drop(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap());
    let ready = runtime
        .activate_prepared(process.generation, WAIT, &Cancellation::default())
        .unwrap();
    assert!(ready.listeners_ready);
    assert!(!ready.forwarding_verified);
    handshake_fails(port, None, "localhost");
    no_target(&target);
    handshake_fails(port, Some(&ca), "wrong.invalid");
    no_target(&target);
    {
        let mut plain = connect(port);
        plain.write_all(b"not-tls\r\n").unwrap();
        let mut b = [0; 1];
        let _ = plain.read(&mut b);
    }
    no_target(&target);
    {
        let mut client = tls(port, Some(&ca), "localhost");
        let request = trojan(b"wrong-synthetic-password", target_port, b"must-not-arrive");
        client.write_all(request.expose()).unwrap();
        client.flush().unwrap();
        let mut b = [0; 1];
        let _ = client.read(&mut b);
    }
    no_target(&target);
    let nonce = Sha256::digest(format!("target nonce:{}:{}", now(), std::process::id()).as_bytes())
        .to_vec();
    let sent = nonce.clone();
    let reply = Sha256::digest(&nonce).to_vec();
    let expected = reply.clone();
    let target_thread = std::thread::spawn(move || {
        let end = Instant::now() + WAIT;
        let mut stream = loop {
            match target.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < end, "target accept deadline");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => panic!("target accept failure"),
            }
        };
        stream.set_read_timeout(Some(IO_WAIT)).unwrap();
        stream.set_write_timeout(Some(IO_WAIT)).unwrap();
        let mut actual = vec![0; sent.len()];
        stream.read_exact(&mut actual).unwrap();
        assert_eq!(actual, sent);
        stream.write_all(&reply).unwrap();
    });
    {
        let mut client = tls(port, Some(&ca), "localhost");
        let request = trojan(password.expose(), target_port, &nonce);
        client.write_all(request.expose()).unwrap();
        client.flush().unwrap();
        let mut actual = vec![0; expected.len()];
        client.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
    }
    target_thread.join().unwrap();
    assert!(
        !runtime
            .snapshot(process.generation)
            .unwrap()
            .forwarding_verified
    );
    let stop = runtime
        .stop_active(process.generation, Duration::ZERO)
        .unwrap();
    assert!(stop.process_exited);
    assert_eq!(stop.remaining_tasks, 0);
    assert!(!Path::new(&format!("/proc/{}", process.pid)).exists());
    drop(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap());
    drop(lease);
    mark_fixture_phase(&store, &operation, OperationState::Canceled);
    {
        let mut lease = store.asset_writer().unwrap();
        let version = lease.state().version;
        importer
            .retire(
                &mut lease,
                vault.as_ref(),
                TlsRetireRequest {
                    actor: actor().as_str().into(),
                    expected_version: version,
                    action: "wire-retire".into(),
                    idempotency: "wire-retire-request".into(),
                    asset: "wire-certificate".into(),
                    asset_revision: 1,
                    confirmed: true,
                    confirm_history_loss: true,
                },
                deadline(),
                &cancel,
            )
            .unwrap();
    }
    let retired_operation = synthetic_stage(
        &store,
        self::config(port, &credential.secret_ref),
        vp_product_core_adapter::inspect_build()
            .unwrap()
            .build
            .release,
        "retired",
    );
    let lease = store.asset_writer().unwrap();
    assert!(TlsMaterialAdmission::for_staging(
        &lease,
        vault.as_ref(),
        &policy,
        &wall,
        lease.state().version,
        &retired_operation,
        deadline(),
        &cancel
    )
    .is_err());
    assert_eq!(runtime.prepared_generation(), None);
    drop(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap());
    println!("PASS: actual SQL/vault credential and certificate provisioning, plan-bound resolver, sealed worker prepare-no-bind, trusted Trojan/TLS target nonce, bounded zero-target negatives, stop/reap and retired-material refusal; synthetic Staging, NOT production apply/recovery");
}
fn process_identity(pid: u32) -> Option<(u64, u32, u32, char)> {
    let text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => panic!("cannot read owned process identity"),
    };
    let fields: Vec<_> = text
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    Some((
        fields[19].parse().unwrap(),
        fields[1].parse().unwrap(),
        fields[3].parse().unwrap(),
        fields[0].chars().next().unwrap(),
    ))
}
struct WorkerHandle {
    fd: rustix::fd::OwnedFd,
    pid: u32,
    ticks: u64,
    port: u16,
}
impl WorkerHandle {
    fn ended(&self) -> bool {
        process_identity(self.pid)
            .is_none_or(|(ticks, _, _, state)| ticks != self.ticks || state == 'Z')
    }
    fn stop_exact(&self) {
        // pidfd remains the original worker even if its numeric PID is reused.
        let _ = rustix::process::pidfd_send_signal(&self.fd, rustix::process::Signal::KILL);
    }
    fn wait_ended(&self) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if self.ended() && TcpListener::bind((Ipv4Addr::LOCALHOST, self.port)).is_ok() {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
struct OwnedJourney {
    root: Option<tempfile::TempDir>,
    child: Child,
    worker: Option<WorkerHandle>,
}
impl OwnedJourney {
    fn wait(&mut self, duration: Duration) -> Option<std::process::ExitStatus> {
        let until = Instant::now() + duration;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() >= until {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn terminate_after_handoff(&mut self) {
        assert!(
            self.worker.is_some(),
            "force requires retained worker pidfd"
        );
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        self.worker.as_ref().unwrap().stop_exact();
        assert!(
            self.worker.as_ref().unwrap().wait_ended(),
            "owned worker cleanup failed"
        );
    }
}
impl Drop for OwnedJourney {
    fn drop(&mut self) {
        // Before handoff, EOF asks the actual worker owner to abort and reap.
        // Do not force it into an unowned-grandchild state.
        drop(self.child.stdin.take());
        let until = Instant::now() + Duration::from_secs(20);
        while Instant::now() < until {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                if let Some(worker) = &self.worker {
                    if !worker.ended() {
                        worker.stop_exact();
                    }
                    if !worker.wait_ended() {
                        eprintln!("VP_WIRE_OWNED_WORKER_CLEANUP_FAILED");
                        if let Some(root) = self.root.take() {
                            let preserved = root.into_path();
                            eprintln!(
                                "VP_WIRE_UNRESOLVED_FIXTURE_RETAINED={}",
                                preserved.display()
                            );
                        }
                    }
                }
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if let Some(worker) = &self.worker {
            let _ = self.child.kill();
            let _ = self.child.wait();
            worker.stop_exact();
            if !worker.wait_ended() {
                eprintln!("VP_WIRE_OWNED_WORKER_CLEANUP_FAILED");
                if let Some(root) = self.root.take() {
                    let preserved = root.into_path();
                    eprintln!(
                        "VP_WIRE_UNRESOLVED_FIXTURE_RETAINED={}",
                        preserved.display()
                    );
                }
            }
        } else {
            // Explicit unresolved failure, never successful cleanup or an
            // excuse to signal a parsed numeric PID.
            if let Some(root) = self.root.take() {
                let preserved = root.into_path();
                eprintln!(
                    "VP_WIRE_UNRESOLVED_FIXTURE_RETAINED={}",
                    preserved.display()
                );
            }
            eprintln!("VP_WIRE_PRE_HANDOFF_COOPERATIVE_ABORT_FAILED: journey {} unresolved; no force without worker identity",self.child.id());
        }
    }
}
#[derive(Clone, Copy)]
enum Mode {
    AbortBeforePidfd,
    ForceAfterHandoff,
    Full,
}
fn run(mode: Mode) {
    use rustix::process::{pidfd_open, Pid, PidfdFlags};
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut owned = OwnedJourney {
        child: Command::new(std::env::current_exe().unwrap())
            .arg("--owned-child")
            .arg(dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
        worker: None,
        root: Some(dir),
    };
    let stdout = owned.child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut lines = Vec::new();
        let mut sent = false;
        for line in std::io::BufReader::new(stdout.take(16384)).lines() {
            let line = line.unwrap();
            if !sent {
                if let Some(marker) = line.strip_prefix("VP_WIRE_WORKER=") {
                    let _ = sender.send(marker.to_owned());
                    sent = true;
                }
            }
            lines.push(line);
        }
        lines
    });
    let marker = receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("worker handoff marker timeout");
    let fields: Vec<_> = marker.split(':').collect();
    assert_eq!(fields.len(), 3);
    let pid: u32 = fields[0].parse().unwrap();
    let ticks: u64 = fields[1].parse().unwrap();
    let port: u16 = fields[2].parse().unwrap();
    assert!(pid > 1 && pid != std::process::id() && pid != owned.child.id());
    if matches!(mode, Mode::AbortBeforePidfd) {
        drop(owned.child.stdin.take());
        assert!(owned
            .wait(Duration::from_secs(20))
            .expect("cooperative abort timeout")
            .success());
        let lines = reader.join().unwrap();
        assert!(lines
            .iter()
            .any(|s| s == &format!("VP_WIRE_ABORT_REAPED={pid}:{ticks}")));
        assert!(process_identity(pid).is_none_or(|(current, _, _, _)| current != ticks));
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
        println!("PASS: pre-pidfd cooperative abort explicitly reaped worker before activation");
        return;
    }
    let session = process_identity(std::process::id()).unwrap().2;
    assert_eq!(process_identity(owned.child.id()).unwrap().2, session);
    let expected = (ticks, owned.child.id(), session);
    let before = process_identity(pid).expect("worker ended before handoff");
    assert_eq!((before.0, before.1, before.2), expected);
    let fd = pidfd_open(
        Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(),
        PidfdFlags::empty(),
    )
    .unwrap();
    let after = process_identity(pid).expect("worker ended during handoff");
    assert_eq!((after.0, after.1, after.2), expected);
    owned.worker = Some(WorkerHandle {
        fd,
        pid,
        ticks,
        port,
    });
    if matches!(mode, Mode::ForceAfterHandoff) {
        // Force before activation authorization, retaining exact worker cleanup.
        owned.terminate_after_handoff();
        reader.join().unwrap();
        println!("PASS: post-handoff forced journey termination cleaned exact retained worker");
        return;
    }
    owned.child.stdin.take().unwrap().write_all(&[1]).unwrap();
    let status = match owned.wait(Duration::from_secs(90)) {
        Some(status) => status,
        None => {
            owned.terminate_after_handoff();
            panic!("owned journey deadline");
        }
    };
    let lines = reader.join().unwrap();
    assert!(status.success(), "owned journey failed");
    assert!(owned.worker.as_ref().unwrap().wait_ended());
    for line in lines {
        if line.starts_with("PASS:") {
            println!("{line}");
        }
    }
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 3 && args[1] == "--owned-child" {
        child(Path::new(&args[2]));
        return;
    }
    assert_eq!(args.len(), 1, "unexpected test arguments");
    run(Mode::AbortBeforePidfd);
    run(Mode::ForceAfterHandoff);
    run(Mode::Full);
}
