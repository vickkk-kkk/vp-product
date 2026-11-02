//! Explicit private full-runtime profile; no adoption of administrator-only roots.
//! No automatic migration, recovery, key generation, public bind or deployment.
use rustix::{
    event::{poll, PollFd, PollFlags, Timespec},
    io::Errno,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{IsTerminal, Read, Write},
    net::{SocketAddr, TcpListener},
    os::fd::AsFd,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use vp_product_api::{
    ApiState, BootstrapCredential, OperationWorker, PublicationNetworkPolicy, SecurityPolicy,
    TrustedPublicationBase,
};
use vp_product_control::{
    ContentDigest, ControlService, ControlStore, InstanceBinding, SystemClock,
    FRESH_RUNTIME_PROFILE,
};
use vp_product_core_adapter::managed::VerifiedWorker;
use vp_product_domain::{SecretBytes, SecretRef};
use vp_product_runtime_executor::{BoundRuntimeIdentity, ManagedExecutor, NoHostChanges};
use vp_product_secrets::{
    DurableSecretStore, MasterKey, Namespace, SecretKind, VaultDirectoryIdentity,
};
use vp_product_storage::{BoundDirectory, BoundOpenMode, DirectoryIdentity, FreshSqliteStore};
use zeroize::{Zeroize, Zeroizing};

fn secret<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    schema_version: u16,
    username: String,
    #[serde(deserialize_with = "secret")]
    token: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    master_key_hex: Zeroizing<String>,
    namespace: String,
    genesis_id: String,
    preparation_digest: ContentDigest,
    activation_intent_digest: ContentDigest,
    artifact_set_digest: ContentDigest,
    expected_control_directory: DirectoryIdentity,
    expected_vault_directory: DirectoryIdentity,
    expected_runtime_directory: DirectoryIdentity,
    credentials: Vec<CredentialInput>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialInput {
    reference: SecretRef,
    version: u64,
    #[serde(deserialize_with = "secret")]
    value: Zeroizing<String>,
}
struct Options {
    fresh: bool,
    control: PathBuf,
    vault: PathBuf,
    runtime: PathBuf,
    bind: SocketAddr,
    origin: String,
    worker: PathBuf,
    worker_sha256: String,
    probe_bind: SocketAddr,
    publication_base: Option<TrustedPublicationBase>,
    web_root: Option<PathBuf>,
}
fn options(args: Vec<String>) -> Result<Options, &'static str> {
    let mut a = args.into_iter();
    let fresh = match a.next().as_deref() {
        Some("serve-fresh") => true,
        Some("serve-paired") => false,
        _ => return Err("INVALID_ACTION"),
    };
    let mut m = BTreeMap::new();
    while let Some(k) = a.next() {
        if ![
            "--control-root",
            "--vault-root",
            "--runtime-root",
            "--bind",
            "--origin",
            "--worker",
            "--worker-sha256",
            "--probe-bind",
            "--publication-base",
            "--web-root",
        ]
        .contains(&k.as_str())
        {
            return Err("INVALID_ARGUMENTS");
        }
        let v = a.next().ok_or("INVALID_ARGUMENTS")?;
        if m.insert(k, v).is_some() {
            return Err("INVALID_ARGUMENTS");
        }
    }
    let mut take = |k| m.remove(k).ok_or("INVALID_ARGUMENTS");
    let control = PathBuf::from(take("--control-root")?);
    let vault = PathBuf::from(take("--vault-root")?);
    let runtime = PathBuf::from(take("--runtime-root")?);
    let bind: SocketAddr = take("--bind")?.parse().map_err(|_| "INVALID_ARGUMENTS")?;
    let origin = take("--origin")?;
    let worker = PathBuf::from(take("--worker")?);
    let worker_sha256 = take("--worker-sha256")?;
    let probe_bind: SocketAddr = take("--probe-bind")?
        .parse()
        .map_err(|_| "INVALID_ARGUMENTS")?;
    let publication_base = m
        .remove("--publication-base")
        .map(|base| {
            TrustedPublicationBase::new(
                &base,
                PublicationNetworkPolicy::DevelopmentLoopback,
                &origin,
            )
            .map_err(|_| "INVALID_PUBLICATION_BASE")
        })
        .transpose()?;
    let web_root = m.remove("--web-root").map(PathBuf::from);
    if web_root.as_ref().is_some_and(|p| !p.is_absolute()) {
        return Err("INVALID_WEB_ROOT");
    }
    if !worker.is_absolute()
        || probe_bind.ip() != std::net::Ipv4Addr::LOCALHOST
        || !control.is_absolute()
        || !vault.is_absolute()
        || !runtime.is_absolute()
        || !bind.ip().is_loopback()
        || bind.port() == 0
        || !m.is_empty()
    {
        return Err("INVALID_ARGUMENTS");
    }
    Ok(Options {
        fresh,
        control,
        vault,
        runtime,
        bind,
        origin,
        worker,
        worker_sha256,
        probe_bind,
        publication_base,
        web_root,
    })
}
fn read_sensitive(fd: &impl AsFd) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut bytes = Zeroizing::new(Vec::with_capacity(8193));
    let mut chunk = Zeroizing::new([0u8; 512]);
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("INPUT_DEADLINE")?;
        let timeout = Timespec::try_from(remaining).map_err(|_| "INPUT_DEADLINE")?;
        let mut fds = [PollFd::new(fd, PollFlags::IN)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => return Err("INPUT_DEADLINE"),
            Ok(_) => (),
            Err(Errno::INTR) => continue,
            Err(_) => return Err("INPUT_UNAVAILABLE"),
        }
        if fds[0]
            .revents()
            .intersects(PollFlags::ERR | PollFlags::NVAL)
        {
            return Err("INPUT_UNAVAILABLE");
        }
        let capacity = (8193 - bytes.len()).min(chunk.len());
        let n = match rustix::io::read(fd, &mut chunk[..capacity]) {
            Ok(n) => n,
            Err(Errno::INTR | Errno::AGAIN) => continue,
            Err(_) => return Err("INPUT_UNAVAILABLE"),
        };
        if n == 0 {
            break;
        }
        if bytes.len() + n > 8192 {
            return Err("INPUT_LIMIT");
        }
        bytes.extend_from_slice(&chunk[..n]);
        chunk.zeroize();
    }
    if bytes.is_empty() || bytes.contains(&b'\\') {
        return Err("INVALID_INPUT");
    }
    Ok(bytes)
}
fn master(value: &str) -> Result<MasterKey, &'static str> {
    if value.len() != 64 {
        return Err("INVALID_KEY");
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(32));
    for pair in value.as_bytes().chunks_exact(2) {
        let digit = |b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        bytes
            .push(digit(pair[0]).ok_or("INVALID_KEY")? << 4 | digit(pair[1]).ok_or("INVALID_KEY")?);
    }
    MasterKey::new(SecretBytes::new(std::mem::take(&mut *bytes))).map_err(|_| "INVALID_KEY")
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactSet {
    profile: &'static str,
    executable_sha256: String,
    sql_layout: u16,
    payload_read: u16,
    payload_write: u16,
    vault_binding_kind: u8,
    core_commit: String,
    core_abi_major: u16,
    core_abi_minor: u16,
    runtime_available: bool,
    worker_sha256: String,
    runtime_journal_payload: u16,
    artifact_binding_version: u16,
    publication_delivery: bool,
    publication_network_policy: &'static str,
    explicit_web_root: bool,
    management_api_version: u16,
}
fn artifacts(worker: &VerifiedWorker) -> Result<(ArtifactSet, ContentDigest), &'static str> {
    let mut file = File::open("/proc/self/exe").map_err(|_| "EXECUTABLE_IDENTITY")?;
    let length = file.metadata().map_err(|_| "EXECUTABLE_IDENTITY")?.len();
    if length == 0 || length > 256 * 1024 * 1024 {
        return Err("EXECUTABLE_IDENTITY");
    }
    let mut hash = Sha256::new();
    let mut chunk = [0; 65536];
    let mut total = 0;
    loop {
        let n = file.read(&mut chunk).map_err(|_| "EXECUTABLE_IDENTITY")?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > length {
            return Err("EXECUTABLE_IDENTITY");
        }
        hash.update(&chunk[..n]);
    }
    if total != length {
        return Err("EXECUTABLE_IDENTITY");
    }
    let core = vp_product_core_adapter::inspect_build().map_err(|_| "CORE_IDENTITY")?;
    if !core.runtime_enabled {
        return Err("RUNTIME_NOT_COMPILED");
    }
    let value = ArtifactSet {
        profile: FRESH_RUNTIME_PROFILE,
        executable_sha256: format!("{:x}", hash.finalize()),
        sql_layout: 1,
        payload_read: 3,
        payload_write: 3,
        vault_binding_kind: 5,
        core_commit: core.integration_commit,
        core_abi_major: vp_product_domain::ABI_MAJOR,
        core_abi_minor: vp_product_domain::ABI_MINOR,
        runtime_available: true,
        worker_sha256: worker.sha256().to_owned(),
        runtime_journal_payload: 2,
        artifact_binding_version: 1,
        publication_delivery: true,
        publication_network_policy: "explicit_same_origin_loopback",
        explicit_web_root: true,
        management_api_version: 1,
    };
    let digest =
        ContentDigest::of("vp.fresh-artifact-set.v1", &value).map_err(|_| "ARTIFACT_IDENTITY")?;
    Ok((value, digest))
}
struct Ready {
    store: Arc<FreshSqliteStore>,
    vault: Arc<DurableSecretStore>,
    executor: Arc<ManagedExecutor>,
    _vault_admission: BoundDirectory,
    credential: BootstrapCredential,
    policy: SecurityPolicy,
    publication_base: Option<TrustedPublicationBase>,
    web: Option<Arc<crate::web::WebRoot>>,
    listener: TcpListener,
    binding: InstanceBinding,
}
fn prepare(options: Options, mut input: Input) -> Result<Ready, &'static str> {
    if input.schema_version != 1 {
        return Err("INVALID_INPUT");
    }
    if input.credentials.len() > 8 || (!options.fresh && !input.credentials.is_empty()) {
        return Err("INVALID_CREDENTIAL_PROVISIONING");
    }
    let mut references = BTreeSet::new();
    for credential in &input.credentials {
        if credential.version == 0
            || credential.value.is_empty()
            || credential.value.len() > 1024
            || credential.reference.as_str() == "secret:vp-instance-binding-v1"
            || crate::probes::parse_uuid(credential.value.as_bytes()).is_err()
            || !references.insert(credential.reference.clone())
        {
            return Err("INVALID_CREDENTIAL_PROVISIONING");
        }
    }
    // Authenticated sealed snapshot + Linux executable memfd preflight before
    // root acquisition/writes. Actual spawn recaptures/rechecks sealed bytes.
    let worker = VerifiedWorker::new(&options.worker, &options.worker_sha256)
        .map_err(|_| "WORKER_IDENTITY")?;
    let policy = SecurityPolicy::new(&options.origin).map_err(|_| "INVALID_ORIGIN")?;
    let (_, artifact_digest) = artifacts(&worker)?;
    if artifact_digest != input.artifact_set_digest {
        return Err("ARTIFACT_MISMATCH");
    }
    let credential = BootstrapCredential::new(
        &input.username,
        SecretBytes::new(input.token.as_bytes().to_vec()),
    )
    .map_err(|_| "INVALID_ADMINISTRATOR")?;
    let mut hash = Sha256::new();
    hash.update(b"vp.fresh-administrator.v1\0");
    hash.update((input.username.len() as u64).to_be_bytes());
    hash.update(input.username.as_bytes());
    hash.update(input.token.as_bytes());
    let admin = ContentDigest::parse(format!("{:x}", hash.finalize()))
        .map_err(|_| "INVALID_ADMINISTRATOR")?;
    input.token.zeroize();
    let key = master(&input.master_key_hex)?;
    input.master_key_hex.zeroize();
    let namespace = Namespace::new(&input.namespace).map_err(|_| "INVALID_NAMESPACE")?;
    let control = BoundDirectory::open(&options.control, input.expected_control_directory)
        .map_err(|_| "CONTROL_BINDING")?;
    let admitted_vault = BoundDirectory::admit(&options.vault, input.expected_vault_directory)
        .map_err(|_| "VAULT_BINDING")?;
    let runtime = BoundDirectory::admit(&options.runtime, input.expected_runtime_directory)
        .map_err(|_| "RUNTIME_BINDING")?;
    control
        .disjoint(&admitted_vault)
        .and_then(|_| control.disjoint(&runtime))
        .and_then(|_| admitted_vault.disjoint(&runtime))
        .map_err(|_| "ROOTS_OVERLAP")?;
    let web = options
        .web_root
        .as_ref()
        .map(|path| {
            crate::fresh_web::open(
                path.clone(),
                &options.origin,
                [&options.control, &options.vault, &options.runtime],
            )
        })
        .transpose()
        .map_err(|_| "WEB_ASSET_ADMISSION")?;
    if options.fresh {
        control.require_empty().map_err(|_| "CONTROL_NOT_FRESH")?;
        runtime.require_empty().map_err(|_| "RUNTIME_NOT_FRESH")?;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let vault = DurableSecretStore::open_fresh_profile(
        &options.vault,
        namespace,
        key,
        VaultDirectoryIdentity {
            device: input.expected_vault_directory.device,
            inode: input.expected_vault_directory.inode,
        },
        deadline,
    )
    .map_err(|_| "VAULT_AUTHENTICATION")?;
    if options.fresh {
        vault
            .require_manifest_only(deadline)
            .map_err(|_| "VAULT_NOT_FRESH")?;
    }
    let runtime = runtime.lock().map_err(|_| "RUNTIME_BUSY")?;
    let observation = vault
        .inspect_read_only(deadline)
        .map_err(|_| "VAULT_INSPECTION")?;
    let binding = InstanceBinding {
        binding_version: 1,
        genesis_id: input.genesis_id,
        vault_id: observation.vault_id,
        namespace_digest: ContentDigest::parse(observation.namespace_digest)
            .map_err(|_| "VAULT_INSPECTION")?,
        administrator_commitment: admin,
        preparation_digest: input.preparation_digest,
        activation_intent_digest: input.activation_intent_digest,
        artifact_set_digest: artifact_digest,
        profile: FRESH_RUNTIME_PROFILE.into(),
    };
    binding.validate().map_err(|_| "INVALID_GENESIS")?;
    if !options.fresh
        && vault
            .instance_binding(deadline)
            .map_err(|_| "PAIRING_UNAVAILABLE")?
            != binding
    {
        return Err("PAIRING_MISMATCH");
    }
    // Binding a listener creates no HTTP service; port conflict precedes writes.
    let listener = TcpListener::bind(options.bind).map_err(|_| "BIND_UNAVAILABLE")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "BIND_UNAVAILABLE")?;
    let probe_listener =
        TcpListener::bind(options.probe_bind).map_err(|_| "PROBE_BIND_UNAVAILABLE")?;
    let control = control
        .anchor_before_threads()
        .map_err(|_| "CONTROL_CWD_BINDING")?;
    let store = if options.fresh {
        runtime.require_empty().map_err(|_| "RUNTIME_NOT_FRESH")?;
        let store = FreshSqliteStore::create(control, binding.clone())
            .map_err(|_| "CONTROL_INITIALIZATION_UNCERTAIN")?;
        vault
            .claim_instance_binding(&binding, deadline)
            .map_err(|_| "VAULT_CLAIM_UNCERTAIN")?;
        for credential in &mut input.credentials {
            vault
                .put(
                    &credential.reference,
                    SecretKind::Credential,
                    credential.version,
                    SecretBytes::new(std::mem::take(&mut *credential.value).into_bytes()),
                    deadline,
                )
                .map_err(|_| "CREDENTIAL_PROVISIONING_UNCERTAIN")?;
        }
        store
    } else {
        let store = FreshSqliteStore::open_initialized(control, binding.clone())
            .map_err(|_| "CONTROL_PAIRING_MISMATCH")?;
        if store
            .read()
            .map_err(|_| "CONTROL_STATE_UNAVAILABLE")?
            .needs_recovery()
        {
            return Err("RECOVERY_REQUIRED");
        }
        store
    };
    let vault = Arc::new(vault);
    // This is the first possible thread creation; cwd was anchored above.
    let probe = crate::probes::LoopbackProbe::from_listener(probe_listener, vault.clone())
        .map_err(|_| "PROBE_START_UNAVAILABLE")?;
    let identity = BoundRuntimeIdentity {
        genesis: binding.digest().map_err(|_| "INVALID_GENESIS")?,
        release: vp_product_core_adapter::inspect_build()
            .map_err(|_| "CORE_IDENTITY")?
            .build
            .release,
        worker_digest: ContentDigest::parse(worker.sha256().to_owned())
            .map_err(|_| "WORKER_IDENTITY")?,
    };
    let executor = Arc::new(
        ManagedExecutor::open_bound(
            runtime,
            if options.fresh {
                BoundOpenMode::CreateFresh
            } else {
                BoundOpenMode::OpenExisting
            },
            identity,
            worker,
            vault.clone(),
            probe,
            Arc::new(SystemClock),
        )
        .map_err(|_| "BOUND_RUNTIME_UNAVAILABLE")?,
    );
    // Pair control and runtime history without clearing stale records, writing
    // artifacts, launching a worker or invoking shutdown/recovery on mismatch.
    let startup_state = if options.fresh {
        vp_product_control::StoredState::default()
    } else {
        store.read().map_err(|_| "CONTROL_STATE_UNAVAILABLE")?
    };
    executor
        .validate_startup_pair(&startup_state)
        .map_err(|_| "CONTROL_RUNTIME_PAIRING_MISMATCH")?;
    if options.fresh {
        store
            .mark_initialized()
            .map_err(|_| "GENESIS_TRANSITION_UNCERTAIN")?;
    }
    Ok(Ready {
        store: Arc::new(store),
        vault,
        executor,
        _vault_admission: admitted_vault,
        credential,
        policy,
        publication_base: options.publication_base,
        web,
        listener,
        binding,
    })
}
async fn serve(ready: Ready) -> Result<(), &'static str> {
    let executor = ready.executor.clone();
    let result = serve_inner(ready).await;
    let stopped = tokio::task::spawn_blocking(move || executor.shutdown())
        .await
        .map_err(|_| "RUNTIME_SHUTDOWN")?
        .map_err(|_| "RUNTIME_SHUTDOWN");
    result.and(stopped)
}
async fn serve_inner(ready: Ready) -> Result<(), &'static str> {
    let Ready {
        store,
        vault,
        executor,
        _vault_admission,
        credential,
        policy,
        publication_base,
        web,
        listener,
        binding,
    } = ready;
    let _held = _vault_admission;
    // Install both handlers before any child reconciliation. Cancellation waits
    // for the blocking owner operation, then outer serve performs exact shutdown.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "SIGNAL_UNAVAILABLE")?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| "SIGNAL_UNAVAILABLE")?;
    let durable = store.read().map_err(|_| "CONTROL_STATE_UNAVAILABLE")?;
    if durable.needs_recovery() {
        return Err("RECOVERY_REQUIRED");
    }
    if let Some(active) = durable.active().cloned() {
        let restarted = executor.clone();
        let mut task = tokio::task::spawn_blocking(move || restarted.reconcile_committed(&active));
        let canceled = tokio::select! {
            result = &mut task => {
                result.map_err(|_| "RUNTIME_RECONCILIATION")?.map_err(|_| "RUNTIME_RECONCILIATION")?;
                false
            }
            _ = terminate.recv() => true,
            _ = interrupt.recv() => true,
        };
        if canceled {
            let _ = task.await;
            return Err("STARTUP_CANCELED");
        }
    }
    let control = Arc::new(
        ControlService::new(
            store,
            executor,
            Arc::new(NoHostChanges),
            Arc::new(SystemClock),
        )
        .with_secret_manager(Arc::new(crate::secret_manager::VaultSecretManager::new(
            vault,
        ))),
    );
    let listener =
        tokio::net::TcpListener::from_std(listener).map_err(|_| "LISTENER_UNAVAILABLE")?;
    let address = listener.local_addr().map_err(|_| "LISTENER_UNAVAILABLE")?;
    let web_available = web.is_some();
    let publication_available = publication_base.is_some();
    let (worker, handle) = OperationWorker::start(control.clone());
    let state = match ApiState::new_with_publication_base(
        control,
        worker.clone(),
        credential,
        policy,
        publication_base,
    ) {
        Ok(value) => value,
        Err(_) => {
            worker.stop();
            let _ = handle.await;
            return Err("API_UNAVAILABLE");
        }
    };
    let shutdown = worker.clone();
    if emit(
        &json!({"protocolVersion":1,"status":"http_ready","genesisId":binding.genesis_id,
        "profile":FRESH_RUNTIME_PROFILE,"endpoint":address.to_string(),"runtimeAvailable":true,
        "productionCertified":false,"recoveryEligible":false,"webAvailable":web_available,"publicationAvailable":publication_available}),
    )
    .is_err()
    {
        worker.stop();
        let _ = handle.await;
        return Err("READINESS_OUTPUT_UNAVAILABLE");
    }
    let mut router = vp_product_api::router(state);
    if let Some(root) = web {
        router = router.fallback(move |request: axum::extract::Request| {
            let root = root.clone();
            async move { crate::web::serve(root, request).await }
        });
    }
    let result = axum::serve(listener, router).with_graceful_shutdown(async move {
        tokio::select! { _=interrupt.recv()=>{}, _=terminate.recv()=>{}, _=shutdown.stopped()=>{} }
        shutdown.stop();
    }).await;
    worker.stop();
    handle.await.map_err(|_| "WORKER_SHUTDOWN")?;
    if worker.failed() {
        return Err("WORKER_FAILED");
    }
    result.map_err(|_| "HTTP_STOPPED")
}
fn emit(value: &serde_json::Value) -> Result<(), &'static str> {
    writeln!(std::io::stdout().lock(), "{value}").map_err(|_| "OUTPUT_UNAVAILABLE")
}
pub fn main_entry() -> std::process::ExitCode {
    let result = (|| {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args.first().is_some_and(|a| a == "describe") {
            if args.len() != 5 || args[1] != "--worker" || args[3] != "--worker-sha256" {
                return Err("INVALID_DESCRIPTOR_ARGUMENTS");
            }
            let worker = VerifiedWorker::new(&args[2], &args[4]).map_err(|_| "WORKER_IDENTITY")?;
            let (metadata, digest) = artifacts(&worker)?;
            emit(
                &json!({"descriptorVersion":2,"metadata":metadata,"artifactSetDigest":digest,"createsState":false,"startsService":false}),
            )?;
            return Ok(());
        }
        let options = options(args)?;
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            return Err("TTY_INPUT_REFUSED");
        }
        let bytes = read_sensitive(&stdin)?;
        let input: Input = serde_json::from_slice(&bytes).map_err(|_| "INVALID_INPUT")?;
        drop(bytes);
        let ready = prepare(options, input)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| "ASYNC_RUNTIME_UNAVAILABLE")?;
        runtime.block_on(serve(ready))
    })();
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(code) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "{}",
                json!({"protocolVersion":1,"status":"refused","code":code,"outcome":"inspect_retained_state_no_automatic_retry","recoveryEligible":false})
            );
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        [
            "serve-fresh",
            "--control-root",
            "/private/control",
            "--vault-root",
            "/private/vault",
            "--runtime-root",
            "/private/runtime",
            "--bind",
            "127.0.0.1:18080",
            "--origin",
            "http://127.0.0.1:18080",
            "--worker",
            "/private/worker",
            "--worker-sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--probe-bind",
            "127.0.0.1:0",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn runtime_profile_requires_explicit_loopback_roots_worker_and_probe() {
        assert!(options(args()).is_ok());
        let mut bad = args();
        bad[8] = "0.0.0.0:18080".into();
        assert!(options(bad).is_err());
        let mut bad = args();
        bad[16] = "0.0.0.0:0".into();
        assert!(options(bad).is_err());
        let mut bad = args();
        bad[12] = "worker".into();
        assert!(options(bad).is_err());
        let mut bad = args();
        bad.extend(["--worker".into(), "/other".into()]);
        assert!(options(bad).is_err());
        let mut bad = args();
        bad[0] = "automatic-recover".into();
        assert!(options(bad).is_err());
    }
    #[test]
    fn publication_base_is_explicit_same_origin_loopback_only() {
        let mut valid = args();
        valid.extend(["--publication-base".into(), "http://127.0.0.1:18080".into()]);
        assert!(options(valid).is_ok());
        for base in [
            "http://127.0.0.1:18081",
            "https://example.invalid",
            "http://evil.invalid",
            "http://127.0.0.1:18080/path",
            "http://127.0.0.1:18080/",
        ] {
            let mut bad = args();
            bad.extend(["--publication-base".into(), base.into()]);
            assert!(options(bad).is_err());
        }
    }
    #[test]
    fn credential_input_has_no_implicit_version_or_generation() {
        assert!(serde_json::from_str::<CredentialInput>(r#"{"reference":"secret:fixture","version":1,"value":"00000000-0000-0000-0000-000000000001"}"#).is_ok());
        assert!(serde_json::from_str::<CredentialInput>(
            r#"{"reference":"secret:fixture","value":"synthetic"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CredentialInput>(
            r#"{"reference":"secret:fixture","version":1,"value":"synthetic","generate":true}"#
        )
        .is_err());
    }
}
