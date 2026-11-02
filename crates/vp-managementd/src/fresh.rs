//! Explicit internal first-login profile; data-plane runtime is unavailable.
//! No automatic migration, recovery, key generation, public bind or deployment.
use rustix::{
    event::{poll, PollFd, PollFlags, Timespec},
    io::Errno,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{IsTerminal, Read, Write},
    net::{SocketAddr, TcpListener},
    os::fd::AsFd,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use vp_product_api::{ApiState, BootstrapCredential, OperationWorker, SecurityPolicy};
use vp_product_control::{
    ContentDigest, ControlService, ControlStore, InstanceBinding, SystemClock, UnavailableRuntime,
    UnavailableSystem, FRESH_ADMIN_PROFILE,
};
use vp_product_domain::SecretBytes;
use vp_product_secrets::{DurableSecretStore, MasterKey, Namespace, VaultDirectoryIdentity};
use vp_product_storage::{BoundDirectory, DirectoryIdentity, FreshSqliteStore};
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
}
struct Options {
    fresh: bool,
    control: PathBuf,
    vault: PathBuf,
    runtime: PathBuf,
    bind: SocketAddr,
    origin: String,
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
    if !control.is_absolute()
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
}
fn artifacts() -> Result<(ArtifactSet, ContentDigest), &'static str> {
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
    let value = ArtifactSet {
        profile: FRESH_ADMIN_PROFILE,
        executable_sha256: format!("{:x}", hash.finalize()),
        sql_layout: 1,
        payload_read: 3,
        payload_write: 3,
        vault_binding_kind: 5,
        core_commit: core.integration_commit,
        core_abi_major: vp_product_domain::ABI_MAJOR,
        core_abi_minor: vp_product_domain::ABI_MINOR,
        runtime_available: false,
    };
    let digest =
        ContentDigest::of("vp.fresh-artifact-set.v1", &value).map_err(|_| "ARTIFACT_IDENTITY")?;
    Ok((value, digest))
}
struct Ready {
    store: Arc<FreshSqliteStore>,
    _vault: DurableSecretStore,
    _vault_admission: BoundDirectory,
    _runtime: BoundDirectory,
    credential: BootstrapCredential,
    policy: SecurityPolicy,
    listener: TcpListener,
    binding: InstanceBinding,
}
fn prepare(options: Options, mut input: Input) -> Result<Ready, &'static str> {
    if input.schema_version != 1 {
        return Err("INVALID_INPUT");
    }
    let policy = SecurityPolicy::new(&options.origin).map_err(|_| "INVALID_ORIGIN")?;
    let (_, artifact_digest) = artifacts()?;
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
        profile: FRESH_ADMIN_PROFILE.into(),
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
    let control = control
        .anchor_before_threads()
        .map_err(|_| "CONTROL_CWD_BINDING")?;
    let reservation=serde_json::to_vec(&json!({"schemaVersion":1,"bindingDigest":binding.digest().map_err(|_|"INVALID_GENESIS")?,"runtimeAvailable":false})).map_err(|_|"INVALID_GENESIS")?;
    let store = if options.fresh {
        runtime.require_empty().map_err(|_| "RUNTIME_NOT_FRESH")?;
        let store = FreshSqliteStore::create(control, binding.clone())
            .map_err(|_| "CONTROL_INITIALIZATION_UNCERTAIN")?;
        vault
            .claim_instance_binding(&binding, deadline)
            .map_err(|_| "VAULT_CLAIM_UNCERTAIN")?;
        runtime
            .publish("fresh-runtime.v1", &reservation)
            .map_err(|_| "RUNTIME_RESERVATION_UNCERTAIN")?;
        store
            .mark_initialized()
            .map_err(|_| "GENESIS_TRANSITION_UNCERTAIN")?;
        store
    } else {
        if runtime.names().map_err(|_| "RUNTIME_INSPECTION")? != ["fresh-runtime.v1".to_owned()]
            || runtime
                .read("fresh-runtime.v1", 16384)
                .map_err(|_| "RUNTIME_INSPECTION")?
                != reservation
        {
            return Err("RUNTIME_PAIRING_MISMATCH");
        }
        FreshSqliteStore::open_initialized(control, binding.clone())
            .map_err(|_| "CONTROL_PAIRING_MISMATCH")?
    };
    Ok(Ready {
        store: Arc::new(store),
        _vault: vault,
        _vault_admission: admitted_vault,
        _runtime: runtime,
        credential,
        policy,
        listener,
        binding,
    })
}
async fn serve(ready: Ready) -> Result<(), &'static str> {
    let Ready {
        store,
        _vault,
        _vault_admission,
        _runtime,
        credential,
        policy,
        listener,
        binding,
    } = ready;
    let _held = (_vault, _vault_admission, _runtime);
    let control = Arc::new(ControlService::new(
        store.clone(),
        Arc::new(UnavailableRuntime),
        Arc::new(UnavailableSystem),
        Arc::new(SystemClock),
    ));
    if store
        .read()
        .map_err(|_| "CONTROL_STATE_UNAVAILABLE")?
        .needs_recovery()
    {
        return Err("RECOVERY_REQUIRED");
    }
    let listener =
        tokio::net::TcpListener::from_std(listener).map_err(|_| "LISTENER_UNAVAILABLE")?;
    let address = listener.local_addr().map_err(|_| "LISTENER_UNAVAILABLE")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "SIGNAL_UNAVAILABLE")?;
    let (worker, handle) = OperationWorker::start(control.clone());
    let state = match ApiState::new(control, worker.clone(), credential, policy) {
        Ok(v) => v,
        Err(_) => {
            worker.stop();
            let _ = handle.await;
            return Err("API_UNAVAILABLE");
        }
    };
    let shutdown = worker.clone();
    if emit(&json!({"protocolVersion":1,"status":"http_ready","genesisId":binding.genesis_id,"profile":FRESH_ADMIN_PROFILE,"endpoint":address.to_string(),"runtimeAvailable":false,"recoveryEligible":false})).is_err() {
        worker.stop();
        let _ = handle.await;
        return Err("READINESS_OUTPUT_UNAVAILABLE");
    }
    let result=axum::serve(listener,vp_product_api::router(state)).with_graceful_shutdown(async move{tokio::select!{_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{},_=shutdown.stopped()=>{}}shutdown.stop();}).await;
    worker.stop();
    handle.await.map_err(|_| "WORKER_SHUTDOWN")?;
    result.map_err(|_| "HTTP_STOPPED")
}
fn emit(value: &serde_json::Value) -> Result<(), &'static str> {
    writeln!(std::io::stdout().lock(), "{value}").map_err(|_| "OUTPUT_UNAVAILABLE")
}
pub fn main_entry() -> std::process::ExitCode {
    let result = (|| {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args == ["describe"] {
            let (metadata, digest) = artifacts()?;
            emit(
                &json!({"descriptorVersion":1,"metadata":metadata,"artifactSetDigest":digest,"createsState":false,"startsService":false}),
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
