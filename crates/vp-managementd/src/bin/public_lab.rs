//! Foreground-only, fresh-instance experimental lab. Never a release installer.
//! All generated credentials stay in a private output directory, never stdout.
#![forbid(unsafe_code)]
use base64::Engine;
use serde::Serialize;
use std::{collections::{BTreeMap, BTreeSet}, fs::File, io::Read, net::{IpAddr, Ipv4Addr, SocketAddr}, path::{Path, PathBuf}, sync::Arc, time::{Duration, Instant}};
use vp_product_control::{CancellationToken, ContentDigest, ControlService, InstanceBinding, OperationState, PlanRequest, ApplyRequest, SecretManager, SystemClock, TlsBackendPolicy, TlsImportRequest, TlsImportService, WriterLease, FRESH_TLS_RUNTIME_PROFILE};
use vp_product_core_adapter::managed::{Cancellation, VerifiedWorker};
use vp_product_domain::*;
use vp_product_runtime_executor::{NoHostChanges, experimental_public::{reserve_fresh, SingleIpProbeConfig}};
use vp_product_secrets::{Limits, MasterKey, Namespace, TlsExperimentalSecretManager, TlsSecretStore, VaultDirectoryIdentity};
use vp_product_storage::{BoundDirectory, DirectoryIdentity, TlsSqliteStore};
use zeroize::{Zeroize, Zeroizing};

struct Options { session_root: Option<PathBuf>, control: PathBuf, vault: PathBuf, runtime: PathBuf, output: PathBuf, worker: PathBuf,
    worker_sha: String, bind: Ipv4Addr, ports: [u16;3], vmess_port: Option<u16>, targets: Vec<SocketAddr>, probe: SingleIpProbeConfig }
fn parse(mut args: impl Iterator<Item=String>) -> Result<Options, &'static str> {
    let mut values = BTreeMap::new(); let mut targets = Vec::new(); let mut create = false; let mut cloudflare = false; let mut custom_confirm = false;
    while let Some(key) = args.next() {
        if key == "--confirm-test-access" { if create { return Err("DUPLICATE_ARGUMENT"); } create = true; continue; }
        if key == "--confirm-cloudflare-probe" { if cloudflare { return Err("DUPLICATE_ARGUMENT"); } cloudflare = true; continue; }
        if key == "--confirm-custom-probe" { if custom_confirm { return Err("DUPLICATE_ARGUMENT"); } custom_confirm = true; continue; }
        let value = args.next().ok_or("MISSING_ARGUMENT")?;
        if key == "--target" { targets.push(value.parse::<SocketAddr>().map_err(|_| "INVALID_TARGET")?); continue; }
        if !["--session-root","--control-root","--vault-root","--runtime-root","--output-root","--worker","--worker-sha256","--bind-ip","--trojan-port","--vless-port","--ss-port","--vmess-port","--probe-target","--probe-name","--probe-path","--probe-status","--probe-ca-der"].contains(&key.as_str())
            || values.insert(key, value).is_some() { return Err("INVALID_ARGUMENT"); }
    }
    if !create { return Err("CONFIRMATION_REQUIRED"); }
    let session_root = values.remove("--session-root").map(PathBuf::from);
    let roots = if let Some(root) = &session_root {
        if !root.is_absolute() || ["--control-root","--vault-root","--runtime-root","--output-root"].iter().any(|key| values.contains_key(*key)) { return Err("INVALID_ARGUMENT"); }
        [root.join("control"), root.join("vault"), root.join("runtime"), root.join("output")]
    } else {
        [PathBuf::from(values.remove("--control-root").ok_or("MISSING_ARGUMENT")?), PathBuf::from(values.remove("--vault-root").ok_or("MISSING_ARGUMENT")?),
         PathBuf::from(values.remove("--runtime-root").ok_or("MISSING_ARGUMENT")?), PathBuf::from(values.remove("--output-root").ok_or("MISSING_ARGUMENT")?)]
    };
    let [control, vault, runtime, output] = roots;
    let mut take = |key: &str| values.remove(key).ok_or("MISSING_ARGUMENT");
    let worker = PathBuf::from(take("--worker")?); let worker_sha = take("--worker-sha256")?;
    let bind: Ipv4Addr = take("--bind-ip")?.parse().map_err(|_| "INVALID_BIND")?;
    let mut port = |key| -> Result<u16, &'static str> { let n: u16 = take(key)?.parse().map_err(|_| "INVALID_PORT")?; if n == 0 { return Err("INVALID_PORT"); } Ok(n) };
    let ports = [port("--trojan-port")?, port("--vless-port")?, port("--ss-port")?];
    let vmess_port = values.remove("--vmess-port").map(|v| v.parse::<u16>().map_err(|_| "INVALID_PORT")).transpose()?;
    if vmess_port == Some(0) { return Err("INVALID_PORT"); }
    let custom_keys = ["--probe-target","--probe-name","--probe-path","--probe-status","--probe-ca-der"];
    let custom_count = custom_keys.iter().filter(|k| values.contains_key(**k)).count();
    let probe = if custom_count == 0 {
        if !cloudflare || custom_confirm { return Err("CONFIRMATION_REQUIRED"); }
        SingleIpProbeConfig::cloudflare_trace()
    } else {
        if custom_count != custom_keys.len() || !custom_confirm || cloudflare { return Err("CONFIRMATION_REQUIRED"); }
        let target: SocketAddr = values.remove("--probe-target").ok_or("MISSING_ARGUMENT")?.parse().map_err(|_| "INVALID_TARGET")?;
        let target_name = values.remove("--probe-name").ok_or("MISSING_ARGUMENT")?;
        let path = values.remove("--probe-path").ok_or("MISSING_ARGUMENT")?;
        let status: u16 = values.remove("--probe-status").ok_or("MISSING_ARGUMENT")?.parse().map_err(|_| "INVALID_TARGET")?;
        let ca_path = PathBuf::from(values.remove("--probe-ca-der").ok_or("MISSING_ARGUMENT")?);
        let root = read_public_ca(&ca_path)?;
        vp_product_core_adapter::managed::probe_client_v2::validate_tls_trust(std::slice::from_ref(&root), &target_name).map_err(|_| "INVALID_TARGET")?;
        if !path.starts_with('/') || path.len()>256 || !path.bytes().all(|b| (0x21..=0x7e).contains(&b)) || !(200..=299).contains(&status) { return Err("INVALID_TARGET"); }
        SingleIpProbeConfig { target, target_trust: vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust::PinnedDer(vec![root]), target_name, path, expected_status: status }
    };
    if !values.is_empty() || [&control,&vault,&runtime,&output,&worker].iter().any(|p| !p.is_absolute())
        || (bind.is_loopback() && !cfg!(feature = "local-probe-test")) || bind.is_unspecified() || bind.is_multicast() || ports.into_iter().chain(vmess_port).collect::<BTreeSet<_>>().len()!=3 + usize::from(vmess_port.is_some())
        || worker_sha.len()!=64 || !worker_sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err("INVALID_ARGUMENT"); }
    if !targets.contains(&probe.target) { targets.push(probe.target); }
    if targets.len()>64 || targets.iter().copied().collect::<BTreeSet<_>>().len()!=targets.len() || targets.iter().any(|t| t.ip()==IpAddr::V4(bind)) { return Err("INVALID_TARGET"); }
    Ok(Options { session_root, control, vault, runtime, output, worker, worker_sha, bind, ports, vmess_port, targets, probe })
}
fn read_public_ca(path: &Path) -> Result<Vec<u8>, &'static str> {
    if !path.is_absolute() { return Err("INVALID_TARGET"); }
    let fd = rustix::fs::open(path, rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC, rustix::fs::Mode::empty()).map_err(|_| "INVALID_TARGET")?;
    let file = File::from(fd); let meta = file.metadata().map_err(|_| "INVALID_TARGET")?;
    if !meta.is_file() || meta.len() == 0 || meta.len()>65536 { return Err("INVALID_TARGET"); }
    let mut bytes = Vec::new(); file.take(65537).read_to_end(&mut bytes).map_err(|_| "INVALID_TARGET")?;
    if bytes.len() as u64 != meta.len() { return Err("INVALID_TARGET"); }
    Ok(bytes)
}
fn cap(path: &Path, locked: bool) -> Result<BoundDirectory, &'static str> {
    let file = File::open(path).map_err(|_| "DIRECTORY_UNAVAILABLE")?;
    let identity = DirectoryIdentity::of(&file).map_err(|_| "DIRECTORY_UNAVAILABLE")?;
    let dir = BoundDirectory::admit(path, identity).map_err(|_| "DIRECTORY_UNAVAILABLE")?;
    if locked { dir.lock().map_err(|_| "DIRECTORY_BUSY") } else { Ok(dir) }
}
fn random<const N: usize>() -> Result<Zeroizing<[u8;N]>, &'static str> {
    let mut value = Zeroizing::new([0u8;N]); getrandom::fill(&mut *value).map_err(|_| "RANDOM_UNAVAILABLE")?; Ok(value)
}
fn pem(label: &str, der: &[u8]) -> Zeroizing<Vec<u8>> {
    let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(der));
    let mut out = Zeroizing::new(format!("-----BEGIN {label}-----\n").into_bytes());
    for line in encoded.as_bytes().chunks(64) { out.extend_from_slice(line); out.push(b'\n'); }
    out.extend_from_slice(format!("-----END {label}-----\n").as_bytes()); out
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct ClientExport<'a> { schema_version: u16, warning: &'static str, bind_ip: Ipv4Addr, tls_server_name: &'static str,
    ca_pem: &'a str, certificate_expires_at_unix: i64, permitted_targets: &'a [SocketAddr],
    trojan_port: u16, trojan_password: &'a str, vless_port: u16, vless_uuid: &'a str,
    websocket_path: &'static str, websocket_alpn: &'static str, shadowsocks_port: u16, shadowsocks_method: &'static str, shadowsocks_password: &'a str,
    #[serde(skip_serializing_if="Option::is_none")] vmess_port: Option<u16>,
    #[serde(skip_serializing_if="Option::is_none")] vmess_uuid: Option<&'a str> }
fn start(options: Options) -> Result<(), &'static str> {
    let deadline = || Instant::now()+Duration::from_secs(20);
    let worker = VerifiedWorker::for_server_v2(&options.worker, &options.worker_sha, deadline(), &Cancellation::default()).map_err(|_| "WORKER_IDENTITY")?;
    vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2::probe_worker(&worker, Duration::from_secs(10), &Cancellation::default()).map_err(|_| "WORKER_EXECUTION_UNAVAILABLE")?;
    let release = vp_product_core_adapter::inspect_build().map_err(|_| "BUILD_IDENTITY")?.build.release;
    // Validate every target before any filesystem mutation.
    vp_product_compiler::server_v2::ServerCompilerV2::for_public_experiment(release.clone(), options.targets.clone()).map_err(|_| "INVALID_TARGET")?;
    let session = options.session_root.as_ref().map(|path| cap(path, true)).transpose()?;
    if let Some(root) = &session { root.require_empty().map_err(|_| "ROOT_NOT_EMPTY")?; }
    // Reserve requested ports before any creation. A later race fails closed.
    let mut held_ports = Vec::new();
    for port in options.ports.into_iter().chain(options.vmess_port) { held_ports.push(std::net::TcpListener::bind((options.bind, port)).map_err(|_| "BIND_UNAVAILABLE")?); }
    if let Some(root) = &session {
        for name in ["control", "vault", "runtime", "output"] {
            drop(root.child(name, vp_product_storage::BoundOpenMode::CreateFresh).map_err(|_| "SESSION_CREATION_UNCERTAIN")?);
        }
    }
    let control = cap(&options.control, true)?; let vault_root = cap(&options.vault, false)?;
    let runtime_root = cap(&options.runtime, false)?; let output = cap(&options.output, true)?;
    for (a,b) in [(&control,&vault_root),(&control,&runtime_root),(&control,&output),(&vault_root,&runtime_root),(&vault_root,&output),(&runtime_root,&output)] { a.disjoint(b).map_err(|_| "ROOTS_OVERLAP")?; }
    for root in [&control,&vault_root,&runtime_root,&output] { root.require_empty().map_err(|_| "ROOT_NOT_EMPTY")?; }
    let now = time::OffsetDateTime::now_utc();
    let ca_key = rcgen::KeyPair::generate().map_err(|_| "CERTIFICATE_GENERATION")?;
    let mut ca_params = rcgen::CertificateParams::new(vec!["vp-lab-ca.invalid".into()]).map_err(|_| "CERTIFICATE_GENERATION")?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.not_before = now - time::Duration::hours(1); ca_params.not_after = now + time::Duration::days(2);
    let ca = ca_params.self_signed(&ca_key).map_err(|_| "CERTIFICATE_GENERATION")?;
    let leaf_key = rcgen::KeyPair::generate().map_err(|_| "CERTIFICATE_GENERATION")?;
    let mut leaf_params = rcgen::CertificateParams::new(vec!["vp-lab.invalid".into()]).map_err(|_| "CERTIFICATE_GENERATION")?;
    leaf_params.not_before = now - time::Duration::hours(1); leaf_params.not_after = now + time::Duration::days(2);
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).map_err(|_| "CERTIFICATE_GENERATION")?;
    let ca_pem = pem("CERTIFICATE", ca.der());
    let mut chain_pem = pem("CERTIFICATE", leaf.der()); chain_pem.extend_from_slice(&ca_pem);
    let key_der = Zeroizing::new(leaf_key.serialize_der()); let key_pem = pem("PRIVATE KEY", &key_der);
    let policy = TlsBackendPolicy::new("lab-admin".into(), vec![ca.der().to_vec()], "vp-lab.invalid".into()).map_err(|_| "TLS_POLICY")?;
    let mut master = random::<32>()?; let genesis = random::<16>()?;
    let genesis_id = genesis.iter().map(|b| format!("{b:02x}")).collect::<String>();
    // Explicitly consented private 0600 file: retained even if later steps fail.
    output.atomic_file("vault-master.key", "vault-master.pending", &*master, 32, false).map_err(|_| "KEY_WRITE_UNCERTAIN")?;
    let vault_identity = vault_root.identity().map_err(|_| "VAULT_BINDING")?;
    let vault = TlsSecretStore::initialize_bound(&options.vault, Namespace::new("vp-public-lab").map_err(|_| "VAULT_NAMESPACE")?,
        MasterKey::new(SecretBytes::new(master.to_vec())).map_err(|_| "VAULT_KEY")?, Limits::default(),
        VaultDirectoryIdentity { device: vault_identity.device, inode: vault_identity.inode }, deadline()).map_err(|_| "VAULT_INITIALIZATION_UNCERTAIN")?;
    master.zeroize();
    let receipt = vault.inspect_read_only(deadline()).map_err(|_| "VAULT_INSPECTION")?;
    let artifact = ContentDigest::of("vp.public-lab-artifacts.v1", &(&options.worker_sha, &release)).map_err(|_| "BUILD_IDENTITY")?;
    let probe_fingerprint = options.probe.fingerprint().map_err(|_| "INVALID_TARGET")?;
    let prepare = ContentDigest::of("vp.public-lab-prepare.v1", &(&options.bind, &options.ports, &options.vmess_port, &options.targets, probe_fingerprint)).map_err(|_| "INVALID_ARGUMENT")?;
    let binding = InstanceBinding { binding_version: 1, genesis_id, vault_id: receipt.vault_id,
        namespace_digest: ContentDigest::parse(receipt.namespace_digest).map_err(|_| "VAULT_INSPECTION")?,
        administrator_commitment: ContentDigest::bytes(b"vp-public-lab-local-admin"), preparation_digest: prepare.clone(),
        activation_intent_digest: prepare, artifact_set_digest: artifact, profile: FRESH_TLS_RUNTIME_PROFILE.into() };
    vault.claim_instance_binding(&binding, deadline()).map_err(|_| "VAULT_CLAIM_UNCERTAIN")?;
    let control = control.anchor_before_threads().map_err(|_| "CONTROL_ANCHOR")?;
    let store = Arc::new(TlsSqliteStore::create(control, binding.clone()).map_err(|_| "CONTROL_INITIALIZATION_UNCERTAIN")?);
    let vault = Arc::new(vault);
    let mut reservation = reserve_fresh(runtime_root, &vault_root, store.as_ref(), vault.as_ref(), binding, &worker).map_err(|_| "RUNTIME_INITIALIZATION_UNCERTAIN")?;
    let export_targets = options.targets.clone();
    #[cfg(feature = "local-probe-test")]
    let fixture_targets = options.targets.clone();
    let attached = reservation.attach_single_ip(store.as_ref(), vault.clone(), policy, worker, options.probe, options.targets).map_err(|_| "RUNTIME_ATTACHMENT_UNCERTAIN")?;
    let manager = Arc::new(TlsExperimentalSecretManager::new(vault.clone()));
    let control = ControlService::new(store.clone(), attached.executor(), Arc::new(NoHostChanges), Arc::new(SystemClock)).with_secret_manager(manager.clone());
    let actor = UserId::new("lab-admin").map_err(|_| "INTERNAL_ID")?;
    let mut kinds = vec![NodeCredentialKind::Password {}, NodeCredentialKind::Uuid {}, NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }];
    if options.vmess_port.is_some() { kinds.push(NodeCredentialKind::Uuid {}); }
    let mut refs = Vec::new();
    for (index, kind) in kinds.iter().enumerate() {
        let summary = control.create_credential(&actor, Revision::ZERO, IdempotencyKey::new(format!("lab-credential-{index}")).map_err(|_| "INTERNAL_ID")?,
            CredentialCreatePayload { kind: kind.clone(), confirm_generate: ExplicitConfirmation::try_from(true).map_err(|_| "CONFIRMATION_REQUIRED")? }).map_err(|_| "CREDENTIAL_INITIALIZATION_UNCERTAIN")?;
        refs.push(summary.secret_ref);
    }
    {
        let mut lease = store.asset_writer().map_err(|_| "CONTROL_UNAVAILABLE")?;
        let version = lease.state().version;
        TlsImportService::new(&TlsBackendPolicy::new("lab-admin".into(), vec![ca.der().to_vec()], "vp-lab.invalid".into()).map_err(|_| "TLS_POLICY")?, &SystemClock)
            .import(&mut lease, vault.as_ref(), TlsImportRequest { actor: "lab-admin".into(), expected_version: version,
                action: "lab-import".into(), idempotency: "lab-import-request".into(), asset: "lab-certificate".into(), confirmed: true,
                chain: SecretBytes::new(chain_pem.to_vec()), key: SecretBytes::new(key_pem.to_vec()) }, deadline(), &CancellationToken::default()).map_err(|_| "CERTIFICATE_IMPORT_UNCERTAIN")?;
    }
    #[cfg(feature = "local-probe-test")]
    let plan_bind: Ipv4Addr = match std::env::var("VP_LAB_TEST_PLAN_IP") {
        Ok(value) => value.parse().map_err(|_| "INVALID_TEST_ADDRESS")?, Err(_) => options.bind,
    };
    #[cfg(not(feature = "local-probe-test"))]
    let plan_bind = options.bind;
    let mut config_value = serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[
        {"schemaVersion":1,"id":"lab-trojan","name":"lab-trojan","enabled":true,"bind":{"address":plan_bind,"port":options.ports[0]},"protocol":{"kind":"proxy","protocol":{"kind":"trojan"},"users":[{"id":"lab-user","credentialRef":refs[0],"enabled":true}]},"transport":{"kind":"tcp"},"security":{"kind":"tls","certificateRef":"lab-certificate","privateKeyRef":"secret:tls-key-lab-import","alpn":[]},"requirements":[]},
        {"schemaVersion":1,"id":"lab-vless","name":"lab-vless","enabled":true,"bind":{"address":plan_bind,"port":options.ports[1]},"protocol":{"kind":"proxy","protocol":{"kind":"vless","flow":null},"users":[{"id":"lab-user","credentialRef":refs[1],"enabled":true}]},"transport":{"kind":"ws","path":"/vp","host":null,"earlyData":null},"security":{"kind":"tls","certificateRef":"lab-certificate","privateKeyRef":"secret:tls-key-lab-import","alpn":["http/1.1"]},"requirements":[]},
        {"schemaVersion":1,"id":"lab-ss","name":"lab-ss","enabled":true,"bind":{"address":plan_bind,"port":options.ports[2]},"protocol":{"kind":"proxy","protocol":{"kind":"shadowsocks","method":"aes-128-gcm"},"users":[{"id":"lab-user","credentialRef":refs[2],"enabled":true}]},"transport":{"kind":"tcp"},"security":{"kind":"none"},"requirements":[]}
    ]});
    if let Some(port) = options.vmess_port {
        config_value["listeners"].as_array_mut().ok_or("CONFIGURATION_INVALID")?.push(serde_json::json!({"schemaVersion":1,"id":"lab-vmess","name":"lab-vmess","enabled":true,"bind":{"address":plan_bind,"port":port},"protocol":{"kind":"proxy","protocol":{"kind":"vmess","cipher":"auto","alterId":0},"users":[{"id":"lab-user","credentialRef":refs[3],"enabled":true}]},"transport":{"kind":"ws","path":"/vp","host":null,"earlyData":null},"security":{"kind":"tls","certificateRef":"lab-certificate","privateKeyRef":"secret:tls-key-lab-import","alpn":["http/1.1"]},"requirements":[]}));
    }
    let config: ProductConfig = serde_json::from_value(config_value).map_err(|_| "CONFIGURATION_INVALID")?;
    #[cfg(feature = "local-probe-test")]
    if std::env::var_os("VP_LAB_TEST_PLAN_IP").is_some() {
        eprintln!("VP_LAB_TEST: domain validation: {:?}", config.validate().map(|_| ()));
        let compiler = vp_product_compiler::server_v2::ServerCompilerV2::for_public_experiment(release.clone(), fixture_targets).map_err(|_| "INVALID_TARGET")?;
        eprintln!("VP_LAB_TEST: compiler validation: {:?}", compiler.compile(&config, &release).map(|_| ()));
    }
    eprintln!("VP_LAB: provisioning complete; validating the experimental configuration");
    let plan = control.plan(PlanRequest { principal: actor.clone(), expected_revision: Revision::ZERO, config, release, resources: vec![], ttl_ms: 180_000 }).map_err(|e| { eprintln!("VP_LAB_DIAGNOSTIC: plan: {e}"); "PLAN_REJECTED" })?;
    let operation = control.submit(ApplyRequest { principal: actor, plan_id: plan.body().id.clone(), confirmed_hash: plan.hash().clone(), expected_revision: Revision::ZERO,
        idempotency_key: IdempotencyKey::new("lab-apply").map_err(|_| "INTERNAL_ID")? }).map_err(|_| "APPLY_REJECTED")?;
    drop(held_ports);
    eprintln!("VP_LAB: starting experimental listeners; verification may contact the configured HTTPS target");
    let result = control.run(&operation.id, &CancellationToken::default()).map_err(|_| "APPLY_UNCERTAIN")?;
    if result.state != OperationState::Committed {
        if let Some(reason) = &result.failure { eprintln!("VP_LAB_DIAGNOSTIC: operation {:?}: {reason}", result.state); }
        else { eprintln!("VP_LAB_DIAGNOSTIC: operation {:?}", result.state); }
        return Err("APPLY_NOT_COMMITTED_INSPECT_STATE");
    }
    // Persist the committed journal transition before exporting credentials.
    // Failure is uncertain and leaves state for inspection, not silent retry.
    attached.finalize_committed(store.as_ref()).map_err(|_| "JOURNAL_FINALIZATION_UNCERTAIN")?;
    let mut secrets = Vec::new();
    for (reference, kind) in refs.iter().zip(kinds.iter()) { secrets.push(manager.load_credential(reference, kind, Some(1), deadline()).map_err(|_| "CREDENTIAL_UNAVAILABLE")?.ok_or("CREDENTIAL_UNAVAILABLE")?); }
    let text = |i: usize| std::str::from_utf8(secrets[i].expose()).map_err(|_| "CREDENTIAL_UNAVAILABLE");
    let export = ClientExport { schema_version: 1, warning: "EXPERIMENTAL LAB: exact IPv4 TCP targets only; no restart or upgrade support",
        bind_ip: options.bind, tls_server_name: "vp-lab.invalid", ca_pem: std::str::from_utf8(&ca_pem).map_err(|_| "TLS_POLICY")?,
        certificate_expires_at_unix: (now + time::Duration::days(2)).unix_timestamp(), permitted_targets: &export_targets,
        trojan_port: options.ports[0], trojan_password: text(0)?, vless_port: options.ports[1], vless_uuid: text(1)?, websocket_path: "/vp", websocket_alpn: "http/1.1",
        shadowsocks_port: options.ports[2], shadowsocks_method: "aes-128-gcm", shadowsocks_password: text(2)?, vmess_port: options.vmess_port, vmess_uuid: if options.vmess_port.is_some() { Some(text(3)?) } else { None } };
    let mut encoded = Zeroizing::new(Vec::new()); serde_json::to_writer(&mut *encoded, &export).map_err(|_| "EXPORT_UNAVAILABLE")?;
    output.atomic_file("client-secrets.json", "client-secrets.pending", &encoded, 65536, false).map_err(|_| "EXPORT_WRITE_UNCERTAIN")?;
    eprintln!("VP_LAB: started; private client material is in the chosen output directory. Foreground session only; restart and upgrade are not supported.");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| "SIGNAL_UNAVAILABLE")?;
    runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|_| "SIGNAL_UNAVAILABLE")?;
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        Ok::<(), &'static str>(())
    })?;
    drop(control); drop(attached); eprintln!("VP_LAB: foreground session ended. Verify worker exit and listener closure independently. The finalized journal retains historical process identity, not a live-status claim. Automatic reopening is unsupported."); Ok(())
}
fn preflight(mut args: impl Iterator<Item=String>) -> Result<(), &'static str> {
    let mut worker = None; let mut sha = None;
    while let Some(key) = args.next() {
        let value = args.next().ok_or("MISSING_ARGUMENT")?;
        match key.as_str() {
            "--worker" if worker.is_none() => worker = Some(PathBuf::from(value)),
            "--worker-sha256" if sha.is_none() => sha = Some(value),
            _ => return Err("INVALID_ARGUMENT"),
        }
    }
    let worker = worker.ok_or("MISSING_ARGUMENT")?; let sha = sha.ok_or("MISSING_ARGUMENT")?;
    let verified = VerifiedWorker::for_server_v2(&worker, &sha, Instant::now()+Duration::from_secs(20), &Cancellation::default()).map_err(|_| "WORKER_OR_HOST_UNAVAILABLE")?;
    vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2::probe_worker(&verified, Duration::from_secs(10), &Cancellation::default()).map_err(|_| "WORKER_EXECUTION_UNAVAILABLE")?;
    let release = vp_product_core_adapter::inspect_build().map_err(|_| "BUILD_IDENTITY")?.build.release;
    let result = serde_json::json!({"status":"PREREQUISITES_PRESENT_NOT_EXECUTION_CERTIFIED", "architecture":std::env::consts::ARCH,
        "workerSha256":sha, "releaseIdentity":release, "testFixture":cfg!(feature = "local-probe-test") || vp_product_core_adapter::local_probe_test_enabled(), "startsWorkerBriefly":true, "startsListener":false, "writesState":false});
    serde_json::to_writer(std::io::stdout().lock(), &result).map_err(|_| "OUTPUT_UNAVAILABLE")?; println!(); Ok(())
}
fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("--help") && args.next().is_none() {
        println!("VP public lab: foreground, experimental, fresh instance only. No automatic restart or upgrade.\n\nBefore starting: provide an empty 0700 session directory (or four separate empty 0700 directories), a reviewed worker and SHA-256, one assigned local IPv4, three free TCP ports (and a fourth if enabling VMess), and explicit approval to create test access. The selected HTTPS probe sends a request exposing the server's source IP. Credentials and the vault master key are written to 0600 files in the output directory; never include those files in a report. Existing proxy services and firewall settings are not changed.\n\n--check-host --worker ABSOLUTE_PATH --worker-sha256 SHA256 briefly starts and reaps the worker to check compatibility; no listener or state is created.\n\nStart options: (--session-root PATH | --control-root PATH --vault-root PATH --runtime-root PATH --output-root PATH) --worker PATH --worker-sha256 SHA256 --bind-ip IPV4 --trojan-port PORT --vless-port PORT --ss-port PORT [--vmess-port PORT] [--target IPV4:PORT ...] --confirm-test-access (--confirm-cloudflare-probe | --probe-target IPV4:PORT --probe-name NAME --probe-path PATH --probe-status CODE --probe-ca-der FILE --confirm-custom-probe)");
        return;
    }
    let result = if first.as_deref() == Some("--check-host") { preflight(args) } else { parse(first.into_iter().chain(args)).and_then(start) };
    if let Err(code) = result { eprintln!("VP_LAB_REFUSED: {code}; retain state and inspect before retrying"); std::process::exit(1); }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        ["--control-root","/tmp/vp-control","--vault-root","/tmp/vp-vault","--runtime-root","/tmp/vp-runtime",
         "--output-root","/tmp/vp-output","--worker","/tmp/vp-worker","--worker-sha256",&"a".repeat(64),
         "--bind-ip","192.0.2.2","--trojan-port","18443","--vless-port","18444","--ss-port","18445",
         "--confirm-test-access","--confirm-cloudflare-probe"].iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn parser_requires_explicit_credential_and_external_probe_confirmations() {
        let mut a = args(); a.retain(|v| v != "--confirm-test-access"); assert!(matches!(parse(a.into_iter()), Err("CONFIRMATION_REQUIRED")));
        let mut a = args(); a.retain(|v| v != "--confirm-cloudflare-probe"); assert!(matches!(parse(a.into_iter()), Err("CONFIRMATION_REQUIRED")));
        let parsed = parse(args().into_iter()).unwrap();
        assert_eq!(parsed.targets, vec!["1.1.1.1:443".parse().unwrap()]);
    }
    #[test]
    fn optional_vmess_port_is_distinct_and_nonzero() {
        let base = args();
        assert_eq!(parse(base.clone().into_iter()).unwrap().vmess_port, None);
        let mut enabled = base.clone(); enabled.extend(["--vmess-port".into(), "18446".into()]);
        assert_eq!(parse(enabled.into_iter()).unwrap().vmess_port, Some(18446));
        let mut overlap = base.clone(); overlap.extend(["--vmess-port".into(), "18443".into()]);
        assert!(parse(overlap.into_iter()).is_err());
        let mut zero = base; zero.extend(["--vmess-port".into(), "0".into()]);
        assert!(parse(zero.into_iter()).is_err());
    }
    #[test]
    fn parser_rejects_duplicate_ports_loopback_and_unexpected_flags() {
        let mut a = args(); let i = a.iter().position(|v| v == "--ss-port").unwrap(); a[i+1] = "18443".into(); assert!(parse(a.into_iter()).is_err());
        let mut a = args(); let i = a.iter().position(|v| v == "--bind-ip").unwrap(); a[i+1] = "127.0.0.1".into(); assert!(parse(a.into_iter()).is_err());
        let mut a = args(); a.extend(["--unknown".into(), "x".into()]); assert!(parse(a.into_iter()).is_err());
        let mut a = args(); a.extend(["--target".into(), "1.1.1.1:443".into(), "--target".into(), "1.1.1.1:443".into()]); assert!(parse(a.into_iter()).is_err());
    }
    #[test]
    fn session_root_derives_separate_private_paths_and_rejects_conflicts() {
        let original = args(); let mut only = Vec::new(); let mut iter = original.into_iter();
        while let Some(key) = iter.next() {
            if ["--control-root","--vault-root","--runtime-root","--output-root"].contains(&key.as_str()) { iter.next(); }
            else { only.push(key); }
        }
        only.extend(["--session-root".into(), "/tmp/vp-session".into()]);
        let parsed = parse(only.clone().into_iter()).unwrap();
        assert_eq!(parsed.control, PathBuf::from("/tmp/vp-session/control"));
        assert_eq!(parsed.output, PathBuf::from("/tmp/vp-session/output"));
        only.extend(["--vault-root".into(), "/tmp/other".into()]); assert!(parse(only.into_iter()).is_err());
    }
    #[test]
    fn custom_https_probe_requires_explicit_consent_and_valid_pinned_ca() {
        let temp = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["example.invalid".into()]).unwrap();
        let ca = temp.path().join("ca.der"); std::fs::write(&ca, cert.cert.der()).unwrap();
        let mut a = args(); a.retain(|v| v != "--confirm-cloudflare-probe");
        a.extend(["--probe-target".into(), "8.8.8.8:443".into(), "--probe-name".into(), "example.invalid".into(),
            "--probe-path".into(), "/health".into(), "--probe-status".into(), "204".into(), "--probe-ca-der".into(), ca.to_str().unwrap().into()]);
        assert!(matches!(parse(a.clone().into_iter()), Err("CONFIRMATION_REQUIRED")));
        a.push("--confirm-custom-probe".into());
        let parsed = parse(a.clone().into_iter()).unwrap();
        assert_eq!(parsed.probe.target, "8.8.8.8:443".parse().unwrap());
        assert!(parsed.targets.contains(&parsed.probe.target));
        let original = parsed.probe.fingerprint().unwrap();
        let index = a.iter().position(|v| v == "--probe-path").unwrap(); a[index+1] = "/different".into();
        assert_ne!(parse(a.clone().into_iter()).unwrap().probe.fingerprint().unwrap(), original);
        a[index+1] = "/bad\r\nInjected".into(); assert!(parse(a.into_iter()).is_err());
        let link = temp.path().join("link.der"); std::os::unix::fs::symlink(&ca, &link).unwrap();
        assert!(read_public_ca(&link).is_err());
    }
    #[test]
    fn private_client_export_is_restricted_and_contains_explicit_test_limits() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
        let dir = cap(root.path(), true).unwrap(); let targets = ["1.1.1.1:443".parse().unwrap()];
        let export = ClientExport { schema_version: 1, warning: "synthetic", bind_ip: "192.0.2.2".parse().unwrap(), tls_server_name: "vp-lab.invalid", ca_pem: "synthetic-public-ca", certificate_expires_at_unix: 123,
            permitted_targets: &targets, trojan_port: 1, trojan_password: "synthetic-trojan", vless_port: 2, vless_uuid: "synthetic-uuid", websocket_path: "/vp", websocket_alpn: "http/1.1",
            shadowsocks_port: 3, shadowsocks_method: "aes-128-gcm", shadowsocks_password: "synthetic-ss", vmess_port: None, vmess_uuid: None };
        let mut bytes = Zeroizing::new(Vec::new()); serde_json::to_writer(&mut *bytes, &export).unwrap();
        dir.atomic_file("client-secrets.json", "client-secrets.pending", &bytes, 65536, false).unwrap();
        let path = root.path().join("client-secrets.json");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let parsed: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(parsed["permittedTargets"][0], "1.1.1.1:443"); assert_eq!(parsed["websocketAlpn"], "http/1.1");
    }
    #[test]
    fn pem_encoding_round_trips_without_logging_material() {
        let value = pem("PRIVATE KEY", &[1,2,3,4]);
        assert!(value.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
        assert!(value.ends_with(b"-----END PRIVATE KEY-----\n"));
    }
}
