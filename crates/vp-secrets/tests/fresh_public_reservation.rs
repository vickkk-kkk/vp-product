//! Real local vault/control/journal admission; no listener or external service.
use std::{sync::Arc, fs::{self, File}, os::unix::fs::{MetadataExt, PermissionsExt}, path::Path, process::Command, time::{Duration, Instant}};
use sha2::{Digest, Sha256};
use vp_product_control::{ContentDigest, InstanceBinding, FRESH_TLS_RUNTIME_PROFILE};
use vp_product_core_adapter::managed::{Cancellation, VerifiedWorker};
use vp_product_domain::SecretBytes;
use vp_product_runtime_executor::experimental_public::{reserve_fresh, inspect_committed_restart, SingleIpProbeConfig};
use vp_product_secrets::{Limits, MasterKey, Namespace, TlsSecretStore, VaultDirectoryIdentity};
use vp_product_storage::{BoundDirectory, DirectoryIdentity, TlsSqliteStore};
fn cap(path: &Path) -> BoundDirectory {
    BoundDirectory::admit(path, DirectoryIdentity::of(&File::open(path).unwrap()).unwrap()).unwrap()
}
fn case(name: &str) {
    let temp = tempfile::tempdir().unwrap();
    let control = temp.path().join("control");
    let vault_path = temp.path().join("vault");
    let runtime = temp.path().join("runtime");
    let wrong = temp.path().join("wrong");
    for path in [&control, &vault_path, &runtime, &wrong] {
        fs::create_dir(path).unwrap(); fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let control_cap = cap(&control);
    let vault_cap = cap(&vault_path);
    let runtime_cap = if name == "same" { cap(&vault_path) } else { cap(&runtime) };
    let wrong_cap = cap(&wrong);
    let m = fs::metadata(&vault_path).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let vault = TlsSecretStore::initialize_bound(&vault_path, Namespace::new("fresh-test").unwrap(),
        MasterKey::new(SecretBytes::new(vec![61; 32])).unwrap(), Limits::default(),
        VaultDirectoryIdentity { device: m.dev(), inode: m.ino() }, deadline).unwrap();
    let receipt = vault.inspect_read_only(deadline).unwrap();
    let digest = ContentDigest::bytes(b"synthetic fresh test");
    let binding = InstanceBinding { binding_version: 1, genesis_id: "9".repeat(32), vault_id: receipt.vault_id,
        namespace_digest: ContentDigest::parse(receipt.namespace_digest).unwrap(), administrator_commitment: digest.clone(),
        preparation_digest: digest.clone(), activation_intent_digest: digest.clone(), artifact_set_digest: digest,
        profile: FRESH_TLS_RUNTIME_PROFILE.into() };
    vault.claim_instance_binding(&binding, deadline).unwrap();
    let mut control_binding = binding.clone();
    if name == "wrong_control" { control_binding.genesis_id = "8".repeat(32); }
    let store = TlsSqliteStore::create(control_cap.lock().unwrap().anchor_before_threads().unwrap(), control_binding).unwrap();
    let path = std::env::var("VP_TEST_WORKER").unwrap();
    let hash = format!("{:x}", Sha256::digest(fs::read(&path).unwrap()));
    let worker = VerifiedWorker::for_server_v2(path, &hash, deadline, &Cancellation::default()).unwrap();
    let saved_binding = binding.clone();
    let mut requested_binding = binding;
    if name == "wrong_vault" { requested_binding.genesis_id = "7".repeat(32); }
    let result = reserve_fresh(runtime_cap, if name == "wrong" { &wrong_cap } else { &vault_cap }, &store, &vault, requested_binding, &worker);
    if matches!(name, "wrong" | "same" | "wrong_control" | "wrong_vault") {
        assert!(result.is_err());
        assert!(fs::read_dir(&runtime).unwrap().next().is_none());
    } else if name == "no_active" {
        drop(result.unwrap());
        store.mark_initialized().unwrap();
        let policy = vp_product_control::TlsBackendPolicy::new("actor".into(), vec![vec![1]], "localhost".into()).unwrap();
        let before = fs::read(runtime.join("runtime.journal.json")).unwrap();
        assert!(inspect_committed_restart(cap(&runtime), &vault_cap, &store, &vault, &saved_binding, &policy,
            &worker, "8.8.8.8:443".parse().unwrap(), &vp_product_control::SystemClock,
            &vp_product_control::CancellationToken::default(), deadline).is_err());
        assert_eq!(before, fs::read(runtime.join("runtime.journal.json")).unwrap());
    } else if name == "single_ip_valid" || name == "single_ip_bad" || name == "single_ip_default" {
        let mut reservation = result.unwrap(); let vault = Arc::new(vault);
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let root = cert.cert.der().to_vec();
        let policy = vp_product_control::TlsBackendPolicy::new("actor".into(), vec![root.clone()], "localhost".into()).unwrap();
        let target = "8.8.8.8:443".parse().unwrap();
        let config = if name == "single_ip_default" { SingleIpProbeConfig::cloudflare_trace() } else {
            SingleIpProbeConfig { target, target_trust: vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust::PinnedDer(vec![root]), target_name: "localhost".into(), path: "/health".into(), expected_status: 204 }
        };
        let expected_target = config.target;
        let allowed = if name == "single_ip_bad" { vec!["1.1.1.1:443".parse().unwrap()] } else { vec![expected_target] };
        let attached = reservation.attach_single_ip(&store, vault, policy, worker, config, allowed);
        if name == "single_ip_bad" { assert!(attached.is_err()); assert!(store.with_preparing(|_| Ok(())).is_ok()); }
        else { assert_eq!(attached.unwrap().probe_target(), expected_target); assert!(store.with_preparing(|_| Ok(())).is_err()); }
    } else if name == "invalid_probe" {
        let mut reservation = result.unwrap();
        let vault = Arc::new(vault);
        for _ in 0..2 {
            let policy = vp_product_control::TlsBackendPolicy::new("actor".into(), vec![vec![1]], "localhost".into()).unwrap();
            assert!(reservation.attach(&store, vault.clone(), policy, worker.clone(), "127.0.0.1".parse().unwrap(), vec!["8.8.8.8:443".parse().unwrap()]).is_err());
            assert!(store.with_preparing(|_| Ok(())).is_ok());
        }
    } else {
        assert!(result.is_ok());
        assert!(fs::read_dir(&runtime).unwrap().next().is_some());
        store.mark_initialized().unwrap();
        assert!(store.with_preparing(|_| Ok(())).is_err());
    }
    println!("{name}: passed");
}
fn main() {
    if let Some(name) = std::env::args().nth(1) { case(&name); return; }
    for name in ["wrong", "same", "wrong_control", "wrong_vault", "valid", "invalid_probe", "no_active", "single_ip_bad", "single_ip_valid", "single_ip_default"] {
        assert!(Command::new(std::env::current_exe().unwrap()).arg(name).status().unwrap().success());
    }
}
