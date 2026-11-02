//! New synthetic instance only: real authenticated vault + SQL aggregate/journal.
//! Isolated process owns cwd anchor. No runtime/worker/network/listener involved.
#![allow(clippy::unwrap_used)]
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use vp_product_control::*;
use vp_product_domain::{SecretBytes, SecretRef};
use vp_product_secrets::{Limits, MasterKey, Namespace, TlsSecretStore, VaultDirectoryIdentity};
use vp_product_storage::{BoundDirectory, DirectoryIdentity, TlsSqliteStore};
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn key() -> MasterKey {
    MasterKey::new(SecretBytes::new(vec![73; 32])).unwrap()
}
fn ns() -> Namespace {
    Namespace::new("tls-io-synthetic").unwrap()
}
fn identity(p: &Path) -> VaultDirectoryIdentity {
    let m = fs::metadata(p).unwrap();
    VaultDirectoryIdentity {
        device: m.dev(),
        inode: m.ino(),
    }
}
struct Wall;
impl Clock for Wall {
    fn now_ms(&self) -> Result<u64, ControlError> {
        Ok(1_735_689_600_000)
    }
}
fn materials() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let k = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(vec!["synthetic.invalid".into()]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca.self_signed(&k).unwrap();
    let leaf_k = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf.not_before = rcgen::date_time_ymd(2024, 1, 1);
    leaf.not_after = rcgen::date_time_ymd(2026, 1, 1);
    let leaf = leaf.signed_by(&leaf_k, &ca, &k).unwrap();
    (
        leaf.pem().into_bytes(),
        leaf_k.serialize_pem().into_bytes(),
        ca.der().to_vec(),
    )
}
fn root(path: &Path) -> vp_product_storage::AnchoredControlRoot {
    let id = DirectoryIdentity::of(&File::open(path).unwrap()).unwrap();
    BoundDirectory::open(path, id)
        .unwrap()
        .anchor_before_threads()
        .unwrap()
}
struct FaultVault<'a> {
    inner: &'a TlsSecretStore,
    put_count: std::cell::Cell<usize>,
    fail: usize,
}
impl TlsVaultIo for FaultVault<'_> {
    fn binding(&self, d: Instant) -> Result<InstanceBinding, ControlError> {
        self.inner.binding(d)
    }
    fn read(&self, r: &SecretRef, d: Instant) -> Result<Option<TlsRawRecord>, ControlError> {
        self.inner.read(r, d)
    }
    fn put(&self, r: TlsRawRecord, d: Instant) -> Result<(), ControlError> {
        let count = self.put_count.get() + 1;
        self.put_count.set(count);
        if count == self.fail {
            return Err(ControlError::StorageUnavailable);
        }
        self.inner.put(r, d)
    }
    fn retire(&self, r: &SecretRef, k: u8, v: u64, d: Instant) -> Result<(), ControlError> {
        self.inner.retire(r, k, v, d)
    }
    fn tombstone(&self, r: &SecretRef, d: Instant) -> Result<TlsTombstone, ControlError> {
        self.inner.tombstone(r, d)
    }
}
fn child(path: &Path, mode: &str, phase: &str) {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let (chain, key_bytes, anchor): (Vec<u8>, Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&input).unwrap();
    let policy =
        TlsBackendPolicy::new("administrator".into(), vec![anchor], "localhost".into()).unwrap();
    let service = TlsImportService::new(&policy, &Wall);
    let cancel = CancellationToken::default();
    let control = path.join("control");
    let vault_path = path.join("vault");
    if phase == "import" {
        for p in [&control, &vault_path] {
            fs::create_dir(p).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let vault = TlsSecretStore::initialize_bound(
            &vault_path,
            ns(),
            key(),
            Limits::default(),
            identity(&vault_path),
            deadline(),
        )
        .unwrap();
        let observation = vault.inspect_read_only(deadline()).unwrap();
        let d = ContentDigest::bytes(b"synthetic-only-not-runtime");
        let binding = InstanceBinding {
            binding_version: 1,
            genesis_id: "1".repeat(32),
            vault_id: observation.vault_id,
            namespace_digest: ContentDigest::parse(observation.namespace_digest).unwrap(),
            administrator_commitment: d.clone(),
            preparation_digest: d.clone(),
            activation_intent_digest: d.clone(),
            artifact_set_digest: d,
            profile: FRESH_TLS_RUNTIME_PROFILE.into(),
        };
        vault.claim_instance_binding(&binding, deadline()).unwrap();
        let store = TlsSqliteStore::create(root(&control), binding.clone()).unwrap();
        store.mark_initialized().unwrap();
        let mut lease = store.asset_writer().unwrap();
        let request = TlsImportRequest {
            actor: "administrator".into(),
            expected_version: 0,
            action: "actual-import".into(),
            idempotency: "request-1".into(),
            asset: "actual-asset".into(),
            confirmed: true,
            chain: SecretBytes::new(chain.clone()),
            key: SecretBytes::new(key_bytes.clone()),
        };
        let faults = FaultVault {
            inner: &vault,
            put_count: std::cell::Cell::new(0),
            fail: if mode == "partial" { 2 } else { 0 },
        };
        let result = service.import(&mut lease, &faults, request, deadline(), &cancel);
        if mode == "partial" {
            assert!(result.is_err());
            assert_eq!(lease.aggregate().state().version, 1);
            assert!(lease.aggregate().needs_recovery());
        } else {
            result.unwrap();
            assert_eq!(lease.aggregate().state().version, 2);
        }
        return;
    }
    let vault =
        TlsSecretStore::open(&vault_path, ns(), key(), identity(&vault_path), deadline()).unwrap();
    let binding = vault.binding(deadline()).unwrap();
    let store = TlsSqliteStore::open_initialized(root(&control), binding).unwrap();
    if phase == "retire" {
        if mode == "partial" {
            assert!(store.read().is_err());
            assert!(store.writer().is_err());
            let mut lease = store.asset_writer().unwrap();
            let req = || TlsActionRequest {
                actor: "administrator".into(),
                expected_version: 1,
                action: "actual-import".into(),
                confirmed: true,
            };
            assert!(service
                .recover(&mut lease, &vault, req(), deadline(), &cancel)
                .is_err());
            service
                .reupload_missing(
                    &mut lease,
                    &vault,
                    req(),
                    SecretBytes::new(chain),
                    SecretBytes::new(key_bytes),
                    deadline(),
                    &cancel,
                )
                .unwrap();
            assert_eq!(lease.aggregate().state().version, 2);
        }
        assert_eq!(store.read().unwrap().version, 2);
        let mut lease = store.asset_writer().unwrap();
        service
            .retire(
                &mut lease,
                &vault,
                TlsRetireRequest {
                    actor: "administrator".into(),
                    expected_version: 2,
                    action: "actual-retire".into(),
                    idempotency: "request-retire".into(),
                    asset: "actual-asset".into(),
                    asset_revision: 1,
                    confirmed: true,
                    confirm_history_loss: false,
                },
                deadline(),
                &cancel,
            )
            .unwrap();
        assert_eq!(lease.aggregate().state().version, 4);
        return;
    }
    assert_eq!(phase, "verify");
    assert_eq!(store.read().unwrap().version, 4);
    for (r, k) in [("tls-chain-actual-import", 6), ("tls-key-actual-import", 2)] {
        let r = SecretRef::new(r).unwrap();
        assert!(vault.read(&r, deadline()).is_err());
        assert_eq!(vault.tombstone(&r, deadline()).unwrap().kind, k);
        assert!(vault
            .put(
                TlsRawRecord {
                    reference: r,
                    kind: k,
                    version: 2,
                    bytes: SecretBytes::new(vec![1])
                },
                deadline()
            )
            .is_err());
    }
    let payload = serde_json::to_vec(store.asset_writer().unwrap().aggregate()).unwrap();
    assert!(!payload.windows(11).any(|w| w == b"PRIVATE KEY"));
    println!("{mode}: actual vault + SQL import/reopen/retirement passed");
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 4 {
        child(Path::new(&args[2]), &args[1], &args[3]);
        return;
    }
    let d = tempfile::tempdir().unwrap();
    for mode in ["normal", "partial"] {
        let path = d.path().join(mode);
        fs::create_dir(&path).unwrap();
        // Synthetic fixture bytes exist only in parent memory and child stdin.
        let input = serde_json::to_vec(&materials()).unwrap();
        for phase in ["import", "retire", "verify"] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .arg(mode)
                .arg(&path)
                .arg(phase)
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(&input).unwrap();
            assert!(child.wait().unwrap().success());
        }
    }
}

// Test-only PEM encoding.
use base64::Engine;
fn encode(label: &str, bytes: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        for byte in chunk {
            out.push(*byte as char);
        }
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
trait TestPem {
    fn pem(&self) -> String;
    fn serialize_pem(&self) -> String {
        self.pem()
    }
}
impl TestPem for rcgen::Certificate {
    fn pem(&self) -> String {
        encode("CERTIFICATE", self.der().as_ref())
    }
}
impl TestPem for rcgen::KeyPair {
    fn pem(&self) -> String {
        encode("PRIVATE KEY", &self.serialize_der())
    }
}
