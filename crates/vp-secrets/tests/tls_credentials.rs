//! Actual SQL/vault/shared-control credential journey. No runtime or network.
//! Synthetic master material and isolated roots only; each phase owns its anchor.
#![allow(clippy::unwrap_used)]
use std::{
    fs::{self, File},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};
use vp_product_control::*;
use vp_product_domain::*;
use vp_product_secrets::{
    Limits, MasterKey, Namespace, TlsPasswordSecretManager, TlsSecretStore, VaultDirectoryIdentity,
};
use vp_product_storage::{BoundDirectory, DirectoryIdentity, TlsSqliteStore};
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn key() -> MasterKey {
    MasterKey::new(SecretBytes::new(vec![87; 32])).unwrap()
}
fn ns() -> Namespace {
    Namespace::new("tls-credential-test").unwrap()
}
fn identity(path: &Path) -> VaultDirectoryIdentity {
    let m = fs::metadata(path).unwrap();
    VaultDirectoryIdentity {
        device: m.dev(),
        inode: m.ino(),
    }
}
fn root(path: &Path) -> vp_product_storage::AnchoredControlRoot {
    let id = DirectoryIdentity::of(&File::open(path).unwrap()).unwrap();
    BoundDirectory::open(path, id)
        .unwrap()
        .anchor_before_threads()
        .unwrap()
}
fn actor() -> UserId {
    UserId::new("synthetic-admin").unwrap()
}
fn payload() -> CredentialCreatePayload {
    CredentialCreatePayload {
        kind: NodeCredentialKind::Password {},
        confirm_generate: ExplicitConfirmation::try_from(true).unwrap(),
    }
}
struct UncertainPut(TlsPasswordSecretManager);
impl SecretManager for UncertainPut {
    fn supported_kinds(&self) -> Vec<NodeCredentialKind> {
        self.0.supported_kinds()
    }
    fn generate_credential(
        &self,
        k: &NodeCredentialKind,
        d: Instant,
    ) -> Result<GeneratedCredential, ControlError> {
        self.0.generate_credential(k, d)
    }
    fn put_credential(
        &self,
        r: &SecretRef,
        k: &NodeCredentialKind,
        v: u64,
        b: SecretBytes,
        d: Instant,
    ) -> Result<(), ControlError> {
        self.0.put_credential(r, k, v, b, d)?;
        // Authenticated durable bytes exist, but caller receives an uncertain outcome.
        Err(ControlError::RecoveryRequired)
    }
    fn load_credential(
        &self,
        r: &SecretRef,
        k: &NodeCredentialKind,
        v: Option<u64>,
        d: Instant,
    ) -> Result<Option<SecretBytes>, ControlError> {
        self.0.load_credential(r, k, v, d)
    }
    fn retire_credential(&self, r: &SecretRef, v: u64, d: Instant) -> Result<(), ControlError> {
        self.0.retire_credential(r, v, d)
    }
    fn generate_publication_token(&self, d: Instant) -> Result<SecretBytes, ControlError> {
        self.0.generate_publication_token(d)
    }
    fn publication_verifier(&self, t: &[u8]) -> Result<ContentDigest, ControlError> {
        self.0.publication_verifier(t)
    }
    fn verify_publication_token(&self, v: &ContentDigest, t: &[u8]) -> bool {
        self.0.verify_publication_token(v, t)
    }
}
fn child(path: &Path, mode: &str, phase: &str) {
    let control_path = path.join("control");
    let vault_path = path.join("vault");
    let (vault, store) = if phase == "create" {
        for p in [&control_path, &vault_path] {
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
        let digest = ContentDigest::bytes(b"synthetic-credential-journey-not-runtime");
        let binding = InstanceBinding {
            binding_version: 1,
            genesis_id: "8".repeat(32),
            vault_id: observation.vault_id,
            namespace_digest: ContentDigest::parse(observation.namespace_digest).unwrap(),
            administrator_commitment: digest.clone(),
            preparation_digest: digest.clone(),
            activation_intent_digest: digest.clone(),
            artifact_set_digest: digest,
            profile: FRESH_TLS_RUNTIME_PROFILE.into(),
        };
        vault.claim_instance_binding(&binding, deadline()).unwrap();
        let store = TlsSqliteStore::create(root(&control_path), binding).unwrap();
        store.mark_initialized().unwrap();
        (vault, store)
    } else {
        let vault =
            TlsSecretStore::open(&vault_path, ns(), key(), identity(&vault_path), deadline())
                .unwrap();
        let binding = vault.binding(deadline()).unwrap();
        let store = TlsSqliteStore::open_initialized(root(&control_path), binding).unwrap();
        (vault, store)
    };
    let vault = Arc::new(vault);
    let store = Arc::new(store);
    let manager = Arc::new(TlsPasswordSecretManager::new(vault.clone()));
    let selected: Arc<dyn SecretManager> = if phase == "create" && mode == "uncertain" {
        Arc::new(UncertainPut(TlsPasswordSecretManager::new(vault.clone())))
    } else {
        manager.clone()
    };
    let service = ControlService::new(
        store.clone(),
        Arc::new(UnavailableRuntime),
        Arc::new(UnavailableSystem),
        Arc::new(SystemClock),
    )
    .with_secret_manager(selected);
    if phase == "create" {
        let result = service.create_credential(
            &actor(),
            Revision::ZERO,
            IdempotencyKey::new("create-password").unwrap(),
            payload(),
        );
        if mode == "uncertain" {
            assert!(matches!(result, Err(ControlError::RecoveryRequired)));
            assert!(store.read().unwrap().secrets.needs_recovery());
        } else {
            let created = result.unwrap();
            let again = service
                .create_credential(
                    &actor(),
                    Revision::ZERO,
                    IdempotencyKey::new("create-password").unwrap(),
                    payload(),
                )
                .unwrap();
            assert_eq!(created.id, again.id);
            assert_eq!(created.secret_ref, again.secret_ref);
            assert_eq!(store.read().unwrap().secrets.credentials.len(), 1);
        }
        return;
    }
    if phase == "retire" {
        service.recover().unwrap();
        let state = store.read().unwrap();
        assert!(!state.secrets.needs_recovery());
        assert_eq!(state.secrets.credentials.len(), 1);
        let record = state.secrets.credentials.values().next().unwrap();
        let bytes = manager
            .load_credential(
                &record.summary.secret_ref,
                &record.summary.kind,
                Some(record.vault_version),
                deadline(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(bytes.expose().len(), 64);
        let serialized = serde_json::to_vec(&state).unwrap();
        assert!(!serialized
            .windows(bytes.expose().len())
            .any(|w| w == bytes.expose()));
        let before = store.read().unwrap().version;
        assert!(service
            .create_credential(
                &actor(),
                Revision::new(1).unwrap(),
                IdempotencyKey::new("stale-create").unwrap(),
                payload()
            )
            .is_err());
        assert_eq!(before, store.read().unwrap().version);
        let result = service
            .retire_credential(
                &actor(),
                &record.summary.id,
                record.summary.revision,
                IdempotencyKey::new("retire-password").unwrap(),
                CredentialRetirePayload {
                    confirm_retire: ExplicitConfirmation::try_from(true).unwrap(),
                },
            )
            .unwrap();
        assert_eq!(result.state, CredentialState::Retired);
        assert!(manager
            .load_credential(
                &record.summary.secret_ref,
                &record.summary.kind,
                None,
                deadline()
            )
            .is_err());
        return;
    }
    let state = store.read().unwrap();
    assert!(!state.secrets.needs_recovery());
    assert_eq!(state.secrets.credentials.len(), 1);
    let record = state.secrets.credentials.values().next().unwrap();
    assert_eq!(record.summary.state, CredentialState::Retired);
    assert!(manager
        .load_credential(
            &record.summary.secret_ref,
            &record.summary.kind,
            None,
            deadline()
        )
        .is_err());
    assert!(vault
        .put_credential(
            &record.summary.secret_ref,
            record.vault_version + 1,
            SecretBytes::new(b"replacement-forbidden".to_vec()),
            deadline()
        )
        .is_err());
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 5 && args[1] == "child" {
        child(Path::new(&args[2]), &args[3], &args[4]);
        return;
    }
    for mode in ["normal", "uncertain"] {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for phase in ["create", "retire", "final"] {
            let status = Command::new(std::env::current_exe().unwrap())
                .arg("child")
                .arg(root.path())
                .arg(mode)
                .arg(phase)
                .status()
                .unwrap();
            assert!(status.success());
        }
    }
    println!("PASS: actual SQL/vault/control password create, idempotency, uncertain-write recovery and irreversible retirement in six owned process phases; no runtime/network acceptance");
}
