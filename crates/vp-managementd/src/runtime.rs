//! Explicit opt-in development composition. All secrets arrive via inherited
//! stdin at startup. Later node/subscription generation requires a confirmed
//! authenticated control action; no secret is persisted as plaintext or in argv/env.
use crate::probes::LoopbackProbe;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use vp_product_control::{ContentDigest, SystemClock};
use vp_product_core_adapter::managed::VerifiedWorker;
use vp_product_domain::{SecretBytes, SecretRef};
use vp_product_runtime_executor::ManagedExecutor;
use vp_product_secrets::{DurableSecretStore, Limits, MasterKey, Namespace, SecretKind};
use zeroize::{Zeroize, Zeroizing};

pub struct RuntimeOptions {
    pub root: PathBuf,
    pub worker: PathBuf,
    pub worker_sha256: String,
    pub vault_root: PathBuf,
    pub vault_namespace: String,
    pub initialize_vault: bool,
    pub probe_bind: SocketAddr,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultInput {
    #[serde(deserialize_with = "crate::secret_input")]
    master_key_hex: Zeroizing<String>,
    credentials: Vec<CredentialInput>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialInput {
    reference: SecretRef,
    version: u64,
    #[serde(deserialize_with = "crate::secret_input")]
    value: Zeroizing<String>,
}
pub struct ManagedComposition {
    pub executor: Arc<ManagedExecutor>,
    pub secret_manager: Arc<crate::secret_manager::VaultSecretManager>,
}
pub fn compose(
    options: RuntimeOptions,
    mut input: VaultInput,
) -> Result<ManagedComposition, &'static str> {
    if !options.root.is_absolute()
        || !options.vault_root.is_absolute()
        || options.root == options.vault_root
    {
        return Err("independent absolute private runtime/vault roots required");
    }
    if input.credentials.len() > 32 || (!options.initialize_vault && !input.credentials.is_empty())
    {
        return Err("credential provisioning requires explicit one-time vault initialize");
    }
    let mut refs = BTreeSet::new();
    for credential in &input.credentials {
        if credential.version == 0
            || credential.value.is_empty()
            || credential.value.len() > 1024
            || !refs.insert(credential.reference.clone())
        {
            return Err("invalid immutable credential provisioning input");
        }
    }
    // Reject an untrusted worker before one-time durable provisioning begins.
    let worker = VerifiedWorker::new(&options.worker, &options.worker_sha256)
        .map_err(|_| "worker verification failed")?;
    let digest =
        ContentDigest::parse(options.worker_sha256).map_err(|_| "invalid worker digest")?;
    let release = vp_product_core_adapter::inspect_build()
        .map_err(|_| "compiled runtime identity unavailable")?
        .build
        .release;
    let key = master_key(&input.master_key_hex)?;
    input.master_key_hex.zeroize();
    let namespace =
        Namespace::new(&options.vault_namespace).map_err(|_| "invalid vault namespace")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    // Authentication/open errors NEVER fall back to initialization or replacement.
    let vault = if options.initialize_vault {
        DurableSecretStore::initialize(
            &options.vault_root,
            namespace,
            key,
            Limits::default(),
            deadline,
        )
    } else {
        DurableSecretStore::open(&options.vault_root, namespace, key, deadline)
    }
    .map_err(|_| "vault authentication/provisioning refused")?;
    for credential in &mut input.credentials {
        vault
            .put(
                &credential.reference,
                SecretKind::Credential,
                credential.version,
                SecretBytes::new(std::mem::take(&mut *credential.value).into_bytes()),
                deadline,
            )
            .map_err(|_| {
                "immutable credential provisioning incomplete; inspect durable vault before retry"
            })?;
    }
    drop(input);
    let vault = Arc::new(vault);
    let probe = LoopbackProbe::bind(options.probe_bind, vault.clone())
        .map_err(|_| "approved loopback probe unavailable")?;
    let secret_manager = Arc::new(crate::secret_manager::VaultSecretManager::new(
        vault.clone(),
    ));
    let executor = ManagedExecutor::open(
        &options.root,
        release,
        worker,
        digest,
        vault,
        probe,
        Arc::new(SystemClock),
    )
    .map(Arc::new)
    .map_err(|_| "runtime durable state or exact release identity refused")?;
    Ok(ManagedComposition {
        executor,
        secret_manager,
    })
}
fn master_key(hex: &str) -> Result<MasterKey, &'static str> {
    if hex.len() != 64 {
        return Err("external vault master key must be 32 bytes");
    }
    let mut key = zeroize::Zeroizing::new(Vec::with_capacity(32));
    for pair in hex.as_bytes().chunks_exact(2) {
        let digit = |b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        key.push(
            digit(pair[0]).ok_or("invalid external vault master key")? << 4
                | digit(pair[1]).ok_or("invalid external vault master key")?,
        );
    }
    MasterKey::new(SecretBytes::new(std::mem::take(&mut *key)))
        .map_err(|_| "invalid external vault master key")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn explicit_master_key_shape_and_redacted_debug() {
        assert!(master_key("").is_err());
        assert!(master_key(&"g".repeat(64)).is_err());
        let key = master_key(&"a".repeat(64)).unwrap();
        assert_eq!(format!("{key:?}"), "MasterKey([REDACTED])");
    }
    #[test]
    fn unknown_bootstrap_vault_fields_fail_closed() {
        assert!(serde_json::from_str::<VaultInput>(
            r#"{"masterKeyHex":"opaque","credentials":[],"fallbackGenerate":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<VaultInput>(r#"{"masterKeyHex":"opaque","credentials":[{"reference":"secret:one","version":1,"value":"synthetic","rotateInPlace":true}]}"#).is_err());
    }
}
