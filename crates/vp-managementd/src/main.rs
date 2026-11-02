//! Linux loopback composition root. No installer, route, firewall or proxy actions.
#![forbid(unsafe_code)]
mod probes;
mod runtime;
mod secret_generation;
mod secret_manager;
mod web;
use serde::Deserialize;
use std::{io::Read, net::SocketAddr, path::PathBuf, sync::Arc};
use vp_product_api::{ApiState, BootstrapCredential, OperationWorker, SecurityPolicy};
use vp_product_control::{
    Clock, ControlService, ControlStore, RuntimeExecutor, SystemClock, SystemExecutor,
    UnavailableRuntime, UnavailableSystem,
};
use vp_product_domain::SecretBytes;
use vp_product_runtime_executor::NoHostChanges;
use zeroize::Zeroizing;

/// One bounded inherited stdin JSON. Never argv/env/public setup or an automatically
/// generated/persisted administrator or vault key. Legacy management-only input remains valid.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BootstrapInput {
    username: String,
    #[serde(deserialize_with = "secret_input")]
    token: Zeroizing<String>,
    vault: Option<runtime::VaultInput>,
}
// Wrap secrets at the field boundary, so even partially rejected JSON structs
// wipe values already decoded before an unknown/missing-field error.
fn secret_input<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}
struct Options {
    root: PathBuf,
    bind: SocketAddr,
    origin: String,
    web_root: Option<PathBuf>,
    runtime: Option<runtime::RuntimeOptions>,
    publication_base: Option<vp_product_api::TrustedPublicationBase>,
}
fn options() -> Result<Options, &'static str> {
    options_from(std::env::args().skip(1))
}
fn options_from(mut args: impl Iterator<Item = String>) -> Result<Options, &'static str> {
    let mut values = std::collections::BTreeMap::new();
    while let Some(flag) = args.next() {
        if ![
            "--state-root",
            "--bind",
            "--origin",
            "--web-root",
            "--runtime-profile",
            "--runtime-root",
            "--worker",
            "--worker-sha256",
            "--vault-root",
            "--vault-namespace",
            "--vault-action",
            "--probe-bind",
            "--subscription-public-base",
            "--subscription-network-profile",
        ]
        .contains(&flag.as_str())
        {
            return Err("unsupported option");
        }
        let value = args.next().ok_or("missing option value")?;
        if values.insert(flag, value).is_some() {
            return Err("repeated option");
        }
    }
    let root = PathBuf::from(
        values
            .remove("--state-root")
            .ok_or("explicit private --state-root required")?,
    );
    if !root.is_absolute() {
        return Err("absolute private state root required");
    }
    let bind: SocketAddr = values
        .remove("--bind")
        .ok_or("explicit --bind required")?
        .parse()
        .map_err(|_| "invalid bind address")?;
    if !bind.ip().is_loopback() || bind.port() == 0 {
        return Err("only explicit nonzero loopback binding is permitted");
    }
    let origin = values
        .remove("--origin")
        .ok_or("explicit --origin required")?;
    let web_root = values.remove("--web-root").map(PathBuf::from);
    let publication_base = match (
        values.remove("--subscription-public-base"),
        values.remove("--subscription-network-profile"),
    ) {
        (None, None) => None,
        (Some(base), Some(profile)) => {
            let policy = match profile.as_str() {
                "https" => vp_product_api::PublicationNetworkPolicy::Https,
                "development-loopback" => {
                    vp_product_api::PublicationNetworkPolicy::DevelopmentLoopback
                }
                _ => return Err("unsupported subscription network profile"),
            };
            Some(
                vp_product_api::TrustedPublicationBase::new(&base, policy, &origin)
                    .map_err(|_| "invalid explicitly trusted subscription base")?,
            )
        }
        _ => return Err("subscription base and network profile must be explicit together"),
    };
    let runtime = match values.remove("--runtime-profile") {
        None => None,
        Some(profile) if profile == "loopback-vless-v1" => {
            let mut required = |key| {
                values
                    .remove(key)
                    .ok_or("runtime profile requires every explicit runtime/vault/probe option")
            };
            let runtime_root = PathBuf::from(required("--runtime-root")?);
            let vault_root = PathBuf::from(required("--vault-root")?);
            if runtime_root == root || vault_root == root {
                return Err("control/runtime/vault roots must be independent");
            }
            Some(runtime::RuntimeOptions {
                root: runtime_root,
                vault_root,
                worker: PathBuf::from(required("--worker")?),
                worker_sha256: required("--worker-sha256")?,
                vault_namespace: required("--vault-namespace")?,
                initialize_vault: match required("--vault-action")?.as_str() {
                    "initialize" => true,
                    "open" => false,
                    _ => return Err("vault action must be explicit initialize or open"),
                },
                probe_bind: required("--probe-bind")?
                    .parse()
                    .map_err(|_| "invalid approved probe address")?,
            })
        }
        Some(_) => return Err("unsupported runtime profile"),
    };
    if !values.is_empty() {
        return Err("runtime options require explicit supported runtime profile");
    }
    Ok(Options {
        root,
        bind,
        origin,
        web_root,
        runtime,
        publication_base,
    })
}
fn migration_root(args: Vec<String>) -> Result<Option<PathBuf>, &'static str> {
    if !args.iter().any(|a| a == "--state-upgrade") {
        return Ok(None);
    }
    if args.len() != 4 {
        return Err("offline migration accepts only state-root and state-upgrade");
    }
    let mut root = None;
    let mut action = None;
    for pair in args.chunks_exact(2) {
        match pair[0].as_str() {
            "--state-root" if root.is_none() => root = Some(PathBuf::from(&pair[1])),
            "--state-upgrade" if action.is_none() => action = Some(pair[1].as_str()),
            _ => return Err("invalid offline migration options"),
        }
    }
    let root = root.ok_or("offline migration requires explicit state-root")?;
    if !root.is_absolute() || action != Some("v1-to-v2") {
        return Err("unsupported explicit control payload migration");
    }
    Ok(Some(root))
}
async fn run() -> Result<(), &'static str> {
    if !cfg!(target_os = "linux") {
        return Err("this composition root supports Linux only");
    }
    // Offline maintenance only: no HTTP, vault access, worker, credential input
    // or automatic restore. Caller must first stop/wait the old service.
    if let Some(root) = migration_root(std::env::args().skip(1).collect())? {
        let at = SystemClock
            .now_ms()
            .map_err(|_| "migration clock unavailable")?;
        let receipt = tokio::task::spawn_blocking(move || {
            vp_product_storage::SqliteStore::migrate_v1_to_v2(root, at)
        })
        .await
        .map_err(|_| "migration task failed")?
        .map_err(|_| "explicit control payload migration refused; inspect durable outcome")?;
        let encoded =
            serde_json::to_string(&receipt).map_err(|_| "migration receipt unavailable")?;
        println!("{encoded}");
        return Ok(());
    }
    let options = options()?;
    let policy =
        SecurityPolicy::new(&options.origin).map_err(|_| "invalid canonical web origin")?;
    let web = options
        .web_root
        .map(|path| web::WebRoot::open(path, &options.origin))
        .transpose()?;
    let mut bytes = Zeroizing::new(Vec::new());
    let limit = if options.runtime.is_some() {
        64 * 1024
    } else {
        4096
    };
    std::io::stdin()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "bootstrap input unavailable")?;
    if bytes.len() > limit as usize {
        return Err("bootstrap input too large");
    }
    let mut bootstrap: BootstrapInput =
        serde_json::from_slice(&bytes).map_err(|_| "invalid bootstrap input")?;
    let credential = BootstrapCredential::new(
        &bootstrap.username,
        SecretBytes::new(std::mem::take(&mut *bootstrap.token).into_bytes()),
    )
    .map_err(|_| "invalid external bootstrap credential")?;
    drop(bytes);
    let vault_input = bootstrap.vault.take();
    drop(bootstrap);
    if options.runtime.is_some() != vault_input.is_some() {
        return Err("runtime profile and explicit external vault input must be supplied together");
    }
    // Bind before starting/reconciling any data-plane generation, but do not serve
    // requests until every startup authentication/recovery boundary succeeds.
    let listener = tokio::net::TcpListener::bind(options.bind)
        .await
        .map_err(|_| "loopback bind failed")?;
    let storage = Arc::new(
        vp_product_storage::SqliteStore::open(&options.root)
            .map_err(|_| "private control storage unavailable")?,
    );
    let managed = match (options.runtime, vault_input) {
        (Some(options), Some(input)) => Some(
            tokio::task::spawn_blocking(move || runtime::compose(options, input))
                .await
                .map_err(|_| "runtime composition task failed")??,
        ),
        (None, None) => None,
        _ => return Err("runtime bootstrap mismatch"),
    };
    let runtime: Arc<dyn RuntimeExecutor> = managed
        .as_ref()
        .map(|r| r.executor.clone() as Arc<dyn RuntimeExecutor>)
        .unwrap_or_else(|| Arc::new(UnavailableRuntime));
    let system: Arc<dyn SystemExecutor> = if managed.is_some() {
        Arc::new(NoHostChanges)
    } else {
        Arc::new(UnavailableSystem)
    };
    let mut control = ControlService::new(storage.clone(), runtime, system, Arc::new(SystemClock));
    if let Some(managed) = &managed {
        control = control.with_secret_manager(managed.secret_manager.clone());
    }
    let control = Arc::new(control);
    let recovering = control.clone();
    tokio::task::spawn_blocking(move || recovering.recover())
        .await
        .map_err(|_| "startup recovery task failed")?
        .map_err(|_| "startup recovery requires intervention")?;
    let durable = storage
        .read()
        .map_err(|_| "recovered control state unavailable")?;
    if durable.needs_recovery() {
        return Err("unfinished recovery blocks serving and runtime restart");
    }
    if let (Some(runtime), Some(active)) = (
        managed.as_ref().map(|m| m.executor.clone()),
        durable.active().cloned(),
    ) {
        tokio::task::spawn_blocking(move || runtime.reconcile_committed(&active))
            .await
            .map_err(|_| "committed runtime reconciliation task failed")?
            .map_err(|_| "committed runtime reconciliation failed; not serving stale health")?;
    }
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "termination handler unavailable")?;
    let (worker, handle) = OperationWorker::start(control.clone());
    let state = match ApiState::new_with_publication_base(
        control,
        worker.clone(),
        credential,
        policy,
        options.publication_base,
    ) {
        Ok(state) => state,
        Err(_) => {
            worker.stop();
            let _ = handle.await;
            return Err("API initialization failed");
        }
    };
    let mut router = vp_product_api::router(state);
    if let Some(root) = web {
        router = router.fallback(move |request: axum::extract::Request| {
            let root = root.clone();
            async move { web::serve(root, request).await }
        });
    }
    let shutdown_worker = worker.clone();
    let serving = axum::serve(listener, router).with_graceful_shutdown(async move {
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {}, _ = shutdown_worker.stopped() => {} }
        shutdown_worker.stop();
    }).await;
    worker.stop();
    handle
        .await
        .map_err(|_| "worker termination requires recovery")?;
    // Shared control has finished/compensated its current operation before the
    // exact owned runtime is stopped. Never abandon a half-applied transaction.
    if let Some(runtime) = managed {
        tokio::task::spawn_blocking(move || runtime.executor.shutdown())
            .await
            .map_err(|_| "runtime shutdown task failed")?
            .map_err(|_| "runtime shutdown requires recovery")?;
    }
    if worker.failed() {
        return Err("operation worker stopped; restart recovery required");
    }
    serving.map_err(|_| "HTTP service stopped with an error")
}
#[tokio::main]
async fn main() {
    if let Err(reason) = run().await {
        eprintln!("vp-managementd: {reason}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn parse(values: &[&str]) -> Result<Options, &'static str> {
        options_from(values.iter().map(|s| (*s).to_owned()))
    }
    #[test]
    fn no_defaults_public_bind_or_implicit_runtime_profile() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[
            "--state-root",
            "/private/control",
            "--bind",
            "0.0.0.0:18080",
            "--origin",
            "http://localhost:18080"
        ])
        .is_err());
        assert!(parse(&[
            "--state-root",
            "/private/control",
            "--bind",
            "127.0.0.1:18080",
            "--origin",
            "http://localhost:18080",
            "--worker",
            "/private/worker"
        ])
        .is_err());
        assert!(parse(&[
            "--state-root",
            "/private/control",
            "--bind",
            "127.0.0.1:18080",
            "--origin",
            "http://localhost:18080",
            "--runtime-profile",
            "automatic"
        ])
        .is_err());
        assert!(parse(&[
            "--state-root",
            "/private/control",
            "--bind",
            "127.0.0.1:18080",
            "--origin",
            "http://localhost:18080",
            "--runtime-profile",
            "loopback-vless-v1"
        ])
        .is_err());
    }
    #[test]
    fn offline_migration_never_accepts_runtime_or_credential_flags() {
        let args = |values: &[&str]| values.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            migration_root(args(&[
                "--state-root",
                "/private/control",
                "--state-upgrade",
                "v1-to-v2"
            ]))
            .unwrap(),
            Some(PathBuf::from("/private/control"))
        );
        assert_eq!(
            migration_root(args(&["--state-root", "/private/control"])).unwrap(),
            None
        );
        for values in [
            vec!["--state-root", "relative", "--state-upgrade", "v1-to-v2"],
            vec![
                "--state-root",
                "/private/control",
                "--state-upgrade",
                "v2-to-v1",
            ],
            vec![
                "--state-root",
                "/private/control",
                "--state-upgrade",
                "v1-to-v2",
                "--bind",
                "127.0.0.1:8080",
            ],
            vec!["--state-upgrade", "v1-to-v2", "--state-upgrade", "v1-to-v2"],
        ] {
            assert!(migration_root(args(&values)).is_err());
        }
    }
    #[test]
    fn subscription_base_requires_explicit_matching_network_policy() {
        let base = [
            "--state-root",
            "/private/control",
            "--bind",
            "127.0.0.1:8080",
            "--origin",
            "http://127.0.0.1:8080",
        ];
        let mut flags = base.to_vec();
        flags.extend(["--subscription-public-base", "http://127.0.0.1:8080"]);
        assert!(parse(&flags).is_err());
        flags.extend(["--subscription-network-profile", "development-loopback"]);
        assert!(parse(&flags).is_ok());
        *flags.last_mut().unwrap() = "https";
        assert!(parse(&flags).is_err());
        let mut flags = base.to_vec();
        flags.extend([
            "--subscription-public-base",
            "https://subscription.example.invalid",
            "--subscription-network-profile",
            "https",
        ]);
        assert!(parse(&flags).is_ok());
    }
    #[test]
    fn legacy_stdin_and_strict_sensitive_fields() {
        assert!(serde_json::from_str::<BootstrapInput>(
            r#"{"username":"test-only","token":"synthetic"}"#
        )
        .is_ok());
        for input in [
            r#"{"username":"test-only","token":"synthetic","token":"duplicate"}"#,
            r#"{"username":"test-only","token":"synthetic","generateKey":true}"#,
        ] {
            assert!(serde_json::from_str::<BootstrapInput>(input).is_err());
        }
    }
}
