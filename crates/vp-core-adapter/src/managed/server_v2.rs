//! Additive typed factory for server recipe v2. The separate private v2 worker
//! uses its no-bind Prepared stage; live v1 stdio framing stays unchanged.
//! Only this product crate depends on upstream protocol/transport constructors.
use super::{BoundListener, Failure, StopReport, WorkerSnapshot};
#[path = "credential_payloads_v2.rs"]
mod credential_payloads;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use vp_core::{
    task_scope::{DestinationPolicy, TaskScope},
    Inbound, InboundCtx,
};
use vp_product_compiler::server_v2::*;
use vp_product_domain::{CertificateId, SecretBytes, SecretRef};
use vp_transport::server::{
    HttpRoute, ServerLimits, ServerNetwork, ServerTlsIdentity, ServerTransport,
};
use zeroize::Zeroizing;

/// Deliberately NO Serialize/Deserialize/Clone. A protected resolver builds this
/// immediately before start. New stdio v2 encoding requires an independently
/// reviewed bounded, zeroizing frame; it must never serialize this to disk.
#[derive(Default)]
pub struct ServerInputsV2 {
    pub credentials: BTreeMap<SecretRef, SecretBytes>,
    pub certificate_chains: BTreeMap<CertificateId, SecretBytes>,
    pub private_keys: BTreeMap<SecretRef, SecretBytes>,
}
impl std::fmt::Debug for ServerInputsV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerInputsV2([REDACTED])")
    }
}
fn invalid<T>(_: T) -> Failure {
    Failure::InvalidConfig
}
fn text(secret: &SecretBytes) -> Result<&str, Failure> {
    let value = std::str::from_utf8(secret.expose()).map_err(invalid)?;
    if value.is_empty() || value.len() > 4096 {
        return Err(Failure::InvalidConfig);
    }
    Ok(value)
}
fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, b)| {
            if [8, 13, 18, 23].contains(&index) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}
fn validate_psk(value: &str, key_bytes: u8) -> bool {
    // Canonical STANDARD Base64 only: no whitespace, URL-safe alphabet, truncated
    // padding or colon-delimited multiuser identity chain. The core decodes too.
    let (len, padding) = match key_bytes {
        16 => (24, 2),
        32 => (44, 1),
        _ => return false,
    };
    if value.len() != len || !value.as_bytes()[len - padding..].iter().all(|b| *b == b'=') {
        return false;
    }
    if !value.as_bytes()[..len - padding]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b))
    {
        return false;
    }
    let last = value.as_bytes()[len - padding - 1];
    let sextet = match last {
        b'A'..=b'Z' => last - b'A',
        b'a'..=b'z' => last - b'a' + 26,
        b'0'..=b'9' => last - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return false,
    };
    if padding == 2 {
        sextet & 15 == 0
    } else {
        sextet & 3 == 0
    }
}
fn expected_inputs(recipe: &ServerRecipeV2, inputs: &ServerInputsV2) -> Result<(), Failure> {
    let mut credentials = BTreeSet::new();
    let mut certificates = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for listener in &recipe.listeners {
        for user in &listener.credentials {
            credentials.insert(&user.reference);
        }
        if let ServerSecurityV2::Tls {
            certificate_ref,
            private_key_ref,
            ..
        } = &listener.security
        {
            certificates.insert(certificate_ref);
            keys.insert(private_key_ref);
        }
    }
    if inputs.credentials.keys().collect::<BTreeSet<_>>() != credentials
        || inputs.certificate_chains.keys().collect::<BTreeSet<_>>() != certificates
        || inputs.private_keys.keys().collect::<BTreeSet<_>>() != keys
    {
        return Err(Failure::InvalidConfig);
    }
    let total = inputs
        .credentials
        .values()
        .chain(inputs.certificate_chains.values())
        .chain(inputs.private_keys.values())
        .try_fold(0_usize, |total, bytes| {
            total.checked_add(bytes.expose().len())
        })
        .ok_or(Failure::InvalidConfig)?;
    if total > 2 * 1024 * 1024 {
        return Err(Failure::InvalidConfig);
    }
    for cert in inputs.certificate_chains.values() {
        if cert.expose().is_empty() || cert.expose().len() > 128 * 1024 {
            return Err(Failure::InvalidConfig);
        }
    }
    for key in inputs.private_keys.values() {
        if key.expose().is_empty() || key.expose().len() > 65536 {
            return Err(Failure::InvalidConfig);
        }
    }
    Ok(())
}
/// Constructs every listener before binding any. Missing inputs, wrong secret
/// encoding, mismatched cert/key and unsupported combinations fail first. Calls
/// real typed vp_core protocol constructors, NOT ignored ListenerCfg YAML fields.
pub fn prepare(
    recipe: &ServerRecipeV2,
    inputs: &ServerInputsV2,
) -> Result<Vec<Arc<dyn Inbound>>, Failure> {
    let release = crate::inspect_build().map_err(invalid)?.build.release;
    let extended = matches!(recipe.profile, ServerProfileV2::LoopbackExtendedCoreUncertified | ServerProfileV2::PublicExperimentalUncertified);
    let compiler = match recipe.profile {
        ServerProfileV2::LoopbackDevelopmentUncertified => ServerCompilerV2::for_loopback_development(release),
        ServerProfileV2::LoopbackExtendedCoreUncertified => ServerCompilerV2::for_loopback_server_extensions(release),
        ServerProfileV2::PublicExperimentalUncertified => {
            #[cfg(feature = "experimental-public")]
            { ServerCompilerV2::for_public_experiment(release, recipe.public_targets.clone().ok_or(Failure::InvalidConfig)?) }
            #[cfg(not(feature = "experimental-public"))]
            { return Err(Failure::InvalidConfig); }
        }
    }.map_err(invalid)?;
    compiler.verify_recipe(recipe).map_err(invalid)?;
    expected_inputs(recipe, inputs)?;
    let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();
    for listener in &recipe.listeners {
        let bind = listener.bind.address.to_string();
        let tag = listener.id.as_str();
        let port = listener.bind.port;
        let mut users = Zeroizing::new(Vec::<String>::new());
        let mut tuples = Zeroizing::new(Vec::<(String, String)>::new());
        let mut distinct = BTreeSet::new();
        for user in &listener.credentials {
            let secret = inputs
                .credentials
                .get(&user.reference)
                .ok_or(Failure::InvalidConfig)?;
            let tuple = match user.encoding {
                CredentialEncodingV2::SocksUsernamePasswordJsonV1 {} => {
                    let tuple = credential_payloads::decode_socks(secret).map_err(invalid)?;
                    Some((
                        tuple.username.expose().to_owned(),
                        tuple.password.expose().to_owned(),
                    ))
                }
                CredentialEncodingV2::TuicUuidPasswordJsonV1 {} => {
                    let tuple = credential_payloads::decode_tuic(secret).map_err(invalid)?;
                    Some((
                        tuple.uuid.expose().to_owned(),
                        tuple.password.expose().to_owned(),
                    ))
                }
                _ => None,
            };
            if let Some(tuple) = tuple {
                // Tuples with repeated identity are ambiguous even if passwords differ.
                let tuple = Zeroizing::new(tuple);
                let protected: &(String, String) = &tuple;
                if tuples.iter().any(|existing| existing.0 == protected.0) {
                    return Err(Failure::InvalidConfig);
                }
                tuples.push((protected.0.clone(), protected.1.clone()));
                continue;
            }
            let value = text(
                inputs
                    .credentials
                    .get(&user.reference)
                    .ok_or(Failure::InvalidConfig)?,
            )?;
            let valid = match user.encoding {
                CredentialEncodingV2::SocksUsernamePasswordJsonV1 {}
                | CredentialEncodingV2::TuicUuidPasswordJsonV1 {} => {
                    return Err(Failure::InvalidConfig)
                }
                CredentialEncodingV2::CanonicalUuidTextV1 {} => canonical_uuid(value),
                CredentialEncodingV2::PasswordUtf8V1 {}
                | CredentialEncodingV2::ShadowsocksLegacyPasswordUtf8V1 {} => true,
                CredentialEncodingV2::Shadowsocks2022PskBase64V1 { key_bytes } => {
                    validate_psk(value, key_bytes)
                }
            };
            if !valid || !distinct.insert(value) {
                return Err(Failure::InvalidConfig);
            }
            users.push(value.to_owned());
        }
        let identity = match &listener.security {
            ServerSecurityV2::None {} => None,
            ServerSecurityV2::Tls {
                certificate_ref,
                private_key_ref,
                alpn,
            } => {
                let cert = inputs
                    .certificate_chains
                    .get(certificate_ref)
                    .ok_or(Failure::InvalidConfig)?
                    .expose();
                let key = inputs
                    .private_keys
                    .get(private_key_ref)
                    .ok_or(Failure::InvalidConfig)?
                    .expose();
                Some(
                    if extended {
                        ServerTlsIdentity::from_pem_with_alpn(
                            cert,
                            key,
                            alpn.iter().map(|p| p.as_bytes().to_vec()).collect(),
                        )
                    } else {
                        ServerTlsIdentity::from_pem(cert, key)
                    }
                    .map_err(invalid)?,
                )
            }
        };
        if matches!(listener.protocol, ServerProtocolV2::Socks5Authenticated {}) {
            inbounds.push(Arc::new(
                vp_protocol::inbound::Socks5Inbound::new_authenticated(bind, port, tag, &tuples)
                    .map_err(invalid)?,
            ));
            continue;
        }
        if let ServerProtocolV2::Tuic {
            congestion_control,
            udp_relay_mode,
        } = listener.protocol
        {
            let ServerSecurityV2::Tls {
                certificate_ref,
                private_key_ref,
                alpn,
            } = &listener.security
            else {
                return Err(Failure::InvalidConfig);
            };
            use vp_product_domain::{CongestionControl as C, TuicUdpRelayMode as M};
            use vp_protocol::tuic::{
                TuicCongestionControl as CoreC, TuicInbound, TuicServerOptions,
                TuicUdpRelayMode as CoreM,
            };
            let options = TuicServerOptions {
                congestion_control: match congestion_control {
                    C::Cubic => CoreC::Cubic,
                    C::NewReno => CoreC::NewReno,
                    C::Bbr => CoreC::Bbr,
                },
                udp_relay_mode: match udp_relay_mode {
                    M::Native => CoreM::Native,
                    M::Quic => CoreM::Quic,
                },
                alpn: alpn.iter().map(|p| p.as_bytes().to_vec()).collect(),
            };
            inbounds.push(Arc::new(
                TuicInbound::new_with_options(
                    &bind,
                    port,
                    tag,
                    std::mem::take(&mut *tuples),
                    inputs.certificate_chains[certificate_ref].expose().to_vec(),
                    inputs.private_keys[private_key_ref].expose().to_vec(),
                    options,
                )
                .map_err(invalid)?,
            ));
            continue;
        }
        if let ServerProtocolV2::Shadowsocks { method } = listener.protocol {
            let password = users.first().ok_or(Failure::InvalidConfig)?;
            inbounds.push(Arc::new(
                vp_protocol::ss::SsInbound::new(&bind, port, tag, cipher_name(method), password)
                    .map_err(invalid)?,
            ));
            continue;
        }
        if matches!(listener.protocol, ServerProtocolV2::Hysteria2 {}) {
            let ServerSecurityV2::Tls {
                certificate_ref,
                private_key_ref,
                ..
            } = &listener.security
            else {
                return Err(Failure::InvalidConfig);
            };
            let password = users.first().ok_or(Failure::InvalidConfig)?;
            // The identity above already verified bounded PEM, leaf/key match
            // and one private key before this constructor can bind UDP.
            inbounds.push(Arc::new(vp_protocol::hysteria2::Hysteria2Inbound::new(
                &bind,
                port,
                tag,
                password,
                inputs.certificate_chains[certificate_ref].expose().to_vec(),
                inputs.private_keys[private_key_ref].expose().to_vec(),
            )));
            continue;
        }
        let network = match &listener.transport {
            ServerTransportV2::Tcp {} => ServerNetwork::Tcp,
            ServerTransportV2::WebSocket { decoded_path, host } => ServerNetwork::WebSocket(
                HttpRoute::new(decoded_path, host.iter().cloned().collect()).map_err(invalid)?,
            ),
            ServerTransportV2::HttpUpgrade { decoded_path, host } => ServerNetwork::HttpUpgrade(
                HttpRoute::new(decoded_path, vec![host.clone()]).map_err(invalid)?,
            ),
            ServerTransportV2::Http2 {
                decoded_path_prefix,
                host,
            } => ServerNetwork::Http2(
                HttpRoute::new(decoded_path_prefix, vec![host.clone()]).map_err(invalid)?,
            ),
            ServerTransportV2::Quic {} => return Err(Failure::Unsupported),
        };
        let transport = if extended {
            ServerTransport::new_exact_alpn(network, identity, ServerLimits::default())
        } else {
            ServerTransport::new(network, identity, ServerLimits::default())
        }
        .map_err(invalid)?;
        use vp_protocol::stream_inbound::{StreamProtocol, TransportInbound};
        let protocol = match listener.protocol {
            ServerProtocolV2::Vless {} => StreamProtocol::Vless(Arc::new(
                vp_protocol::vless::VlessInbound::new(&bind, port, tag, &users).map_err(invalid)?,
            )),
            ServerProtocolV2::Vmess {} => StreamProtocol::Vmess(Arc::new(
                vp_protocol::vmess::VmessInbound::new(&bind, port, tag, &users).map_err(invalid)?,
            )),
            ServerProtocolV2::Trojan {} => StreamProtocol::Trojan(Arc::new(
                vp_protocol::trojan::TrojanInbound::new(&bind, port, tag, &users)
                    .map_err(invalid)?,
            )),
            ServerProtocolV2::AnyTls {} => StreamProtocol::Anytls(Arc::new(
                vp_protocol::anytls::AnytlsInbound::new(&bind, port, tag, &users)
                    .map_err(invalid)?,
            )),
            _ => return Err(Failure::InvalidConfig),
        };
        inbounds.push(Arc::new(
            TransportInbound::new(&bind, port, tag, transport, protocol, 256).map_err(invalid)?,
        ));
    }
    Ok(inbounds)
}
fn cipher_name(method: vp_product_domain::ShadowsocksCipher) -> &'static str {
    use vp_product_domain::ShadowsocksCipher::*;
    match method {
        Aes128Gcm => "aes-128-gcm",
        Aes256Gcm => "aes-256-gcm",
        Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        Xchacha20IetfPoly1305 => "xchacha20-ietf-poly1305",
        Blake3Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
        Blake3Aes256Gcm2022 => "2022-blake3-aes-256-gcm",
        Blake3Chacha20Poly13052022 => "2022-blake3-chacha20-poly1305",
    }
}

/// A worker-local, fully material-validated candidate. Constructed before any
/// listener bind; consumed once by activation. Never serialized or cloned.
pub struct PreparedServerV2 {
    inbounds: Vec<Arc<dyn Inbound>>,
    expected_listener_tasks: BTreeMap<String, Vec<String>>,
    #[cfg(feature = "experimental-public")]
    public_targets: Option<Arc<vp_core::experimental_exact_targets::ExactTargets>>,
}
impl PreparedServerV2 {
    pub fn prepare(recipe: &ServerRecipeV2, inputs: ServerInputsV2) -> Result<Self, Failure> {
        let inbounds = prepare(recipe, &inputs)?;
        // Raw resolver material drops/zeroizes here. Core protocol/TLS state is
        // retained in this process only, and is destroyed on discard/process exit.
        #[cfg(feature = "experimental-public")]
        let public_targets = if recipe.profile == ServerProfileV2::PublicExperimentalUncertified {
            Some(Arc::new(vp_core::experimental_exact_targets::ExactTargets::new(recipe.public_targets.clone().ok_or(Failure::InvalidConfig)?).ok_or(Failure::InvalidConfig)?))
        } else if cfg!(feature = "local-probe-test") {
            // Explicit debug-only loopback fixture; never a released profile.
            Some(Arc::new(vp_core::experimental_exact_targets::ExactTargets::new(["8.8.8.8:443".parse().map_err(invalid)?]).ok_or(Failure::InvalidConfig)?))
        } else { None };
        let expected_listener_tasks = recipe.listeners.iter().map(|listener| {
            let tag = listener.id.as_str().to_owned();
            let tasks = if matches!(listener.protocol, ServerProtocolV2::Shadowsocks { .. }) {
                let mut tasks = vec![format!("{tag}:tcp")];
                if recipe.profile != ServerProfileV2::PublicExperimentalUncertified && !cfg!(feature = "local-probe-test") { tasks.push(format!("{tag}:udp")); }
                tasks
            } else { vec![tag.clone()] };
            (tag, tasks)
        }).collect();
        Ok(Self { inbounds, expected_listener_tasks, #[cfg(feature = "experimental-public")] public_targets })
    }
}

struct StartGuard {
    scope: Arc<TaskScope>,
    armed: bool,
}
impl Drop for StartGuard {
    fn drop(&mut self) {
        if self.armed {
            self.scope.cancel_all();
        }
    }
}
fn listener_tasks_live(expected: &BTreeMap<String, Vec<String>>, observed: &[String], tag: &str) -> bool {
    expected.get(tag).is_some_and(|tasks| !tasks.is_empty() && tasks.iter().all(|task| observed.contains(task)))
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    #[test]
    fn shadowsocks_requires_each_expected_accept_loop() {
        let both = BTreeMap::from([("ss".to_owned(), vec!["ss:tcp".to_owned(), "ss:udp".to_owned()])]);
        assert!(!listener_tasks_live(&both, &["ss:tcp".into()], "ss"));
        assert!(!listener_tasks_live(&both, &["ss:udp".into()], "ss"));
        assert!(listener_tasks_live(&both, &["ss:tcp".into(), "ss:udp".into()], "ss"));
        let tcp_only = BTreeMap::from([("ss".to_owned(), vec!["ss:tcp".to_owned()])]);
        assert!(listener_tasks_live(&tcp_only, &["ss:tcp".into()], "ss"));
        assert!(!listener_tasks_live(&tcp_only, &["other:tcp".into()], "ss"));
        assert!(!listener_tasks_live(&tcp_only, &["ss:tcp".into()], "missing"));
    }
}

/// Managed in-process entrypoint intended for a separate v2 worker handler.
/// No v1 Request variant, frame limit or management composition is changed here.
pub struct ManagedServerV2 {
    _app: Arc<vp_app::App>,
    scope: Arc<TaskScope>,
    bound: Vec<BoundListener>,
    expected_listener_tasks: BTreeMap<String, Vec<String>>,
}
impl ManagedServerV2 {
    pub async fn start(
        recipe: &ServerRecipeV2,
        inputs: ServerInputsV2,
        timeout: Duration,
    ) -> Result<Self, Failure> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(Failure::InvalidConfig);
        }
        let prepared = PreparedServerV2::prepare(recipe, inputs)?;
        Self::start_prepared(prepared, timeout).await
    }
    pub async fn start_prepared(
        prepared: PreparedServerV2,
        timeout: Duration,
    ) -> Result<Self, Failure> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(Failure::InvalidConfig);
        }
        let inbounds = prepared.inbounds;
        let expected_listener_tasks = prepared.expected_listener_tasks;
        #[cfg(feature = "experimental-public")]
        let policy = if let Some(targets) = prepared.public_targets {
            // Install the immutable process floor before any app/listener startup.
            vp_core::task_scope::install_experimental_process_floor(targets.clone()).map_err(|_| Failure::InvalidConfig)?;
            DestinationPolicy::ExactPublic(targets)
        } else {
            // A worker that has ever installed a public floor is single-use.
            // Reject legacy activation rather than report readiness under a mismatched floor.
            if vp_core::task_scope::experimental_process_floor().is_some() { return Err(Failure::InvalidConfig); }
            DestinationPolicy::LoopbackIpOnly
        };
        #[cfg(not(feature = "experimental-public"))]
        let policy = DestinationPolicy::LoopbackIpOnly;
        let scope = TaskScope::with_destination_policy(policy);
        let mut guard = StartGuard {
            scope: scope.clone(),
            armed: true,
        };
        let operation = async {
            // No core listener YAML, TUN, providers, controller, filesystem
            // credentials or DNS hostname destinations enter this base app.
            let app = vp_app::App::start(
                r#"{"rules":["MATCH,DIRECT"]}"#,
                vp_config::Format::Json,
                &std::env::temp_dir(),
                false,
            )
            .await?;
            let context = InboundCtx {
                router: app.router.clone(),
                stats: app.stats.clone(),
                conns: app.conns.clone(),
            };
            let mut bound = Vec::new();
            for inbound in inbounds {
                let tag = inbound.tag().to_owned();
                let port = inbound.start(context.clone()).await?;
                bound.push(BoundListener {
                    tag,
                    port,
                    accept_loop_live: false,
                });
            }
            Ok::<_, vp_common::Error>((app, bound))
        };
        let outcome = scope.run(tokio::time::timeout(timeout, operation)).await;
        let (app, mut bound) = match outcome {
            Ok(Ok(value)) => value,
            failed => {
                let report = scope.shutdown(Duration::ZERO, Duration::from_secs(1)).await;
                if report.remaining_tasks != 0 {
                    return Err(Failure::CleanupFailed);
                }
                return Err(match failed {
                    Err(_) => Failure::Timeout,
                    Ok(Err(vp_common::Error::Io(e)))
                        if matches!(e.kind(), std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AddrNotAvailable) =>
                    {
                        Failure::BindFailed
                    }
                    _ => Failure::StartupFailed,
                });
            }
        };
        tokio::task::yield_now().await;
        let observed = scope.snapshot();
        if !observed.healthy()
            || bound.is_empty()
            || bound.iter().any(|l| !listener_tasks_live(&expected_listener_tasks, &observed.listeners, &l.tag))
        {
            let _ = scope.shutdown(Duration::ZERO, Duration::from_secs(1)).await;
            return Err(Failure::StartupFailed);
        }
        for listener in &mut bound {
            listener.accept_loop_live = true;
        }
        guard.armed = false;
        Ok(Self {
            _app: app,
            scope,
            bound,
            expected_listener_tasks,
        })
    }
    pub fn snapshot(&self, generation: u64) -> WorkerSnapshot {
        let observed = self.scope.snapshot();
        let mut listeners = self.bound.clone();
        for listener in &mut listeners {
            listener.accept_loop_live = listener_tasks_live(&self.expected_listener_tasks, &observed.listeners, &listener.tag);
        }
        WorkerSnapshot {
            generation,
            pid: std::process::id(),
            listeners_ready: observed.healthy() && listeners.iter().all(|l| l.accept_loop_live),
            listeners,
            active_tasks: observed.task_count(),
            task_panics: observed.panics,
            forwarding_verified: false,
            probe_ledger: if vp_core::task_scope::experimental_process_floor().is_some() {
                let (hashes, saturated) = vp_core::experimental_virtual_probe::snapshot();
                Some(super::ProbeLedgerObservation { version: 1, token_hashes: hashes.iter().map(|v| v.iter().map(|b| format!("{b:02x}")).collect()).collect(), saturated })
            } else { None },
        }
    }
    pub async fn shutdown(&self, generation: u64, drain: Duration) -> Result<StopReport, Failure> {
        if drain > Duration::from_secs(5) {
            return Err(Failure::InvalidConfig);
        }
        let report = self.scope.shutdown(drain, Duration::from_secs(1)).await;
        Ok(StopReport {
            generation,
            drained: report.drained,
            forced_tasks: report.forced_tasks,
            remaining_tasks: report.remaining_tasks,
            process_exited: false,
        })
    }
}
impl Drop for ManagedServerV2 {
    fn drop(&mut self) {
        self.scope.cancel_all();
    }
}

#[cfg(test)]
#[path = "server_v2_tests.rs"]
mod tests;
