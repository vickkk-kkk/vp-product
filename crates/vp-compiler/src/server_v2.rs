//! Independent v2 server composition recipe. Existing v1 artifacts remain v1;
//! they are neither rewritten nor implicitly accepted by this compiler.
//! Pure mapping is not runtime readiness or interoperability certification.
use crate::{error, CompileError, CompileFailure, Compiler};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::{IpAddr, SocketAddr}};
use vp_product_domain::*;

pub const SERVER_RECIPE_VERSION: u16 = 2;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerProfileV2 {
    LoopbackDevelopmentUncertified,
    /// Requires the reviewed authenticated SOCKS/TUIC/exact-ALPN core patchset.
    LoopbackExtendedCoreUncertified,
    /// Explicit, bounded public experiment; the runtime still rejects this profile.
    PublicExperimentalUncertified,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerRecipeV2 {
    pub recipe_version: u16,
    pub profile: ServerProfileV2,
    pub release: ReleaseIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_targets: Option<Vec<SocketAddr>>,
    pub source: ProductConfig,
    pub listeners: Vec<ServerListenerV2>,
}
impl std::fmt::Debug for ServerRecipeV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerRecipeV2")
            .field("recipe_version", &self.recipe_version)
            .field("listener_count", &self.listeners.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerListenerV2 {
    pub id: ListenerId,
    pub bind: BindAddress,
    pub protocol: ServerProtocolV2,
    pub transport: ServerTransportV2,
    pub security: ServerSecurityV2,
    pub credentials: Vec<ServerCredentialRefV2>,
    pub capability: Option<CapabilityKey>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerProtocolV2 {
    Vless {},
    Vmess {},
    Trojan {},
    AnyTls {},
    Shadowsocks {
        method: ShadowsocksCipher,
    },
    Hysteria2 {},
    Socks5Authenticated {},
    Tuic {
        #[serde(rename = "congestionControl")]
        congestion_control: CongestionControl,
        #[serde(rename = "udpRelayMode")]
        udp_relay_mode: TuicUdpRelayMode,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerTransportV2 {
    Tcp {},
    /// Configured URI path is decoded exactly once for the core route matcher;
    /// the original encoded representation remains in source for round-trip.
    WebSocket {
        #[serde(rename = "decodedPath")]
        decoded_path: String,
        host: Option<String>,
    },
    /// sing-box upgrade-to-raw-stream profile, not RFC6455/WebSocket framing.
    HttpUpgrade {
        #[serde(rename = "decodedPath")]
        decoded_path: String,
        host: String,
    },
    /// V2Ray HTTP/2 wire profile: the core uses a decoded path PREFIX, not gRPC.
    Http2 {
        #[serde(rename = "decodedPathPrefix")]
        decoded_path_prefix: String,
        host: String,
    },
    Quic {},
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerSecurityV2 {
    None {},
    Tls {
        #[serde(rename = "certificateRef")]
        certificate_ref: CertificateId,
        #[serde(rename = "privateKeyRef")]
        private_key_ref: SecretRef,
        /// Exact list, never overwritten by a generic TLS helper.
        alpn: Vec<String>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialEncodingV2 {
    SocksUsernamePasswordJsonV1 {},
    TuicUuidPasswordJsonV1 {},
    CanonicalUuidTextV1 {},
    PasswordUtf8V1 {},
    ShadowsocksLegacyPasswordUtf8V1 {},
    Shadowsocks2022PskBase64V1 {
        #[serde(rename = "keyBytes")]
        key_bytes: u8,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerCredentialRefV2 {
    pub user_id: UserId,
    pub reference: SecretRef,
    pub encoding: CredentialEncodingV2,
}
pub struct ServerCompilerV2 {
    pin: Compiler,
    profile: ServerProfileV2,
    public_targets: Option<Vec<SocketAddr>>,
}
impl ServerCompilerV2 {
    pub fn for_loopback_development(release: ReleaseIdentity) -> Result<Self, CompileError> {
        Ok(Self {
            pin: Compiler::for_loopback_development(release)?,
            profile: ServerProfileV2::LoopbackDevelopmentUncertified,
            public_targets: None,
        })
    }
    pub fn for_loopback_server_extensions(release: ReleaseIdentity) -> Result<Self, CompileError> {
        Ok(Self {
            pin: Compiler::for_loopback_development(release)?,
            profile: ServerProfileV2::LoopbackExtendedCoreUncertified,
            public_targets: None,
        })
    }
    /// Plans only; no runtime or network permission is granted here.
    pub fn for_public_experiment(release: ReleaseIdentity, targets: Vec<SocketAddr>) -> Result<Self, CompileError> {
        let unique: BTreeSet<_> = targets.iter().copied().collect();
        if targets.is_empty() || targets.len() > 64 || unique.len() != targets.len()
            || targets.iter().any(|target| target.port() == 0 || !public_target_allowed(target.ip())) {
            return Err(error(CompileFailure::InvalidConfiguration, "publicTargets"));
        }
        Ok(Self { pin: Compiler::for_loopback_development(release)?, profile: ServerProfileV2::PublicExperimentalUncertified, public_targets: Some(unique.into_iter().collect()) })
    }
    pub fn target(&self) -> &ReleaseIdentity {
        self.pin.target()
    }
    pub fn compile(
        &self,
        source: &ProductConfig,
        release: &ReleaseIdentity,
    ) -> Result<ServerRecipeV2, CompileError> {
        if release != self.pin.target() {
            return Err(error(CompileFailure::ReleaseMismatch, "release"));
        }
        source
            .validate()
            .map_err(|_| error(CompileFailure::InvalidConfiguration, "config"))?;
        if !source.nodes.is_empty() {
            return Err(error(CompileFailure::UnsupportedField, "nodes"));
        }
        if !source.subscriptions.is_empty() {
            return Err(error(CompileFailure::UnsupportedField, "subscriptions"));
        }
        if source.listeners.len() > 128 {
            return Err(error(CompileFailure::UnsupportedField, "listeners"));
        }
        let mut listeners = Vec::new();
        let mut binds = BTreeSet::new();
        for (index, listener) in source.listeners.iter().enumerate() {
            let field = |name: &str| format!("listeners[{index}].{name}");
            if self.profile == ServerProfileV2::PublicExperimentalUncertified {
                if !listener.bind.address.is_ipv4() || listener.bind.address.is_unspecified() || listener.bind.address.is_loopback()
                    || self.public_targets.as_ref().is_none_or(|targets| targets.iter().any(|target| target.ip() == listener.bind.address)) {
                    return Err(error(CompileFailure::InvalidConfiguration, field("bind.address")));
                }
            }
            if self.profile != ServerProfileV2::PublicExperimentalUncertified && !listener.bind.address.is_loopback() {
                return Err(error(
                    CompileFailure::LoopbackRequired,
                    field("bind.address"),
                ));
            }
            if ["mixed", "http", "socks5", "redir", "tproxy", "tun"].contains(&listener.id.as_str())
            {
                return Err(error(CompileFailure::UnsupportedField, field("id")));
            }
            let ServerProtocol::Proxy { protocol, users } = &listener.protocol else {
                return Err(error(
                    CompileFailure::UnsupportedProtocol,
                    field("protocol"),
                ));
            };
            let (protocol, encoding) = match protocol {
                Protocol::Vless { flow: None } => (
                    ServerProtocolV2::Vless {},
                    CredentialEncodingV2::CanonicalUuidTextV1 {},
                ),
                Protocol::Vless { .. } => {
                    return Err(error(
                        CompileFailure::UnsupportedField,
                        field("protocol.protocol.flow"),
                    ))
                }
                Protocol::Vmess {
                    cipher: VmessCipher::Auto,
                    alter_id: 0,
                } => (
                    ServerProtocolV2::Vmess {},
                    CredentialEncodingV2::CanonicalUuidTextV1 {},
                ),
                Protocol::Vmess { alter_id, .. } => {
                    return Err(error(
                        CompileFailure::UnsupportedField,
                        field(if *alter_id == 0 {
                            "protocol.protocol.cipher"
                        } else {
                            "protocol.protocol.alterId"
                        }),
                    ))
                }
                Protocol::Trojan {} => (
                    ServerProtocolV2::Trojan {},
                    CredentialEncodingV2::PasswordUtf8V1 {},
                ),
                Protocol::AnyTls {} => (
                    ServerProtocolV2::AnyTls {},
                    CredentialEncodingV2::PasswordUtf8V1 {},
                ),
                Protocol::Hysteria2 {
                    obfuscation_ref: None,
                } => (
                    ServerProtocolV2::Hysteria2 {},
                    CredentialEncodingV2::PasswordUtf8V1 {},
                ),
                Protocol::Hysteria2 { .. } => {
                    return Err(error(
                        CompileFailure::UnsupportedField,
                        field("protocol.protocol.obfuscationRef"),
                    ))
                }
                Protocol::Shadowsocks { method } => (
                    ServerProtocolV2::Shadowsocks { method: *method },
                    match method {
                        ShadowsocksCipher::Blake3Aes128Gcm2022 => {
                            CredentialEncodingV2::Shadowsocks2022PskBase64V1 { key_bytes: 16 }
                        }
                        ShadowsocksCipher::Blake3Aes256Gcm2022
                        | ShadowsocksCipher::Blake3Chacha20Poly13052022 => {
                            CredentialEncodingV2::Shadowsocks2022PskBase64V1 { key_bytes: 32 }
                        }
                        _ => CredentialEncodingV2::ShadowsocksLegacyPasswordUtf8V1 {},
                    },
                ),
                Protocol::Socks5 {}
                    if self.profile == ServerProfileV2::LoopbackExtendedCoreUncertified =>
                {
                    (
                        ServerProtocolV2::Socks5Authenticated {},
                        CredentialEncodingV2::SocksUsernamePasswordJsonV1 {},
                    )
                }
                Protocol::Tuic {
                    congestion_control,
                    udp_relay_mode,
                } if self.profile == ServerProfileV2::LoopbackExtendedCoreUncertified => (
                    ServerProtocolV2::Tuic {
                        congestion_control: *congestion_control,
                        udp_relay_mode: *udp_relay_mode,
                    },
                    CredentialEncodingV2::TuicUuidPasswordJsonV1 {},
                ),
                // No auth-SOCKS constructor exists in this pinned core; the
                // builtin SOCKS handler is anonymous. TUIC's constructor ignores
                // congestion/mode configuration; never fake these mappings.
                Protocol::Socks5 {} => {
                    return Err(error(
                        CompileFailure::UnsupportedProtocol,
                        field("protocol.protocol"),
                    ))
                }
                Protocol::Tuic { .. } => {
                    return Err(error(
                        CompileFailure::UnsupportedField,
                        field("protocol.protocol.congestionControl"),
                    ))
                }
            };
            let transport = match &listener.transport {
                Transport::Tcp {} => ServerTransportV2::Tcp {},
                Transport::Ws {
                    path,
                    host,
                    early_data,
                } => {
                    if early_data.is_some() {
                        return Err(error(
                            CompileFailure::UnsupportedField,
                            field("transport.earlyData"),
                        ));
                    }
                    if host.as_ref().is_some_and(|v| !valid_authority(v)) {
                        return Err(error(
                            CompileFailure::UnsupportedField,
                            field("transport.host"),
                        ));
                    }
                    ServerTransportV2::WebSocket {
                        decoded_path: decode_route(path).ok_or_else(|| {
                            error(CompileFailure::UnsupportedField, field("transport.path"))
                        })?,
                        host: host.clone(),
                    }
                }
                Transport::H2 { path, host } => {
                    if !valid_authority(host) {
                        return Err(error(
                            CompileFailure::UnsupportedField,
                            field("transport.host"),
                        ));
                    }
                    ServerTransportV2::Http2 {
                        decoded_path_prefix: decode_route(path).ok_or_else(|| {
                            error(CompileFailure::UnsupportedField, field("transport.path"))
                        })?,
                        host: host.clone(),
                    }
                }
                Transport::HttpUpgrade { path, host } => {
                    if !valid_authority(host) {
                        return Err(error(
                            CompileFailure::UnsupportedField,
                            field("transport.host"),
                        ));
                    }
                    ServerTransportV2::HttpUpgrade {
                        decoded_path: decode_route(path).ok_or_else(|| {
                            error(CompileFailure::UnsupportedField, field("transport.path"))
                        })?,
                        host: host.clone(),
                    }
                }
                Transport::Quic {}
                    if matches!(
                        protocol,
                        ServerProtocolV2::Hysteria2 {} | ServerProtocolV2::Tuic { .. }
                    ) =>
                {
                    ServerTransportV2::Quic {}
                }
                _ => {
                    return Err(error(
                        CompileFailure::UnsupportedTransport,
                        field("transport"),
                    ))
                }
            };
            if matches!(
                protocol,
                ServerProtocolV2::Shadowsocks { .. }
                    | ServerProtocolV2::AnyTls {}
                    | ServerProtocolV2::Socks5Authenticated {}
            ) && !matches!(transport, ServerTransportV2::Tcp {})
            {
                return Err(error(
                    CompileFailure::UnsupportedTransport,
                    field("transport"),
                ));
            }
            let security = match &listener.security {
                ServerSecurity::None {} => ServerSecurityV2::None {},
                ServerSecurity::Tls {
                    certificate_ref,
                    private_key_ref,
                    alpn,
                } => {
                    let exact: &[&str] = match transport {
                        ServerTransportV2::Tcp {} => &[],
                        ServerTransportV2::WebSocket { .. }
                        | ServerTransportV2::HttpUpgrade { .. } => &["http/1.1"],
                        ServerTransportV2::Http2 { .. } => &["h2"],
                        ServerTransportV2::Quic {} => &["h3"],
                    };
                    let exact_profile = if self.profile
                        == ServerProfileV2::LoopbackExtendedCoreUncertified
                    {
                        let mut seen = BTreeSet::new();
                        let well_formed = alpn.len() <= 16
                            && alpn.iter().all(|p| {
                                !p.is_empty()
                                    && p.len() <= 255
                                    && p.bytes().all(|b| b.is_ascii_graphic())
                                    && seen.insert(p)
                            });
                        well_formed
                            && match transport {
                                ServerTransportV2::Tcp {} => true,
                                ServerTransportV2::WebSocket { .. }
                                | ServerTransportV2::HttpUpgrade { .. } => {
                                    alpn.is_empty()
                                        || alpn.iter().map(String::as_str).collect::<Vec<_>>()
                                            == exact
                                }
                                _ => alpn.iter().map(String::as_str).collect::<Vec<_>>() == exact,
                            }
                    } else {
                        alpn.iter().map(String::as_str).collect::<Vec<_>>() == exact
                    };
                    if !exact_profile {
                        return Err(error(
                            CompileFailure::UnsupportedField,
                            field("security.alpn"),
                        ));
                    }
                    ServerSecurityV2::Tls {
                        certificate_ref: certificate_ref.clone(),
                        private_key_ref: private_key_ref.clone(),
                        alpn: alpn.clone(),
                    }
                }
                ServerSecurity::Reality { .. } => {
                    return Err(error(
                        CompileFailure::UnsupportedSecurity,
                        field("security"),
                    ))
                }
            };
            if matches!(
                protocol,
                ServerProtocolV2::Shadowsocks { .. } | ServerProtocolV2::Socks5Authenticated {}
            ) && !matches!(security, ServerSecurityV2::None {})
            {
                return Err(error(
                    CompileFailure::UnsupportedSecurity,
                    field("security"),
                ));
            }
            if self.profile == ServerProfileV2::PublicExperimentalUncertified && !matches!(
                (&protocol, &transport, &security),
                (ServerProtocolV2::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }, ServerTransportV2::Tcp {}, ServerSecurityV2::None {})
                | (ServerProtocolV2::Trojan {}, ServerTransportV2::Tcp {}, ServerSecurityV2::Tls { .. })
                | (ServerProtocolV2::Vless {}, ServerTransportV2::WebSocket { .. }, ServerSecurityV2::Tls { .. })
            ) { return Err(error(CompileFailure::UnsupportedProtocol, field("protocol"))); }
            let capability = capability(protocol, &transport, &security);
            if listener
                .requirements
                .iter()
                .any(|requested| Some(*requested) != capability)
            {
                return Err(error(
                    CompileFailure::UnsupportedCapability,
                    field("requirements"),
                ));
            }
            let credentials: Vec<_> = users
                .iter()
                .filter(|u| u.enabled)
                .map(|user| ServerCredentialRefV2 {
                    user_id: user.id.clone(),
                    reference: user.credential_ref.clone(),
                    encoding,
                })
                .collect();
            if credentials.len() > 128
                || (matches!(
                    protocol,
                    ServerProtocolV2::Hysteria2 {} | ServerProtocolV2::Shadowsocks { .. }
                ) && credentials.len() != 1)
            {
                return Err(error(
                    CompileFailure::UnsupportedField,
                    field("protocol.users"),
                ));
            }
            if listener.enabled {
                // Conservative TCP/UDP overlap refusal until explicit socket
                // family intent exists; IPv6-v6only is not implicitly assumed.
                if !binds.insert(listener.bind.port) {
                    return Err(error(CompileFailure::ConflictingBind, field("bind.port")));
                }
                listeners.push(ServerListenerV2 {
                    id: listener.id.clone(),
                    bind: listener.bind.clone(),
                    protocol,
                    transport,
                    security,
                    credentials,
                    capability,
                });
            }
        }
        if listeners.is_empty() {
            return Err(error(CompileFailure::NoEnabledListener, "listeners"));
        }
        Ok(ServerRecipeV2 {
            recipe_version: SERVER_RECIPE_VERSION,
            profile: self.profile,
            release: release.clone(),
            public_targets: self.public_targets.clone(),
            source: source.clone(),
            listeners,
        })
    }
    pub fn verify_recipe(&self, recipe: &ServerRecipeV2) -> Result<(), CompileError> {
        if recipe.recipe_version != SERVER_RECIPE_VERSION
            || self.compile(&recipe.source, &recipe.release)? != *recipe
        {
            return Err(error(CompileFailure::InvalidConfiguration, "recipe"));
        }
        Ok(())
    }
}
// Conservative experimental IPv4 policy; worker repeats validation at runtime.
fn public_target_allowed(ip: IpAddr) -> bool {
    let IpAddr::V4(ip) = ip else { return false };
    let [a, b, c, _] = ip.octets();
    !((a == 0) || (a == 10) || (a == 100 && (64..=127).contains(&b)) || a == 127
        || (a == 169 && b == 254) || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 0 || b == 168 || (b == 88 && c == 99)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113) || a >= 224)
}
fn capability(
    protocol: ServerProtocolV2,
    transport: &ServerTransportV2,
    security: &ServerSecurityV2,
) -> Option<CapabilityKey> {
    use ServerProtocolV2 as P;
    use ServerTransportV2 as T;
    let tls = matches!(security, ServerSecurityV2::Tls { .. });
    match (protocol, transport, tls) {
        (P::Tuic { .. }, T::Quic {}, true) => Some(CapabilityKey::Tuic),
        (P::Socks5Authenticated {}, T::Tcp {}, false) => Some(CapabilityKey::SocksAuth),
        (P::Trojan {}, T::Tcp {}, true) => Some(CapabilityKey::TrojanTls),
        (P::AnyTls {}, T::Tcp {}, true) => Some(CapabilityKey::AnyTls),
        (P::Hysteria2 {}, T::Quic {}, true) => Some(CapabilityKey::Hysteria2),
        (P::Shadowsocks { .. }, T::Tcp {}, false) => Some(CapabilityKey::Shadowsocks),
        (P::Vmess {}, T::Tcp {}, false) => Some(CapabilityKey::VmessTcp),
        (P::Vmess {}, T::WebSocket { .. }, false) => Some(CapabilityKey::VmessWs),
        (P::Vmess {}, T::WebSocket { .. }, true) => Some(CapabilityKey::VmessWsTls),
        (P::Vmess {}, T::Http2 { .. }, true) => Some(CapabilityKey::VmessH2Tls),
        (P::Vmess {}, T::HttpUpgrade { .. }, true) => Some(CapabilityKey::VmessHttpUpgradeTls),
        (P::Vless {}, T::WebSocket { .. }, true) => Some(CapabilityKey::VlessWsTls),
        (P::Vless {}, T::Http2 { .. }, true) => Some(CapabilityKey::VlessH2Tls),
        (P::Vless {}, T::HttpUpgrade { .. }, true) => Some(CapabilityKey::VlessHttpUpgradeTls),
        (P::Trojan {}, T::WebSocket { .. }, true) => Some(CapabilityKey::TrojanWsTls),
        (P::Trojan {}, T::Http2 { .. }, true) => Some(CapabilityKey::TrojanH2Tls),
        (P::Trojan {}, T::HttpUpgrade { .. }, true) => Some(CapabilityKey::TrojanHttpUpgradeTls),
        _ => None,
    }
}
fn decode_route(path: &str) -> Option<String> {
    if !path.starts_with('/')
        || path.len() > 2048
        || path
            .bytes()
            .any(|b| b <= 32 || b == 127 || b == b'?' || b == b'#')
    {
        return None;
    }
    let mut bytes = Vec::new();
    let mut input = path.bytes();
    while let Some(b) = input.next() {
        if b == b'%' {
            let high = (input.next()? as char).to_digit(16)?;
            let low = (input.next()? as char).to_digit(16)?;
            bytes.push((high * 16 + low) as u8);
        } else {
            bytes.push(b);
        }
    }
    if bytes
        .iter()
        .any(|b| *b <= 32 || *b == 127 || *b == b'?' || *b == b'#')
    {
        return None;
    }
    String::from_utf8(bytes).ok()
}
fn valid_authority(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 || !value.is_ascii() || value.contains('@') {
        return false;
    }
    let (host, port) = if let Some(stripped) = value.strip_prefix('[') {
        let Some((host, suffix)) = stripped.split_once(']') else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        (host, suffix)
    } else {
        value
            .find(':')
            .map_or((value, ""), |index| (&value[..index], &value[index..]))
    };
    if !port.is_empty()
        && !port.strip_prefix(':').is_some_and(|p| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
        })
    {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
