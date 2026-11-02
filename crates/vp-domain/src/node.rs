use crate::{
    CapabilityKey, CertificateId, ErrorCode, ErrorStage, ListenerId, NodeId, ProductError,
    SecretRef, SourceId, SubscriptionSource, UserId, SCHEMA_VERSION,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}
impl Endpoint {
    pub fn validate(&self) -> Result<(), ProductError> {
        if self.port == 0
            || self.host.is_empty()
            || self.host.len() > 253
            || self
                .host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || !valid_host(&self.host)
        {
            Err(ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Validate).at("endpoint"))
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum ShadowsocksCipher {
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[serde(rename = "xchacha20-ietf-poly1305")]
    Xchacha20IetfPoly1305,
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm2022,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Blake3Aes256Gcm2022,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Blake3Chacha20Poly13052022,
}
impl ShadowsocksCipher {
    pub const ALL: [Self; 7] = [
        Self::Aes128Gcm,
        Self::Aes256Gcm,
        Self::Chacha20IetfPoly1305,
        Self::Xchacha20IetfPoly1305,
        Self::Blake3Aes128Gcm2022,
        Self::Blake3Aes256Gcm2022,
        Self::Blake3Chacha20Poly13052022,
    ];
    pub fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Blake3Aes128Gcm2022
                | Self::Blake3Aes256Gcm2022
                | Self::Blake3Chacha20Poly13052022
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum VlessFlow {
    #[serde(rename = "xtls-rprx-vision")]
    XtlsRprxVision,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum VmessCipher {
    Auto,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TuicUdpRelayMode {
    Native,
    Quic,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Protocol {
    Tuic {
        #[serde(rename = "congestionControl")]
        congestion_control: CongestionControl,
        #[serde(rename = "udpRelayMode")]
        udp_relay_mode: TuicUdpRelayMode,
    },
    Trojan {},
    Hysteria2 {
        #[serde(rename = "obfuscationRef")]
        obfuscation_ref: Option<SecretRef>,
    },
    Vmess {
        cipher: VmessCipher,
        #[serde(rename = "alterId")]
        alter_id: u16,
    },
    Shadowsocks {
        method: ShadowsocksCipher,
    },
    Vless {
        flow: Option<VlessFlow>,
    },
    #[serde(rename = "anytls")]
    AnyTls {},
    Socks5 {},
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Transport {
    Tcp {},
    Ws {
        path: String,
        host: Option<String>,
        #[serde(rename = "earlyData")]
        early_data: Option<EarlyData>,
    },
    /// A distinct, unresolved wire profile; never silently substitute H2 or TCP.
    Http {
        path: String,
        host: String,
    },
    H2 {
        path: String,
        host: String,
    },
    HttpUpgrade {
        path: String,
        host: String,
    },
    Quic {},
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EarlyData {
    pub max_bytes: u16,
    pub header_name: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TlsTrust {
    System {},
    CustomCa {
        #[serde(rename = "certificateRef")]
        certificate_ref: CertificateId,
    },
    SpkiSha256 {
        pins: Vec<String>,
    },
}
/// No insecure/skip-verify variant. Explicit trust is preserved through export.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ClientSecurity {
    None {},
    Tls {
        #[serde(rename = "serverName")]
        server_name: String,
        alpn: Vec<String>,
        trust: TlsTrust,
        /// ClientHello/browser profile (for example "chrome"), never a server
        /// certificate digest or SPKI pin. Trust pins live only in `trust`.
        /// None is unspecified; compiler must preserve or explicitly reject.
        #[serde(rename = "clientHelloFingerprint")]
        client_hello_fingerprint: Option<String>,
    },
    Reality {
        #[serde(rename = "serverName")]
        server_name: String,
        #[serde(rename = "publicKey")]
        public_key: String,
        #[serde(rename = "shortId")]
        short_id: String,
        /// ClientHello/browser profile, not certificate/SPKI pinning. REALITY's
        /// public_key and short_id are separate authentication parameters.
        #[serde(rename = "clientHelloFingerprint")]
        client_hello_fingerprint: Option<String>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeProfile {
    pub schema_version: u16,
    pub id: NodeId,
    pub name: String,
    pub endpoint: Endpoint,
    pub protocol: Protocol,
    pub transport: Transport,
    pub security: ClientSecurity,
    pub credential_ref: SecretRef,
    /// Display/import hints, not authority. Compiler derives the full exact
    /// capability tuple from validated fields even when this list is empty.
    pub requirements: Vec<CapabilityKey>,
    pub source_ref: Option<SourceId>,
}
impl NodeProfile {
    pub fn validate(&self) -> Result<(), ProductError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(invalid("schemaVersion"));
        }
        validate_name(&self.name)?;
        self.endpoint.validate()?;
        validate_protocol_transport(&self.protocol, &self.transport)?;
        let tls = matches!(&self.security, ClientSecurity::Tls { .. });
        if matches!(&self.transport, Transport::Quic {}) && !tls {
            return Err(invalid("security"));
        }
        if matches!(
            &self.protocol,
            Protocol::Tuic { .. }
                | Protocol::Hysteria2 { .. }
                | Protocol::AnyTls {}
                | Protocol::Trojan {}
        ) && !tls
        {
            return Err(invalid("security"));
        }
        if matches!(
            &self.protocol,
            Protocol::Vless {
                flow: Some(VlessFlow::XtlsRprxVision)
            }
        ) && (!matches!(&self.transport, Transport::Tcp {})
            || !matches!(&self.security, ClientSecurity::Reality { .. }))
        {
            return Err(invalid("protocol.flow"));
        }
        match &self.security {
            ClientSecurity::Reality {
                server_name,
                public_key,
                short_id,
                client_hello_fingerprint,
            } => {
                if !matches!(&self.protocol, Protocol::Vless { .. })
                    || !valid_host(server_name)
                    || public_key.len() != 43
                    || !public_key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                    || client_hello_fingerprint
                        .as_ref()
                        .is_some_and(|value| !valid_client_hello_fingerprint(value))
                    || short_id.len() > 16
                    || short_id.len() % 2 != 0
                    || !short_id.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(invalid("security"));
                }
            }
            ClientSecurity::Tls {
                server_name,
                alpn,
                trust,
                client_hello_fingerprint,
            } => {
                if !valid_host(server_name)
                    || client_hello_fingerprint
                        .as_ref()
                        .is_some_and(|value| !valid_client_hello_fingerprint(value))
                    || alpn
                        .iter()
                        .any(|v| v.is_empty() || v.len() > 255 || v.chars().any(char::is_control))
                {
                    return Err(invalid("security"));
                }
                if let TlsTrust::SpkiSha256 { pins } = trust {
                    if pins.is_empty()
                        || pins
                            .iter()
                            .any(|p| p.len() != 64 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
                    {
                        return Err(invalid("security.trust.pins"));
                    }
                }
            }
            ClientSecurity::None {} => {}
        }
        Ok(())
    }
}
fn valid_client_hello_fingerprint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
fn valid_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    let dns = host.strip_suffix('.').unwrap_or(host);
    !dns.is_empty()
        && dns.is_ascii()
        && dns.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn valid_source_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    // No unrestricted source list. Host bits must be zero for canonical policy.
    match address {
        IpAddr::V4(ip) => {
            prefix > 0
                && prefix <= 32
                && (prefix == 32 || u32::from(ip) & (u32::MAX >> prefix) == 0)
        }
        IpAddr::V6(ip) => {
            prefix > 0
                && prefix <= 128
                && (prefix == 128 || u128::from(ip) & (u128::MAX >> prefix) == 0)
        }
    }
}
fn invalid(field: &str) -> ProductError {
    ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Validate).at(field)
}
fn validate_name(name: &str) -> Result<(), ProductError> {
    if name.trim().is_empty() || name.chars().count() > 128 || name.chars().any(char::is_control) {
        Err(invalid("name"))
    } else {
        Ok(())
    }
}
fn validate_protocol_transport(
    protocol: &Protocol,
    transport: &Transport,
) -> Result<(), ProductError> {
    if matches!(
        protocol,
        Protocol::Shadowsocks { .. } | Protocol::Socks5 {} | Protocol::AnyTls {}
    ) && !matches!(transport, Transport::Tcp {})
    {
        return Err(invalid("transport"));
    }
    if matches!(protocol, Protocol::Tuic { .. } | Protocol::Hysteria2 { .. })
        && !matches!(transport, Transport::Quic {})
    {
        return Err(invalid("transport"));
    }
    if matches!(transport, Transport::Quic {})
        && !matches!(
            protocol,
            Protocol::Tuic { .. } | Protocol::Hysteria2 { .. } | Protocol::Vmess { .. }
        )
    {
        return Err(invalid("transport"));
    }
    match transport {
        Transport::Ws {
            path,
            host,
            early_data,
        } => {
            if !valid_path(path)
                || host
                    .as_ref()
                    .is_some_and(|v| v.is_empty() || v.chars().any(char::is_control))
            {
                return Err(invalid("transport"));
            }
            if let Some(e) = early_data {
                if e.max_bytes == 0
                    || e.header_name.is_empty()
                    || !e
                        .header_name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                {
                    return Err(invalid("transport.earlyData"));
                }
            }
        }
        Transport::Http { path, host }
        | Transport::H2 { path, host }
        | Transport::HttpUpgrade { path, host } => {
            if !valid_path(path) || host.is_empty() || host.chars().any(char::is_control) {
                return Err(invalid("transport"));
            }
        }
        _ => {}
    }
    Ok(())
}
fn valid_path(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 2048 && !path.chars().any(char::is_control)
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindAddress {
    pub address: IpAddr,
    pub port: u16,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerUser {
    pub id: UserId,
    pub credential_ref: SecretRef,
    pub enabled: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ServerProtocol {
    Proxy {
        protocol: Protocol,
        users: Vec<ListenerUser>,
    },
    Direct {
        target: Endpoint,
        traffic: Vec<crate::Traffic>,
        #[serde(rename = "allowedSources")]
        allowed_sources: Vec<String>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ServerSecurity {
    None {},
    Tls {
        #[serde(rename = "certificateRef")]
        certificate_ref: CertificateId,
        #[serde(rename = "privateKeyRef")]
        private_key_ref: SecretRef,
        alpn: Vec<String>,
    },
    Reality {
        #[serde(rename = "privateKeyRef")]
        private_key_ref: SecretRef,
        #[serde(rename = "serverNames")]
        server_names: Vec<String>,
        #[serde(rename = "shortIds")]
        short_ids: Vec<String>,
        #[serde(rename = "handshakeTarget")]
        handshake_target: Endpoint,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerListener {
    pub schema_version: u16,
    pub id: ListenerId,
    pub name: String,
    pub enabled: bool,
    pub bind: BindAddress,
    pub protocol: ServerProtocol,
    pub transport: Transport,
    pub security: ServerSecurity,
    /// Display/import hints, not authority. Compiler derives the full exact
    /// capability tuple from validated fields even when this list is empty.
    pub requirements: Vec<CapabilityKey>,
}
impl ServerListener {
    pub fn validate(&self) -> Result<(), ProductError> {
        if self.schema_version != SCHEMA_VERSION || self.bind.port == 0 {
            return Err(invalid("bind"));
        }
        validate_name(&self.name)?;
        match &self.protocol {
            ServerProtocol::Proxy { protocol, users } => {
                validate_protocol_transport(protocol, &self.transport)?;
                if users.is_empty()
                    || !users.iter().any(|u| u.enabled)
                    || users
                        .iter()
                        .map(|u| &u.id)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        != users.len()
                {
                    return Err(invalid("protocol.users"));
                }
                if matches!(
                    protocol,
                    Protocol::Vless {
                        flow: Some(VlessFlow::XtlsRprxVision)
                    }
                ) && (!matches!(&self.transport, Transport::Tcp {})
                    || !matches!(&self.security, ServerSecurity::Reality { .. }))
                {
                    return Err(invalid("protocol.flow"));
                }
                if matches!(&self.transport, Transport::Quic {})
                    && !matches!(&self.security, ServerSecurity::Tls { .. })
                {
                    return Err(invalid("security"));
                }
                if matches!(&self.security, ServerSecurity::Reality { .. })
                    && !matches!(protocol, Protocol::Vless { .. })
                {
                    return Err(invalid("security"));
                }
                if matches!(
                    protocol,
                    Protocol::Tuic { .. }
                        | Protocol::Hysteria2 { .. }
                        | Protocol::AnyTls {}
                        | Protocol::Trojan {}
                ) && !matches!(&self.security, ServerSecurity::Tls { .. })
                {
                    return Err(invalid("security"));
                }
            }
            ServerProtocol::Direct {
                target,
                traffic,
                allowed_sources,
            } => {
                target.validate()?;
                if traffic.is_empty()
                    || allowed_sources.is_empty()
                    || !matches!(&self.transport, Transport::Tcp {})
                    || !matches!(&self.security, ServerSecurity::None {})
                {
                    return Err(invalid("protocol"));
                }
                if allowed_sources.iter().any(|v| !valid_source_cidr(v)) {
                    return Err(invalid("protocol.allowedSources"));
                }
            }
        }
        match &self.security {
            ServerSecurity::Tls { alpn, .. } => {
                if alpn
                    .iter()
                    .any(|v| v.is_empty() || v.len() > 255 || v.chars().any(char::is_control))
                {
                    return Err(invalid("security.alpn"));
                }
            }
            ServerSecurity::Reality {
                server_names,
                short_ids,
                handshake_target,
                ..
            } => {
                handshake_target.validate()?;
                if server_names.is_empty()
                    || server_names.iter().any(|n| !valid_host(n))
                    || short_ids.is_empty()
                    || short_ids.iter().any(|id| {
                        id.len() > 16
                            || id.len() % 2 != 0
                            || !id.bytes().all(|b| b.is_ascii_hexdigit())
                    })
                {
                    return Err(invalid("security"));
                }
            }
            ServerSecurity::None {} => {}
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductConfig {
    pub schema_version: u16,
    pub minimum_reader_version: u16,
    pub nodes: Vec<NodeProfile>,
    pub listeners: Vec<ServerListener>,
    pub subscriptions: Vec<SubscriptionSource>,
}
impl ProductConfig {
    pub fn validate(&self) -> Result<(), ProductError> {
        if self.schema_version != SCHEMA_VERSION
            || self.minimum_reader_version == 0
            || self.minimum_reader_version > SCHEMA_VERSION
        {
            return Err(invalid("schemaVersion"));
        }
        for node in &self.nodes {
            node.validate()?;
        }
        for listener in &self.listeners {
            listener.validate()?;
        }
        for source in &self.subscriptions {
            source.validate()?;
        }
        let unique = |ids: Vec<&str>| {
            let count = ids.len();
            ids.into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == count
        };
        if !unique(self.nodes.iter().map(|v| v.id.as_str()).collect())
            || !unique(self.listeners.iter().map(|v| v.id.as_str()).collect())
            || !unique(self.subscriptions.iter().map(|v| v.id.as_str()).collect())
        {
            return Err(invalid("id"));
        }
        if self
            .nodes
            .iter()
            .filter_map(|n| n.source_ref.as_ref())
            .any(|s| !self.subscriptions.iter().any(|v| &v.id == s))
        {
            return Err(invalid("sourceRef"));
        }
        Ok(())
    }
}
