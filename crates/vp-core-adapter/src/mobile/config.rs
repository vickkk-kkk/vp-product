//! Exact mobile input mapping: product node model, not unchecked upstream JSON.
use serde::Deserialize;
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc};
use vp_product_domain::*;
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credential {
    Password { value: String },
    Uuid { value: String },
    UsernamePassword { username: String, password: String },
    UuidPassword { uuid: String, password: String },
}
impl Drop for Credential {
    fn drop(&mut self) {
        match self {
            Self::Password { value } | Self::Uuid { value } => value.zeroize(),
            Self::UsernamePassword { username, password } => {
                username.zeroize();
                password.zeroize()
            }
            Self::UuidPassword { uuid, password } => {
                uuid.zeroize();
                password.zeroize()
            }
        }
    }
}
pub const CONNECT_PAYLOAD_VERSION: u16 = 2;
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserDnsRoute {
    SelectedProxy,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserDnsPolicy {
    pub route: UserDnsRoute,
    pub servers: Vec<SocketAddr>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsPolicy {
    pub bootstrap_servers: Vec<SocketAddr>,
    pub user: UserDnsPolicy,
}
fn legacy_dns_present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}
pub struct Built {
    pub outbound: Arc<dyn vp_core::Outbound>,
    pub user_dns: Arc<vp_tun::user_dns::UserDns>,
    pub bootstrap_servers: Vec<SocketAddr>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Connect {
    pub schema_version: Option<u16>,
    pub node: NodeProfile,
    pub credential: Credential,
    pub config_revision: Revision,
    pub dns: Option<DnsPolicy>,
    // A recognized legacy field exists only to produce an explicit migration
    // error. Even null counts as present; it is never used as a resolver list.
    #[serde(
        default,
        rename = "dnsServers",
        deserialize_with = "legacy_dns_present"
    )]
    legacy_dns_servers: bool,
}
fn unsupported(field: &str) -> ProductError {
    ProductError::new(ErrorCode::ConfigUnsupported, ErrorStage::Validate).at(field)
}
fn invalid(field: &str) -> ProductError {
    ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Validate).at(field)
}
fn valid_uuid(value: &str) -> bool {
    // TUIC defers its UUID parse until after dialing. Validate here before any
    // runtime/FD/hook action; ASCII also avoids upstream UTF-8 byte slicing.
    match value.len() {
        32 => value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        36 => value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        }),
        _ => false,
    }
}
fn require_full_tun_traffic(udp: bool) -> Result<(), ProductError> {
    if udp {
        Ok(())
    } else {
        Err(unsupported("node.protocol.udp"))
    }
}
impl Connect {
    pub fn validate_version(&self) -> Result<(), ProductError> {
        if self.legacy_dns_servers || self.schema_version != Some(CONNECT_PAYLOAD_VERSION) {
            return Err(
                ProductError::new(ErrorCode::UpgradeIncompatible, ErrorStage::Validate).at(
                    if self.legacy_dns_servers {
                        "dnsServers"
                    } else {
                        "schemaVersion"
                    },
                ),
            );
        }
        Ok(())
    }
    pub fn build(&self) -> Result<Built, ProductError> {
        self.validate_version()?;
        let policy = self.dns.as_ref().ok_or_else(|| invalid("dns"))?;
        self.node.validate()?;
        let valid_secret = |s: &str| !s.is_empty() && s.len() <= 8192 && !s.contains('\0');
        let valid_credential = match &self.credential {
            Credential::Password { value } => valid_secret(value),
            Credential::Uuid { value } => valid_uuid(value),
            Credential::UsernamePassword { username, password } => {
                valid_secret(username)
                    && valid_secret(password)
                    && username.len() <= 255
                    && password.len() <= 255
            }
            Credential::UuidPassword { uuid, password } => {
                valid_uuid(uuid) && valid_secret(password)
            }
        };
        if !valid_credential {
            return Err(invalid("credential"));
        }
        let bootstrap = Arc::new(
            vp_dns::Resolver::bootstrap(policy.bootstrap_servers.clone(), &self.node.endpoint.host)
                .map_err(|_| invalid("dns.bootstrapServers"))?,
        );
        let mut p = json!({"name":self.node.id.as_str(),"server":self.node.endpoint.host,"port":self.node.endpoint.port,"udp":true});
        match (&self.node.protocol, &self.credential) {
            (Protocol::Shadowsocks { method }, Credential::Password { value }) => {
                p["type"] = json!("ss");
                p["cipher"] = json!(method);
                p["password"] = json!(value);
            }
            (Protocol::Vless { flow }, Credential::Uuid { value }) => {
                p["type"] = json!("vless");
                p["uuid"] = json!(value);
                p["flow"] = json!(flow);
            }
            (Protocol::Vmess { cipher, alter_id }, Credential::Uuid { value }) => {
                if *alter_id != 0 {
                    return Err(unsupported("node.protocol.alterId"));
                }
                p["type"] = json!("vmess");
                p["uuid"] = json!(value);
                p["cipher"] = json!(cipher);
                p["alter_id"] = json!(alter_id);
            }
            (Protocol::Trojan {}, Credential::Password { value }) => {
                p["type"] = json!("trojan");
                p["password"] = json!(value);
            }
            (Protocol::Socks5 {}, Credential::UsernamePassword { username, password }) => {
                p["type"] = json!("socks5");
                p["username"] = json!(username);
                p["password"] = json!(password);
            }
            (Protocol::AnyTls {}, Credential::Password { value }) => {
                p["type"] = json!("anytls");
                p["password"] = json!(value);
            }
            (
                Protocol::Hysteria2 {
                    obfuscation_ref: None,
                },
                Credential::Password { value },
            ) => {
                p["type"] = json!("hysteria2");
                p["password"] = json!(value);
            }
            (
                Protocol::Tuic {
                    congestion_control,
                    udp_relay_mode,
                },
                Credential::UuidPassword { uuid, password },
            ) => {
                if !matches!(congestion_control, CongestionControl::Cubic) {
                    return Err(unsupported("node.protocol.congestionControl"));
                }
                p["type"] = json!("tuic");
                p["uuid"] = json!(uuid);
                p["password"] = json!(password);
                p["udp_relay_mode"] = json!(udp_relay_mode);
            }
            _ => return Err(unsupported("node.protocol_or_credential")),
        }
        match &self.node.transport {
            Transport::Tcp {} | Transport::Quic {} => {}
            Transport::Ws {
                path,
                host,
                early_data: None,
            } => {
                p["network"] = json!("ws");
                p["ws_opts"] =
                    json!({"path":path,"headers":host.as_ref().map(|h|json!({"Host":h}))});
            }
            _ => return Err(unsupported("node.transport")),
        }
        if matches!(&self.node.transport, Transport::Quic {})
            && !matches!(
                &self.node.protocol,
                Protocol::Tuic { .. } | Protocol::Hysteria2 { .. }
            )
        {
            return Err(unsupported("node.transport"));
        }
        match &self.node.security {
            ClientSecurity::None {} => {
                if !matches!(
                    &self.node.protocol,
                    Protocol::Shadowsocks { .. }
                        | Protocol::Socks5 {}
                        | Protocol::Vless { .. }
                        | Protocol::Vmess { .. }
                ) {
                    return Err(unsupported("node.security"));
                }
            }
            ClientSecurity::Tls {
                server_name,
                alpn,
                trust: TlsTrust::System {},
                client_hello_fingerprint: None,
            } => {
                if matches!(
                    &self.node.protocol,
                    Protocol::Shadowsocks { .. } | Protocol::Socks5 {}
                ) {
                    return Err(unsupported("node.security"));
                }
                if matches!(&self.node.protocol, Protocol::AnyTls {}) && !alpn.is_empty() {
                    return Err(unsupported("node.security.alpn"));
                }
                if matches!(&self.node.protocol, Protocol::Tuic { .. })
                    && !alpn.is_empty()
                    && alpn != &["h3"]
                {
                    return Err(unsupported("node.security"));
                }
                if matches!(&self.node.protocol, Protocol::Hysteria2 { .. })
                    && !alpn.is_empty()
                    && alpn != &["h3"]
                {
                    return Err(unsupported("node.security.alpn"));
                }
                p["tls"] = json!(true);
                if matches!(
                    &self.node.protocol,
                    Protocol::Hysteria2 { .. } | Protocol::Tuic { .. }
                ) {
                    p["sni"] = json!(server_name);
                } else {
                    p["server_name"] = json!(server_name);
                }
                p["alpn"] = json!(alpn);
            }
            // REALITY/fingerprint support requires the independently verified
            // transport patch; never silently downgrade to ordinary TLS.
            _ => return Err(unsupported("node.security")),
        }
        if let Protocol::Vless { flow: Some(_) } = self.node.protocol {
            return Err(unsupported("node.protocol.flow"));
        }
        let cfg: vp_config::ProxyCfg =
            serde_json::from_value(p).map_err(|_| invalid("credential"))?;
        let outbound = vp_protocol::build_outbound_eager(
            &cfg,
            &vp_protocol::OutboundDeps {
                dns: bootstrap,
                ipv6: false,
            },
        )
        .map_err(|_| invalid("credential"))?;
        // The mobile host captures a full IP tunnel. Never accept a TCP-only
        // outbound and silently drop UDP, even via an opt-in debug action.
        require_full_tun_traffic(outbound.support_udp())?;
        let user_dns = match &policy.user.route {
            UserDnsRoute::SelectedProxy => vp_tun::user_dns::UserDns::selected_proxy(
                outbound.clone(),
                policy.user.servers.clone(),
            )
            .map_err(|_| invalid("dns.user.servers"))?,
        };
        Ok(Built {
            outbound,
            user_dns: Arc::new(user_dns),
            bootstrap_servers: policy.bootstrap_servers.clone(),
        })
    }
}
pub fn erase_json(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(erase_json),
        Value::Object(m) => m.values_mut().for_each(erase_json),
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Fixture/setup failures must fail these tests immediately.
mod tests {
    use super::*;
    fn config() -> Value {
        json!({"schemaVersion":2,"node":{"schemaVersion":1,"id":"test-node","name":"Test","endpoint":{"host":"127.0.0.1","port":1080},"protocol":{"kind":"socks5"},"transport":{"kind":"tcp"},"security":{"kind":"none"},"credentialRef":"secret:test","requirements":[],"sourceRef":null},"credential":{"kind":"username_password","username":"test","password":"test-only"},"configRevision":1,"dns":{"bootstrapServers":["127.0.0.1:5353"],"user":{"route":"selected_proxy","servers":["127.0.0.1:5353"]}}})
    }
    #[test]
    fn canonical_socks_maps_without_network() {
        let c: Connect = serde_json::from_value(config()).unwrap();
        assert!(c.build().is_ok());
    }
    #[test]
    fn unknown_security_field_is_not_ignored() {
        let mut c = config();
        c["node"]["security"]["skipVerify"] = json!(true);
        assert!(serde_json::from_value::<Connect>(c).is_err());
    }
    #[test]
    fn tls_on_socks_is_rejected_not_downgraded() {
        let mut c = config();
        c["node"]["security"] = json!({"kind":"tls","serverName":"example.invalid","alpn":[],"trust":{"kind":"system"},"clientHelloFingerprint":null});
        let c: Connect = serde_json::from_value(c).unwrap();
        assert!(c.build().is_err());
    }
    #[test]
    fn explicit_ip_resolver_required() {
        let mut c = config();
        c["dns"]["bootstrapServers"] = json!([]);
        let c: Connect = serde_json::from_value(c).unwrap();
        assert!(c.build().is_err());
    }
    #[test]
    fn full_tun_never_treats_tcp_only_outbound_as_valid() {
        let error = require_full_tun_traffic(false).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigUnsupported);
        assert!(require_full_tun_traffic(true).is_ok());
    }
    #[test]
    fn tuic_uuid_is_validated_without_dialing_or_a_runtime() {
        let mut value = config();
        value["node"]["protocol"] =
            json!({"kind":"tuic","congestionControl":"cubic","udpRelayMode":"native"});
        value["node"]["transport"] = json!({"kind":"quic"});
        value["node"]["security"] = json!({"kind":"tls","serverName":"fixture.invalid","alpn":["h3"],"trust":{"kind":"system"},"clientHelloFingerprint":null});
        for uuid in [
            "not-a-uuid",
            "éééééééééééééééé",
            "00000000-0000-0000-0000-00000000000x",
        ] {
            value["credential"] =
                json!({"kind":"uuid_password","uuid":uuid,"password":"test-only"});
            let input: Connect = serde_json::from_value(value.clone()).unwrap();
            let error = input.build().err().unwrap();
            assert_eq!(error.code, ErrorCode::ConfigInvalid);
        }
        for uuid in [
            "01234567-89ab-cdef-0123-456789abcdef",
            "0123456789abcdef0123456789abcdef",
        ] {
            value["credential"] =
                json!({"kind":"uuid_password","uuid":uuid,"password":"test-only"});
            let input: Connect = serde_json::from_value(value.clone()).unwrap();
            assert!(input.build().unwrap().outbound.support_udp());
        }
    }
    #[test]
    fn legacy_dns_is_migration_required_including_null_or_mixed_fields() {
        let mut legacy = config();
        legacy.as_object_mut().unwrap().remove("schemaVersion");
        legacy.as_object_mut().unwrap().remove("dns");
        legacy["dnsServers"] = json!(["127.0.0.1:5353"]);
        for value in [
            legacy,
            {
                let mut mixed = config();
                mixed["dnsServers"] = Value::Null;
                mixed
            },
            {
                let mut future = config();
                future["schemaVersion"] = json!(3);
                future
            },
        ] {
            let input: Connect = serde_json::from_value(value).unwrap();
            assert_eq!(
                input.build().err().unwrap().code,
                ErrorCode::UpgradeIncompatible
            );
        }
    }
    #[test]
    fn explicit_proxy_dns_route_and_numeric_user_servers_are_required() {
        let mut value = config();
        value["dns"]["user"]["route"] = json!("direct");
        assert!(serde_json::from_value::<Connect>(value).is_err());
        let mut value = config();
        value["dns"]["user"]["servers"] = json!([]);
        let input: Connect = serde_json::from_value(value).unwrap();
        assert_eq!(input.build().err().unwrap().code, ErrorCode::ConfigInvalid);
    }
    #[test]
    fn dns_numeric_endpoint_limits_and_scope_are_exact() {
        for user in [false, true] {
            for servers in [
                json!([]),
                json!(["0.0.0.0:53"]),
                json!(["224.0.0.1:53"]),
                json!(["127.0.0.1:0"]),
                json!(["[::]:53"]),
                json!(["[ff02::1]:53"]),
                json!(vec!["127.0.0.1:53"; 5]),
            ] {
                let mut value = config();
                if user {
                    value["dns"]["user"]["servers"] = servers;
                } else {
                    value["dns"]["bootstrapServers"] = servers;
                }
                let input: Connect = serde_json::from_value(value).unwrap();
                let error = input.build().err().unwrap();
                assert_eq!(error.code, ErrorCode::ConfigInvalid);
                assert_eq!(
                    error.field_path.as_deref(),
                    Some(if user {
                        "dns.user.servers"
                    } else {
                        "dns.bootstrapServers"
                    })
                );
            }
        }
        for servers in [
            json!(["127.0.0.1:53"]),
            json!(["[::1]:5353", "127.0.0.1:53", "127.0.0.1:53", "[::1]:53"]),
        ] {
            let mut value = config();
            value["dns"]["bootstrapServers"] = servers.clone();
            value["dns"]["user"]["servers"] = servers;
            assert!(serde_json::from_value::<Connect>(value)
                .unwrap()
                .build()
                .is_ok());
        }
        let mut value = config();
        value["dns"]["bootstrapServers"] = json!(["[fe80::1%2]:53"]);
        assert!(serde_json::from_value::<Connect>(value.clone())
            .unwrap()
            .build()
            .is_ok());
        value["dns"]["user"]["servers"] = json!(["[fe80::1%2]:53"]);
        assert!(serde_json::from_value::<Connect>(value)
            .unwrap()
            .build()
            .is_err());
        for endpoint in [
            "resolver.invalid:53",
            "127.0.0.1",
            "[::1]",
            "127.0.0.1:65536",
            "[fe80::1%wlan0]:53",
        ] {
            let mut value = config();
            value["dns"]["user"]["servers"] = json!([endpoint]);
            assert!(serde_json::from_value::<Connect>(value).is_err());
        }
    }
}
