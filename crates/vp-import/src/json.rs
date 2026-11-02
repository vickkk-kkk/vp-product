//! Strict JSON subset extraction. No YAML loader, object constructors, includes,
//! provider downloads, scripts, or full-config execution.
use crate::*;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{cell::Cell, collections::BTreeMap};

enum Value {
    Null,
    Bool(bool),
    Number(u64),
    OtherNumber,
    String(Zeroizing<String>),
    Array(Vec<Value>),
    Object(Object),
}
type Object = BTreeMap<String, Value>;
struct Seed<'a> {
    duplicate: &'a Cell<bool>,
    limit: &'a Cell<bool>,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> std::result::Result<Value, D::Error> {
        if self.depth > 32 {
            self.limit.set(true);
            return Err(de::Error::custom("nesting limit"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(if v >= 0 {
            Value::Number(v as u64)
        } else {
            Value::OtherNumber
        })
    }
    fn visit_f64<E: de::Error>(self, _v: f64) -> std::result::Result<Value, E> {
        Ok(Value::OtherNumber)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        self.visit_string(v.to_owned())
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        let value = Zeroizing::new(v);
        if value.len() > MAX_COMPONENT_BYTES {
            self.limit.set(true);
            return Err(de::Error::custom("string limit"));
        }
        Ok(Value::String(value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = a.next_element_seed(Seed {
            duplicate: self.duplicate,
            limit: self.limit,
            depth: self.depth + 1,
        })? {
            if values.len() >= MAX_ENTRIES {
                self.limit.set(true);
                return Err(de::Error::custom("array limit"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut values = Object::new();
        while let Some(key) = a.next_key::<String>()? {
            if values.len() >= 64 || key.len() > 128 {
                self.limit.set(true);
                return Err(de::Error::custom("map limit"));
            }
            if values.contains_key(&key) {
                self.duplicate.set(true);
                return Err(de::Error::custom("duplicate key"));
            }
            let value = a.next_value_seed(Seed {
                duplicate: self.duplicate,
                limit: self.limit,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
fn read(text: &str) -> Result<Value> {
    let duplicate = Cell::new(false);
    let limit = Cell::new(false);
    let mut d = serde_json::Deserializer::from_str(text);
    let parsed = Seed {
        duplicate: &duplicate,
        limit: &limit,
        depth: 0,
    }
    .deserialize(&mut d)
    .and_then(|v| d.end().map(|_| v));
    parsed.map_err(|_| {
        issue(
            if duplicate.get() {
                IssueKind::DuplicateField
            } else if limit.get() {
                IssueKind::InputLimit
            } else {
                IssueKind::InvalidSyntax
            },
            "json",
        )
    })
}
fn object(v: Value) -> Result<Object> {
    match v {
        Value::Object(v) => Ok(v),
        _ => Err(invalid("json.object")),
    }
}
fn string(o: &mut Object, key: &str) -> Result<Option<Zeroizing<String>>> {
    match o.remove(key) {
        None => Ok(None),
        Some(Value::String(v)) => Ok(Some(v)),
        _ => Err(invalid("json.field_type")),
    }
}
fn text(o: &mut Object, key: &str) -> Result<Option<String>> {
    string(o, key).map(|v| v.map(|v| v.to_string()))
}
fn required(o: &mut Object, key: &str) -> Result<String> {
    text(o, key)?.ok_or_else(|| invalid("json.required_field"))
}
fn secret(o: &mut Object, key: &str) -> Result<SecretBytes> {
    Ok(SecretBytes::new(
        string(o, key)?
            .ok_or_else(|| invalid("credential"))?
            .as_bytes()
            .to_vec(),
    ))
}
fn boolean(o: &mut Object, key: &str) -> Result<Option<bool>> {
    match o.remove(key) {
        None => Ok(None),
        Some(Value::Bool(v)) => Ok(Some(v)),
        _ => Err(invalid("json.field_type")),
    }
}
fn number(o: &mut Object, key: &str) -> Result<Option<u64>> {
    match o.remove(key) {
        None => Ok(None),
        Some(Value::Number(v)) => Ok(Some(v)),
        _ => Err(invalid("json.field_type")),
    }
}
fn finish(o: &Object) -> Result<()> {
    if o.is_empty() {
        Ok(())
    } else {
        Err(issue(IssueKind::UnknownField, "json.node_fields"))
    }
}
fn strings(o: &mut Object, key: &str) -> Result<Vec<String>> {
    match o.remove(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .into_iter()
            .map(|v| match v {
                Value::String(v) => Ok(v.to_string()),
                _ => Err(invalid("json.field_type")),
            })
            .collect(),
        _ => Err(invalid("json.field_type")),
    }
}
pub(crate) fn detect(input: &str) -> Result<ImportFormat> {
    let obj = object(read(input)?)?;
    match (obj.contains_key("proxies"), obj.contains_key("outbounds")) {
        (true, false) => Ok(ImportFormat::ClashNodes),
        (false, true) => Ok(ImportFormat::SingBoxOutbounds),
        _ => Err(issue(IssueKind::UnsupportedFormat, "format")),
    }
}
pub(crate) fn parse_nodes(input: &str, format: ImportFormat) -> Result<ImportBatch> {
    if !input.starts_with('{') {
        return Err(issue(IssueKind::UnsupportedFormat, "format.clash_yaml"));
    }
    let mut obj = object(read(input)?)?;
    let key = if format == ImportFormat::ClashNodes {
        "proxies"
    } else {
        "outbounds"
    };
    let values = match obj.remove(key) {
        Some(Value::Array(v)) if !v.is_empty() => v,
        _ => return Err(invalid("json.nodes")),
    };
    let has_top_fields = !obj.is_empty();
    let diagnostics = if has_top_fields {
        vec![issue(
            IssueKind::UnimportedTopLevelFields,
            "json.top_level_fields",
        )]
    } else {
        Vec::new()
    };
    let entries = values
        .into_iter()
        .enumerate()
        .map(|(i, v)| {
            let candidate = object(v).and_then(|o| {
                if format == ImportFormat::ClashNodes {
                    parse_clash(o)
                } else {
                    parse_sing_box(o)
                }
            });
            match candidate {
                Ok(candidate) => StagedEntry {
                    index: i as u32,
                    candidate: Some(candidate),
                    diagnostics: Vec::new(),
                },
                Err(error) => StagedEntry {
                    index: i as u32,
                    candidate: None,
                    diagnostics: vec![error],
                },
            }
        })
        .collect::<Vec<_>>();
    let has_unimported_fields = has_top_fields || entries.iter().any(|e| e.candidate.is_none());
    Ok(ImportBatch {
        format,
        entries,
        diagnostics,
        has_unimported_fields,
    })
}

fn parse_sing_box(mut o: Object) -> Result<ImportCandidate> {
    let kind = required(&mut o, "type")?;
    let name = text(&mut o, "tag")?.unwrap_or_else(|| "Imported node".into());
    let host = required(&mut o, "server")?;
    let port = number(&mut o, "server_port")?.ok_or_else(|| invalid("endpoint.port"))?;
    let port = u16::try_from(port).map_err(|_| invalid("endpoint.port"))?;
    let endpoint = Endpoint { host, port };
    endpoint.validate().map_err(|_| invalid("endpoint"))?;
    let (protocol, credential, obfuscation) = match kind.as_str() {
        "shadowsocks" => (
            Protocol::Shadowsocks {
                method: uri::parse_cipher(&required(&mut o, "method")?)?,
            },
            Credential::password(secret(&mut o, "password")?.expose().to_vec()),
            None,
        ),
        "vmess" => {
            let cipher =
                uri::parse_vmess_cipher(text(&mut o, "security")?.as_deref().unwrap_or("auto"))?;
            if number(&mut o, "alter_id")?.unwrap_or(0) != 0 {
                return Err(unsupported("protocol.alterId"));
            }
            (
                Protocol::Vmess {
                    cipher,
                    alter_id: 0,
                },
                Credential::uuid(secret(&mut o, "uuid")?.expose().to_vec()),
                None,
            )
        }
        "vless" => {
            let flow = match text(&mut o, "flow")?.as_deref() {
                None | Some("") => None,
                Some("xtls-rprx-vision") => Some(VlessFlow::XtlsRprxVision),
                _ => return Err(unsupported("protocol.flow")),
            };
            (
                Protocol::Vless { flow },
                Credential::uuid(secret(&mut o, "uuid")?.expose().to_vec()),
                None,
            )
        }
        "trojan" | "anytls" => (
            if kind == "trojan" {
                Protocol::Trojan {}
            } else {
                Protocol::AnyTls {}
            },
            Credential::password(secret(&mut o, "password")?.expose().to_vec()),
            None,
        ),
        "hysteria2" => {
            let obfuscation = if let Some(v) = o.remove("obfs") {
                let mut obfs = object(v)?;
                if required(&mut obfs, "type")? != "salamander" {
                    return Err(unsupported("obfuscation.type"));
                }
                let secret = secret(&mut obfs, "password")?;
                finish(&obfs)?;
                Some(secret)
            } else {
                None
            };
            (
                Protocol::Hysteria2 {
                    obfuscation_ref: None,
                },
                Credential::password(secret(&mut o, "password")?.expose().to_vec()),
                obfuscation,
            )
        }
        "tuic" => {
            let congestion_control = match text(&mut o, "congestion_control")?
                .as_deref()
                .unwrap_or("cubic")
            {
                "cubic" => CongestionControl::Cubic,
                "new_reno" => CongestionControl::NewReno,
                "bbr" => CongestionControl::Bbr,
                _ => return Err(unsupported("protocol.congestionControl")),
            };
            let udp_relay_mode = match text(&mut o, "udp_relay_mode")?
                .as_deref()
                .unwrap_or("native")
            {
                "native" => TuicUdpRelayMode::Native,
                "quic" => TuicUdpRelayMode::Quic,
                _ => return Err(unsupported("protocol.udpRelayMode")),
            };
            (
                Protocol::Tuic {
                    congestion_control,
                    udp_relay_mode,
                },
                Credential {
                    kind: CredentialKind::UuidPassword,
                    primary: secret(&mut o, "uuid")?,
                    secondary: Some(secret(&mut o, "password")?),
                },
                None,
            )
        }
        "socks" => {
            if text(&mut o, "version")?.is_some_and(|v| v != "5") {
                return Err(unsupported("protocol.socks_version"));
            }
            let user = string(&mut o, "username")?;
            let pass = string(&mut o, "password")?;
            let credential = match (user, pass) {
                (None, None) => Credential {
                    kind: CredentialKind::None,
                    primary: SecretBytes::new(Vec::new()),
                    secondary: None,
                },
                (Some(u), Some(p)) => Credential {
                    kind: CredentialKind::UsernamePassword,
                    primary: SecretBytes::new(u.as_bytes().to_vec()),
                    secondary: Some(SecretBytes::new(p.as_bytes().to_vec())),
                },
                _ => return Err(invalid("credential")),
            };
            (Protocol::Socks5 {}, credential, None)
        }
        _ => return Err(unsupported("json.outbound_type")),
    };
    let transport = match o.remove("transport") {
        Some(v) => parse_transport(object(v)?)?,
        None if matches!(protocol, Protocol::Tuic { .. } | Protocol::Hysteria2 { .. }) => {
            Transport::Quic {}
        }
        None => Transport::Tcp {},
    };
    let security = match o.remove("tls") {
        Some(v) => parse_tls(object(v)?, &endpoint.host)?,
        None => ClientSecurity::None {},
    };
    // Every remaining field (network restriction, multiplex, dialer, TLS paths,
    // QUIC tuning, plugin) is rejected rather than dropped as "client local".
    finish(&o)?;
    ImportCandidate::new(
        NodePreview {
            name,
            endpoint,
            protocol,
            transport,
            security,
            has_obfuscation: obfuscation.is_some(),
        },
        SecretBundle {
            credential,
            obfuscation,
        },
    )
}
fn parse_transport(mut o: Object) -> Result<Transport> {
    let kind = required(&mut o, "type")?;
    let path = text(&mut o, "path")?.unwrap_or_else(|| "/".into());
    let transport = match kind.as_str() {
        "ws" => {
            let host = match o.remove("headers") {
                None => None,
                Some(v) => {
                    let mut headers = object(v)?;
                    let host = text(&mut headers, "Host")?;
                    finish(&headers)?;
                    host
                }
            };
            // max_early_data and early_data_header_name remain unsupported;
            // adapters differ on path-query early-data conventions.
            Transport::Ws {
                path,
                host,
                early_data: None,
            }
        }
        "httpupgrade" => Transport::HttpUpgrade {
            path,
            host: required(&mut o, "host")?,
        },
        _ => return Err(unsupported("transport.type")),
    };
    finish(&o)?;
    Ok(transport)
}
fn parse_tls(mut o: Object, endpoint_host: &str) -> Result<ClientSecurity> {
    if !boolean(&mut o, "enabled")?.unwrap_or(false) {
        finish(&o)?;
        return Ok(ClientSecurity::None {});
    }
    if boolean(&mut o, "insecure")?.unwrap_or(false) {
        return Err(issue(IssueKind::InsecureTrust, "security.trust"));
    }
    if boolean(&mut o, "disable_sni")?.unwrap_or(false) {
        return Err(unsupported("security.disableSni"));
    }
    let server_name = text(&mut o, "server_name")?.unwrap_or_else(|| endpoint_host.into());
    let alpn = strings(&mut o, "alpn")?;
    let client_hello_fingerprint = match o.remove("utls") {
        None => None,
        Some(v) => {
            let mut u = object(v)?;
            let enabled = boolean(&mut u, "enabled")?.unwrap_or(false);
            let fp = text(&mut u, "fingerprint")?;
            finish(&u)?;
            if enabled {
                Some(fp.unwrap_or_else(|| "chrome".into()))
            } else if fp.is_some() {
                return Err(unsupported("security.disabledUtls"));
            } else {
                None
            }
        }
    };
    let security = if let Some(v) = o.remove("reality") {
        if !alpn.is_empty() {
            return Err(unsupported("security.reality.alpn"));
        }
        let mut r = object(v)?;
        if !boolean(&mut r, "enabled")?.unwrap_or(false) {
            return Err(unsupported("security.disabledReality"));
        }
        let public_key = required(&mut r, "public_key")?;
        let short_id = text(&mut r, "short_id")?.unwrap_or_default();
        finish(&r)?;
        ClientSecurity::Reality {
            server_name,
            public_key,
            short_id,
            client_hello_fingerprint,
        }
    } else {
        ClientSecurity::Tls {
            server_name,
            alpn,
            trust: TlsTrust::System {},
            client_hello_fingerprint,
        }
    };
    finish(&o)?;
    Ok(security)
}

fn parse_clash(mut o: Object) -> Result<ImportCandidate> {
    // The canonical domain currently has no per-node UDP allow/deny field.
    // Preserve that distinction: only explicit udp:true is accepted here;
    // omitted/default-false and udp:false cannot be silently widened.
    if boolean(&mut o, "udp")? != Some(true) {
        return Err(unsupported("clash.udp_policy"));
    }
    let kind = required(&mut o, "type")?;
    // Initial safe extraction supports SS/SOCKS5 only. TLS/transport dialects
    // need fixtures for their differing implicit defaults before admitting.
    if !matches!(kind.as_str(), "ss" | "socks5") {
        return Err(unsupported("clash.node_type"));
    }
    let name = required(&mut o, "name")?;
    let host = required(&mut o, "server")?;
    let port = u16::try_from(number(&mut o, "port")?.ok_or_else(|| invalid("endpoint.port"))?)
        .map_err(|_| invalid("endpoint.port"))?;
    let endpoint = Endpoint { host, port };
    let (protocol, credential) = if kind == "ss" {
        let method = uri::parse_cipher(&required(&mut o, "cipher")?)?;
        (
            Protocol::Shadowsocks { method },
            Credential::password(secret(&mut o, "password")?.expose().to_vec()),
        )
    } else {
        if boolean(&mut o, "tls")?.unwrap_or(false) {
            return Err(unsupported("clash.socks_tls"));
        }
        let username = string(&mut o, "username")?;
        let password = string(&mut o, "password")?;
        let credential = match (username, password) {
            (None, None) => Credential {
                kind: CredentialKind::None,
                primary: SecretBytes::new(Vec::new()),
                secondary: None,
            },
            (Some(u), Some(p)) => Credential {
                kind: CredentialKind::UsernamePassword,
                primary: SecretBytes::new(u.as_bytes().to_vec()),
                secondary: Some(SecretBytes::new(p.as_bytes().to_vec())),
            },
            _ => return Err(invalid("credential")),
        };
        (Protocol::Socks5 {}, credential)
    };
    finish(&o)?;
    ImportCandidate::new(
        NodePreview {
            name,
            endpoint,
            protocol,
            transport: Transport::Tcp {},
            security: ClientSecurity::None {},
            has_obfuscation: false,
        },
        SecretBundle {
            credential,
            obfuscation: None,
        },
    )
}

pub(crate) fn parse_vmess_legacy(encoded: &str) -> Result<ImportCandidate> {
    let bytes = encoding::decode_base64(encoded, MAX_URI_BYTES)?;
    let input =
        std::str::from_utf8(&bytes).map_err(|_| issue(IssueKind::InvalidUtf8, "vmess.json"))?;
    let mut o = object(read(input)?)?;
    if required(&mut o, "v")? != "2" {
        return Err(unsupported("vmess.version"));
    }
    let name = required(&mut o, "ps")?;
    let host = required(&mut o, "add")?;
    // The documented v2 QR schema uses strings for these numeric fields.
    let port = required(&mut o, "port")?
        .parse::<u16>()
        .map_err(|_| invalid("endpoint.port"))?;
    let id = secret(&mut o, "id")?;
    if text(&mut o, "aid")?.as_deref().unwrap_or("0") != "0" {
        return Err(unsupported("protocol.alterId"));
    }
    let cipher = uri::parse_vmess_cipher(text(&mut o, "scy")?.as_deref().unwrap_or("auto"))?;
    let network = required(&mut o, "net")?;
    let header = text(&mut o, "type")?.unwrap_or_else(|| "none".into());
    if header != "none" {
        return Err(unsupported("transport.headerType"));
    }
    let host_header = text(&mut o, "host")?.filter(|s| !s.is_empty());
    let path = text(&mut o, "path")?.unwrap_or_default();
    let transport = match network.as_str() {
        "tcp" if host_header.is_none() && path.is_empty() => Transport::Tcp {},
        "ws" => Transport::Ws {
            path: if path.is_empty() { "/".into() } else { path },
            host: host_header,
            early_data: None,
        },
        _ => return Err(unsupported("transport.legacy_wire_profile")),
    };
    let tls = text(&mut o, "tls")?.unwrap_or_default();
    let security = match tls.as_str() {
        "" => ClientSecurity::None {},
        "tls" => ClientSecurity::Tls {
            server_name: text(&mut o, "sni")?
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| host.clone()),
            alpn: uri::alpn(text(&mut o, "alpn")?.filter(|s| !s.is_empty()))?,
            trust: TlsTrust::System {},
            client_hello_fingerprint: text(&mut o, "fp")?.filter(|v| !v.is_empty()),
        },
        _ => return Err(unsupported("security.type")),
    };
    finish(&o)?;
    ImportCandidate::new(
        NodePreview {
            name,
            endpoint: Endpoint { host, port },
            protocol: Protocol::Vmess {
                cipher,
                alter_id: 0,
            },
            transport,
            security,
            has_obfuscation: false,
        },
        SecretBundle {
            credential: Credential {
                kind: CredentialKind::Uuid,
                primary: id,
                secondary: None,
            },
            obfuscation: None,
        },
    )
}
