use crate::encoding::{decode_base64, decode_component};
use crate::*;
use std::collections::BTreeMap;

struct Uri<'a> {
    scheme: &'a str,
    userinfo: Option<&'a str>,
    endpoint: Endpoint,
    query: BTreeMap<String, Zeroizing<String>>,
    name: String,
}
impl<'a> Uri<'a> {
    fn take(&mut self, key: &str) -> Option<Zeroizing<String>> {
        self.query.remove(key)
    }
    fn value(&mut self, key: &str) -> Option<String> {
        self.take(key).map(|v| v.to_string())
    }
    fn finish(&self) -> Result<()> {
        if self.query.is_empty() {
            Ok(())
        } else {
            Err(issue(IssueKind::UnknownField, "uri.query"))
        }
    }
}
pub(crate) fn parse_uri(input: &str) -> Result<ImportCandidate> {
    if !input.is_ascii()
        || input
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b"\"<>\\^`{|}".contains(&b))
    {
        return Err(issue(IssueKind::InvalidSyntax, "uri"));
    }
    let (scheme, remainder) = input
        .split_once("://")
        .ok_or_else(|| invalid("uri.scheme"))?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme == "vmess" && !remainder.contains('@') {
        return crate::json::parse_vmess_legacy(remainder);
    }
    if !matches!(
        scheme.as_str(),
        "ss" | "socks" | "socks5" | "vmess" | "vless" | "trojan" | "hy2" | "hysteria2" | "anytls"
    ) {
        return Err(issue(IssueKind::UnsupportedScheme, "uri.scheme"));
    }
    let mut uri = split(&scheme, remainder)?;
    for flag in ["insecure", "allowInsecure", "skip-cert-verify"] {
        if let Some(v) = uri.take(flag) {
            if v.as_str() != "0" && v.as_str() != "false" {
                return Err(issue(IssueKind::InsecureTrust, "security.trust"));
            }
            // Only the formats that define this flag may accept a false value.
            if flag != "insecure" || !matches!(uri.scheme, "hy2" | "hysteria2" | "anytls") {
                return Err(unsupported("security.option"));
            }
        }
    }
    let (protocol, transport, security, credential, obfuscation) = match uri.scheme {
        "ss" => parse_ss(&mut uri)?,
        "socks" | "socks5" => parse_socks(&mut uri)?,
        "vmess" | "vless" => parse_xray(&mut uri)?,
        "trojan" => {
            // Trojan base authority plus the documented sni query dialect.
            let credential = password(&uri, false)?;
            let server_name = uri
                .value("sni")
                .unwrap_or_else(|| uri.endpoint.host.clone());
            let security = ClientSecurity::Tls {
                server_name,
                alpn: Vec::new(),
                trust: TlsTrust::System {},
                client_hello_fingerprint: None,
            };
            (
                Protocol::Trojan {},
                Transport::Tcp {},
                security,
                credential,
                None,
            )
        }
        "hy2" | "hysteria2" | "anytls" => {
            let credential = password(&uri, true)?;
            let server_name = uri
                .value("sni")
                .unwrap_or_else(|| uri.endpoint.host.clone());
            let security = ClientSecurity::Tls {
                server_name,
                alpn: Vec::new(),
                trust: TlsTrust::System {},
                client_hello_fingerprint: None,
            };
            if uri.scheme == "anytls" {
                (
                    Protocol::AnyTls {},
                    Transport::Tcp {},
                    security,
                    credential,
                    None,
                )
            } else {
                let obfuscation = match uri.take("obfs") {
                    None => {
                        if uri.query.contains_key("obfs-password") {
                            return Err(invalid("obfuscation"));
                        }
                        None
                    }
                    Some(v) if v.as_str() == "salamander" => Some(SecretBytes::new(
                        uri.take("obfs-password")
                            .ok_or_else(|| invalid("obfuscation.password"))?
                            .as_bytes()
                            .to_vec(),
                    )),
                    Some(_) => return Err(unsupported("obfuscation.type")),
                };
                // pinSHA256 is a CERTIFICATE hash, not TlsTrust::SpkiSha256.
                if uri.query.contains_key("pinSHA256") {
                    return Err(unsupported("security.certificate_pin"));
                }
                (
                    Protocol::Hysteria2 {
                        obfuscation_ref: None,
                    },
                    Transport::Quic {},
                    security,
                    credential,
                    obfuscation,
                )
            }
        }
        _ => return Err(issue(IssueKind::UnsupportedScheme, "uri.scheme")),
    };
    uri.finish()?;
    ImportCandidate::new(
        NodePreview {
            name: uri.name,
            endpoint: uri.endpoint,
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
type Parts = (
    Protocol,
    Transport,
    ClientSecurity,
    Credential,
    Option<SecretBytes>,
);
fn split<'a>(scheme: &'a str, input: &'a str) -> Result<Uri<'a>> {
    let (before_fragment, fragment) = input
        .split_once('#')
        .map_or((input, None), |(a, b)| (a, Some(b)));
    if fragment.is_some_and(|s| s.contains('#')) {
        return Err(invalid("uri.fragment"));
    }
    let (authority_path, query) = before_fragment
        .split_once('?')
        .map_or((before_fragment, None), |(a, b)| (a, Some(b)));
    let authority = authority_path.strip_suffix('/').unwrap_or(authority_path);
    if authority.contains('/') {
        return Err(unsupported("uri.path"));
    }
    let (userinfo, endpoint) = authority
        .rsplit_once('@')
        .map_or((None, authority), |(a, b)| (Some(a), b));
    if userinfo.is_some_and(|u| u.contains('@')) {
        return Err(invalid("uri.userinfo"));
    }
    let default_port = if matches!(scheme, "hy2" | "hysteria2" | "anytls") {
        Some(443)
    } else {
        None
    };
    let endpoint = parse_endpoint(endpoint, default_port)?;
    let mut fields = BTreeMap::new();
    if let Some(query) = query {
        if query.is_empty() {
            return Err(invalid("uri.query"));
        }
        for (i, pair) in query.split('&').enumerate() {
            if i >= MAX_QUERY_FIELDS {
                return Err(issue(IssueKind::InputLimit, "uri.query"));
            }
            let (key, value) = pair.split_once('=').ok_or_else(|| invalid("uri.query"))?;
            let key = decode_component(key)?.to_string();
            if key.is_empty() || key.len() > 64 {
                return Err(invalid("uri.query"));
            }
            let value = decode_component(value)?;
            if fields.insert(key, value).is_some() {
                return Err(issue(IssueKind::DuplicateField, "uri.query"));
            }
        }
    }
    let name = match fragment {
        Some(f) => decode_component(f)?.to_string(),
        None => "Imported node".into(),
    };
    Ok(Uri {
        scheme,
        userinfo,
        endpoint,
        query: fields,
        name,
    })
}
pub(crate) fn parse_endpoint(input: &str, default_port: Option<u16>) -> Result<Endpoint> {
    let (host, port) = if let Some(tail) = input.strip_prefix('[') {
        let (host, tail) = tail.split_once(']').ok_or_else(|| invalid("endpoint"))?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid("endpoint.host"));
        }
        let port = if tail.is_empty() {
            default_port.ok_or_else(|| invalid("endpoint.port"))?
        } else {
            parse_port(tail.strip_prefix(':').ok_or_else(|| invalid("endpoint"))?)?
        };
        (host, port)
    } else {
        if input.contains('[') || input.contains(']') {
            return Err(invalid("endpoint.host"));
        }
        let (host, port) = match input.rsplit_once(':') {
            Some((h, p)) => (h, parse_port(p)?),
            None => (input, default_port.ok_or_else(|| invalid("endpoint.port"))?),
        };
        if host.contains(':') {
            return Err(invalid("endpoint.ipv6_brackets"));
        }
        (host, port)
    };
    let host = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        host.to_ascii_lowercase()
    };
    let endpoint = Endpoint { host, port };
    endpoint.validate().map_err(|_| invalid("endpoint"))?;
    Ok(endpoint)
}
fn parse_port(value: &str) -> Result<u16> {
    if value.contains(',') || value.contains('-') {
        return Err(unsupported("endpoint.port_hopping"));
    }
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("endpoint.port"));
    }
    let port = value.parse::<u16>().map_err(|_| invalid("endpoint.port"))?;
    if port == 0 {
        return Err(invalid("endpoint.port"));
    }
    Ok(port)
}
fn password(uri: &Uri<'_>, allow_absent: bool) -> Result<Credential> {
    let raw = match uri.userinfo {
        Some(v) => v,
        None if allow_absent => return Err(unsupported("credential.empty_auth")),
        None => return Err(invalid("credential")),
    };
    Ok(Credential::password(
        decode_component(raw)?.as_bytes().to_vec(),
    ))
}
fn parse_ss(uri: &mut Uri<'_>) -> Result<Parts> {
    let raw = uri.userinfo.ok_or_else(|| unsupported("uri.ss_legacy"))?;
    let (method, password, was_base64) = if let Some((m, p)) = raw.split_once(':') {
        (
            decode_component(m)?.to_string(),
            decode_component(p)?,
            false,
        )
    } else {
        let decoded = decode_base64(raw, MAX_COMPONENT_BYTES)?;
        let decoded = std::str::from_utf8(&decoded).map_err(|_| invalid("credential"))?;
        let (m, p) = decoded
            .split_once(':')
            .ok_or_else(|| invalid("credential"))?;
        (m.to_string(), Zeroizing::new(p.to_string()), true)
    };
    let method = parse_cipher(&method)?;
    if method.is_2022() && was_base64 {
        return Err(invalid("uri.ss2022_userinfo"));
    }
    if uri.query.contains_key("plugin") {
        return Err(unsupported("transport.plugin"));
    }
    Ok((
        Protocol::Shadowsocks { method },
        Transport::Tcp {},
        ClientSecurity::None {},
        Credential::password(password.as_bytes().to_vec()),
        None,
    ))
}
pub(crate) fn parse_cipher(method: &str) -> Result<ShadowsocksCipher> {
    use ShadowsocksCipher::*;
    match method {
        "aes-128-gcm" => Ok(Aes128Gcm),
        "aes-256-gcm" => Ok(Aes256Gcm),
        "chacha20-ietf-poly1305" => Ok(Chacha20IetfPoly1305),
        "xchacha20-ietf-poly1305" => Ok(Xchacha20IetfPoly1305),
        "2022-blake3-aes-128-gcm" => Ok(Blake3Aes128Gcm2022),
        "2022-blake3-aes-256-gcm" => Ok(Blake3Aes256Gcm2022),
        "2022-blake3-chacha20-poly1305" => Ok(Blake3Chacha20Poly13052022),
        _ => Err(unsupported("protocol.cipher")),
    }
}
fn parse_socks(uri: &mut Uri<'_>) -> Result<Parts> {
    let credential = match uri.userinfo {
        None => Credential {
            kind: CredentialKind::None,
            primary: SecretBytes::new(Vec::new()),
            secondary: None,
        },
        Some(raw) => {
            let (user, pass) = raw
                .split_once(':')
                .ok_or_else(|| unsupported("uri.socks_base64_auth"))?;
            Credential {
                kind: CredentialKind::UsernamePassword,
                primary: SecretBytes::new(decode_component(user)?.as_bytes().to_vec()),
                secondary: Some(SecretBytes::new(
                    decode_component(pass)?.as_bytes().to_vec(),
                )),
            }
        }
    };
    Ok((
        Protocol::Socks5 {},
        Transport::Tcp {},
        ClientSecurity::None {},
        credential,
        None,
    ))
}
fn parse_xray(uri: &mut Uri<'_>) -> Result<Parts> {
    let id = decode_component(uri.userinfo.ok_or_else(|| invalid("credential"))?)?;
    if !valid_uuid(&id) {
        return Err(invalid("credential.uuid"));
    }
    let protocol = if uri.scheme == "vmess" {
        Protocol::Vmess {
            cipher: parse_vmess_cipher(uri.value("encryption").as_deref().unwrap_or("auto"))?,
            alter_id: 0,
        }
    } else {
        if uri.value("encryption").is_some_and(|e| e != "none") {
            return Err(unsupported("protocol.encryption"));
        }
        let flow = match uri.value("flow").as_deref() {
            None | Some("") => None,
            Some("xtls-rprx-vision") => Some(VlessFlow::XtlsRprxVision),
            _ => return Err(unsupported("protocol.flow")),
        };
        Protocol::Vless { flow }
    };
    let transport = match uri.value("type").as_deref().unwrap_or("tcp") {
        "tcp" => Transport::Tcp {},
        "ws" => Transport::Ws {
            path: uri.value("path").unwrap_or_else(|| "/".into()),
            host: uri.value("host"),
            early_data: None,
        },
        "httpupgrade" => Transport::HttpUpgrade {
            path: uri.value("path").unwrap_or_else(|| "/".into()),
            host: uri
                .value("host")
                .ok_or_else(|| unsupported("transport.httpupgrade.host_default"))?,
        },
        // HTTP/QUIC names have historically incompatible wire meanings.
        _ => return Err(unsupported("transport.type")),
    };
    let security = match uri.value("security").as_deref().unwrap_or("none") {
        "none" => ClientSecurity::None {},
        "tls" => ClientSecurity::Tls {
            server_name: uri
                .value("sni")
                .unwrap_or_else(|| uri.endpoint.host.clone()),
            alpn: alpn(uri.value("alpn"))?,
            trust: TlsTrust::System {},
            client_hello_fingerprint: Some(uri.value("fp").unwrap_or_else(|| "chrome".into())),
        },
        "reality" => ClientSecurity::Reality {
            server_name: uri
                .value("sni")
                .unwrap_or_else(|| uri.endpoint.host.clone()),
            public_key: uri
                .value("pbk")
                .ok_or_else(|| invalid("security.publicKey"))?,
            short_id: uri.value("sid").unwrap_or_default(),
            client_hello_fingerprint: Some(
                uri.value("fp")
                    .ok_or_else(|| invalid("security.clientHelloFingerprint"))?,
            ),
        },
        _ => return Err(unsupported("security.type")),
    };
    Ok((
        protocol,
        transport,
        security,
        Credential::uuid(id.as_bytes().to_vec()),
        None,
    ))
}
pub(crate) fn parse_vmess_cipher(value: &str) -> Result<VmessCipher> {
    match value {
        "auto" => Ok(VmessCipher::Auto),
        "aes-128-gcm" => Ok(VmessCipher::Aes128Gcm),
        "chacha20-poly1305" => Ok(VmessCipher::Chacha20Poly1305),
        "none" => Ok(VmessCipher::None),
        _ => Err(unsupported("protocol.cipher")),
    }
}
pub(crate) fn alpn(value: Option<String>) -> Result<Vec<String>> {
    match value {
        None => Ok(Vec::new()),
        Some(v) => {
            if v.is_empty() {
                return Err(invalid("security.alpn"));
            }
            let values: Vec<String> = v.split(',').map(str::to_owned).collect();
            if values.len() > 16
                || values
                    .iter()
                    .any(|v| v.is_empty() || v.len() > 255 || v.chars().any(char::is_whitespace))
            {
                return Err(invalid("security.alpn"));
            }
            Ok(values)
        }
    }
}
