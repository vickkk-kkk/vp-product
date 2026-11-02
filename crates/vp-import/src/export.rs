use crate::encoding::{encode_base64, encode_component};
use crate::*;

/// Explicit credential export boundary. Caller must authorize disclosure and
/// obtain this exact node's secrets from its vault; this pure function cannot
/// prove that a supplied credential belongs to a SecretRef. Returned text must
/// not be logged, implicitly copied to clipboard, or placed in an ordinary DTO.
/// IDs/source/requirements are local metadata, not exported connection fields.
pub fn export_uri(node: &NodeProfile, secrets: &SecretBundle) -> Result<SecretText> {
    export(node, secrets).map_err(|mut e| {
        e.error.stage = ErrorStage::Export;
        e
    })
}
fn lossy(path: &'static str) -> ImportIssue {
    issue(IssueKind::LossyExport, path)
}
fn export(node: &NodeProfile, secrets: &SecretBundle) -> Result<SecretText> {
    node.validate().map_err(|_| invalid("node"))?;
    validate_security(&node.security)?;
    validate_secrets(&node.protocol, secrets)?;
    let expected_obfs = matches!(
        &node.protocol,
        Protocol::Hysteria2 {
            obfuscation_ref: Some(_)
        }
    );
    if expected_obfs != secrets.obfuscation.is_some() {
        return Err(issue(IssueKind::SecretBindingMismatch, "obfuscation"));
    }
    let credential = text_secret(&secrets.credential.primary)?;
    let mut query: Vec<(&str, String)> = Vec::new();
    let scheme;
    let userinfo;
    match &node.protocol {
        Protocol::Shadowsocks { method } => {
            require_plain_tcp(node)?;
            scheme = "ss";
            let method_name = cipher_name(*method);
            userinfo = if method.is_2022() {
                format!(
                    "{}:{}",
                    encode_component(method_name),
                    encode_component(credential)
                )
            } else {
                let combined = Zeroizing::new(format!("{method_name}:{credential}"));
                encode_base64(combined.as_bytes())
            };
        }
        Protocol::Socks5 {} => {
            require_plain_tcp(node)?;
            scheme = "socks5";
            userinfo = if secrets.credential.kind == CredentialKind::None {
                String::new()
            } else {
                let pass = text_secret(
                    secrets
                        .credential
                        .secondary
                        .as_ref()
                        .ok_or_else(|| invalid("credential"))?,
                )?;
                format!(
                    "{}:{}",
                    encode_component(credential),
                    encode_component(pass)
                )
            };
        }
        Protocol::Vmess { cipher, alter_id } => {
            if *alter_id != 0 {
                return Err(lossy("protocol.alterId"));
            }
            scheme = "vmess";
            userinfo = encode_component(credential);
            query.push(("encryption", vmess_cipher_name(*cipher).into()));
            xray_transport(&node.transport, &mut query)?;
            xray_security(&node.security, &mut query)?;
        }
        Protocol::Vless { flow } => {
            scheme = "vless";
            userinfo = encode_component(credential);
            query.push(("encryption", "none".into()));
            if flow.is_some() {
                query.push(("flow", "xtls-rprx-vision".into()));
            }
            xray_transport(&node.transport, &mut query)?;
            xray_security(&node.security, &mut query)?;
        }
        Protocol::Trojan {} | Protocol::AnyTls {} | Protocol::Hysteria2 { .. } => {
            scheme = match &node.protocol {
                Protocol::Trojan {} => "trojan",
                Protocol::AnyTls {} => "anytls",
                _ => "hysteria2",
            };
            if (scheme == "hysteria2" && node.transport != Transport::Quic {})
                || (scheme != "hysteria2" && node.transport != Transport::Tcp {})
            {
                return Err(lossy("transport"));
            }
            match &node.security {
                ClientSecurity::Tls {
                    server_name,
                    alpn,
                    trust: TlsTrust::System {},
                    client_hello_fingerprint: None,
                } if alpn.is_empty() => {
                    query.push(("sni", server_name.clone()));
                }
                _ => return Err(lossy("security")),
            }
            userinfo = encode_component(credential);
            if let Some(obfs) = &secrets.obfuscation {
                query.push(("obfs", "salamander".into()));
                query.push(("obfs-password", text_secret(obfs)?.into()));
            }
        }
        Protocol::Tuic { .. } => return Err(lossy("uri.tuic_dialect")),
    }
    let userinfo = Zeroizing::new(userinfo);
    let host = if node.endpoint.host.contains(':') {
        format!("[{}]", node.endpoint.host)
    } else {
        node.endpoint.host.clone()
    };
    let auth_separator = if userinfo.is_empty() { "" } else { "@" };
    let mut result = Zeroizing::new(format!(
        "{scheme}://{}{auth_separator}{host}:{}",
        userinfo.as_str(),
        node.endpoint.port
    ));
    // Query values include obfuscation passwords. Wipe on normal drop.
    for (i, (key, value)) in query.into_iter().enumerate() {
        let value = Zeroizing::new(value);
        result.push(if i == 0 { '?' } else { '&' });
        result.push_str(key);
        result.push('=');
        result.push_str(&encode_component(&value));
    }
    result.push('#');
    result.push_str(&encode_component(&node.name));
    if result.len() > MAX_URI_BYTES {
        return Err(issue(IssueKind::InputLimit, "uri"));
    }
    Ok(SecretText::new(std::mem::take(&mut *result)))
}
fn require_plain_tcp(node: &NodeProfile) -> Result<()> {
    if node.transport != (Transport::Tcp {}) || node.security != (ClientSecurity::None {}) {
        return Err(lossy("transport.security"));
    }
    Ok(())
}
fn xray_transport(transport: &Transport, query: &mut Vec<(&str, String)>) -> Result<()> {
    match transport {
        Transport::Tcp {} => query.push(("type", "tcp".into())),
        Transport::Ws {
            path,
            host,
            early_data: None,
        } => {
            query.push(("type", "ws".into()));
            query.push(("path", path.clone()));
            if let Some(host) = host {
                query.push(("host", host.clone()));
            }
        }
        Transport::HttpUpgrade { path, host } => {
            query.push(("type", "httpupgrade".into()));
            query.push(("path", path.clone()));
            query.push(("host", host.clone()));
        }
        _ => return Err(lossy("transport")),
    }
    Ok(())
}
fn xray_security(security: &ClientSecurity, query: &mut Vec<(&str, String)>) -> Result<()> {
    match security {
        ClientSecurity::None {} => query.push(("security", "none".into())),
        ClientSecurity::Tls {
            server_name,
            alpn,
            trust: TlsTrust::System {},
            client_hello_fingerprint: Some(fp),
        } => {
            query.push(("security", "tls".into()));
            query.push(("sni", server_name.clone()));
            query.push(("fp", fp.clone()));
            if !alpn.is_empty() {
                query.push(("alpn", alpn.join(",")));
            }
        }
        ClientSecurity::Reality {
            server_name,
            public_key,
            short_id,
            client_hello_fingerprint: Some(fp),
        } => {
            query.push(("security", "reality".into()));
            query.push(("sni", server_name.clone()));
            query.push(("pbk", public_key.clone()));
            query.push(("sid", short_id.clone()));
            query.push(("fp", fp.clone()));
        }
        // URI default fp=chrome cannot represent unspecified native TLS.
        // CA/SPKI/certificate trust is never replaced with skip-verification.
        _ => return Err(lossy("security")),
    }
    Ok(())
}
fn cipher_name(cipher: ShadowsocksCipher) -> &'static str {
    use ShadowsocksCipher::*;
    match cipher {
        Aes128Gcm => "aes-128-gcm",
        Aes256Gcm => "aes-256-gcm",
        Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        Xchacha20IetfPoly1305 => "xchacha20-ietf-poly1305",
        Blake3Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
        Blake3Aes256Gcm2022 => "2022-blake3-aes-256-gcm",
        Blake3Chacha20Poly13052022 => "2022-blake3-chacha20-poly1305",
    }
}
fn vmess_cipher_name(cipher: VmessCipher) -> &'static str {
    match cipher {
        VmessCipher::Auto => "auto",
        VmessCipher::Aes128Gcm => "aes-128-gcm",
        VmessCipher::Chacha20Poly1305 => "chacha20-poly1305",
        VmessCipher::None => "none",
    }
}
