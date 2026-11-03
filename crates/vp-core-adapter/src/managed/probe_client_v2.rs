//! Experimental bounded local client for an explicitly supplied challenge target.
//! A response is not independent interoperability or release certification.
use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};
use sha2::{Digest, Sha224, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vp_core::{Outbound, ProxyStream, Session};
use vp_product_compiler::server_v2::{ServerListenerV2, ServerProtocolV2, ServerSecurityV2, ServerTransportV2};
use vp_product_domain::{Protocol, SecretBytes, ServerListener, ServerProtocol, ServerSecurity, ShadowsocksCipher, Transport};
use zeroize::{Zeroize, Zeroizing};
use super::Failure;

/// Validate a TLS server name without network access.
pub fn validate_server_name(name: &str) -> Result<(), Failure> {
    rustls::pki_types::ServerName::try_from(name.to_owned()).map(|_| ()).map_err(|_| Failure::InvalidConfig)
}
/// Validate supplied TLS trust inputs without opening a socket.
pub fn validate_tls_trust(root_der: &[Vec<u8>], tls_name: &str) -> Result<(), Failure> {
    if root_der.is_empty() || root_der.len() > 8 || root_der.iter().map(Vec::len).sum::<usize>() > 65536 { return Err(Failure::InvalidConfig); }
    rustls::pki_types::ServerName::try_from(tls_name.to_owned()).map_err(|_| Failure::InvalidConfig)?;
    let mut roots = rustls::RootCertStore::empty();
    for der in root_der { roots.add(rustls::pki_types::CertificateDer::from(der.clone())).map_err(|_| Failure::InvalidConfig)?; }
    Ok(())
}

/// Reserved in-process sink address; never a network destination.
pub fn virtual_probe_target() -> SocketAddr { vp_core::experimental_virtual_probe::TARGET }
/// A one-way observation key; probe tokens are random and never logged.
pub fn virtual_probe_hash(token: &[u8; 32]) -> String { Sha256::digest(token).iter().map(|b| format!("{b:02x}")).collect() }

/// Perform one bounded protocol attempt to a numeric challenge target. A false
/// result means no expected response was observed, not proof of rejection. The
/// caller must also inspect the target's own one-use challenge ledger.
pub async fn challenge(
    listener: &ServerListenerV2, source: &ServerListener, target: SocketAddr,
    credential: &SecretBytes, root_der: &[Vec<u8>], tls_name: &str, token: &[u8; 32], timeout: Duration,
) -> Result<bool, Failure> {
    validate_request(listener, source, target, credential, timeout)?;
    tokio::time::timeout(timeout, attempt(listener, source, target, credential, root_der, tls_name, token))
        .await.map_err(|_| Failure::Timeout)?
}
fn validate_request(listener: &ServerListenerV2, source: &ServerListener, target: SocketAddr,
    credential: &SecretBytes, timeout: Duration) -> Result<(), Failure> {
    let protocol_matches = matches!((&listener.protocol, &source.protocol),
        (ServerProtocolV2::Trojan {}, ServerProtocol::Proxy { protocol: Protocol::Trojan {}, .. })
        | (ServerProtocolV2::Vless {}, ServerProtocol::Proxy { protocol: Protocol::Vless { flow: None }, .. })
        | (ServerProtocolV2::Vmess {}, ServerProtocol::Proxy { protocol: Protocol::Vmess { cipher: vp_product_domain::VmessCipher::Auto, alter_id: 0 }, .. })
        | (ServerProtocolV2::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }, ServerProtocol::Proxy { protocol: Protocol::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }, .. }));
    let security_matches = match (&listener.security, &source.security) {
        (ServerSecurityV2::None {}, ServerSecurity::None {}) => true,
        (ServerSecurityV2::Tls { certificate_ref: a, private_key_ref: b, alpn: c }, ServerSecurity::Tls { certificate_ref: x, private_key_ref: y, alpn: z }) => a == x && b == y && c == z,
        _ => false,
    };
    if timeout.is_zero() || timeout > Duration::from_secs(10) || target.port() == 0
        || !target.is_ipv4() || listener.id != source.id || listener.bind != source.bind
        || !protocol_matches || !security_matches || credential.expose().is_empty() || credential.expose().len() > 4096 {
        return Err(Failure::InvalidConfig);
    }
    Ok(())
}
async fn attempt(
    listener: &ServerListenerV2, source: &ServerListener, target: SocketAddr,
    credential: &SecretBytes, root_der: &[Vec<u8>], tls_name: &str, token: &[u8; 32],
) -> Result<bool, Failure> {
    let mut io = open_proxy(listener, source, target, credential, root_der, tls_name).await?;
    if io.write_all(token).await.is_err() || io.flush().await.is_err() { return Ok(false); }
    if matches!(listener.protocol, ServerProtocolV2::Vless {}) {
        let mut header = [0u8;2];
        if io.read_exact(&mut header).await.is_err() { return Ok(false); }
        if header != [0,0] { return Ok(false); }
    }
    let mut response = [0u8; 12];
    Ok(io.read_exact(&mut response).await.is_ok() && &response == b"VP-ORACLE-OK")
}

/// Establish the protocol carrier; response framing remains with the caller.
async fn open_proxy(listener: &ServerListenerV2, source: &ServerListener, target: SocketAddr,
    credential: &SecretBytes, root_der: &[Vec<u8>], tls_name: &str) -> Result<Box<dyn ProxyStream>, Failure> {
    let tcp = tokio::net::TcpStream::connect(SocketAddr::new(listener.bind.address, listener.bind.port)).await.map_err(|_| Failure::Io)?;
    let mut io: Box<dyn ProxyStream> = Box::new(tcp);
    match &listener.security {
        ServerSecurityV2::None {} => {},
        ServerSecurityV2::Tls { alpn, .. } => {
            validate_tls_trust(root_der, tls_name)?;
            let mut roots = rustls::RootCertStore::empty();
            for der in root_der { roots.add(rustls::pki_types::CertificateDer::from(der.clone())).map_err(|_| Failure::InvalidConfig)?; }
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions().map_err(|_| Failure::InvalidConfig)?
                .with_root_certificates(roots).with_no_client_auth();
            config.alpn_protocols = alpn.iter().map(|v| v.as_bytes().to_vec()).collect();
            let name = rustls::pki_types::ServerName::try_from(tls_name.to_owned()).map_err(|_| Failure::InvalidConfig)?;
            let stream = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, io).await.map_err(|_| Failure::ProtocolViolation)?;
            if !alpn.is_empty() && !stream.get_ref().1.alpn_protocol().is_some_and(|value| alpn.iter().any(|v| v.as_bytes() == value)) { return Err(Failure::ProtocolViolation); }
            io = Box::new(stream);
        }
    }
    match (&listener.transport, &source.transport) {
        (ServerTransportV2::Tcp {}, Transport::Tcp {}) => {},
        (ServerTransportV2::WebSocket { host, .. }, Transport::Ws { path, .. }) => {
            let authority = host.as_deref().unwrap_or(tls_name);
            io = Box::new(vp_transport::ws::ws_handshake_client(io, authority, &vp_transport::WsConfig { path: path.clone(), headers: vec![] }).await.map_err(|_| Failure::ProtocolViolation)?);
        }
        _ => return Err(Failure::InvalidConfig),
    }
    let IpAddr::V4(ip) = target.ip() else { return Err(Failure::InvalidConfig) };
    match listener.protocol {
        ServerProtocolV2::Trojan {} => {
            let mut head = Zeroizing::new(Sha224::digest(credential.expose()).iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes());
            head.extend_from_slice(b"\r\n\x01\x01"); head.extend_from_slice(&ip.octets()); head.extend_from_slice(&target.port().to_be_bytes()); head.extend_from_slice(b"\r\n");
            io.write_all(&head).await.map_err(|_| Failure::Io)?;
        }
        ServerProtocolV2::Vless {} => {
            let uuid = std::str::from_utf8(credential.expose()).map_err(|_| Failure::InvalidConfig)?;
            if uuid.len() != 36 || uuid.bytes().enumerate().any(|(i,b)| if [8,13,18,23].contains(&i) { b != b'-' } else { !b.is_ascii_hexdigit() || b.is_ascii_uppercase() }) { return Err(Failure::InvalidConfig); }
            let mut id = [0u8; 16]; let mut j = 0; let mut high = None;
            for b in uuid.bytes().filter(|b| *b != b'-') { let n = (b as char).to_digit(16).ok_or(Failure::InvalidConfig)? as u8; if let Some(h) = high.take() { id[j] = h << 4 | n; j += 1; } else { high = Some(n); } }
            let mut head = Zeroizing::new(vec![0]); head.extend_from_slice(&id); id.zeroize(); head.extend_from_slice(&[0,1]); head.extend_from_slice(&target.port().to_be_bytes()); head.push(1); head.extend_from_slice(&ip.octets());
            io.write_all(&head).await.map_err(|_| Failure::Io)?;
        }
        ServerProtocolV2::Vmess {} => {
            let uuid = std::str::from_utf8(credential.expose()).map_err(|_| Failure::InvalidConfig)?.to_owned();
            let mut cfg = vp_config::VmessCfg { server: listener.bind.address.to_string(), port: listener.bind.port, uuid, alter_id: 0, cipher: "auto".into(), tls: false, server_name: None, skip_cert_verify: false, client_fingerprint: None, network: None, alpn: None, ech_opts: None, ws_opts: None, grpc_opts: None, http_opts: None, udp: false };
            let built = vp_protocol::vmess::VmessOutbound::new(&cfg); cfg.uuid.zeroize();
            let outbound = built.map_err(|_| Failure::InvalidConfig)?;
            let destination = vp_common::DstAddr::ip(target.ip(), target.port());
            let session = Session::new_tcp("probe".into(), None, destination.clone());
            io = outbound.connect_over(&session, &destination, io).await.map_err(|_| Failure::ProtocolViolation)?;
        }
        ServerProtocolV2::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm } => {
            let mut password = std::str::from_utf8(credential.expose()).map_err(|_| Failure::InvalidConfig)?.to_owned();
            let mut cfg = vp_config::SsCfg { server: listener.bind.address.to_string(), port: listener.bind.port, cipher: "aes-128-gcm".into(), password: std::mem::take(&mut password), udp: false, plugin: None, plugin_opts: None };
            let built = vp_protocol::ss::SsOutbound::new(&cfg); cfg.password.zeroize();
            let outbound = built.map_err(|_| Failure::InvalidConfig)?;
            let destination = vp_common::DstAddr::ip(target.ip(), target.port());
            let session = Session::new_tcp("probe".into(), None, destination.clone());
            io = outbound.connect_over(&session, &destination, io).await.map_err(|_| Failure::ProtocolViolation)?;
        }
        _ => return Err(Failure::InvalidConfig),
    }
    Ok(io)
}

/// Bounded independent TLS/HTTP response through the proxy. This checks an
/// explicitly approved numeric destination and server certificate; it does not
/// prove rejection of invalid credentials or independently certify the client.
/// Trust is chosen by the backend, not by a network response.
#[derive(Clone)]
pub enum HttpsTargetTrust { PinnedDer(Vec<Vec<u8>>), PublicWebPki }
#[allow(clippy::too_many_arguments)]
pub async fn https_status(
    listener: &ServerListenerV2, source: &ServerListener, target: SocketAddr,
    credential: &SecretBytes, inbound_roots: &[Vec<u8>], inbound_name: &str,
    target_roots: &[Vec<u8>], target_name: &str, path: &str, status: u16, timeout: Duration,
) -> Result<bool, Failure> {
    https_status_with_trust(listener, source, target, credential, inbound_roots, inbound_name,
        &HttpsTargetTrust::PinnedDer(target_roots.to_vec()), target_name, path, status, timeout).await
}
#[allow(clippy::too_many_arguments)]
pub async fn https_status_with_trust(
    listener: &ServerListenerV2, source: &ServerListener, target: SocketAddr,
    credential: &SecretBytes, inbound_roots: &[Vec<u8>], inbound_name: &str,
    target_trust: &HttpsTargetTrust, target_name: &str, path: &str, status: u16, timeout: Duration,
) -> Result<bool, Failure> {
    validate_request(listener, source, target, credential, timeout)?;
    rustls::pki_types::ServerName::try_from(target_name.to_owned()).map_err(|_| Failure::InvalidConfig)?;
    if let HttpsTargetTrust::PinnedDer(roots) = target_trust { validate_tls_trust(roots, target_name)?; }
    if !path.starts_with('/') || path.len() > 256 || !path.bytes().all(|b| (0x21..=0x7e).contains(&b))
        || !(200..=299).contains(&status) { return Err(Failure::InvalidConfig); }
    tokio::time::timeout(timeout, async {
        let io = open_proxy(listener, source, target, credential, inbound_roots, inbound_name).await?;
        let io: Box<dyn ProxyStream> = if matches!(listener.protocol, ServerProtocolV2::Vless {}) {
            Box::new(VlessResponse { inner: io, header: [0; 2], used: 0 })
        } else { io };
        let mut roots = rustls::RootCertStore::empty();
        match target_trust {
            HttpsTargetTrust::PinnedDer(items) => for der in items { roots.add(rustls::pki_types::CertificateDer::from(der.clone())).map_err(|_| Failure::InvalidConfig)?; },
            HttpsTargetTrust::PublicWebPki => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        if roots.is_empty() { return Err(Failure::InvalidConfig); }
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().map_err(|_| Failure::InvalidConfig)?
            .with_root_certificates(roots).with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = rustls::pki_types::ServerName::try_from(target_name.to_owned()).map_err(|_| Failure::InvalidConfig)?;
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, io).await.map_err(|_| Failure::ProtocolViolation)?;
        if tls.get_ref().1.alpn_protocol().is_some_and(|v| v != b"http/1.1") { return Err(Failure::ProtocolViolation); }
        let request = format!("GET {path} HTTP/1.1\r\nHost: {target_name}\r\nConnection: close\r\n\r\n");
        tls.write_all(request.as_bytes()).await.map_err(|_| Failure::Io)?;
        tls.flush().await.map_err(|_| Failure::Io)?;
        let mut line = Vec::with_capacity(128);
        while line.len() < 512 {
            let mut byte = [0u8; 1];
            if tls.read_exact(&mut byte).await.is_err() { return Ok(false); }
            line.push(byte[0]);
            if line.ends_with(b"\r\n") { break; }
        }
        if !line.ends_with(b"\r\n") { return Ok(false); }
        let expected = format!("HTTP/1.1 {status} ");
        Ok(line.starts_with(expected.as_bytes()) && line[expected.len()..line.len()-2].iter().all(|b| (0x20..=0x7e).contains(b)))
    }).await.map_err(|_| Failure::Timeout)?
}

/// Strip exactly the fixed VLESS response header on first read, while allowing
/// the TLS client to send its ClientHello before the peer responds.
struct VlessResponse { inner: Box<dyn ProxyStream>, header: [u8; 2], used: usize }
impl tokio::io::AsyncRead for VlessResponse {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, out: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        if out.remaining() == 0 { return std::task::Poll::Ready(Ok(())); }
        while self.used < 2 {
            let mut byte = [0u8; 1]; let mut buf = tokio::io::ReadBuf::new(&mut byte);
            match std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(())) if buf.filled().is_empty() => return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "vless header"))),
                std::task::Poll::Ready(Ok(())) => { let index = self.used; self.header[index] = byte[0]; self.used += 1; }
            }
        }
        if self.header != [0, 0] { return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "vless header"))); }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, out)
    }
}
impl tokio::io::AsyncWrite for VlessResponse {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, bytes: &[u8]) -> std::task::Poll<std::io::Result<usize>> { std::pin::Pin::new(&mut self.inner).poll_write(cx, bytes) }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> { std::pin::Pin::new(&mut self.inner).poll_flush(cx) }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> { std::pin::Pin::new(&mut self.inner).poll_shutdown(cx) }
}

#[cfg(test)]
mod virtual_tests {
    use super::*;
    #[test]
    fn virtual_direct_is_intercepted_and_real_socket_remains_denied() {
        const CHILD: &str = "VP_VIRTUAL_DIRECT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact").arg("managed::probe_client_v2::virtual_tests::virtual_direct_is_intercepted_and_real_socket_remains_denied")
                .arg("--test-threads=1").env(CHILD, "1").status().unwrap();
            assert!(status.success()); return;
        }
        let targets = Arc::new(vp_core::experimental_exact_targets::ExactTargets::new(["8.8.8.8:443".parse().unwrap()]).unwrap());
        vp_core::task_scope::install_experimental_process_floor(targets.clone()).unwrap();
        let scope = vp_core::task_scope::TaskScope::with_destination_policy(vp_core::task_scope::DestinationPolicy::ExactPublic(targets));
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(scope.run(async {
            let target = virtual_probe_target();
            let destination = vp_common::DstAddr::ip(target.ip(), target.port());
            let session = Session::new_tcp("synthetic".into(), None, destination.clone());
            let direct = vp_protocol::direct::DirectOutbound::new(Arc::new(vp_dns::Resolver::new(vec![])), false);
            let mut stream = direct.connect_stream(&session, &destination).await.unwrap();
            let token = [73u8;32]; stream.write_all(&token).await.unwrap();
            let mut ack = [0u8;12]; stream.read_exact(&mut ack).await.unwrap(); assert_eq!(&ack, b"VP-ORACLE-OK");
            let (hashes, saturated) = vp_core::experimental_virtual_probe::snapshot();
            assert!(!saturated); assert!(hashes.iter().any(|h| h.iter().map(|b| format!("{b:02x}")).collect::<String>() == virtual_probe_hash(&token)));
            assert_eq!(vp_core::host_network::connect_tcp(target, vp_core::host_network::Purpose::Proxy).await.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        }));
    }
}
