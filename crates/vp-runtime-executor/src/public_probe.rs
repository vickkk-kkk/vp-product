//! Experimental target-observed probe. It is not wired to management or release.
use std::{collections::BTreeSet, sync::Arc, time::{Duration, Instant}};
use vp_product_compiler::server_v2::{ServerListenerV2, ServerProtocolV2, ServerRecipeV2, ServerSecurityV2};
use vp_product_control::{CheckOutcome, ContentDigest, ControlError, HealthCheck};
use vp_product_core_adapter::managed::{Failure, server_v2::ServerInputsV2};
use vp_product_domain::{SecretBytes, ServerListener};
use zeroize::Zeroize;
use crate::{public_oracle::ProbeOracle, public_stage::PublicProbe};

#[allow(dead_code)]
pub(crate) struct OracleProbe { oracle: Arc<ProbeOracle>, roots: Vec<Vec<u8>>, tls_name: String }
#[allow(dead_code)]
impl OracleProbe {
    pub(crate) fn new(oracle: Arc<ProbeOracle>, policy: &vp_product_control::TlsBackendPolicy) -> Result<Self, ControlError> {
        let (roots, tls_name) = policy.probe_trust();
        vp_product_core_adapter::managed::probe_client_v2::validate_tls_trust(&roots, &tls_name).map_err(|_| ControlError::InvalidConfiguration)?;
        Ok(Self { oracle, roots, tls_name })
    }
    fn listener<'a>(&self, recipe: &'a ServerRecipeV2, id: &str) -> Result<(&'a ServerListenerV2, &'a ServerListener), ControlError> {
        let mut built = recipe.listeners.iter().filter(|v| v.id.as_str() == id);
        let listener = built.next().ok_or(ControlError::InvalidConfiguration)?;
        if built.next().is_some() { return Err(ControlError::InvalidConfiguration); }
        let mut original = recipe.source.listeners.iter().filter(|v| v.id.as_str() == id && v.enabled);
        let source = original.next().ok_or(ControlError::InvalidConfiguration)?;
        if original.next().is_some() { return Err(ControlError::InvalidConfiguration); }
        Ok((listener, source))
    }
    fn first_credential<'a>(&self, listener: &ServerListenerV2, inputs: &'a ServerInputsV2) -> Result<&'a SecretBytes, ControlError> {
        let reference = &listener.credentials.first().ok_or(ControlError::InvalidConfiguration)?.reference;
        inputs.credentials.get(reference).ok_or(ControlError::InvalidConfiguration)
    }
    fn attempt(&self, listener: &ServerListenerV2, source: &ServerListener, credential: &SecretBytes, token: &[u8;32], deadline: Instant, max: Duration) -> Result<bool, Failure> {
        let remaining = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(Failure::Timeout)?.min(max);
        std::thread::scope(|scope| {
            let handle = std::thread::Builder::new().name("vp-probe-client".into()).spawn_scoped(scope, || {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Failure::Io)?;
                runtime.block_on(vp_product_core_adapter::managed::probe_client_v2::challenge(listener, source, self.oracle.address(), credential, &self.roots, &self.tls_name, token, remaining))
            }).map_err(|_| Failure::Io)?;
            handle.join().map_err(|_| Failure::Io)?
        })
    }
    fn accepted(&self, listener: &ServerListenerV2, source: &ServerListener, credential: &SecretBytes, deadline: Instant) -> Result<bool, ControlError> {
        let mut token = self.oracle.register()?;
        let result = (|| {
            let response = self.attempt(listener, source, credential, &token, deadline, Duration::from_secs(3));
            let seen = self.oracle.wait_seen(&token, deadline.min(Instant::now()+Duration::from_millis(300)))?;
            Ok(matches!(response, Ok(true)) && seen)
        })();
        let retired = self.oracle.retire(&token);
        token.zeroize();
        result.and_then(|value| retired.map(|_| value))
    }
    fn wrong_credential(&self, listener: &ServerListenerV2, inputs: &ServerInputsV2) -> Result<SecretBytes, ControlError> {
        for _ in 0..4 {
            let mut random = [0u8;16]; getrandom::fill(&mut random).map_err(|_| ControlError::ExecutorUnavailable)?;
            let mut value = Vec::new();
            for (i, b) in random.iter().enumerate() {
                if matches!(listener.protocol, ServerProtocolV2::Vless {}) && [4,6,8,10].contains(&i) { value.push(b'-'); }
                value.extend_from_slice(format!("{b:02x}").as_bytes());
            }
            random.zeroize();
            if !listener.credentials.iter().filter_map(|c| inputs.credentials.get(&c.reference)).any(|v| v.expose() == value.as_slice()) { return Ok(SecretBytes::new(value)); }
            value.zeroize();
        }
        Err(ControlError::ExecutorUnavailable)
    }
    fn rejected(&self, listener: &ServerListenerV2, source: &ServerListener, inputs: &ServerInputsV2, deadline: Instant) -> Result<bool, ControlError> {
        let good = self.first_credential(listener, inputs)?;
        if !self.accepted(listener, source, good, deadline)? { return Ok(false); }
        let wrong = self.wrong_credential(listener, inputs)?;
        let mut token = self.oracle.register()?;
        let result = (|| {
            let response = self.attempt(listener, source, &wrong, &token, deadline, Duration::from_millis(750));
            let observed = self.oracle.wait_seen(&token, deadline.min(Instant::now()+Duration::from_millis(300)))?;
            let valid_after = self.accepted(listener, source, good, deadline)?;
            let observed_after = self.oracle.seen(&token)?;
            // Negative observation is bounded; transport/TLS failures do not pass.
            Ok(matches!(response, Ok(false)) && !observed && !observed_after && valid_after)
        })();
        let retired = self.oracle.retire(&token);
        token.zeroize();
        result.and_then(|value| retired.map(|_| value))
    }
}
impl PublicProbe for OracleProbe {
    fn validate_policy(&self, policy: &vp_product_control::TlsBackendPolicy) -> Result<(), ControlError> {
        let (roots, name) = policy.probe_trust();
        if roots != self.roots || name != self.tls_name { return Err(ControlError::ResourceConflict); }
        Ok(())
    }
    fn available(&self, recipe: &ServerRecipeV2, checks: &BTreeSet<HealthCheck>) -> Result<(), ControlError> {
        if !self.oracle.is_alive() || recipe.profile != vp_product_compiler::server_v2::ServerProfileV2::PublicExperimentalUncertified
            || recipe.public_targets.as_ref().is_none_or(|v| !v.contains(&self.oracle.address()))
            || recipe.listeners.iter().any(|l| l.bind.address == self.oracle.address().ip()) { return Err(ControlError::ExecutorUnavailable); }
        if recipe.listeners.iter().any(|l| matches!(l.security, ServerSecurityV2::Tls { .. })) && (self.roots.is_empty() || self.tls_name.is_empty()) { return Err(ControlError::ExecutorUnavailable); }
        let tokens = checks.iter().try_fold(0usize, |n, c| n.checked_add(match c { HealthCheck::Process | HealthCheck::ListenerBound(_) => 0, HealthCheck::InvalidAuthenticationRejected(_) => 3, HealthCheck::AuthenticationAccepted(_) | HealthCheck::Forwarding(_) | HealthCheck::SecurityIdentity(_) => 1, _ => 65 })).ok_or(ControlError::ExecutorUnavailable)?;
        if tokens > 64 { return Err(ControlError::ExecutorUnavailable); }
        Ok(())
    }
    fn check(&self, recipe: &ServerRecipeV2, inputs: &ServerInputsV2, check: &HealthCheck, _: u64, deadline: Instant) -> Result<CheckOutcome, ControlError> {
        if !self.oracle.is_alive() { return Err(ControlError::ExecutorUnavailable); }
        let (id, user) = match check {
            HealthCheck::AuthenticationAccepted(u) => (u.listener_id.as_str(), Some(u)),
            HealthCheck::InvalidAuthenticationRejected(id) | HealthCheck::Forwarding(id) | HealthCheck::SecurityIdentity(id) => (id.as_str(), None),
            _ => return Err(ControlError::ExecutorUnavailable),
        };
        let (listener, source) = self.listener(recipe, id)?;
        let passed = if matches!(check, HealthCheck::InvalidAuthenticationRejected(_)) {
            self.rejected(listener, source, inputs, deadline)?
        } else {
            let credential = if let Some(user) = user {
                let mut entries = listener.credentials.iter().filter(|c| c.user_id.as_str() == user.user_id && ContentDigest::of("vp.credential-reference.v1", &c.reference).ok().as_ref() == Some(&user.credential_ref_digest));
                let entry = entries.next().ok_or(ControlError::InvalidConfiguration)?;
                if entries.next().is_some() { return Err(ControlError::InvalidConfiguration); }
                inputs.credentials.get(&entry.reference).ok_or(ControlError::InvalidConfiguration)?
            } else { self.first_credential(listener, inputs)? };
            self.accepted(listener, source, credential, deadline)?
        };
        if !self.oracle.is_alive() { return Err(ControlError::ExecutorUnavailable); }
        Ok(if passed { CheckOutcome::Passed } else { CheckOutcome::Failed })
    }
}

/// Single-IP experimental probe: a process-local, no-socket challenge sink
/// observes authentication, while an independently trusted HTTPS endpoint
/// checks real egress. Configuration must come from a trusted backend, not an
/// untrusted API request. No public release uses this constructor yet.
pub(crate) struct VirtualProbe {
    inbound_roots: Vec<Vec<u8>>, inbound_name: String,
    target: std::net::SocketAddr, target_trust: vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust, target_name: String,
    path: String, status: u16,
}
impl VirtualProbe {
    pub(crate) fn new(policy: &vp_product_control::TlsBackendPolicy, target: std::net::SocketAddr,
        target_trust: vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust, target_name: String, path: String, status: u16) -> Result<Self, ControlError> {
        let (inbound_roots, inbound_name) = policy.probe_trust();
        vp_product_core_adapter::managed::probe_client_v2::validate_tls_trust(&inbound_roots, &inbound_name).map_err(|_| ControlError::InvalidConfiguration)?;
        match &target_trust {
            vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust::PinnedDer(roots) => vp_product_core_adapter::managed::probe_client_v2::validate_tls_trust(roots, &target_name).map_err(|_| ControlError::InvalidConfiguration)?,
            vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust::PublicWebPki => { vp_product_core_adapter::managed::probe_client_v2::validate_server_name(&target_name).map_err(|_| ControlError::InvalidConfiguration)?; }
        }
        if !target.is_ipv4() || target.port() == 0 || !path.starts_with('/') || path.len() > 256
            || !path.bytes().all(|b| (0x21..=0x7e).contains(&b)) || !(200..=299).contains(&status) {
            return Err(ControlError::InvalidConfiguration);
        }
        Ok(Self { inbound_roots, inbound_name, target, target_trust, target_name, path, status })
    }
    fn listener<'a>(&self, recipe: &'a ServerRecipeV2, id: &str) -> Result<(&'a ServerListenerV2, &'a ServerListener), ControlError> {
        let mut built = recipe.listeners.iter().filter(|v| v.id.as_str() == id);
        let listener = built.next().ok_or(ControlError::InvalidConfiguration)?;
        let mut original = recipe.source.listeners.iter().filter(|v| v.id.as_str() == id && v.enabled);
        let source = original.next().ok_or(ControlError::InvalidConfiguration)?;
        if built.next().is_some() || original.next().is_some() { return Err(ControlError::InvalidConfiguration); }
        Ok((listener, source))
    }
    fn credential<'a>(&self, listener: &ServerListenerV2, inputs: &'a ServerInputsV2,
        user: Option<&vp_product_control::AuthenticationProbe>) -> Result<&'a SecretBytes, ControlError> {
        let selected = if let Some(user) = user {
            let mut matches = listener.credentials.iter().filter(|c| c.user_id.as_str() == user.user_id
                && ContentDigest::of("vp.credential-reference.v1", &c.reference).ok().as_ref() == Some(&user.credential_ref_digest));
            let item = matches.next().ok_or(ControlError::InvalidConfiguration)?;
            if matches.next().is_some() { return Err(ControlError::InvalidConfiguration); }
            item
        } else { listener.credentials.first().ok_or(ControlError::InvalidConfiguration)? };
        inputs.credentials.get(&selected.reference).ok_or(ControlError::InvalidConfiguration)
    }
    fn wrong_credential(&self, listener: &ServerListenerV2, inputs: &ServerInputsV2) -> Result<SecretBytes, ControlError> {
        for _ in 0..4 {
            let mut random = [0u8;16]; getrandom::fill(&mut random).map_err(|_| ControlError::ExecutorUnavailable)?;
            let mut value = Vec::new();
            for (i, b) in random.iter().enumerate() {
                if matches!(listener.protocol, ServerProtocolV2::Vless {}) && [4,6,8,10].contains(&i) { value.push(b'-'); }
                value.extend_from_slice(format!("{b:02x}").as_bytes());
            }
            random.zeroize();
            if !listener.credentials.iter().filter_map(|c| inputs.credentials.get(&c.reference)).any(|v| v.expose() == value.as_slice()) { return Ok(SecretBytes::new(value)); }
            value.zeroize();
        }
        Err(ControlError::ExecutorUnavailable)
    }
    fn seen(runtime: &mut vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2, generation: u64, token: &[u8;32]) -> Result<bool, ControlError> {
        let snapshot = runtime.snapshot(generation).map_err(|_| ControlError::HealthFailed)?;
        Self::observed(&snapshot, token)
    }
    fn observed(snapshot: &vp_product_core_adapter::managed::WorkerSnapshot, token: &[u8;32]) -> Result<bool, ControlError> {
        let ledger = snapshot.probe_ledger.as_ref().ok_or(ControlError::ExecutorUnavailable)?;
        if ledger.version != 1 || ledger.saturated || ledger.token_hashes.len() > 64
            || ledger.token_hashes.iter().any(|v| v.len() != 64 || !v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            || ledger.token_hashes.windows(2).any(|w| w[0] >= w[1]) { return Err(ControlError::ExecutorUnavailable); }
        let hash = vp_product_core_adapter::managed::probe_client_v2::virtual_probe_hash(token);
        Ok(ledger.token_hashes.binary_search(&hash).is_ok())
    }
    fn attempt(&self, listener: &ServerListenerV2, source: &ServerListener, credential: &SecretBytes,
        token: &[u8;32], deadline: Instant, maximum: Duration) -> Result<bool, Failure> {
        let remaining = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(Failure::Timeout)?.min(maximum);
        std::thread::scope(|scope| {
            let handle = std::thread::Builder::new().name("vp-virtual-probe-client".into()).spawn_scoped(scope, || {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Failure::Io)?;
                runtime.block_on(vp_product_core_adapter::managed::probe_client_v2::challenge(listener, source,
                    vp_product_core_adapter::managed::probe_client_v2::virtual_probe_target(), credential,
                    &self.inbound_roots, &self.inbound_name, token, remaining))
            }).map_err(|_| Failure::Io)?;
            handle.join().map_err(|_| Failure::Io)?
        })
    }
    fn accepted(&self, listener: &ServerListenerV2, source: &ServerListener, credential: &SecretBytes,
        runtime: &mut vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2, generation: u64, deadline: Instant) -> Result<bool, ControlError> {
        let start = Instant::now(); let mut token = zeroize::Zeroizing::new([0u8;32]);
        getrandom::fill(&mut *token).map_err(|_| ControlError::ExecutorUnavailable)?;
        if Self::seen(runtime, generation, &token)? { return Err(ControlError::ResourceConflict); }
        let result = self.attempt(listener, source, credential, &token, deadline, Duration::from_secs(3));
        let observed = Self::seen(runtime, generation, &token)?;
        if start.elapsed() >= Duration::from_secs(30) { return Err(ControlError::PlanExpired); }
        Ok(matches!(result, Ok(true)) && observed)
    }
    fn rejected(&self, listener: &ServerListenerV2, source: &ServerListener, inputs: &ServerInputsV2,
        runtime: &mut vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2, generation: u64, deadline: Instant) -> Result<bool, ControlError> {
        let good = self.credential(listener, inputs, None)?;
        if !self.accepted(listener, source, good, runtime, generation, deadline)? { return Ok(false); }
        let wrong = self.wrong_credential(listener, inputs)?;
        let start = Instant::now(); let mut token = zeroize::Zeroizing::new([0u8;32]);
        getrandom::fill(&mut *token).map_err(|_| ControlError::ExecutorUnavailable)?;
        if Self::seen(runtime, generation, &token)? { return Err(ControlError::ResourceConflict); }
        let result = self.attempt(listener, source, &wrong, &token, deadline, Duration::from_millis(750));
        let first = Self::seen(runtime, generation, &token)?;
        let good_after = self.accepted(listener, source, good, runtime, generation, deadline)?;
        let second = Self::seen(runtime, generation, &token)?;
        if start.elapsed() >= Duration::from_secs(30) { return Err(ControlError::PlanExpired); }
        Ok(matches!(result, Ok(false)) && !first && !second && good_after)
    }
    fn forwarding(&self, listener: &ServerListenerV2, source: &ServerListener, credential: &SecretBytes,
        runtime: &mut vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2, generation: u64, deadline: Instant) -> Result<bool, ControlError> {
        // Also rejects a saturated ledger; a worker snapshot is identity-checked.
        let zero = [0u8;32]; let _ = Self::seen(runtime, generation, &zero)?;
        let remaining = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(ControlError::PlanExpired)?.min(Duration::from_secs(5));
        let response = std::thread::scope(|scope| {
            let handle = std::thread::Builder::new().name("vp-https-probe-client".into()).spawn_scoped(scope, || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Failure::Io)?;
                rt.block_on(vp_product_core_adapter::managed::probe_client_v2::https_status_with_trust(listener, source, self.target, credential,
                    &self.inbound_roots, &self.inbound_name, &self.target_trust, &self.target_name, &self.path, self.status, remaining))
            }).map_err(|_| Failure::Io)?;
            handle.join().map_err(|_| Failure::Io)?
        });
        let _ = Self::seen(runtime, generation, &zero)?;
        Ok(matches!(response, Ok(true)))
    }
}
impl PublicProbe for VirtualProbe {
    fn validate_policy(&self, policy: &vp_product_control::TlsBackendPolicy) -> Result<(), ControlError> {
        let (roots, name) = policy.probe_trust();
        if roots != self.inbound_roots || name != self.inbound_name { return Err(ControlError::ResourceConflict); }
        Ok(())
    }
    fn available(&self, recipe: &ServerRecipeV2, checks: &BTreeSet<HealthCheck>) -> Result<(), ControlError> {
        if recipe.profile != vp_product_compiler::server_v2::ServerProfileV2::PublicExperimentalUncertified
            || recipe.public_targets.as_ref().is_none_or(|v| !v.contains(&self.target))
            || recipe.listeners.iter().any(|l| l.bind.address == self.target.ip()) { return Err(ControlError::ExecutorUnavailable); }
        let tokens = checks.iter().try_fold(0usize, |n,c| n.checked_add(match c {
            HealthCheck::Process | HealthCheck::ListenerBound(_) | HealthCheck::Forwarding(_) => 0,
            HealthCheck::InvalidAuthenticationRejected(_) => 3,
            HealthCheck::AuthenticationAccepted(_) | HealthCheck::SecurityIdentity(_) => 1,
            _ => 65,
        })).ok_or(ControlError::ExecutorUnavailable)?;
        if tokens > 64 { return Err(ControlError::ExecutorUnavailable); }
        Ok(())
    }
    fn check(&self, _: &ServerRecipeV2, _: &ServerInputsV2, _: &HealthCheck, _: u64, _: Instant) -> Result<CheckOutcome, ControlError> {
        Err(ControlError::ExecutorUnavailable) // exact live worker ownership is mandatory
    }
    fn check_with_runtime(&self, recipe: &ServerRecipeV2, inputs: &ServerInputsV2, check: &HealthCheck,
        generation: u64, deadline: Instant, runtime: &mut vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2) -> Result<CheckOutcome, ControlError> {
        let (id, user) = match check {
            HealthCheck::AuthenticationAccepted(u) => (u.listener_id.as_str(), Some(u)),
            HealthCheck::InvalidAuthenticationRejected(id) | HealthCheck::Forwarding(id) | HealthCheck::SecurityIdentity(id) => (id.as_str(), None),
            _ => return Err(ControlError::ExecutorUnavailable),
        };
        let (listener, source) = self.listener(recipe, id)?;
        let passed = if matches!(check, HealthCheck::InvalidAuthenticationRejected(_)) {
            self.rejected(listener, source, inputs, runtime, generation, deadline)?
        } else {
            let credential = self.credential(listener, inputs, user)?;
            if matches!(check, HealthCheck::Forwarding(_)) { self.forwarding(listener, source, credential, runtime, generation, deadline)? }
            else { self.accepted(listener, source, credential, runtime, generation, deadline)? }
        };
        Ok(if passed { CheckOutcome::Passed } else { CheckOutcome::Failed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use vp_product_compiler::server_v2::ServerCompilerV2;
    use vp_product_core_adapter::managed::{Cancellation, VerifiedWorker, host_v2::ManagedRuntimeV2, protocol_v2::WorkerInstanceV2};
    use vp_product_domain::*;
    fn pem(label: &str, der: &[u8]) -> Vec<u8> {
        const B: &[u8;64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = Vec::new();
        for c in der.chunks(3) {
            let n = ((c[0] as u32)<<16) | ((c.get(1).copied().unwrap_or(0) as u32)<<8) | c.get(2).copied().unwrap_or(0) as u32;
            encoded.extend_from_slice(&[B[((n>>18)&63) as usize], B[((n>>12)&63) as usize], if c.len()>1 { B[((n>>6)&63) as usize] } else { b'=' }, if c.len()>2 { B[(n&63) as usize] } else { b'=' }]);
        }
        let mut out = format!("-----BEGIN {label}-----\n").into_bytes();
        for c in encoded.chunks(64) { out.extend_from_slice(c); out.push(b'\n'); }
        out.extend_from_slice(format!("-----END {label}-----\n").as_bytes()); out
    }
    fn materials(mode: u8, cert: &rcgen::CertifiedKey) -> ServerInputsV2 {
        let mut inputs = ServerInputsV2::default();
        let secret = match mode { 0 => b"synthetic-test-password".to_vec(), 1 => b"12345678-1234-1234-1234-123456789abc".to_vec(), _ => b"synthetic-ss-password".to_vec() };
        inputs.credentials.insert(SecretRef::new("probe-credential").unwrap(), SecretBytes::new(secret));
        if mode < 2 {
            inputs.certificate_chains.insert(CertificateId::new("probe-certificate").unwrap(), SecretBytes::new(pem("CERTIFICATE", cert.cert.der())));
            inputs.private_keys.insert(SecretRef::new("probe-key").unwrap(), SecretBytes::new(pem("PRIVATE KEY", &cert.key_pair.serialize_der())));
        }
        inputs
    }
    #[test]
    fn three_protocol_checks_use_real_local_target_observations() {
        let path = std::path::PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap()).join("debug/vp-core-server-worker-v2");
        let hash = format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap()));
        let worker = VerifiedWorker::for_server_v2(&path, &hash, Instant::now()+Duration::from_secs(10), &Cancellation::default()).unwrap();
        let release = vp_product_core_adapter::inspect_build().unwrap().build.release;
        let compiler = ServerCompilerV2::for_loopback_server_extensions(release.clone()).unwrap();
        for mode in 0..3 {
            let bind = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = bind.local_addr().unwrap().port(); drop(bind);
            let protocol = match mode { 0 => serde_json::json!({"kind":"trojan"}), 1 => serde_json::json!({"kind":"vless","flow":null}), _ => serde_json::json!({"kind":"shadowsocks","method":"aes-128-gcm"}) };
            let transport = if mode == 1 { serde_json::json!({"kind":"ws","path":"/probe","host":null,"earlyData":null}) } else { serde_json::json!({"kind":"tcp"}) };
            let security = if mode < 2 { serde_json::json!({"kind":"tls","certificateRef":"probe-certificate","privateKeyRef":"secret:probe-key","alpn":[]}) } else { serde_json::json!({"kind":"none"}) };
            let source: ProductConfig = serde_json::from_value(serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{"schemaVersion":1,"id":"probe-listener","name":"local-test","enabled":true,"bind":{"address":"127.0.0.1","port":port},"protocol":{"kind":"proxy","protocol":protocol,"users":[{"id":"probe-user","credentialRef":"secret:probe-credential","enabled":true}]},"transport":transport,"security":security,"requirements":[]}]})).unwrap();
            let recipe = compiler.compile(&source, &release).unwrap();
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let oracle = Arc::new(ProbeOracle::bind("127.0.0.1".parse().unwrap()).unwrap());
            let policy = vp_product_control::TlsBackendPolicy::new("probe-user".into(), vec![cert.cert.der().to_vec()], "localhost".into()).unwrap();
            let probe = OracleProbe::new(oracle, &policy).unwrap();
            assert!(probe.validate_policy(&policy).is_ok());
            let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let wrong_policy = vp_product_control::TlsBackendPolicy::new("probe-user".into(), vec![other.cert.der().to_vec()], "localhost".into()).unwrap();
            assert!(probe.validate_policy(&wrong_policy).is_err());
            assert!(probe.available(&recipe, &BTreeSet::new()).is_err()); // Never admit loopback as public.
            let mut runtime = ManagedRuntimeV2::with_generation(worker.clone(), WorkerInstanceV2::new(&format!("probe-test-{mode}")).unwrap(), 0).unwrap();
            let prepared = runtime.prepare_with_spawn_observer(recipe.clone(), materials(mode, &cert), 0, Duration::from_secs(10), &Cancellation::default(), |_| Ok(())).unwrap();
            runtime.activate_prepared(prepared.generation, Duration::from_secs(10), &Cancellation::default()).unwrap();
            let input = materials(mode, &cert);
            let deadline = || Instant::now()+Duration::from_secs(10);
            let id = "probe-listener".to_string();
            let auth = vp_product_control::AuthenticationProbe { listener_id: id.clone(), user_id: "probe-user".into(), credential_ref_digest: ContentDigest::of("vp.credential-reference.v1", &SecretRef::new("probe-credential").unwrap()).unwrap() };
            assert_eq!(probe.check(&recipe, &input, &HealthCheck::AuthenticationAccepted(auth), 1, deadline()).unwrap(), CheckOutcome::Passed, "mode {mode} accepted");
            assert_eq!(probe.check(&recipe, &input, &HealthCheck::InvalidAuthenticationRejected(id.clone()), 1, deadline()).unwrap(), CheckOutcome::Passed, "mode {mode} rejected");
            assert_eq!(probe.check(&recipe, &input, &HealthCheck::Forwarding(id.clone()), 1, deadline()).unwrap(), CheckOutcome::Passed, "mode {mode} forward");
            if mode < 2 { assert_eq!(probe.check(&recipe, &input, &HealthCheck::SecurityIdentity(id), 1, deadline()).unwrap(), CheckOutcome::Passed, "mode {mode} tls"); }
            runtime.stop_active(prepared.generation, Duration::ZERO).unwrap();
        }
    }
    #[test]
    fn virtual_ledger_requires_exact_unsaturated_canonical_observation() {
        use vp_product_core_adapter::managed::{ProbeLedgerObservation, WorkerSnapshot};
        let token = [7u8;32]; let other = [8u8;32];
        let hash = vp_product_core_adapter::managed::probe_client_v2::virtual_probe_hash(&token);
        let mut snapshot = WorkerSnapshot { generation: 1, pid: 1, listeners_ready: true, listeners: vec![], active_tasks: 1,
            task_panics: 0, forwarding_verified: false, probe_ledger: None };
        assert!(VirtualProbe::observed(&snapshot, &token).is_err());
        snapshot.probe_ledger = Some(ProbeLedgerObservation { version: 1, token_hashes: vec![hash.clone()], saturated: false });
        assert!(VirtualProbe::observed(&snapshot, &token).unwrap());
        assert!(!VirtualProbe::observed(&snapshot, &other).unwrap());
        snapshot.probe_ledger.as_mut().unwrap().saturated = true;
        assert!(VirtualProbe::observed(&snapshot, &token).is_err());
        snapshot.probe_ledger.as_mut().unwrap().saturated = false;
        snapshot.probe_ledger.as_mut().unwrap().token_hashes.push(hash);
        assert!(VirtualProbe::observed(&snapshot, &token).is_err());
    }
    #[test]
    fn independent_https_status_traverses_three_real_local_protocols() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let target_root = target_cert.cert.der().to_vec();
        let wrong_root = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap().cert.der().to_vec();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(target_cert.key_pair.serialize_der());
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth()
            .with_single_cert(vec![target_cert.cert.der().clone()], key.into()).unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap(); listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
                for _ in 0..12 {
                    let (tcp, _) = tokio::time::timeout(Duration::from_secs(15), listener.accept()).await.unwrap().unwrap();
                    if let Ok(Ok(mut tls)) = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp)).await {
                        let mut request = Vec::new();
                        while request.len() < 1024 && !request.ends_with(b"\r\n\r\n") {
                            let mut b = [0u8;1];
                            match tokio::time::timeout(Duration::from_secs(3), tls.read_exact(&mut b)).await {
                                Ok(Ok(_)) => request.push(b[0]), _ => break,
                            }
                        }
                        if request.starts_with(b"GET /health HTTP/1.1\r\n") {
                            let _ = tls.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await;
                        }
                    }
                }
            });
        });
        let path = std::path::PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap()).join("debug/vp-core-server-worker-v2");
        let hash = format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap()));
        let worker = VerifiedWorker::for_server_v2(&path, &hash, Instant::now()+Duration::from_secs(10), &Cancellation::default()).unwrap();
        let release = vp_product_core_adapter::inspect_build().unwrap().build.release;
        let compiler = ServerCompilerV2::for_loopback_server_extensions(release.clone()).unwrap();
        for mode in 0..3u8 {
            let bind = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let port = bind.local_addr().unwrap().port(); drop(bind);
            let protocol = match mode { 0 => serde_json::json!({"kind":"trojan"}), 1 => serde_json::json!({"kind":"vless","flow":null}), _ => serde_json::json!({"kind":"shadowsocks","method":"aes-128-gcm"}) };
            let transport = if mode == 1 { serde_json::json!({"kind":"ws","path":"/probe","host":null,"earlyData":null}) } else { serde_json::json!({"kind":"tcp"}) };
            let security = if mode < 2 { serde_json::json!({"kind":"tls","certificateRef":"probe-certificate","privateKeyRef":"secret:probe-key","alpn":[]}) } else { serde_json::json!({"kind":"none"}) };
            let source: ProductConfig = serde_json::from_value(serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{"schemaVersion":1,"id":"probe-listener","name":"probe","enabled":true,"bind":{"address":"127.0.0.1","port":port},"protocol":{"kind":"proxy","protocol":protocol,"users":[{"id":"probe-user","credentialRef":"secret:probe-credential","enabled":true}]},"transport":transport,"security":security,"requirements":[]}]})).unwrap();
            let recipe = compiler.compile(&source, &release).unwrap();
            let inbound_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let mut runtime = ManagedRuntimeV2::with_generation(worker.clone(), WorkerInstanceV2::new(&format!("https-probe-{mode}")).unwrap(), 0).unwrap();
            let prepared = runtime.prepare_with_spawn_observer(recipe.clone(), materials(mode, &inbound_cert), 0, Duration::from_secs(10), &Cancellation::default(), |_| Ok(())).unwrap();
            runtime.activate_prepared(prepared.generation, Duration::from_secs(10), &Cancellation::default()).unwrap();
            let input = materials(mode, &inbound_cert);
            let credential = input.credentials.get(&SecretRef::new("probe-credential").unwrap()).unwrap();
            let run = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let invoke = |roots: &[Vec<u8>], status| run.block_on(vp_product_core_adapter::managed::probe_client_v2::https_status(
                &recipe.listeners[0], &source.listeners[0], target, credential, &[inbound_cert.cert.der().to_vec()], "localhost",
                roots, "localhost", "/health", status, Duration::from_secs(5)));
            assert!(invoke(std::slice::from_ref(&target_root), 204).unwrap(), "mode {mode} valid TLS + HTTP");
            assert!(!invoke(std::slice::from_ref(&target_root), 200).unwrap(), "mode {mode} wrong status");
            assert!(invoke(std::slice::from_ref(&wrong_root), 204).is_err(), "mode {mode} wrong CA");
            let public_trust = vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust::PublicWebPki;
            assert!(run.block_on(vp_product_core_adapter::managed::probe_client_v2::https_status_with_trust(
                &recipe.listeners[0], &source.listeners[0], target, credential, &[inbound_cert.cert.der().to_vec()], "localhost",
                &public_trust, "localhost", "/health", 204, Duration::from_secs(5))).is_err(), "mode {mode} public roots must reject private CA");
            runtime.stop_active(prepared.generation, Duration::ZERO).unwrap();
        }
        server.join().unwrap();
    }

    #[cfg(feature = "local-probe-test")]
    #[test]
    fn virtual_sink_observes_valid_and_invalid_auth_for_three_local_protocols() {
        let path = std::env::var_os("VP_TEST_VIRTUAL_WORKER").map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap()).join("debug/vp-core-server-worker-v2"));
        let hash = format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap()));
        let worker = VerifiedWorker::for_server_v2(&path, &hash, Instant::now()+Duration::from_secs(10), &Cancellation::default()).unwrap();
        let release = vp_product_core_adapter::inspect_build().unwrap().build.release;
        let compiler = ServerCompilerV2::for_loopback_server_extensions(release.clone()).unwrap();
        for mode in 0..3u8 {
            let bind = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let port = bind.local_addr().unwrap().port(); drop(bind);
            let protocol = match mode { 0 => serde_json::json!({"kind":"trojan"}), 1 => serde_json::json!({"kind":"vless","flow":null}), _ => serde_json::json!({"kind":"shadowsocks","method":"aes-128-gcm"}) };
            let transport = if mode == 1 { serde_json::json!({"kind":"ws","path":"/probe","host":null,"earlyData":null}) } else { serde_json::json!({"kind":"tcp"}) };
            let security = if mode < 2 { serde_json::json!({"kind":"tls","certificateRef":"probe-certificate","privateKeyRef":"secret:probe-key","alpn":[]}) } else { serde_json::json!({"kind":"none"}) };
            let source: ProductConfig = serde_json::from_value(serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{"schemaVersion":1,"id":"probe-listener","name":"probe","enabled":true,"bind":{"address":"127.0.0.1","port":port},"protocol":{"kind":"proxy","protocol":protocol,"users":[{"id":"probe-user","credentialRef":"secret:probe-credential","enabled":true}]},"transport":transport,"security":security,"requirements":[]}]})).unwrap();
            let recipe = compiler.compile(&source, &release).unwrap();
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let policy = vp_product_control::TlsBackendPolicy::new("probe-user".into(), vec![cert.cert.der().to_vec()], "localhost".into()).unwrap();
            let probe = VirtualProbe::new(&policy, "8.8.8.8:443".parse().unwrap(), vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust::PinnedDer(vec![cert.cert.der().to_vec()]), "localhost".into(), "/health".into(), 204).unwrap();
            // This test-only loopback recipe is deliberately not production-admissible.
            assert!(probe.available(&recipe, &BTreeSet::new()).is_err());
            let mut runtime = ManagedRuntimeV2::with_generation(worker.clone(), WorkerInstanceV2::new(&format!("virtual-auth-{mode}")).unwrap(), 0).unwrap();
            let prepared = runtime.prepare_with_spawn_observer(recipe.clone(), materials(mode, &cert), 0, Duration::from_secs(10), &Cancellation::default(), |_| Ok(())).unwrap();
            runtime.activate_prepared(prepared.generation, Duration::from_secs(10), &Cancellation::default()).unwrap_or_else(|e| panic!("mode {mode}: {e:?}"));
            let input = materials(mode, &cert); let id = "probe-listener".to_owned();
            let auth = vp_product_control::AuthenticationProbe { listener_id: id.clone(), user_id: "probe-user".into(), credential_ref_digest: ContentDigest::of("vp.credential-reference.v1", &SecretRef::new("probe-credential").unwrap()).unwrap() };
            assert_eq!(probe.check_with_runtime(&recipe, &input, &HealthCheck::AuthenticationAccepted(auth), 1, Instant::now()+Duration::from_secs(10), &mut runtime).unwrap(), CheckOutcome::Passed, "mode {mode} valid");
            assert_eq!(probe.check_with_runtime(&recipe, &input, &HealthCheck::InvalidAuthenticationRejected(id.clone()), 1, Instant::now()+Duration::from_secs(10), &mut runtime).unwrap(), CheckOutcome::Passed, "mode {mode} invalid");
            if mode < 2 { assert_eq!(probe.check_with_runtime(&recipe, &input, &HealthCheck::SecurityIdentity(id), 1, Instant::now()+Duration::from_secs(10), &mut runtime).unwrap(), CheckOutcome::Passed, "mode {mode} TLS"); }
            let snapshot = runtime.snapshot(1).unwrap(); assert!(!snapshot.probe_ledger.unwrap().saturated);
            runtime.stop_active(prepared.generation, Duration::ZERO).unwrap();
        }
    }

}
