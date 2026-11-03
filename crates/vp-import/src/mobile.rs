//! Explicit, ephemeral bridge from a reviewed import to mobile ABI payload v2.
//! No persistence, network, permission request or connection is performed.
use crate::{invalid, AllocatedSecrets, CredentialKind, ImportCandidate, Result};
use serde::Serialize;
use std::{fmt, net::SocketAddr};
use vp_product_domain::{NodeId, NodeProfile, Revision, SecretRef};
use zeroize::Zeroizing;

/// Sensitive JSON; never implements Clone, Serialize or revealing Debug.
pub struct MobilePayload(Zeroizing<String>);
impl MobilePayload {
    /// Explicit transfer to the in-process ABI only. The receiver must protect it.
    pub fn expose(&self) -> &str { self.0.as_str() }
}
impl fmt::Debug for MobilePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("MobilePayload([REDACTED])") }
}

/// An observation of reported state, not a claim of connectivity or leak safety.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobileObservation { Unavailable, Idle, Starting, Verifying, ReportedActive, Stopping, Failed, Stale }

/// Interpret only a bounded, fresh native observation. An engine's reported
/// connected state remains unverified until independent data-plane evidence.
pub fn observe_snapshot(json: &str, now_ms: u64) -> MobileObservation {
    if json.len() > 1_048_576 { return MobileObservation::Unavailable; }
    let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(json) else { return MobileObservation::Unavailable };
    if wrapper.get("schemaVersion").and_then(|v| v.as_u64()) != Some(1) { return MobileObservation::Unavailable; }
    let v = wrapper.get("nativeSnapshot").filter(|v| !v.is_null()).unwrap_or(&wrapper);
    if v.get("schemaVersion").and_then(|v| v.as_u64()) != Some(1) { return MobileObservation::Unavailable; }
    let (Some(observed), Some(until)) = (v.get("observedAt").and_then(|v| v.as_u64()), v.get("validUntil").and_then(|v| v.as_u64()))
        else { return MobileObservation::Unavailable };
    if observed > now_ms || now_ms >= until || until <= observed || until - observed > 60_000 { return MobileObservation::Stale; }
    match v.get("phase").and_then(|v| v.as_str()) {
        Some("idle" | "disconnected") => MobileObservation::Idle,
        Some("preparing" | "awaiting_permission" | "starting") => MobileObservation::Starting,
        Some("verifying" | "reconnecting" | "degraded") => MobileObservation::Verifying,
        Some("connected") => MobileObservation::ReportedActive,
        Some("stopping") => MobileObservation::Stopping,
        Some("failed" | "recoveryRequired" | "recovering") => MobileObservation::Failed,
        _ => MobileObservation::Unavailable,
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Credential<'a> {
    Password { value: &'a str },
    Uuid { value: &'a str },
    UsernamePassword { username: &'a str, password: &'a str },
    UuidPassword { uuid: &'a str, password: &'a str },
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Dns<'a> { bootstrap_servers: &'a [SocketAddr], user: UserDns<'a> }
#[derive(Serialize)]
struct UserDns<'a> { route: &'static str, servers: &'a [SocketAddr] }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Connect<'a> { schema_version: u16, node: &'a NodeProfile, credential: Credential<'a>, config_revision: Revision, dns: Dns<'a> }

/// Create a short-lived request from a candidate the user has selected. The
/// synthetic credential reference exists only inside this ABI request: never
/// store the request or treat that reference as a vault binding. The runtime
/// independently checks protocol, transport, security, DNS and UDP capability.
pub fn encode_ephemeral(candidate: ImportCandidate, id: NodeId, revision: Revision,
    bootstrap_servers: &[SocketAddr], user_dns_servers: &[SocketAddr]) -> Result<MobilePayload> {
    fn valid(servers: &[SocketAddr]) -> bool {
        !servers.is_empty() && servers.len() <= 8 && servers.iter().all(|s| {
            s.port() != 0 && !s.ip().is_unspecified() && !s.ip().is_multicast()
        })
    }
    if !valid(bootstrap_servers) || !valid(user_dns_servers) { return Err(invalid("dns")); }
    if candidate.secrets.obfuscation.is_some() { return Err(crate::unsupported("obfuscation")); }
    let value = std::str::from_utf8(candidate.secrets.credential.primary.expose()).map_err(|_| invalid("credential"))?;
    let secondary = candidate.secrets.credential.secondary.as_ref()
        .map(|s| std::str::from_utf8(s.expose()).map_err(|_| invalid("credential"))).transpose()?;
    let credential = match (candidate.secrets.credential.kind, secondary) {
        (CredentialKind::Password, None) => Credential::Password { value },
        (CredentialKind::Uuid, None) => Credential::Uuid { value },
        (CredentialKind::UsernamePassword, Some(password)) => Credential::UsernamePassword { username: value, password },
        (CredentialKind::UuidPassword, Some(password)) => Credential::UuidPassword { uuid: value, password },
        _ => return Err(invalid("credential")),
    };
    let node = candidate.make_profile(id, None, AllocatedSecrets {
        credential_ref: SecretRef::new("ephemeral-mobile").map_err(|_| invalid("credential"))?,
        obfuscation_ref: None,
    })?;
    node.validate().map_err(|_| invalid("node"))?;
    let payload = Connect { schema_version: 2, node: &node, credential, config_revision: revision,
        dns: Dns { bootstrap_servers, user: UserDns { route: "selected_proxy", servers: user_dns_servers } } };
    serde_json::to_string(&payload).map(|s| MobilePayload(Zeroizing::new(s))).map_err(|_| invalid("payload"))
}
