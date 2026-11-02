//! Real, bounded loopback VLESS health probes. This is development operational
//! evidence, NOT independent protocol certification or an Internet connectivity test.
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use vp_product_compiler::{ExecutionRecipe, RecipeProtocol};
use vp_product_control::{CheckOutcome, ControlError, HealthCheck};
use vp_product_runtime_executor::{ActiveProbe, ImmutableSecretStore, ProbeRequest};
use zeroize::Zeroizing;

const MAX_LISTENERS: usize = 8;
const MAX_USERS: usize = 16;
const IO_LIMIT: Duration = Duration::from_millis(600);
const NEGATIVE_SETTLE: Duration = Duration::from_millis(120);

pub struct LoopbackProbe {
    target: SocketAddr,
    connections: Arc<AtomicU64>,
    payloads: Arc<AtomicU64>,
    stopped: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    serial: Mutex<()>,
    vault: Arc<dyn ImmutableSecretStore>,
}
impl LoopbackProbe {
    /// Explicitly approved, daemon-owned IPv4 loopback echo destination. Port 0
    /// requests an ephemeral local target; it never binds a public interface.
    // Used by the legacy composition; the separate fresh executable reserves
    // its listener before writes and calls from_listener after anchoring cwd.
    #[allow(dead_code)]
    pub fn bind(
        bind: SocketAddr,
        vault: Arc<dyn ImmutableSecretStore>,
    ) -> Result<Arc<Self>, ControlError> {
        if bind.ip() != Ipv4Addr::LOCALHOST {
            return Err(ControlError::PermissionDenied);
        }
        let listener = TcpListener::bind(bind).map_err(|_| ControlError::ExecutorUnavailable)?;
        Self::from_listener(listener, vault)
    }
    /// Fresh startup reserves the port before durable writes, then starts this
    /// thread only after its permanent cwd anchor has been established.
    pub fn from_listener(
        listener: TcpListener,
        vault: Arc<dyn ImmutableSecretStore>,
    ) -> Result<Arc<Self>, ControlError> {
        if listener
            .local_addr()
            .map_err(|_| ControlError::ExecutorUnavailable)?
            .ip()
            != Ipv4Addr::LOCALHOST
        {
            return Err(ControlError::PermissionDenied);
        }
        listener
            .set_nonblocking(true)
            .map_err(|_| ControlError::ExecutorUnavailable)?;
        let target = listener
            .local_addr()
            .map_err(|_| ControlError::ExecutorUnavailable)?;
        let connections = Arc::new(AtomicU64::new(0));
        let payloads = Arc::new(AtomicU64::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let (c, p, stop, fault) = (
            connections.clone(),
            payloads.clone(),
            stopped.clone(),
            failed.clone(),
        );
        let thread = std::thread::Builder::new()
            .name("vp-local-probe-target".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            c.fetch_add(1, Ordering::SeqCst);
                            if stream
                                .set_read_timeout(Some(Duration::from_millis(200)))
                                .is_err()
                                || stream
                                    .set_write_timeout(Some(Duration::from_millis(200)))
                                    .is_err()
                            {
                                fault.store(true, Ordering::Release);
                                break;
                            }
                            let mut marker = [0u8; 32];
                            if stream.read_exact(&mut marker).is_ok() {
                                p.fetch_add(1, Ordering::SeqCst);
                                let _ = stream.write_all(&marker);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Err(_) => {
                            fault.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
            })
            .map_err(|_| ControlError::ExecutorUnavailable)?;
        Ok(Arc::new(Self {
            target,
            connections,
            payloads,
            stopped,
            failed,
            thread: Some(thread),
            serial: Mutex::new(()),
            vault,
        }))
    }
    fn alive(&self) -> Result<(), ControlError> {
        if self.failed.load(Ordering::Acquire) || self.stopped.load(Ordering::Acquire) {
            Err(ControlError::HealthFailed)
        } else {
            Ok(())
        }
    }
    fn wire(
        &self,
        address: SocketAddr,
        credential: &[u8],
        absent_allowed: bool,
        deadline: Instant,
    ) -> Result<bool, ControlError> {
        self.alive()?;
        let uuid = parse_uuid(credential)?;
        let mut marker = [0; 32];
        getrandom::fill(&mut marker).map_err(|_| ControlError::ExecutorUnavailable)?;
        let mut stream = match TcpStream::connect_timeout(&address, remaining(deadline)?) {
            Ok(stream) => stream,
            Err(error)
                if absent_allowed && error.kind() == std::io::ErrorKind::ConnectionRefused =>
            {
                return Ok(false)
            }
            Err(_) => return Err(ControlError::HealthFailed),
        };
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| ControlError::HealthFailed)?;
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| ControlError::HealthFailed)?;
        // Complete VLESS request plus early payload: validates real forwarding,
        // including coalesced first bytes, rather than merely an accepted socket.
        let mut packet = Zeroizing::new(Vec::with_capacity(60));
        packet.push(0);
        packet.extend_from_slice(&uuid);
        packet.extend_from_slice(&[0, 1]);
        packet.extend_from_slice(&self.target.port().to_be_bytes());
        packet.extend_from_slice(&[1, 127, 0, 0, 1]);
        packet.extend_from_slice(&marker);
        if stream.write_all(&packet).is_err() {
            return Ok(false);
        }
        let mut reply = [0; 2];
        if stream.read_exact(&mut reply).is_err() || reply != [0, 0] {
            return Ok(false);
        }
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| ControlError::HealthFailed)?;
        let mut echoed = [0; 32];
        let accepted = stream.read_exact(&mut echoed).is_ok() && marker == echoed;
        let _ = stream.shutdown(Shutdown::Both);
        within(deadline)?;
        Ok(accepted)
    }
    fn rejected(
        &self,
        address: SocketAddr,
        credential: &[u8],
        absent: bool,
        deadline: Instant,
    ) -> Result<CheckOutcome, ControlError> {
        let before = self.connections.load(Ordering::SeqCst);
        let accepted = self.wire(address, credential, absent, deadline)?;
        // Count ALL accepts, not merely echoed payloads: a wrong credential may
        // not even create a target connection. Observe after closing the client.
        if deadline.saturating_duration_since(Instant::now()) < NEGATIVE_SETTLE {
            return Err(ControlError::ExecutorFailed);
        }
        std::thread::sleep(NEGATIVE_SETTLE);
        self.alive()?;
        within(deadline)?;
        Ok(
            if !accepted && self.connections.load(Ordering::SeqCst) == before {
                CheckOutcome::Passed
            } else {
                CheckOutcome::Failed
            },
        )
    }
    fn invalid_credential(
        &self,
        recipe: &ExecutionRecipe,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, ControlError> {
        // Fixed invalid credentials are unsafe if an operator configured that
        // value. Pick a probe-only UUID and compare against EVERY enabled user.
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| ControlError::ExecutorUnavailable)?;
        let configured = recipe.listeners.iter().flat_map(|l| l.users.iter());
        for user in configured {
            let secret = self
                .vault
                .resolve_immutable(&user.credential_ref, deadline)?;
            if parse_uuid(secret.expose())? == random {
                return Err(ControlError::HealthFailed);
            }
        }
        let mut text = Zeroizing::new(Vec::with_capacity(36));
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, byte) in random.into_iter().enumerate() {
            if [4, 6, 8, 10].contains(&i) {
                text.push(b'-');
            }
            text.push(HEX[(byte >> 4) as usize]);
            text.push(HEX[(byte & 15) as usize]);
        }
        Ok(text)
    }
}
impl Drop for LoopbackProbe {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl ActiveProbe for LoopbackProbe {
    fn available(
        &self,
        current: &ExecutionRecipe,
        previous: Option<&ExecutionRecipe>,
        required: &BTreeSet<HealthCheck>,
    ) -> Result<(), ControlError> {
        self.alive()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        for recipe in std::iter::once(current).chain(previous) {
            if recipe.bind_address != Ipv4Addr::LOCALHOST
                || recipe.listeners.len() > MAX_LISTENERS
                || recipe
                    .listeners
                    .iter()
                    .map(|l| l.users.len())
                    .sum::<usize>()
                    > MAX_USERS
                || recipe
                    .listeners
                    .iter()
                    .any(|l| !matches!(l.protocol, RecipeProtocol::Vless {}))
            {
                return Err(ControlError::ExecutorUnavailable);
            }
            for listener in &recipe.listeners {
                if listener.port == self.target.port() {
                    return Err(ControlError::InvalidConfiguration);
                }
                for user in &listener.users {
                    let credential = self
                        .vault
                        .resolve_immutable(&user.credential_ref, deadline)?;
                    parse_uuid(credential.expose())?;
                    within(deadline)?;
                }
            }
        }
        if required
            .iter()
            .any(|c| matches!(c, HealthCheck::SecurityIdentity(_) | HealthCheck::Dns(_)))
        {
            return Err(ControlError::ExecutorUnavailable);
        }
        Ok(())
    }
    fn check(
        &self,
        request: ProbeRequest<'_>,
        deadline: Instant,
    ) -> Result<CheckOutcome, ControlError> {
        let _serial = self
            .serial
            .try_lock()
            .map_err(|_| ControlError::ExecutorUnavailable)?;
        within(deadline)?;
        self.alive()?;
        if request.generation == 0 {
            return Err(ControlError::HealthFailed);
        }
        let id = match request.check {
            HealthCheck::ListenerBound(id)
            | HealthCheck::Forwarding(id)
            | HealthCheck::InvalidAuthenticationRejected(id)
            | HealthCheck::RetiredListenerReleased(id) => id,
            HealthCheck::AuthenticationAccepted(auth)
            | HealthCheck::RetiredAuthenticationRejected(auth) => &auth.listener_id,
            _ => return Err(ControlError::ExecutorUnavailable),
        };
        let current = request
            .current
            .listeners
            .iter()
            .find(|l| l.id.as_str() == id);
        let previous = request.previous.and_then(|r| {
            r.listeners
                .iter()
                .find(|l| l.id.as_str() == id)
                .map(|l| (r, l))
        });
        let (recipe, listener) = current
            .map(|l| (request.current, l))
            .or(previous)
            .ok_or(ControlError::HealthFailed)?;
        let address = SocketAddr::new(recipe.bind_address, listener.port);
        match request.check {
            HealthCheck::ListenerBound(_) => Ok(
                if TcpStream::connect_timeout(&address, remaining(deadline)?).is_ok() {
                    CheckOutcome::Passed
                } else {
                    CheckOutcome::Failed
                },
            ),
            HealthCheck::AuthenticationAccepted(_) | HealthCheck::Forwarding(_) => {
                let resolved;
                let credential = match request.credential {
                    Some(credential) => credential,
                    None => {
                        resolved = self.vault.resolve_immutable(
                            &listener
                                .users
                                .first()
                                .ok_or(ControlError::InvalidConfiguration)?
                                .credential_ref,
                            deadline,
                        )?;
                        &resolved
                    }
                };
                let before = self.payloads.load(Ordering::SeqCst);
                Ok(
                    if self.wire(address, credential.expose(), false, deadline)?
                        && self.payloads.load(Ordering::SeqCst) == before + 1
                    {
                        CheckOutcome::Passed
                    } else {
                        CheckOutcome::Failed
                    },
                )
            }
            HealthCheck::InvalidAuthenticationRejected(_) => self.rejected(
                address,
                &self.invalid_credential(request.current, deadline)?,
                false,
                deadline,
            ),
            HealthCheck::RetiredAuthenticationRejected(_) => self.rejected(
                address,
                request
                    .credential
                    .ok_or(ControlError::InvalidConfiguration)?
                    .expose(),
                current.is_none(),
                deadline,
            ),
            HealthCheck::RetiredListenerReleased(_) => {
                let (old, listener) = previous.ok_or(ControlError::HealthFailed)?;
                Ok(
                    if TcpListener::bind(SocketAddr::new(old.bind_address, listener.port)).is_ok() {
                        CheckOutcome::Passed
                    } else {
                        CheckOutcome::Failed
                    },
                )
            }
            _ => Err(ControlError::ExecutorUnavailable),
        }
    }
    fn stopped(&self, recipe: &ExecutionRecipe, deadline: Instant) -> Result<(), ControlError> {
        let mut held = Vec::new();
        for listener in &recipe.listeners {
            within(deadline)?;
            if !recipe.bind_address.is_loopback() {
                return Err(ControlError::PermissionDenied);
            }
            held.push(
                TcpListener::bind(SocketAddr::new(recipe.bind_address, listener.port))
                    .map_err(|_| ControlError::HealthFailed)?,
            );
        }
        within(deadline)
    }
}
fn remaining(deadline: Instant) -> Result<Duration, ControlError> {
    let duration = deadline
        .saturating_duration_since(Instant::now())
        .min(IO_LIMIT);
    if duration.is_zero() {
        Err(ControlError::ExecutorFailed)
    } else {
        Ok(duration)
    }
}
fn within(deadline: Instant) -> Result<(), ControlError> {
    remaining(deadline).map(|_| ())
}
pub(crate) fn parse_uuid(bytes: &[u8]) -> Result<[u8; 16], ControlError> {
    if bytes.len() != 36 {
        return Err(ControlError::InvalidConfiguration);
    }
    let mut output = [0; 16];
    let mut nibble = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            if byte != b'-' {
                return Err(ControlError::InvalidConfiguration);
            }
            continue;
        }
        let value = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(ControlError::InvalidConfiguration),
        };
        output[nibble / 2] = (output[nibble / 2] << 4) | value;
        nibble += 1;
    }
    Ok(output)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn uuid_probe_decoder_rejects_truncation_nonhex_and_wrong_separators() {
        assert_eq!(
            parse_uuid(b"00000000-0000-0000-0000-000000000001").unwrap()[15],
            1
        );
        for bytes in [
            b"short".as_slice(),
            b"00000000-0000-0000-0000-00000000000z",
            b"0000000000000-0000-0000-000000000001",
        ] {
            assert!(parse_uuid(bytes).is_err());
        }
    }
    #[test]
    fn probe_target_requires_explicit_ipv4_localhost() {
        let vault = Arc::new(vp_product_runtime_executor::UnavailableSecretStore);
        assert!(LoopbackProbe::bind("0.0.0.0:0".parse().unwrap(), vault.clone()).is_err());
        assert!(LoopbackProbe::bind("192.0.2.1:0".parse().unwrap(), vault.clone()).is_err());
        let probe = LoopbackProbe::bind("127.0.0.1:0".parse().unwrap(), vault).unwrap();
        assert_ne!(probe.target.port(), 0);
        assert!(remaining(Instant::now() - Duration::from_millis(1)).is_err());
    }
}
