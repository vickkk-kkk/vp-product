//! Bounded one-use challenge receiver for the experimental active probe.
//! Not wired to installation or a production release.
use std::{collections::BTreeMap, io::{Read, Write}, net::{IpAddr, SocketAddr, TcpListener}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, thread::{self, JoinHandle}, time::{Duration, Instant}};
use vp_product_control::ControlError;
use zeroize::Zeroize;

const MAX_TOKENS: usize = 64;
const MAX_FRAME: Duration = Duration::from_millis(250);
struct State { tokens: BTreeMap<[u8; 32], bool> }
impl Drop for State { fn drop(&mut self) { for (mut token, _) in std::mem::take(&mut self.tokens) { token.zeroize(); } } }
#[allow(dead_code)]
pub(crate) struct ProbeOracle { address: SocketAddr, state: Arc<Mutex<State>>, stop: Arc<AtomicBool>, thread: Option<JoinHandle<()>> }
#[allow(dead_code)]
impl ProbeOracle {
    /// Explicit numeric bind; caller owns and retains this socket until every
    /// worker permitted to reach it has exited. No wildcard or implicit address.
    pub(crate) fn bind(ip: IpAddr) -> Result<Self, ControlError> {
        Self::bind_address(SocketAddr::new(ip, 0))
    }
    /// A restart may re-acquire the exact previously authorized endpoint.
    /// This only reserves a socket; it does not authorize restart or health.
    pub(crate) fn bind_address(address: SocketAddr) -> Result<Self, ControlError> {
        if address.ip().is_unspecified() || address.ip().is_multicast() { return Err(ControlError::InvalidConfiguration); }
        let listener = TcpListener::bind(address).map_err(|_| ControlError::ExecutorUnavailable)?;
        listener.set_nonblocking(true).map_err(|_| ControlError::ExecutorUnavailable)?;
        let address = listener.local_addr().map_err(|_| ControlError::ExecutorUnavailable)?;
        let state = Arc::new(Mutex::new(State { tokens: BTreeMap::new() }));
        let stop = Arc::new(AtomicBool::new(false));
        let inner = state.clone(); let stop_thread = stop.clone();
        let thread = thread::Builder::new().name("vp-test-oracle".into()).spawn(move || {
            while !stop_thread.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut io, _)) => {
                        let _ = io.set_write_timeout(Some(MAX_FRAME));
                        let mut token = [0u8; 32];
                        let until = Instant::now() + MAX_FRAME;
                        let mut used = 0;
                        while used < token.len() {
                            let Some(left) = until.checked_duration_since(Instant::now()).filter(|v| !v.is_zero()) else { break };
                            if io.set_read_timeout(Some(left)).is_err() { break; }
                            match io.read(&mut token[used..]) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => used += n,
                            }
                        }
                        let accepted = if used == token.len() {
                            if let Ok(mut state) = inner.lock() {
                                // All keys have equal length; avoid early byte comparison.
                                let found = state.tokens.keys().find(|candidate| {
                                    candidate.iter().zip(token.iter()).fold(0u8, |v,(a,b)| v | (a ^ b)) == 0
                                }).copied();
                                if let Some(seen) = found.and_then(|key| state.tokens.get_mut(&key)) {
                                    if !*seen { *seen = true; true } else { false }
                                } else { false }
                            } else { false }
                        } else { false };
                        if accepted { let _ = io.write_all(b"VP-ORACLE-OK"); }
                        token.zeroize();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }
        }).map_err(|_| ControlError::ExecutorUnavailable)?;
        Ok(Self { address, state, stop, thread: Some(thread) })
    }
    pub(crate) fn address(&self) -> SocketAddr { self.address }
    pub(crate) fn is_alive(&self) -> bool {
        !self.stop.load(Ordering::Acquire) && self.thread.as_ref().is_some_and(|thread| !thread.is_finished())
    }
    /// One-use unpredictable challenge. Never log or persist these bytes.
    pub(crate) fn register(&self) -> Result<[u8; 32], ControlError> {
        let mut state = self.state.lock().map_err(|_| ControlError::RecoveryRequired)?;
        if state.tokens.len() >= MAX_TOKENS { return Err(ControlError::ResourceConflict); }
        for _ in 0..4 {
            let mut token = [0u8; 32];
            getrandom::fill(&mut token).map_err(|_| ControlError::ExecutorUnavailable)?;
            if !state.tokens.contains_key(&token) { state.tokens.insert(token, false); return Ok(token); }
            token.zeroize();
        }
        Err(ControlError::ExecutorUnavailable)
    }
    pub(crate) fn seen(&self, token: &[u8; 32]) -> Result<bool, ControlError> {
        let state = self.state.lock().map_err(|_| ControlError::RecoveryRequired)?;
        state.tokens.get(token).copied().ok_or(ControlError::NotFound)
    }
    pub(crate) fn retire(&self, token: &[u8; 32]) -> Result<(), ControlError> {
        let mut state = self.state.lock().map_err(|_| ControlError::RecoveryRequired)?;
        let (mut key, _) = state.tokens.remove_entry(token).ok_or(ControlError::NotFound)?;
        key.zeroize();
        Ok(())
    }
    pub(crate) fn wait_seen(&self, token: &[u8; 32], deadline: Instant) -> Result<bool, ControlError> {
        while Instant::now() < deadline {
            if self.seen(token)? { return Ok(true); }
            thread::sleep(Duration::from_millis(5));
        }
        self.seen(token)
    }
}
impl Drop for ProbeOracle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    #[test]
    fn challenge_is_one_use_and_unregistered_input_is_not_counted() {
        let oracle = ProbeOracle::bind("127.0.0.1".parse().unwrap()).unwrap();
        let mut token = oracle.register().unwrap();
        let other = oracle.register().unwrap();
        let mut bad = TcpStream::connect(oracle.address()).unwrap();
        bad.write_all(&[0x55;32]).unwrap(); drop(bad);
        let mut good = TcpStream::connect(oracle.address()).unwrap();
        good.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        good.write_all(&token).unwrap();
        let mut ack = [0u8;12]; good.read_exact(&mut ack).unwrap();
        assert_eq!(&ack,b"VP-ORACLE-OK");
        assert!(oracle.wait_seen(&token, Instant::now()+Duration::from_secs(1)).unwrap());
        assert!(!oracle.wait_seen(&other, Instant::now()+Duration::from_millis(50)).unwrap());
        let mut replay = TcpStream::connect(oracle.address()).unwrap();
        replay.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        replay.write_all(&token).unwrap();
        let mut byte = [0u8;1]; assert!(matches!(replay.read(&mut byte), Ok(0) | Err(_)));
        token.zeroize();
    }
    #[test]
    fn exact_endpoint_cannot_be_reused_while_owned_and_can_be_reacquired_after_drop() {
        let oracle = ProbeOracle::bind("127.0.0.1".parse().unwrap()).unwrap();
        let address = oracle.address();
        assert!(ProbeOracle::bind_address(address).is_err());
        drop(oracle);
        let again = ProbeOracle::bind_address(address).unwrap();
        assert_eq!(again.address(), address);
    }
    #[test]
    fn retired_challenges_release_capacity_and_cannot_be_replayed() {
        let oracle = ProbeOracle::bind("127.0.0.1".parse().unwrap()).unwrap();
        for _ in 0..(MAX_TOKENS * 2) {
            let mut token = oracle.register().unwrap();
            oracle.retire(&token).unwrap();
            assert!(matches!(oracle.seen(&token), Err(ControlError::NotFound)));
            token.zeroize();
        }
    }
    #[test]
    fn rejects_wildcard_and_token_budget_is_bounded() {
        assert!(ProbeOracle::bind("0.0.0.0".parse().unwrap()).is_err());
        let oracle = ProbeOracle::bind("127.0.0.1".parse().unwrap()).unwrap();
        for _ in 0..MAX_TOKENS { oracle.register().unwrap(); }
        assert!(matches!(oracle.register(), Err(ControlError::ResourceConflict)));
    }
}
