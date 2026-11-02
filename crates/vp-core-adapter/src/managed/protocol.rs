//! Private worker protocol: bounded, versioned, no arbitrary paths/plugins/system
//! settings. Credentials exist only in zeroized in-memory config/pipe frames.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{self, BufRead};
use std::net::IpAddr;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_FRAME: usize = 1 << 20;
pub const PROTOCOL_VERSION: u16 = 1;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    InvalidConfig,
    Unsupported,
    Busy,
    StaleGeneration,
    BindFailed,
    StartupFailed,
    Timeout,
    Canceled,
    WorkerExited,
    WorkerIdentityMismatch,
    ProtocolViolation,
    CleanupFailed,
    RollbackFailed,
    Io,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Failure {}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerKind {
    Mixed,
    Http,
    Socks5,
    Vless,
    Vmess,
    Shadowsocks,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerSpec {
    pub tag: String,
    pub kind: ListenerKind,
    pub port: u16,
    #[serde(default)]
    pub users: Vec<String>,
    pub cipher: Option<String>,
}
impl Drop for ListenerSpec {
    fn drop(&mut self) {
        self.users.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerConfig {
    pub schema_version: u16,
    pub bind_address: IpAddr,
    pub listeners: Vec<ListenerSpec>,
}
impl WorkerConfig {
    /// Current execution authority is loopback-only. No root config passthrough.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.schema_version != 1
            || !self.bind_address.is_loopback()
            || self.listeners.is_empty()
            || self.listeners.len() > 128
        {
            return Err(Failure::InvalidConfig);
        }
        let mut names = BTreeSet::new();
        let mut ports = BTreeSet::new();
        let mut builtins = BTreeSet::new();
        let mut credential_bytes = 0_usize;
        for listener in &self.listeners {
            credential_bytes = credential_bytes
                .saturating_add(listener.users.iter().map(String::len).sum::<usize>());
            // JSON escapes can expand each byte sixfold; bound before allocating
            // a serialized credential copy. Exact frame size is checked as well.
            if credential_bytes > MAX_FRAME / 8 {
                return Err(Failure::InvalidConfig);
            }
            if listener.tag.is_empty()
                || listener.tag.len() > 128
                || !listener
                    .tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || !names.insert(&listener.tag)
                || (listener.port != 0 && !ports.insert(listener.port))
            {
                return Err(Failure::InvalidConfig);
            }
            let builtin = match listener.kind {
                ListenerKind::Mixed => Some("mixed"),
                ListenerKind::Http => Some("http"),
                ListenerKind::Socks5 => Some("socks5"),
                _ => None,
            };
            if let Some(tag) = builtin {
                if listener.tag != tag
                    || !builtins.insert(tag)
                    || !listener.users.is_empty()
                    || listener.cipher.is_some()
                {
                    return Err(Failure::InvalidConfig);
                }
            } else {
                if ["mixed", "http", "socks5", "redir", "tproxy", "tun"]
                    .contains(&listener.tag.as_str())
                    || listener.users.is_empty()
                    || listener.users.len() > 128
                    || listener
                        .users
                        .iter()
                        .any(|value| value.is_empty() || value.len() > 4096)
                {
                    return Err(Failure::InvalidConfig);
                }
                if listener.kind == ListenerKind::Shadowsocks {
                    if listener.users.len() != 1
                        || listener.cipher.as_deref().is_none_or(str::is_empty)
                    {
                        return Err(Failure::InvalidConfig);
                    }
                } else if listener.cipher.is_some() {
                    return Err(Failure::InvalidConfig);
                }
            }
        }
        Ok(())
    }
    pub fn to_core_json(&self) -> Result<Zeroizing<String>, Failure> {
        self.validate()?;
        let mut config = serde_json::json!({"allow-lan":true, "bind-address":self.bind_address.to_string(),
            "rules":["IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR6,::1/128,DIRECT,no-resolve", "MATCH,REJECT"]});
        let mut protocol_listeners = Vec::new();
        for listener in &self.listeners {
            match listener.kind {
                ListenerKind::Mixed => config["mixed-port"] = listener.port.into(),
                ListenerKind::Http => config["port"] = listener.port.into(),
                ListenerKind::Socks5 => config["socks-port"] = listener.port.into(),
                kind => {
                    let kind = match kind {
                        ListenerKind::Vless => "vless",
                        ListenerKind::Vmess => "vmess",
                        ListenerKind::Shadowsocks => "ss",
                        _ => return Err(Failure::InvalidConfig),
                    };
                    protocol_listeners.push(serde_json::json!({"name":listener.tag,"type":kind,"port":listener.port,"users":listener.users,"cipher":listener.cipher}));
                }
            }
        }
        config["listeners"] = protocol_listeners.into();
        let result = serde_json::to_string(&config)
            .map(Zeroizing::new)
            .map_err(|_| Failure::InvalidConfig);
        // serde_json::Value holds temporary credential copies; scrub string leaves.
        fn scrub(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(s) => s.zeroize(),
                serde_json::Value::Array(a) => a.iter_mut().for_each(scrub),
                serde_json::Value::Object(m) => m.values_mut().for_each(scrub),
                _ => {}
            }
        }
        scrub(&mut config);
        result
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundListener {
    pub tag: String,
    pub port: u16,
    pub accept_loop_live: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerSnapshot {
    pub generation: u64,
    pub pid: u32,
    pub listeners_ready: bool,
    pub listeners: Vec<BoundListener>,
    pub active_tasks: usize,
    pub task_panics: u64,
    /// Explicitly false: bound + live accept loops are not forwarding evidence.
    pub forwarding_verified: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StopReport {
    pub generation: u64,
    pub drained: bool,
    pub forced_tasks: usize,
    pub remaining_tasks: usize,
    pub process_exited: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Start {
        version: u16,
        generation: u64,
        config: WorkerConfig,
        startup_ms: u64,
    },
    Snapshot {
        generation: u64,
    },
    Stop {
        generation: u64,
        drain_ms: u64,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Hello {
        version: u16,
        core_commit: String,
        patchset_hash: String,
    },
    Started {
        snapshot: WorkerSnapshot,
    },
    Snapshot {
        snapshot: WorkerSnapshot,
    },
    Stopped {
        report: StopReport,
    },
    Failed {
        failure: Failure,
    },
}
/// Never read an unbounded line from the pipe (or silently accept truncated JSON).
pub fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let count =
        std::io::Read::take(&mut *reader, (MAX_FRAME + 1) as u64).read_until(b'\n', &mut bytes)?;
    if count == 0 {
        return Ok(None);
    }
    if count > MAX_FRAME || bytes.last() != Some(&b'\n') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid frame"));
    }
    Ok(Some(bytes))
}
