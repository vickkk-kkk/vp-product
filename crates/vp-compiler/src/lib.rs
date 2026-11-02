//! Pure, exact product-to-worker recipes. No upstream dependency, IO or secrets.
//! The loopback development profile is explicitly NOT protocol certification.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};
use vp_product_domain::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompileFailure {
    InvalidConfiguration,
    ReleaseMismatch,
    IncompatibleRelease,
    UnsupportedField,
    UnsupportedProtocol,
    UnsupportedTransport,
    UnsupportedSecurity,
    UnsupportedCapability,
    ConflictingBind,
    LoopbackRequired,
    NoEnabledListener,
}
/// Only safe schema field paths, never config values or credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompileError {
    pub code: CompileFailure,
    pub field_path: String,
}
impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} at {}", self.code, self.field_path)
    }
}
impl std::error::Error for CompileError {}
fn error(code: CompileFailure, path: impl Into<String>) -> CompileError {
    CompileError {
        code,
        field_path: path.into(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipeProtocol {
    Vless {},
    Vmess {},
    Shadowsocks { method: ShadowsocksCipher },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecipeListener {
    pub id: ListenerId,
    pub port: u16,
    pub protocol: RecipeProtocol,
    pub users: Vec<ListenerUser>,
}
/// Private durable artifact, not an API DTO. References only: serialization
/// cannot access SecretBytes. Original config is retained to bind all metadata,
/// disabled entries and exact semantics to the artifact; never log this object.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExecutionRecipe {
    pub recipe_version: u16,
    pub profile: ExecutionProfile,
    pub release: ReleaseIdentity,
    pub source: ProductConfig,
    pub bind_address: IpAddr,
    pub listeners: Vec<RecipeListener>,
}
impl std::fmt::Debug for ExecutionRecipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionRecipe")
            .field("recipe_version", &self.recipe_version)
            .field("profile", &self.profile)
            .field("listener_count", &self.listeners.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionProfile {
    /// TCP, loopback listeners and loopback forwarding only. Not Internet/VPN.
    LoopbackDevelopmentUncertified,
}
pub struct Compiler {
    target: ReleaseIdentity,
}
impl Compiler {
    pub fn for_loopback_development(target: ReleaseIdentity) -> Result<Self, CompileError> {
        target
            .validate()
            .map_err(|_| error(CompileFailure::IncompatibleRelease, "release"))?;
        if target.patchset_hash.is_none()
            || !target.schema_read.contains(SCHEMA_VERSION)
            || !target.schema_write.contains(SCHEMA_VERSION)
            || target.abi
                != (VersionPair {
                    major: ABI_MAJOR,
                    minor: ABI_MINOR,
                })
            || target.api
                != (VersionPair {
                    major: API_MAJOR,
                    minor: 0,
                })
        {
            return Err(error(CompileFailure::IncompatibleRelease, "release"));
        }
        Ok(Self { target })
    }
    pub fn target(&self) -> &ReleaseIdentity {
        &self.target
    }
    pub fn compile(
        &self,
        config: &ProductConfig,
        release: &ReleaseIdentity,
    ) -> Result<ExecutionRecipe, CompileError> {
        if release != &self.target {
            return Err(error(CompileFailure::ReleaseMismatch, "release"));
        }
        config
            .validate()
            .map_err(|_| error(CompileFailure::InvalidConfiguration, "config"))?;
        // The current worker has no outbound selector/subscription engine. Do not
        // silently turn a client config into direct forwarding.
        if !config.nodes.is_empty() {
            return Err(error(CompileFailure::UnsupportedField, "nodes"));
        }
        if !config.subscriptions.is_empty() {
            return Err(error(CompileFailure::UnsupportedField, "subscriptions"));
        }
        if config.listeners.len() > 128 {
            return Err(error(CompileFailure::UnsupportedField, "listeners"));
        }
        let mut listeners = Vec::new();
        let mut bind = None;
        let mut ports = BTreeSet::new();
        for (index, listener) in config.listeners.iter().enumerate() {
            let path = |suffix: &str| format!("listeners[{index}].{suffix}");
            if !listener.bind.address.is_loopback() {
                return Err(error(
                    CompileFailure::LoopbackRequired,
                    path("bind.address"),
                ));
            }
            if !matches!(listener.security, ServerSecurity::None {}) {
                return Err(error(CompileFailure::UnsupportedSecurity, path("security")));
            }
            if !matches!(listener.transport, Transport::Tcp {}) {
                return Err(error(
                    CompileFailure::UnsupportedTransport,
                    path("transport"),
                ));
            }
            let ServerProtocol::Proxy { protocol, users } = &listener.protocol else {
                return Err(error(CompileFailure::UnsupportedProtocol, path("protocol")));
            };
            let (protocol, capability) = match protocol {
                Protocol::Vless { flow: None } => (RecipeProtocol::Vless {}, None),
                Protocol::Vless { .. } => {
                    return Err(error(
                        CompileFailure::UnsupportedField,
                        path("protocol.protocol.flow"),
                    ))
                }
                Protocol::Vmess {
                    cipher: VmessCipher::Auto,
                    alter_id: 0,
                } => (RecipeProtocol::Vmess {}, Some(CapabilityKey::VmessTcp)),
                Protocol::Vmess { alter_id, .. } => {
                    return Err(error(
                        CompileFailure::UnsupportedField,
                        path(if *alter_id != 0 {
                            "protocol.protocol.alterId"
                        } else {
                            "protocol.protocol.cipher"
                        }),
                    ))
                }
                // SS protocol expansion is enabled only alongside the reviewed
                // adapter mapping; no cipher substitution is permissible.
                Protocol::Shadowsocks { method } => (
                    RecipeProtocol::Shadowsocks { method: *method },
                    Some(CapabilityKey::Shadowsocks),
                ),
                _ => {
                    return Err(error(
                        CompileFailure::UnsupportedProtocol,
                        path("protocol.protocol"),
                    ))
                }
            };
            if listener
                .requirements
                .iter()
                .any(|key| Some(*key) != capability)
            {
                return Err(error(
                    CompileFailure::UnsupportedCapability,
                    path("requirements"),
                ));
            }
            if ["mixed", "http", "socks5", "redir", "tproxy", "tun"].contains(&listener.id.as_str())
            {
                return Err(error(CompileFailure::UnsupportedField, path("id")));
            }
            let enabled_users: Vec<_> = users.iter().filter(|u| u.enabled).cloned().collect();
            if enabled_users.len() > 128
                || (matches!(protocol, RecipeProtocol::Shadowsocks { .. })
                    && enabled_users.len() != 1)
            {
                return Err(error(
                    CompileFailure::UnsupportedField,
                    path("protocol.users"),
                ));
            }
            if listener.enabled {
                if bind.is_some_and(|address| address != listener.bind.address) {
                    return Err(error(
                        CompileFailure::UnsupportedField,
                        path("bind.address"),
                    ));
                }
                if !ports.insert(listener.bind.port) {
                    return Err(error(CompileFailure::ConflictingBind, path("bind.port")));
                }
                bind = Some(listener.bind.address);
                listeners.push(RecipeListener {
                    id: listener.id.clone(),
                    port: listener.bind.port,
                    protocol,
                    users: enabled_users,
                });
            }
        }
        let bind_address =
            bind.ok_or_else(|| error(CompileFailure::NoEnabledListener, "listeners"))?;
        Ok(ExecutionRecipe {
            recipe_version: 1,
            profile: ExecutionProfile::LoopbackDevelopmentUncertified,
            release: release.clone(),
            source: config.clone(),
            bind_address,
            listeners,
        })
    }
    /// Durable recipes are not trusted deserialized instructions. Recompile and
    /// compare every field against the currently pinned compiler semantics.
    pub fn verify_recipe(&self, recipe: &ExecutionRecipe) -> Result<(), CompileError> {
        if self.compile(&recipe.source, &recipe.release)? != *recipe {
            return Err(error(CompileFailure::InvalidConfiguration, "recipe"));
        }
        Ok(())
    }
}
