use crate::{
    ErrorCode, ErrorStage, EvidenceId, ProductError, ReleaseIdentity, SafeCode, ShadowsocksCipher,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum CapabilityKey {
    #[serde(rename = "preset.tuic")]
    Tuic,
    #[serde(rename = "preset.trojan-tls")]
    TrojanTls,
    #[serde(rename = "preset.hysteria2")]
    Hysteria2,
    #[serde(rename = "preset.vmess-ws")]
    VmessWs,
    #[serde(rename = "preset.vmess-tcp")]
    VmessTcp,
    #[serde(rename = "preset.vmess-http")]
    VmessHttp,
    #[serde(rename = "preset.vmess-quic")]
    VmessQuic,
    #[serde(rename = "preset.shadowsocks")]
    Shadowsocks,
    #[serde(rename = "preset.vmess-h2-tls")]
    VmessH2Tls,
    #[serde(rename = "preset.vmess-ws-tls")]
    VmessWsTls,
    #[serde(rename = "preset.vless-h2-tls")]
    VlessH2Tls,
    #[serde(rename = "preset.vless-ws-tls")]
    VlessWsTls,
    #[serde(rename = "preset.trojan-h2-tls")]
    TrojanH2Tls,
    #[serde(rename = "preset.trojan-ws-tls")]
    TrojanWsTls,
    #[serde(rename = "preset.vmess-httpupgrade-tls")]
    VmessHttpUpgradeTls,
    #[serde(rename = "preset.vless-httpupgrade-tls")]
    VlessHttpUpgradeTls,
    #[serde(rename = "preset.trojan-httpupgrade-tls")]
    TrojanHttpUpgradeTls,
    #[serde(rename = "preset.vless-reality-vision")]
    VlessRealityVision,
    #[serde(rename = "preset.vless-h2-reality")]
    VlessH2Reality,
    #[serde(rename = "preset.anytls")]
    AnyTls,
    #[serde(rename = "preset.socks-auth")]
    SocksAuth,
    #[serde(rename = "preset.direct-forward")]
    DirectForward,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Traffic {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    LinuxService,
    Android,
    Ios,
    Macos,
    Windows,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Unimplemented,
    Blocked,
    Experimental,
    Certified,
    Deprecated,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    Tuic,
    Trojan,
    Hysteria2,
    Vmess,
    Shadowsocks,
    Vless,
    #[serde(rename = "anytls")]
    AnyTls,
    Socks5,
    Direct,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Tcp,
    Ws,
    Http,
    H2,
    HttpUpgrade,
    Quic,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecurityKind {
    None,
    Tls,
    Reality,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PresetScope {
    RequiredPublicBaseline,
    ExplicitDecisionRequired,
    Included,
    ExcludedByUserDecision,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresetDefinition {
    pub id: String,
    pub key: CapabilityKey,
    pub name: String,
    pub protocol: ProtocolKind,
    pub transport: TransportKind,
    pub security: SecurityKind,
    pub ciphers: Vec<ShadowsocksCipher>,
    pub scope: PresetScope,
    pub status: CapabilityStatus,
    pub reason: SafeCode,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresetCatalog {
    pub schema_version: u16,
    pub presets: Vec<PresetDefinition>,
}
/// A planning catalog only. No row in this artifact is a certified capability.
pub fn preset_catalog() -> Result<PresetCatalog, serde_json::Error> {
    serde_json::from_str(include_str!("../../../contracts/capabilities/presets.json"))
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescriptor {
    pub key: CapabilityKey,
    pub direction: Direction,
    pub protocol: ProtocolKind,
    pub transport: TransportKind,
    pub security: SecurityKind,
    pub cipher: Option<ShadowsocksCipher>,
    pub traffic: Traffic,
    pub ip_family: IpFamily,
    pub platform: Platform,
    pub status: CapabilityStatus,
    pub reason: SafeCode,
    pub evidence_ids: Vec<EvidenceId>,
    pub release_identity: ReleaseIdentity,
}
impl CapabilityDescriptor {
    /// This checks the shape of a certification claim, not the truth/signature
    /// of evidence. Release verification must independently authenticate it.
    pub fn validate_claim(&self) -> Result<(), ProductError> {
        self.release_identity.validate()?;
        if self.status == CapabilityStatus::Certified
            && (self.evidence_ids.is_empty()
                || self.release_identity.evidence_manifest_hash.is_none()
                || self.release_identity.patchset_hash.is_none())
        {
            return Err(ProductError::new(
                ErrorCode::CapabilityUncertified,
                ErrorStage::Validate,
            ));
        }
        if (self.protocol == ProtocolKind::Shadowsocks) != self.cipher.is_some() {
            return Err(
                ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Validate).at("cipher"),
            );
        }
        Ok(())
    }
}
