//! Pure, bounded import of user-provided text. No fetch, vault or runtime access.
//! A parsed candidate is not a persisted node, a trusted subscription, or a
//! certified capability. Secrets never enter ordinary DTOs or diagnostics.
#![forbid(unsafe_code)]

mod encoding;
mod export;
mod json;
pub mod mobile;
mod uri;

pub use export::export_uri;
use serde::{Deserialize, Serialize};
use std::fmt;
use vp_product_domain::*;
use zeroize::Zeroizing;

pub const MAX_INPUT_BYTES: usize = 1_048_576;
pub const MAX_URI_BYTES: usize = 16_384;
pub const MAX_ENTRIES: usize = 1024;
pub const MAX_QUERY_FIELDS: usize = 32;
pub const MAX_COMPONENT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    /// Detection never fetches URLs; unknown text is not automatically base64.
    Auto,
    NodeUri,
    UriList,
    Base64UriList,
    /// JSON subset only in this tranche. YAML is recognized but unsupported.
    ClashNodes,
    SingBoxOutbounds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueKind {
    InvalidSyntax,
    InvalidValue,
    InputLimit,
    InvalidUtf8,
    DuplicateField,
    UnknownField,
    UnsupportedFormat,
    UnsupportedScheme,
    UnsupportedFeature,
    InsecureTrust,
    UnimportedTopLevelFields,
    SecretBindingMismatch,
    LossyExport,
}

/// Paths are authored constants, never attacker-controlled keys or input text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportIssue {
    pub kind: IssueKind,
    pub error: ProductError,
}
impl fmt::Display for ImportIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)
    }
}
impl std::error::Error for ImportIssue {}
pub(crate) fn issue(kind: IssueKind, path: &'static str) -> ImportIssue {
    let code = match kind {
        IssueKind::InputLimit => ErrorCode::InputTooLarge,
        IssueKind::InvalidUtf8 => ErrorCode::InvalidUtf8,
        IssueKind::UnknownField => ErrorCode::ConfigUnknownField,
        IssueKind::UnsupportedFormat
        | IssueKind::UnsupportedScheme
        | IssueKind::UnsupportedFeature
        | IssueKind::UnimportedTopLevelFields => ErrorCode::ImportUnsupported,
        IssueKind::InsecureTrust => ErrorCode::TlsTrustFailed,
        IssueKind::LossyExport => ErrorCode::ExportLossy,
        _ => ErrorCode::ConfigInvalid,
    };
    ImportIssue {
        kind,
        error: ProductError::new(code, ErrorStage::Decode).at(path),
    }
}
pub(crate) fn invalid(path: &'static str) -> ImportIssue {
    issue(IssueKind::InvalidValue, path)
}
pub(crate) fn unsupported(path: &'static str) -> ImportIssue {
    issue(IssueKind::UnsupportedFeature, path)
}
pub(crate) type Result<T> = std::result::Result<T, ImportIssue>;

/// Credential encoding is explicit. Vault adapters must serialize/encrypt these
/// typed components at their own boundary; never infer a password delimiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialKind {
    None,
    Password,
    Uuid,
    UsernamePassword,
    UuidPassword,
}
pub struct Credential {
    pub kind: CredentialKind,
    pub primary: SecretBytes,
    pub secondary: Option<SecretBytes>,
}
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential([REDACTED])")
    }
}
impl Credential {
    pub fn password(value: Vec<u8>) -> Self {
        Self {
            kind: CredentialKind::Password,
            primary: SecretBytes::new(value),
            secondary: None,
        }
    }
    pub fn uuid(value: Vec<u8>) -> Self {
        Self {
            kind: CredentialKind::Uuid,
            primary: SecretBytes::new(value),
            secondary: None,
        }
    }
}
#[derive(Debug)]
pub struct SecretBundle {
    pub credential: Credential,
    /// This tranche supports only Hysteria2 Salamander obfuscation.
    pub obfuscation: Option<SecretBytes>,
}
/// Supplied only after an authorized vault transaction. These identifiers are
/// never created by the parser. The caller owns rollback if persistence fails.
#[derive(Debug)]
pub struct AllocatedSecrets {
    pub credential_ref: SecretRef,
    pub obfuscation_ref: Option<SecretRef>,
}

/// Canonical redacted preview; its serializer forbids obfuscation vault refs.
pub type NodePreview = ImportNodePreview;

/// Sealed, non-Clone, non-Serialize staging object. Persist only after explicit
/// user selection; no NodeProfile with fake secret references escapes parsing.
/// ```compile_fail
/// use vp_product_import::{parse, ImportFormat};
/// let batch = parse(b"ss://bad", ImportFormat::NodeUri).unwrap();
/// let _ = serde_json::to_string(&batch); // Deliberately unavailable.
/// ```
pub struct ImportCandidate {
    preview: NodePreview,
    secrets: SecretBundle,
}
impl fmt::Debug for ImportCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImportCandidate([REDACTED])")
    }
}
impl ImportCandidate {
    pub fn preview(&self) -> &NodePreview {
        &self.preview
    }
    /// Explicit secret boundary for a vault adapter, not a UI DTO.
    pub fn secrets(&self) -> &SecretBundle {
        &self.secrets
    }
    pub(crate) fn new(preview: NodePreview, secrets: SecretBundle) -> Result<Self> {
        preview.validate().map_err(|_| invalid("preview"))?;
        if preview.has_obfuscation != secrets.obfuscation.is_some() {
            return Err(invalid("obfuscation"));
        }
        let candidate = Self { preview, secrets };
        candidate.validate()?;
        Ok(candidate)
    }
    fn validate(&self) -> Result<()> {
        // Structural validation only: local sentinels never leave this method,
        // identify no vault entry, and are never exposed in a result or report.
        let node = self.make_profile(
            NodeId::new("validation-only").map_err(|_| invalid("node"))?,
            None,
            AllocatedSecrets {
                credential_ref: SecretRef::new("validation-only").map_err(|_| invalid("node"))?,
                obfuscation_ref: if self.secrets.obfuscation.is_some() {
                    Some(SecretRef::new("validation-only-obfs").map_err(|_| invalid("node"))?)
                } else {
                    None
                },
            },
        )?;
        node.validate().map_err(|_| invalid("node"))?;
        validate_secrets(&node.protocol, &self.secrets)?;
        validate_security(&node.security)?;
        Ok(())
    }
    fn make_profile(
        &self,
        id: NodeId,
        source_ref: Option<SourceId>,
        allocated: AllocatedSecrets,
    ) -> Result<NodeProfile> {
        if allocated.obfuscation_ref.is_some() != self.secrets.obfuscation.is_some() {
            return Err(issue(
                IssueKind::SecretBindingMismatch,
                "secrets.obfuscation",
            ));
        }
        let mut protocol = self.preview.protocol.clone();
        if let Protocol::Hysteria2 { obfuscation_ref } = &mut protocol {
            *obfuscation_ref = allocated.obfuscation_ref;
        }
        Ok(NodeProfile {
            schema_version: SCHEMA_VERSION,
            id,
            name: self.preview.name.clone(),
            endpoint: self.preview.endpoint.clone(),
            protocol,
            transport: self.preview.transport.clone(),
            security: self.preview.security.clone(),
            credential_ref: allocated.credential_ref,
            requirements: Vec::new(),
            source_ref,
        })
    }
    /// Caller must bind refs to exactly `secrets()`, atomically with node storage.
    /// No network, storage, capability approval, or automatic selection occurs.
    pub fn materialize(
        self,
        id: NodeId,
        source_ref: Option<SourceId>,
        allocated: AllocatedSecrets,
    ) -> Result<NodeProfile> {
        let node = self.make_profile(id, source_ref, allocated)?;
        node.validate().map_err(|_| invalid("node"))?;
        Ok(node)
    }
}

pub struct StagedEntry {
    pub index: u32,
    pub candidate: Option<ImportCandidate>,
    pub diagnostics: Vec<ImportIssue>,
}
impl fmt::Debug for StagedEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedEntry")
            .field("index", &self.index)
            .field("has_candidate", &self.candidate.is_some())
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}
#[derive(Debug)]
pub struct ImportBatch {
    pub format: ImportFormat,
    pub entries: Vec<StagedEntry>,
    pub diagnostics: Vec<ImportIssue>,
    pub has_unimported_fields: bool,
}
impl ImportBatch {
    /// Domain report deliberately includes no node until actual vault binding.
    /// Candidate preview lives behind the nonserializable staging boundary.
    pub fn review_report(&self) -> ImportReport {
        ImportReport {
            schema_version: SCHEMA_VERSION,
            entries: self
                .entries
                .iter()
                .map(|e| ImportEntry {
                    index: e.index,
                    disposition: if e.candidate.is_some() {
                        ImportDisposition::NeedsReview
                    } else {
                        ImportDisposition::Rejected
                    },
                    node: None,
                    preview: e.candidate.as_ref().map(|c| c.preview().clone()),
                    duplicate_of: None,
                    diagnostics: e.diagnostics.iter().map(|d| d.error.clone()).collect(),
                })
                .collect(),
            diagnostics: self.diagnostics.iter().map(|d| d.error.clone()).collect(),
            has_unimported_fields: self.has_unimported_fields,
        }
    }
}

/// Input must be the already-decoded QR text or downloaded file bytes. The
/// caller retains ownership of original input and must protect/erase it itself.
pub fn parse(input: &[u8], format: ImportFormat) -> Result<ImportBatch> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(issue(IssueKind::InputLimit, "input"));
    }
    let text = std::str::from_utf8(input).map_err(|_| issue(IssueKind::InvalidUtf8, "input"))?;
    let text = text.trim();
    if text.is_empty() {
        return Err(invalid("input"));
    }
    let format = if format == ImportFormat::Auto {
        if text.starts_with('{') {
            json::detect(text)?
        } else if text.starts_with("proxies:") || text.starts_with("---") {
            ImportFormat::ClashNodes
        } else if text.contains("://") {
            if text.lines().count() == 1 {
                ImportFormat::NodeUri
            } else {
                ImportFormat::UriList
            }
        } else {
            return Err(issue(IssueKind::UnsupportedFormat, "format"));
        }
    } else {
        format
    };
    match format {
        ImportFormat::NodeUri | ImportFormat::UriList => parse_list(text, format),
        ImportFormat::Base64UriList => {
            let compact = Zeroizing::new(
                text.chars()
                    .filter(|c| !matches!(c, '\r' | '\n'))
                    .collect::<String>(),
            );
            let decoded = encoding::decode_base64(&compact, MAX_INPUT_BYTES)?;
            let decoded = std::str::from_utf8(&decoded)
                .map_err(|_| issue(IssueKind::InvalidUtf8, "subscription"))?;
            let mut batch = parse_list(decoded, ImportFormat::UriList)?;
            batch.format = format;
            Ok(batch)
        }
        ImportFormat::ClashNodes | ImportFormat::SingBoxOutbounds => {
            json::parse_nodes(text, format)
        }
        ImportFormat::Auto => Err(issue(IssueKind::UnsupportedFormat, "format")),
    }
}
fn parse_list(text: &str, format: ImportFormat) -> Result<ImportBatch> {
    if format == ImportFormat::NodeUri && text.lines().count() != 1 {
        return Err(invalid("uri"));
    }
    // Bound physical lines too; blank-line floods cannot bypass entry limits.
    if text.lines().count() > MAX_ENTRIES {
        return Err(issue(IssueKind::InputLimit, "entries"));
    }
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed = if line.len() > MAX_URI_BYTES {
            Err(issue(IssueKind::InputLimit, "uri"))
        } else {
            uri::parse_uri(line)
        };
        let (candidate, diagnostics) = match parsed {
            Ok(c) => (Some(c), Vec::new()),
            Err(e) => (None, vec![e]),
        };
        entries.push(StagedEntry {
            index: index as u32,
            candidate,
            diagnostics,
        });
    }
    if entries.is_empty() {
        return Err(invalid("entries"));
    }
    let has_unimported_fields = entries.iter().any(|e| e.candidate.is_none());
    Ok(ImportBatch {
        format,
        entries,
        diagnostics: Vec::new(),
        has_unimported_fields,
    })
}

/// Explicitly secret-bearing URI output; no implicit Display/Serialize/Clone.
pub struct SecretText(Zeroizing<String>);
impl SecretText {
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}
impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText([REDACTED])")
    }
}
pub(crate) fn text_secret(secret: &SecretBytes) -> Result<&str> {
    std::str::from_utf8(secret.expose()).map_err(|_| invalid("credential"))
}
pub(crate) fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
pub(crate) fn validate_secrets(protocol: &Protocol, secrets: &SecretBundle) -> Result<()> {
    let c = &secrets.credential;
    let primary = text_secret(&c.primary)?;
    if primary.len() > MAX_COMPONENT_BYTES || primary.chars().any(char::is_control) {
        return Err(invalid("credential"));
    }
    let expected = match protocol {
        Protocol::Vmess { .. } | Protocol::Vless { .. } => CredentialKind::Uuid,
        Protocol::Tuic { .. } => CredentialKind::UuidPassword,
        Protocol::Socks5 {} => {
            if c.kind == CredentialKind::None {
                CredentialKind::None
            } else {
                CredentialKind::UsernamePassword
            }
        }
        _ => CredentialKind::Password,
    };
    if c.kind != expected {
        return Err(issue(IssueKind::SecretBindingMismatch, "credential.kind"));
    }
    if matches!(
        expected,
        CredentialKind::Uuid | CredentialKind::UuidPassword
    ) && !valid_uuid(primary)
    {
        return Err(invalid("credential.uuid"));
    }
    if expected == CredentialKind::None && (!primary.is_empty() || c.secondary.is_some()) {
        return Err(invalid("credential"));
    }
    if expected != CredentialKind::None && primary.is_empty() {
        return Err(invalid("credential"));
    }
    if matches!(
        expected,
        CredentialKind::UsernamePassword | CredentialKind::UuidPassword
    ) {
        let secondary = text_secret(c.secondary.as_ref().ok_or_else(|| invalid("credential"))?)?;
        if secondary.is_empty()
            || secondary.len() > MAX_COMPONENT_BYTES
            || secondary.chars().any(char::is_control)
        {
            return Err(invalid("credential"));
        }
        if expected == CredentialKind::UsernamePassword
            && (primary.len() > 255 || secondary.len() > 255)
        {
            return Err(invalid("credential"));
        }
    } else if c.secondary.is_some() {
        return Err(invalid("credential"));
    }
    if let Some(obfs) = &secrets.obfuscation {
        if !matches!(protocol, Protocol::Hysteria2 { .. }) {
            return Err(invalid("obfuscation"));
        }
        let obfs = text_secret(obfs)?;
        if obfs.is_empty() || obfs.len() > MAX_COMPONENT_BYTES || obfs.chars().any(char::is_control)
        {
            return Err(invalid("obfuscation"));
        }
    }
    if let Protocol::Shadowsocks { method } = protocol {
        if method.is_2022() {
            // Extensible identity-key chains need a separate explicit contract.
            if primary.contains(':') {
                return Err(unsupported("credential.identity_chain"));
            }
            let key = encoding::decode_base64(primary, 32)?;
            let expected = if *method == ShadowsocksCipher::Blake3Aes128Gcm2022 {
                16
            } else {
                32
            };
            if key.len() != expected {
                return Err(invalid("credential.key_length"));
            }
        }
    }
    Ok(())
}
pub(crate) fn validate_security(security: &ClientSecurity) -> Result<()> {
    match security {
        ClientSecurity::Tls {
            alpn,
            client_hello_fingerprint,
            ..
        } => {
            if alpn.len() > 16
                || alpn
                    .iter()
                    .any(|v| v.contains(',') || v.chars().any(char::is_control))
            {
                return Err(invalid("security.alpn"));
            }
            if client_hello_fingerprint.as_ref().is_some_and(|v| {
                v.is_empty()
                    || v.len() > 64
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            }) {
                return Err(invalid("security.client_hello_fingerprint"));
            }
        }
        ClientSecurity::Reality {
            public_key,
            client_hello_fingerprint,
            ..
        } => {
            if encoding::decode_base64(public_key, 32)?.len() != 32 {
                return Err(invalid("security.publicKey"));
            }
            if client_hello_fingerprint.as_ref().is_some_and(|v| {
                v.is_empty()
                    || v.len() > 64
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            }) {
                return Err(invalid("security.client_hello_fingerprint"));
            }
        }
        _ => {}
    }
    Ok(())
}
