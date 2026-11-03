//! Pure protocol3 public association codec. No IPC, secrets, process ownership,
//! registry authority, signature verification, runtime startup or restart API.
//! These DTOs are correlation data, never admission authority. Future worker IO
//! must derive observations from actual typed material, never caller assertions.
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use vp_product_compiler::server_v2::{CredentialEncodingV2, ServerCompilerV2, ServerProtocolV2, ServerRecipeV2, ServerSecurityV2, ServerTransportV2};
use vp_product_domain::{OperationId, SecretRef, CertificateId, MAX_WIRE_COUNTER};

pub const PROTOCOL: u16 = 3;
pub const MAX_ACTIVATE_BYTES: usize = 256 * 1024;
pub const MAX_HEADER_BYTES: usize = 8192;
pub const MAX_MANIFEST_BYTES: usize = 512 * 1024;
pub const MAX_RECIPE_BYTES: usize = 1024 * 1024;
pub const MAX_LISTENERS: usize = 128;
pub const MAX_ASSOCIATIONS: usize = 512;
pub const MAX_SELECTED_CERTIFICATES: usize = 8;
pub const MAX_CHAIN_CERTIFICATES: usize = 128;
pub const MAX_CERTIFICATE_OCCURRENCES: usize = 4096;
pub const MAX_ADMISSION_MS: u64 = 10_000;
pub const PREPARED_LEASE_MS: u64 = 30_000;
pub const ADMISSION_DOMAIN: &str = "vp.server-activation-admission.v3";
pub const MANIFEST_DOMAIN: &str = "vp.server-preparation-manifest.v3";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    UnsupportedProtocol, MalformedFrame, FrameTooLarge, StructuralLimit,
    InvalidState, GenerationConflict, GenerationExhausted, PreparationMismatch,
    AdmissionDigestMismatch, Replay, PreparedExpired, AdmissionExpired,
    ClockUnavailable, ClockRegression, PathMismatch, UnsupportedCertificateMetadata,
    CertificateNotYetValid, CertificateExpired, Canceled, StartupTimeout,
    StartupFailed, CleanupUncertain,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HexDigest(String);
impl TryFrom<String> for HexDigest {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { Ok(Self(value)) }
        else { Err("invalid digest") }
    }
}
impl From<HexDigest> for String { fn from(v: HexDigest) -> Self { v.0 } }
impl HexDigest {
    pub fn as_str(&self) -> &str { &self.0 }
    /// Public content only. Never pass passwords, private keys or their hashes.
    pub fn public_bytes(bytes: &[u8]) -> Self {
        let bytes = Sha256::digest(bytes);
        let mut text = String::with_capacity(64);
        for byte in bytes { use std::fmt::Write; let _ = write!(text, "{byte:02x}"); }
        Self(text)
    }
}
// Deliberately omit Debug for nonce/digest-bearing DTOs and reference records.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WorkerInstance(String);
impl TryFrom<String> for WorkerInstance {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) { Ok(Self(value)) }
        else { Err("invalid worker instance") }
    }
}
impl From<WorkerInstance> for String { fn from(v: WorkerInstance) -> Self { v.0 } }

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role { CertificateChain, PrivateKey, Password }
impl Role { fn kind(self) -> u8 { match self { Self::CertificateChain => 6, Self::PrivateKey => 2, Self::Password => 1 } } }

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialIdentity {
    pub role: Role,
    /// CertificateId for a chain; SecretRef for keys/passwords, as in recipe2.
    pub recipe_reference: String,
    /// Actual authenticated vault record reference, including chain backing ref.
    pub record_reference: SecretRef,
    pub kind: u8,
    pub version: u64,
    pub chain_digest: Option<HexDigest>,
}
impl MaterialIdentity {
    fn validate(&self) -> Result<(), Failure> {
        counter(self.version)?;
        if self.kind != self.role.kind() || self.version == 0 { return Err(Failure::PreparationMismatch); }
        match self.role {
            Role::CertificateChain => {
                CertificateId::new(self.recipe_reference.clone()).map_err(|_| Failure::PreparationMismatch)?;
                if self.chain_digest.is_none() { return Err(Failure::PreparationMismatch); }
            }
            _ => {
                let r = SecretRef::try_from(self.recipe_reference.clone()).map_err(|_| Failure::PreparationMismatch)?;
                if r != self.record_reference || self.chain_digest.is_some() { return Err(Failure::PreparationMismatch); }
            }
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Association {
    pub listener_index: u16,
    pub user_index: Option<u16>,
    pub material: MaterialIdentity,
    pub asset_revision: Option<u64>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationManifest {
    pub protocol: u16,
    pub instance_id: WorkerInstance,
    pub generation: u64,
    pub recipe_digest: HexDigest,
    /// Existing vp.release-identity.v1 domain over exact recipe.release.
    pub release_digest: HexDigest,
    pub associations: Vec<Association>,
}
fn counter(n: u64) -> Result<(), Failure> { if n <= MAX_WIRE_COUNTER { Ok(()) } else { Err(Failure::StructuralLimit) } }

/// Canonical JSON: lexicographically sorted object keys, preserved array order,
/// serde_json compact scalars. Only typed public DTOs enter this function.
fn canonical(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), Failure> {
    match value {
        serde_json::Value::Object(map) => {
            out.push(b'{');
            let sorted: BTreeMap<_, _> = map.iter().collect();
            for (i, (key, value)) in sorted.into_iter().enumerate() {
                if i != 0 { out.push(b','); }
                serde_json::to_writer(&mut *out, key).map_err(|_| Failure::MalformedFrame)?;
                out.push(b':'); canonical(value, out)?;
            }
            out.push(b'}');
        }
        serde_json::Value::Array(values) => {
            out.push(b'[');
            for (i, value) in values.iter().enumerate() { if i != 0 { out.push(b','); } canonical(value, out)?; }
            out.push(b']');
        }
        _ => serde_json::to_writer(out, value).map_err(|_| Failure::MalformedFrame)?,
    }
    Ok(())
}
fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, Failure> {
    let value = serde_json::to_value(value).map_err(|_| Failure::MalformedFrame)?;
    let mut out = Vec::new(); canonical(&value, &mut out)?; Ok(out)
}
fn domain_digest(domain: &str, value: &serde_json::Value) -> Result<HexDigest, Failure> {
    // UTF8 domain || NUL || canonical JSON. Domains are fixed reviewed constants.
    let mut bytes = domain.as_bytes().to_vec(); bytes.push(0); canonical(value, &mut bytes)?;
    Ok(HexDigest::public_bytes(&bytes))
}
/// Reuses the existing control release identity domain/encoding, not a new identity.
pub fn release_digest(release: &vp_product_domain::ReleaseIdentity) -> Result<HexDigest, Failure> {
    domain_digest("vp.release-identity.v1", &serde_json::to_value(release).map_err(|_| Failure::MalformedFrame)?)
}
// serde struct derives also accept positional sequences. This public-frame
// preflight narrows wire DTOs to objects; the second typed parse of ORIGINAL
// bytes still detects duplicate keys (never deserialize the normalized Value).
fn require_object_nodes(bytes: &[u8], sequence: Option<&str>, nested: Option<&str>, limit: usize) -> Result<(), Failure> {
    let root: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Failure::MalformedFrame)?;
    let object = root.as_object().ok_or(Failure::MalformedFrame)?;
    let Some(sequence) = sequence else { return Ok(()); };
    let rows = object.get(sequence).and_then(serde_json::Value::as_array).ok_or(Failure::MalformedFrame)?;
    if rows.len() > limit { return Err(Failure::StructuralLimit); }
    for row in rows {
        let object = row.as_object().ok_or(Failure::MalformedFrame)?;
        if let Some(field) = nested {
            if !object.get(field).is_some_and(serde_json::Value::is_object) { return Err(Failure::MalformedFrame); }
        }
    }
    Ok(())
}
impl PreparationManifest {
    pub fn decode(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() > MAX_MANIFEST_BYTES { return Err(Failure::FrameTooLarge); }
        require_object_nodes(bytes, Some("associations"), Some("material"), MAX_ASSOCIATIONS)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Failure::MalformedFrame)?;
        value.validate_shape()?; Ok(value)
    }
    pub fn validate_shape(&self) -> Result<(), Failure> {
        if self.protocol != PROTOCOL { return Err(Failure::UnsupportedProtocol); }
        counter(self.generation)?;
        if self.generation == 0 || self.associations.is_empty() || self.associations.len() > MAX_ASSOCIATIONS { return Err(Failure::StructuralLimit); }
        let mut previous = None;
        for a in &self.associations {
            if usize::from(a.listener_index) >= MAX_LISTENERS { return Err(Failure::StructuralLimit); }
            a.material.validate()?;
            let key = (a.listener_index, a.material.role, a.user_index);
            if previous.is_some_and(|p| p >= key) { return Err(Failure::PreparationMismatch); }
            previous = Some(key);
            if (a.material.role == Role::Password) != a.user_index.is_some()
                || (a.material.role == Role::CertificateChain) != a.asset_revision.is_some() { return Err(Failure::PreparationMismatch); }
            if let Some(revision) = a.asset_revision { counter(revision)?; if revision == 0 { return Err(Failure::PreparationMismatch); } }
        }
        if canonical_bytes(self)?.len() > MAX_MANIFEST_BYTES { return Err(Failure::FrameTooLarge); }
        Ok(())
    }
    pub fn digest(&self) -> Result<HexDigest, Failure> {
        self.validate_shape()?;
        domain_digest(MANIFEST_DOMAIN, &serde_json::to_value(self).map_err(|_| Failure::MalformedFrame)?)
    }
    /// Future worker MUST supply observations from its actual bounded typed
    /// material records. This pure comparison cannot authenticate vault metadata.
    /// Exact compiler output is compared, never mutable recipe DTO claims alone.
    pub fn verify_preparation(&self, recipe_bytes: &[u8], compiler: &ServerCompilerV2, observations: &[MaterialIdentity]) -> Result<(), Failure> {
        self.validate_shape()?;
        if recipe_bytes.len() > MAX_RECIPE_BYTES || observations.len() > MAX_ASSOCIATIONS { return Err(Failure::StructuralLimit); }
        let recipe: ServerRecipeV2 = serde_json::from_slice(recipe_bytes).map_err(|_| Failure::MalformedFrame)?;
        if compiler.compile(&recipe.source, &recipe.release).map_err(|_| Failure::PreparationMismatch)? != recipe
            || self.recipe_digest != HexDigest::public_bytes(recipe_bytes)
            || self.release_digest != release_digest(&recipe.release)? { return Err(Failure::PreparationMismatch); }
        if recipe.listeners.is_empty() || recipe.listeners.len() > MAX_LISTENERS { return Err(Failure::StructuralLimit); }
        let mut expected = BTreeMap::new();
        for (index, listener) in recipe.listeners.iter().enumerate() {
            if !matches!(listener.protocol, ServerProtocolV2::Trojan {}) || !matches!(listener.transport, ServerTransportV2::Tcp {}) || !listener.bind.address.is_loopback() { return Err(Failure::PreparationMismatch); }
            let ServerSecurityV2::Tls { certificate_ref, private_key_ref, .. } = &listener.security else { return Err(Failure::PreparationMismatch); };
            let index = u16::try_from(index).map_err(|_| Failure::StructuralLimit)?;
            expected.insert((index, Role::CertificateChain, None), certificate_ref.as_str());
            expected.insert((index, Role::PrivateKey, None), private_key_ref.as_str());
            if listener.credentials.is_empty() { return Err(Failure::PreparationMismatch); }
            for (user, credential) in listener.credentials.iter().enumerate() {
                if !matches!(credential.encoding, CredentialEncodingV2::PasswordUtf8V1 {}) { return Err(Failure::PreparationMismatch); }
                let user = u16::try_from(user).map_err(|_| Failure::StructuralLimit)?;
                expected.insert((index, Role::Password, Some(user)), credential.reference.as_str());
                if expected.len() > MAX_ASSOCIATIONS { return Err(Failure::StructuralLimit); }
            }
        }
        if expected.len() != self.associations.len() { return Err(Failure::PreparationMismatch); }
        let mut associated = BTreeSet::new();
        // A recipe reference denotes one immutable identity across all listeners.
        // Deduplicating only MaterialIdentity would omit the asset revision and
        // permit a shared certificate ref to alias different backing records.
        let mut shared = BTreeMap::new();
        for a in &self.associations {
            if expected.get(&(a.listener_index, a.material.role, a.user_index)).copied() != Some(a.material.recipe_reference.as_str()) { return Err(Failure::PreparationMismatch); }
            let key = (a.material.role, a.material.recipe_reference.as_str());
            let identity = (&a.material, a.asset_revision);
            if shared.insert(key, identity).is_some_and(|previous| previous != identity) {
                return Err(Failure::PreparationMismatch);
            }
            associated.insert(a.material.clone());
        }
        let mut observed = BTreeSet::new();
        let mut refs = BTreeMap::new();
        for record in observations {
            record.validate()?;
            if !observed.insert(record.clone()) || refs.insert(record.record_reference.as_str(), record).is_some() { return Err(Failure::PreparationMismatch); }
        }
        if observed != associated { return Err(Failure::PreparationMismatch); }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode { Activate, Restore }
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedPath {
    pub listener_index: u16,
    pub chain_digest: HexDigest,
    pub anchor_digest: HexDigest,
    pub certificate_digests: Vec<HexDigest>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub protocol: u16,
    pub mode: Mode,
    pub instance_id: WorkerInstance,
    pub generation: u64,
    pub recipe_digest: HexDigest,
    pub preparation_manifest_digest: HexDigest,
    pub prepared_nonce: HexDigest,
    pub transition_operation_id: OperationId,
    pub revision_owner_operation_id: OperationId,
    pub transition_plan_hash: HexDigest,
    pub revision_owner_plan_hash: HexDigest,
    pub target_revision: u64,
    pub config_digest: HexDigest,
    pub release_digest: HexDigest,
    pub artifact_digest: HexDigest,
    pub aggregate_version: u64,
    pub policy_fingerprint: HexDigest,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub max_startup_ms: u64,
    pub allowed_clock_skew_ms: u64,
    pub paths: Vec<SelectedPath>,
    pub admission_digest: HexDigest,
}
impl Admission {
    pub fn decode(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() > MAX_ACTIVATE_BYTES { return Err(Failure::FrameTooLarge); }
        require_object_nodes(bytes, Some("paths"), None, MAX_LISTENERS)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Failure::MalformedFrame)?;
        value.validate()?; Ok(value)
    }
    /// Digest computation is public correlation, not issuance of authority.
    pub fn computed_digest(&self) -> Result<HexDigest, Failure> {
        let mut value = serde_json::to_value(self).map_err(|_| Failure::MalformedFrame)?;
        value.as_object_mut().ok_or(Failure::MalformedFrame)?.remove("admission_digest");
        domain_digest(ADMISSION_DOMAIN, &value)
    }
    pub fn validate(&self) -> Result<(), Failure> {
        if self.protocol != PROTOCOL { return Err(Failure::UnsupportedProtocol); }
        for n in [self.generation, self.target_revision, self.aggregate_version, self.issued_at_ms, self.expires_at_ms] { counter(n)?; }
        if self.generation == 0 || self.target_revision == 0 || self.paths.is_empty() || self.paths.len() > MAX_LISTENERS { return Err(Failure::StructuralLimit); }
        if self.allowed_clock_skew_ms != 0 || self.max_startup_ms == 0 || self.max_startup_ms > MAX_ADMISSION_MS
            || self.expires_at_ms.checked_sub(self.issued_at_ms).filter(|v| *v > 0 && *v <= MAX_ADMISSION_MS).is_none() { return Err(Failure::StructuralLimit); }
        if self.mode == Mode::Activate && (self.transition_operation_id != self.revision_owner_operation_id || self.transition_plan_hash != self.revision_owner_plan_hash) { return Err(Failure::PreparationMismatch); }
        if self.mode == Mode::Restore && self.transition_operation_id == self.revision_owner_operation_id { return Err(Failure::PreparationMismatch); }
        let mut previous = None;
        for path in &self.paths {
            if usize::from(path.listener_index) >= MAX_LISTENERS || previous.is_some_and(|p| p >= path.listener_index)
                || path.certificate_digests.is_empty() || path.certificate_digests.len() > MAX_SELECTED_CERTIFICATES { return Err(Failure::StructuralLimit); }
            previous = Some(path.listener_index);
            if path.certificate_digests.iter().collect::<BTreeSet<_>>().len() != path.certificate_digests.len() { return Err(Failure::PathMismatch); }
        }
        let mut header = serde_json::to_value(self).map_err(|_| Failure::MalformedFrame)?;
        header.as_object_mut().ok_or(Failure::MalformedFrame)?.insert("paths".into(), serde_json::Value::Array(Vec::new()));
        if canonical_bytes(&header)?.len() > MAX_HEADER_BYTES || canonical_bytes(self)?.len() > MAX_ACTIVATE_BYTES { return Err(Failure::FrameTooLarge); }
        if self.admission_digest != self.computed_digest()? { return Err(Failure::AdmissionDigestMismatch); }
        Ok(())
    }
}

/// Public receipt only; generating the one-use nonce and consuming it is a
/// future worker responsibility, not represented by this DTO as complete.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedReceipt {
    pub protocol: u16,
    pub instance_id: WorkerInstance,
    pub generation: u64,
    pub recipe_digest: HexDigest,
    pub preparation_manifest_digest: HexDigest,
    pub prepared_nonce: HexDigest,
}
impl PreparedReceipt {
    pub fn decode(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() > MAX_HEADER_BYTES { return Err(Failure::FrameTooLarge); }
        require_object_nodes(bytes, None, None, 0)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Failure::MalformedFrame)?;
        if value.protocol != PROTOCOL { return Err(Failure::UnsupportedProtocol); }
        counter(value.generation)?;
        if value.generation == 0 { return Err(Failure::StructuralLimit); }
        Ok(value)
    }
    pub fn validate_for(&self, manifest: &PreparationManifest) -> Result<(), Failure> {
        if self.protocol != PROTOCOL { return Err(Failure::UnsupportedProtocol); }
        if self.instance_id != manifest.instance_id || self.generation != manifest.generation
            || self.recipe_digest != manifest.recipe_digest || self.preparation_manifest_digest != manifest.digest()? {
            return Err(Failure::PreparationMismatch);
        }
        Ok(())
    }
}

/// Metadata only, produced by future worker from exact received chain DER.
/// Unsupported unused certificates are retained as None, not falsely verified.
pub struct PreparedChain {
    pub listener_index: u16,
    pub chain_digest: HexDigest,
    pub leaf_digest: HexDigest,
    pub certificates: BTreeMap<HexDigest, Option<(i64, i64)>>,
}
pub struct PreparedAssociation {
    manifest: PreparationManifest,
    nonce: HexDigest,
    chains: Vec<PreparedChain>,
}
impl PreparedAssociation {
    /// No nonce generation/lease/spawn in this pure slice. Trusted worker must
    /// generate randomness and retain an independent monotonic deadline.
    pub fn checked(manifest: PreparationManifest, nonce: HexDigest, recipe: &[u8], compiler: &ServerCompilerV2, observations: &[MaterialIdentity], chains: Vec<PreparedChain>) -> Result<Self, Failure> {
        manifest.verify_preparation(recipe, compiler, observations)?;
        if chains.is_empty() || chains.len() > MAX_LISTENERS { return Err(Failure::StructuralLimit); }
        let expected: Vec<_> = manifest.associations.iter().filter(|a| a.material.role == Role::CertificateChain).collect();
        if expected.len() != chains.len() { return Err(Failure::PathMismatch); }
        let mut total = 0_usize;
        for (chain, association) in chains.iter().zip(expected) {
            total = total.checked_add(chain.certificates.len()).ok_or(Failure::StructuralLimit)?;
            if chain.certificates.is_empty() || chain.certificates.len() > MAX_CHAIN_CERTIFICATES || total > MAX_CERTIFICATE_OCCURRENCES { return Err(Failure::StructuralLimit); }
            if chain.listener_index != association.listener_index || association.material.chain_digest.as_ref() != Some(&chain.chain_digest)
                || !chain.certificates.contains_key(&chain.leaf_digest) { return Err(Failure::PathMismatch); }
            if chain.certificates.values().flatten().any(|(before, after)| before > after) { return Err(Failure::UnsupportedCertificateMetadata); }
        }
        Ok(Self { manifest, nonce, chains })
    }
    pub fn match_admission(&self, admission: &Admission) -> Result<(), Failure> {
        admission.validate()?;
        if admission.instance_id != self.manifest.instance_id || admission.generation != self.manifest.generation
            || admission.recipe_digest != self.manifest.recipe_digest || admission.release_digest != self.manifest.release_digest
            || admission.preparation_manifest_digest != self.manifest.digest()? || admission.prepared_nonce != self.nonce { return Err(Failure::PreparationMismatch); }
        if admission.paths.len() != self.chains.len() { return Err(Failure::PathMismatch); }
        for (path, chain) in admission.paths.iter().zip(&self.chains) {
            if path.listener_index != chain.listener_index || path.chain_digest != chain.chain_digest
                || path.certificate_digests.first() != Some(&chain.leaf_digest) { return Err(Failure::PathMismatch); }
            for digest in &path.certificate_digests {
                chain.certificates.get(digest).ok_or(Failure::PathMismatch)?.as_ref().ok_or(Failure::UnsupportedCertificateMetadata)?;
            }
        }
        Ok(())
    }
    /// Pure sampled-time check; returned duration must be intersected with a
    /// separately retained monotonic lease/deadline by the future worker.
    pub fn check_time(&self, admission: &Admission, now_ms: u64, prepared_floor_ms: u64, last_observed_ms: u64, prepared_remaining_ms: u64) -> Result<u64, Failure> {
        self.match_admission(admission)?;
        counter(now_ms)?;
        if prepared_remaining_ms == 0 { return Err(Failure::PreparedExpired); }
        if now_ms < prepared_floor_ms || now_ms < last_observed_ms || now_ms < admission.issued_at_ms { return Err(Failure::ClockRegression); }
        if now_ms >= admission.expires_at_ms { return Err(Failure::AdmissionExpired); }
        let mut remaining = prepared_remaining_ms.min(PREPARED_LEASE_MS).min(admission.expires_at_ms - now_ms).min(admission.max_startup_ms);
        let seconds = i64::try_from(now_ms / 1000).map_err(|_| Failure::ClockUnavailable)?;
        for (path, chain) in admission.paths.iter().zip(&self.chains) {
            for digest in &path.certificate_digests {
                let (before, after) = chain.certificates.get(digest).and_then(|v| *v).ok_or(Failure::UnsupportedCertificateMetadata)?;
                if seconds < before { return Err(Failure::CertificateNotYetValid); }
                if seconds > after { return Err(Failure::CertificateExpired); }
                let cutoff = after.checked_add(1).and_then(|s| u64::try_from(s).ok()).and_then(|s| s.checked_mul(1000)).ok_or(Failure::ClockUnavailable)?;
                remaining = remaining.min(cutoff.checked_sub(now_ms).ok_or(Failure::CertificateExpired)?);
            }
        }
        if remaining == 0 { return Err(Failure::StartupTimeout); }
        Ok(remaining)
    }
}
/// Pure next-generation validation. Consumption/burn and durable reservation are
/// deliberately not represented as complete by this function.
pub fn validate_reserved_generation(previous: u64, reserved: u64) -> Result<(), Failure> {
    counter(previous)?; counter(reserved)?;
    let next = previous.checked_add(1).filter(|v| *v <= MAX_WIRE_COUNTER).ok_or(Failure::GenerationExhausted)?;
    if reserved != next { return Err(Failure::GenerationConflict); }
    Ok(())
}

#[cfg(test)]
mod tests;
