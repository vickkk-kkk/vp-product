//! Private backend composition only; no HTTP request accepts policy or IO ports.
//! Ports are trusted backend dependencies, not externally supplied attestations.
use super::*;
use crate::{CancellationToken, Clock};
use std::time::Instant;
use subtle::ConstantTimeEq;
use vp_product_domain::{SecretBytes, SecretRef};

pub trait TlsAssetWriterLease {
    fn aggregate(&self) -> &TlsControlEnvelope;
    fn persist_asset(&mut self, mutation: TlsAssetMutation) -> Result<(), ControlError>;
}
/// Raw authenticated observation, never a caller-provided verified certificate.
/// No Debug/Serialize/Clone: bytes may contain a private key.
pub struct TlsRawRecord {
    pub reference: SecretRef,
    pub kind: u8,
    pub version: u64,
    pub bytes: SecretBytes,
}
pub struct TlsTombstone {
    pub reference: SecretRef,
    pub kind: u8,
    pub version: u64,
}
pub trait TlsVaultIo {
    fn binding(&self, deadline: Instant) -> Result<InstanceBinding, ControlError>;
    /// None only for a never-reserved ref. Retired/uncertain records are errors.
    fn read(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<Option<TlsRawRecord>, ControlError>;
    fn put(&self, record: TlsRawRecord, deadline: Instant) -> Result<(), ControlError>;
    fn retire(
        &self,
        reference: &SecretRef,
        kind: u8,
        version: u64,
        deadline: Instant,
    ) -> Result<(), ControlError>;
    fn tombstone(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<TlsTombstone, ControlError>;
}
/// Constructed by trusted backend provisioning, NEVER deserialized from requests.
/// Explicit anchors are trusted inputs, not public trust/CA self-signature proof.
pub struct TlsBackendPolicy {
    pub(super) actor: String,
    pub(super) anchors: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub(super) name: rustls::pki_types::ServerName<'static>,
    pub(super) fingerprint: String,
}
impl TlsBackendPolicy {
    pub fn new(actor: String, anchors: Vec<Vec<u8>>, name: String) -> Result<Self, ControlError> {
        if !token(&actor)
            || anchors.is_empty()
            || anchors.len() > 8
            || name.len() > 253
            || anchors.iter().map(Vec::len).sum::<usize>() > 65536
        {
            return Err(ControlError::InvalidRequest);
        }
        let parsed_name = rustls::pki_types::ServerName::try_from(name.clone())
            .map_err(|_| ControlError::InvalidRequest)?;
        let fingerprint = ContentDigest::of(
            "vp.private-tls.policy.v1",
            &(&anchors, &name, "webpki-ring-server-usage-name-time-v1"),
        )?
        .as_str()
        .to_owned();
        Ok(Self {
            actor,
            anchors: anchors.into_iter().map(Into::into).collect(),
            name: parsed_name,
            fingerprint,
        })
    }
}
/// Authenticated actor is supplied by backend caller, never inferred from PEM.
/// Exact expected aggregate version and explicit confirmation are mandatory.
pub struct TlsImportRequest {
    pub actor: String,
    pub expected_version: u64,
    pub action: String,
    pub idempotency: String,
    pub asset: String,
    pub confirmed: bool,
    pub chain: SecretBytes,
    pub key: SecretBytes,
}
pub struct TlsActionRequest {
    pub actor: String,
    pub expected_version: u64,
    pub action: String,
    pub confirmed: bool,
}
pub struct TlsImportService<'a> {
    policy: &'a TlsBackendPolicy,
    clock: &'a dyn Clock,
}
impl<'a> TlsImportService<'a> {
    pub fn new(policy: &'a TlsBackendPolicy, clock: &'a dyn Clock) -> Self {
        Self { policy, clock }
    }
    fn check(
        &self,
        actor: &str,
        confirmed: bool,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<u64, ControlError> {
        checkpoint(deadline, cancel)?;
        if actor != self.policy.actor {
            return Err(ControlError::PermissionDenied);
        }
        if !confirmed {
            return Err(ControlError::ConfirmationMismatch);
        }
        self.clock.now_ms()
    }
    fn bound(
        &self,
        lease: &dyn TlsAssetWriterLease,
        vault: &dyn TlsVaultIo,
        deadline: Instant,
    ) -> Result<(), ControlError> {
        lease.aggregate().validate()?;
        if &vault.binding(deadline)? != lease.aggregate().binding() {
            return Err(ControlError::ResourceConflict);
        }
        Ok(())
    }
    pub fn import(
        &self,
        lease: &mut dyn TlsAssetWriterLease,
        vault: &dyn TlsVaultIo,
        request: TlsImportRequest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), ControlError> {
        let now = self.check(&request.actor, request.confirmed, deadline, cancel)?;
        self.bound(lease, vault, deadline)?;
        lease
            .aggregate()
            .require_admission(request.expected_version)?;
        if !token(&request.action) || request.action.len() > 80 {
            return Err(ControlError::InvalidRequest);
        }
        let chain_ref = SecretRef::new(&format!("tls-chain-{}", request.action))
            .map_err(|_| ControlError::InvalidRequest)?;
        let key_ref = SecretRef::new(&format!("tls-key-{}", request.action))
            .map_err(|_| ControlError::InvalidRequest)?;
        // No adoption of an arbitrary record even when it contains identical bytes.
        if vault.read(&chain_ref, deadline)?.is_some() || vault.read(&key_ref, deadline)?.is_some()
        {
            return Err(ControlError::ResourceConflict);
        }
        let facts = super::validation::verify(
            &request.chain,
            &request.key,
            self.policy,
            now,
            deadline,
            cancel,
        )?;
        checkpoint(deadline, cancel)?;
        let mutation = lease.aggregate().reserve_import(
            request.expected_version,
            &request.actor,
            &request.action,
            &request.idempotency,
            &request.asset,
            chain_ref.as_str(),
            key_ref.as_str(),
            now,
            VerifiedTlsImport { facts },
        )?;
        lease.persist_asset(mutation)?;
        // Each write is a separate durable boundary. No rollback/automatic retry.
        checkpoint(deadline, cancel)?;
        vault.put(
            TlsRawRecord {
                reference: chain_ref,
                kind: 6,
                version: 1,
                bytes: SecretBytes::new(request.chain.expose().to_vec()),
            },
            deadline,
        )?;
        checkpoint(deadline, cancel)?;
        vault.put(
            TlsRawRecord {
                reference: key_ref,
                kind: 2,
                version: 1,
                bytes: SecretBytes::new(request.key.expose().to_vec()),
            },
            deadline,
        )?;
        self.complete_pending(
            lease,
            vault,
            &request.actor,
            &request.action,
            deadline,
            cancel,
            Some((&request.chain, &request.key)),
        )
    }
    fn pending(
        &self,
        lease: &dyn TlsAssetWriterLease,
        actor: &str,
        action: &str,
    ) -> Result<(Asset, u64), ControlError> {
        let e = lease.aggregate();
        e.validate()?;
        let a = e
            .certificate_actions
            .get(action)
            .ok_or(ControlError::NotFound)?;
        if a.actor != actor || a.phase != ActionPhase::ImportReserved {
            return Err(ControlError::RecoveryRequired);
        }
        let asset = e
            .certificate_assets
            .get(&a.asset_id)
            .ok_or(ControlError::CorruptState)?;
        if asset.facts.policy != self.policy.fingerprint {
            return Err(ControlError::ResourceConflict);
        }
        Ok((asset.clone(), a.created_at_ms))
    }
    fn complete_pending(
        &self,
        lease: &mut dyn TlsAssetWriterLease,
        vault: &dyn TlsVaultIo,
        actor: &str,
        action: &str,
        deadline: Instant,
        cancel: &CancellationToken,
        uploaded: Option<(&SecretBytes, &SecretBytes)>,
    ) -> Result<(), ControlError> {
        let (asset, created) = self.pending(lease, actor, action)?;
        let chain = exact_read(vault, &asset.chain_ref, 6, asset.chain_version, deadline)?
            .ok_or(ControlError::RecoveryRequired)?;
        let key = exact_read(vault, &asset.key_ref, 2, asset.key_version, deadline)?
            .ok_or(ControlError::RecoveryRequired)?;
        let now = self.check(actor, true, deadline, cancel)?;
        if now < created {
            return Err(ControlError::PlanExpired);
        }
        if let Some((uploaded_chain, uploaded_key)) = uploaded {
            if !bool::from(chain.expose().ct_eq(uploaded_chain.expose()))
                || !bool::from(key.expose().ct_eq(uploaded_key.expose()))
            {
                return Err(ControlError::ResourceConflict);
            }
        }
        let facts = super::validation::verify(&chain, &key, self.policy, now, deadline, cancel)?;
        checkpoint(deadline, cancel)?;
        let proof = VerifiedTlsReadback {
            facts,
            asset_id: asset.id,
            chain_ref: asset.chain_ref,
            chain_version: asset.chain_version,
            key_ref: asset.key_ref,
            key_version: asset.key_version,
        };
        let mutation = lease.aggregate().complete_import(
            lease.aggregate().state.version,
            action,
            now,
            proof,
        )?;
        lease.persist_asset(mutation)
    }
    /// Explicit recovery only. Missing input is not automatically recreated.
    pub fn recover(
        &self,
        lease: &mut dyn TlsAssetWriterLease,
        vault: &dyn TlsVaultIo,
        request: TlsActionRequest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), ControlError> {
        self.check(&request.actor, request.confirmed, deadline, cancel)?;
        self.bound(lease, vault, deadline)?;
        if lease.aggregate().state.version != request.expected_version {
            return Err(ControlError::ResourceConflict);
        }
        self.complete_pending(
            lease,
            vault,
            &request.actor,
            &request.action,
            deadline,
            cancel,
            None,
        )
    }
    /// Reupload only never-reserved missing records of the SAME durable action.
    /// Present records must match intent and uploaded exact public identity first.
    pub fn reupload_missing(
        &self,
        lease: &mut dyn TlsAssetWriterLease,
        vault: &dyn TlsVaultIo,
        request: TlsActionRequest,
        chain: SecretBytes,
        key: SecretBytes,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), ControlError> {
        let now = self.check(&request.actor, request.confirmed, deadline, cancel)?;
        self.bound(lease, vault, deadline)?;
        if lease.aggregate().state.version != request.expected_version {
            return Err(ControlError::ResourceConflict);
        }
        let (asset, created) = self.pending(lease, &request.actor, &request.action)?;
        if now < created {
            return Err(ControlError::PlanExpired);
        }
        let facts = super::validation::verify(&chain, &key, self.policy, now, deadline, cancel)?;
        if facts != asset.facts {
            return Err(ControlError::ResourceConflict);
        }
        let existing_chain = exact_read(vault, &asset.chain_ref, 6, asset.chain_version, deadline)?;
        let existing_key = exact_read(vault, &asset.key_ref, 2, asset.key_version, deadline)?;
        // Revalidate the final combined pair BEFORE making any missing writes.
        let combined = super::validation::verify(
            existing_chain.as_ref().unwrap_or(&chain),
            existing_key.as_ref().unwrap_or(&key),
            self.policy,
            now,
            deadline,
            cancel,
        )?;
        if combined != asset.facts {
            return Err(ControlError::ResourceConflict);
        }
        checkpoint(deadline, cancel)?;
        if existing_chain.is_none() {
            vault.put(
                TlsRawRecord {
                    reference: parse_ref(&asset.chain_ref)?,
                    kind: 6,
                    version: asset.chain_version,
                    bytes: chain,
                },
                deadline,
            )?;
        }
        checkpoint(deadline, cancel)?;
        if existing_key.is_none() {
            vault.put(
                TlsRawRecord {
                    reference: parse_ref(&asset.key_ref)?,
                    kind: 2,
                    version: asset.key_version,
                    bytes: key,
                },
                deadline,
            )?;
        }
        self.complete_pending(
            lease,
            vault,
            &request.actor,
            &request.action,
            deadline,
            cancel,
            None,
        )
    }
    /// Abort retains all refs/ciphertext/history. It does not undo any vault write.
    pub fn abort(
        &self,
        lease: &mut dyn TlsAssetWriterLease,
        request: TlsActionRequest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), ControlError> {
        let now = self.check(&request.actor, request.confirmed, deadline, cancel)?;
        self.pending(lease, &request.actor, &request.action)?;
        let mutation =
            lease
                .aggregate()
                .abort_import(request.expected_version, &request.action, now)?;
        lease.persist_asset(mutation)
    }
}
fn parse_ref(value: &str) -> Result<SecretRef, ControlError> {
    SecretRef::try_from(value.to_owned()).map_err(|_| ControlError::CorruptState)
}
fn exact_read(
    vault: &dyn TlsVaultIo,
    reference: &str,
    kind: u8,
    version: u64,
    deadline: Instant,
) -> Result<Option<SecretBytes>, ControlError> {
    let reference = parse_ref(reference)?;
    match vault.read(&reference, deadline)? {
        None => Ok(None),
        Some(r) if r.reference == reference && r.kind == kind && r.version == version => {
            Ok(Some(r.bytes))
        }
        Some(_) => Err(ControlError::ResourceConflict),
    }
}
fn checkpoint(deadline: Instant, cancel: &CancellationToken) -> Result<(), ControlError> {
    if cancel.is_canceled() {
        Err(ControlError::Canceled)
    } else if Instant::now() >= deadline {
        Err(ControlError::PlanExpired)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

pub struct TlsRetireRequest {
    pub actor: String,
    pub expected_version: u64,
    pub action: String,
    pub idempotency: String,
    pub asset: String,
    pub asset_revision: u64,
    pub confirmed: bool,
    pub confirm_history_loss: bool,
}
impl TlsImportService<'_> {
    pub fn retire(
        &self,
        lease: &mut dyn TlsAssetWriterLease,
        vault: &dyn TlsVaultIo,
        request: TlsRetireRequest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), ControlError> {
        let now = self.check(&request.actor, request.confirmed, deadline, cancel)?;
        self.bound(lease, vault, deadline)?;
        let asset = lease
            .aggregate()
            .certificate_assets
            .get(&request.asset)
            .ok_or(ControlError::NotFound)?;
        if asset.facts.policy != self.policy.fingerprint {
            return Err(ControlError::ResourceConflict);
        }
        let mutation = lease.aggregate().reserve_retirement(
            request.expected_version,
            &request.asset,
            request.asset_revision,
            &request.actor,
            &request.action,
            &request.idempotency,
            request.confirm_history_loss,
            now,
        )?;
        lease.persist_asset(mutation)?;
        self.retire_pending(
            lease,
            vault,
            &request.actor,
            &request.action,
            deadline,
            cancel,
        )
    }
    /// Resume the exact pending action; never unretire or substitute a reference.
    pub fn recover_retirement(
        &self,
        lease: &mut dyn TlsAssetWriterLease,
        vault: &dyn TlsVaultIo,
        request: TlsActionRequest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), ControlError> {
        self.check(&request.actor, request.confirmed, deadline, cancel)?;
        self.bound(lease, vault, deadline)?;
        if lease.aggregate().state.version != request.expected_version {
            return Err(ControlError::ResourceConflict);
        }
        self.retire_pending(
            lease,
            vault,
            &request.actor,
            &request.action,
            deadline,
            cancel,
        )
    }
    fn retire_pending(
        &self,
        lease: &mut dyn TlsAssetWriterLease,
        vault: &dyn TlsVaultIo,
        actor: &str,
        action: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), ControlError> {
        let e = lease.aggregate();
        e.validate()?;
        let a = e
            .certificate_actions
            .get(action)
            .ok_or(ControlError::NotFound)?;
        if a.actor != actor || a.phase != ActionPhase::RetireReserved {
            return Err(ControlError::RecoveryRequired);
        }
        let asset = e
            .certificate_assets
            .get(&a.asset_id)
            .ok_or(ControlError::CorruptState)?
            .clone();
        if asset.facts.policy != self.policy.fingerprint {
            return Err(ControlError::ResourceConflict);
        }
        let created = a.created_at_ms;
        if self.check(actor, true, deadline, cancel)? < created {
            return Err(ControlError::PlanExpired);
        }
        let chain = parse_ref(&asset.chain_ref)?;
        let key = parse_ref(&asset.key_ref)?;
        vault.retire(&chain, 6, asset.chain_version, deadline)?;
        checkpoint(deadline, cancel)?;
        vault.retire(&key, 2, asset.key_version, deadline)?;
        checkpoint(deadline, cancel)?;
        let c = vault.tombstone(&chain, deadline)?;
        let k = vault.tombstone(&key, deadline)?;
        if c.reference != chain
            || c.kind != 6
            || c.version != asset.chain_version
            || k.reference != key
            || k.kind != 2
            || k.version != asset.key_version
        {
            return Err(ControlError::ResourceConflict);
        }
        let now = self.check(actor, true, deadline, cancel)?;
        if now < created {
            return Err(ControlError::PlanExpired);
        }
        let proof = VerifiedTlsRetirement {
            asset_id: asset.id,
            chain_ref: asset.chain_ref,
            chain_version: asset.chain_version,
            key_ref: asset.key_ref,
            key_version: asset.key_version,
        };
        let mutation = lease.aggregate().complete_retirement(
            lease.aggregate().state.version,
            action,
            now,
            proof,
        )?;
        lease.persist_asset(mutation)
    }
}
