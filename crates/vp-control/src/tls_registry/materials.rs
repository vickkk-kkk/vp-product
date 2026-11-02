//! Ephemeral plan-bound material access while the caller retains the aggregate
//! writer. No durable proof, lifecycle admission or production selection.
use super::{service::*, *};
use crate::{CancellationToken, Clock, OperationState};
use std::time::Instant;
use vp_product_domain::*;

/// Trusted backend read port. No mutation or unrestricted store escape hatch.
pub trait TlsMaterialVault: Send + Sync {
    fn material_binding(&self, deadline: Instant) -> Result<InstanceBinding, ControlError>;
    fn read_tls_material(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<Option<TlsRawRecord>, ControlError>;
    fn read_credential_material(
        &self,
        reference: &SecretRef,
        deadline: Instant,
    ) -> Result<Option<TlsRawRecord>, ControlError>;
}

/// Not Clone/Debug/Serialize. The aggregate borrow prevents a normal writer
/// checkpoint until this context is dropped. Backend lease implementations are
/// trusted; this is not a lock-acquisition API or fresh-instance admission.
pub struct TlsMaterialAdmission<'a> {
    aggregate: &'a TlsControlEnvelope,
    plan: &'a crate::ChangePlan,
    vault: &'a dyn TlsMaterialVault,
    policy: &'a TlsBackendPolicy,
    clock: &'a dyn Clock,
    cancel: &'a CancellationToken,
    deadline: Instant,
    external_cancel: &'a (dyn Fn() -> bool + Sync),
    admitted_at_ms: u64,
}
impl<'a> TlsMaterialAdmission<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn for_staging(
        lease: &'a dyn TlsAssetWriterLease,
        vault: &'a dyn TlsMaterialVault,
        policy: &'a TlsBackendPolicy,
        clock: &'a dyn Clock,
        expected_version: u64,
        operation: &OperationId,
        deadline: Instant,
        cancel: &'a CancellationToken,
    ) -> Result<Self, ControlError> {
        let e = lease.aggregate();
        e.require_ordinary_access()?;
        if e.state.version != expected_version {
            return Err(ControlError::ResourceConflict);
        }
        if e.state.secrets.needs_recovery() {
            return Err(ControlError::RecoveryRequired);
        }
        let op = e
            .state
            .operations
            .get(operation)
            .ok_or(ControlError::NotFound)?;
        if op.state != OperationState::Staging
            || op.cancel_requested
            || op.mutation_started
            || e.state.operations.values().any(|other| {
                other.id != *operation
                    && !other.state.is_terminal()
                    && other.state != OperationState::Queued
            })
        {
            return Err(ControlError::RecoveryRequired);
        }
        let plan = e
            .state
            .plans
            .get(&op.plan_id)
            .ok_or(ControlError::CorruptState)?;
        plan.verify_integrity()?;
        if plan.body().principal != op.principal
            || plan.body().base_revision != e.state.active_revision
        {
            return Err(ControlError::ResourceConflict);
        }
        let now = clock.now_ms()?;
        let value = Self {
            aggregate: e,
            plan,
            vault,
            policy,
            clock,
            cancel,
            deadline,
            admitted_at_ms: now,
            external_cancel: &never_cancel,
        };
        value.check()?;
        let listeners: Vec<_> = value
            .config()
            .listeners
            .iter()
            .filter(|l| l.enabled)
            .collect();
        if listeners.is_empty() || listeners.len() > 128 {
            return Err(ControlError::InvalidConfiguration);
        }
        for listener in listeners {
            if !listener.bind.address.is_loopback()
                || !matches!(listener.transport, Transport::Tcp {})
            {
                return Err(ControlError::InvalidConfiguration);
            }
            let ServerProtocol::Proxy {
                protocol: Protocol::Trojan {},
                users,
            } = &listener.protocol
            else {
                return Err(ControlError::InvalidConfiguration);
            };
            let ServerSecurity::Tls {
                certificate_ref,
                private_key_ref,
                ..
            } = &listener.security
            else {
                return Err(ControlError::InvalidConfiguration);
            };
            value.pair(certificate_ref, private_key_ref, 65536, 65536)?;
            if !users.iter().any(|u| u.enabled) {
                return Err(ControlError::InvalidConfiguration);
            }
            for user in users.iter().filter(|u| u.enabled) {
                value.password(&user.credential_ref, 4096)?;
            }
        }
        Ok(value)
    }
    fn budget<'b>(
        &'b self,
        deadline: Instant,
        cancel: &'b (dyn Fn() -> bool + Sync),
    ) -> TlsMaterialAdmission<'b> {
        TlsMaterialAdmission {
            aggregate: self.aggregate,
            plan: self.plan,
            vault: self.vault,
            policy: self.policy,
            clock: self.clock,
            cancel: self.cancel,
            deadline: self.deadline.min(deadline),
            admitted_at_ms: self.admitted_at_ms,
            external_cancel: cancel,
        }
    }
    /// Adapter deadlines/cancellation remain active inside reads and PEM parsing.
    pub fn password_at(
        &self,
        reference: &SecretRef,
        max_bytes: usize,
        deadline: Instant,
        cancel: &(dyn Fn() -> bool + Sync),
    ) -> Result<SecretBytes, ControlError> {
        self.budget(deadline, cancel).password(reference, max_bytes)
    }
    pub fn certificate_chain_at(
        &self,
        reference: &CertificateId,
        max_bytes: usize,
        deadline: Instant,
        cancel: &(dyn Fn() -> bool + Sync),
    ) -> Result<SecretBytes, ControlError> {
        self.budget(deadline, cancel)
            .certificate_chain(reference, max_bytes)
    }
    pub fn private_key_at(
        &self,
        reference: &SecretRef,
        max_bytes: usize,
        deadline: Instant,
        cancel: &(dyn Fn() -> bool + Sync),
    ) -> Result<SecretBytes, ControlError> {
        self.budget(deadline, cancel)
            .private_key(reference, max_bytes)
    }
    pub fn config(&self) -> &ProductConfig {
        &self.plan.body().config
    }
    pub fn release(&self) -> &ReleaseIdentity {
        &self.plan.body().release
    }
    pub fn aggregate_version(&self) -> u64 {
        self.aggregate.state.version
    }
    fn valid_clock(&self, now: u64, floor: u64) -> Result<u64, ControlError> {
        if now < floor
            || now < self.admitted_at_ms
            || now < self.plan.body().created_at_ms
            || now >= self.plan.body().expires_at_ms
        {
            return Err(ControlError::PlanExpired);
        }
        Ok(now)
    }
    fn check_since(&self, floor: u64) -> Result<u64, ControlError> {
        if self.cancel.is_canceled() || (self.external_cancel)() {
            return Err(ControlError::Canceled);
        }
        if Instant::now() >= self.deadline {
            return Err(ControlError::PlanExpired);
        }
        let before = self.valid_clock(self.clock.now_ms()?, floor)?;
        if self.vault.material_binding(self.deadline)? != *self.aggregate.binding() {
            return Err(ControlError::ResourceConflict);
        }
        if self.cancel.is_canceled() || (self.external_cancel)() {
            return Err(ControlError::Canceled);
        }
        if Instant::now() >= self.deadline {
            return Err(ControlError::PlanExpired);
        }
        self.valid_clock(self.clock.now_ms()?, before)
    }
    fn check(&self) -> Result<u64, ControlError> {
        self.check_since(self.admitted_at_ms)
    }
    pub fn password(
        &self,
        reference: &SecretRef,
        max_bytes: usize,
    ) -> Result<SecretBytes, ControlError> {
        let observed = self.check()?;
        let authorized = self
            .config()
            .listeners
            .iter()
            .filter(|l| l.enabled)
            .any(|l| {
                matches!(&l.protocol, ServerProtocol::Proxy { protocol: Protocol::Trojan {}, users }
                if users.iter().any(|u| u.enabled && &u.credential_ref == reference))
            });
        if !authorized {
            return Err(ControlError::PermissionDenied);
        }
        let mut records = self
            .aggregate
            .state
            .secrets
            .credentials
            .values()
            .filter(|c| &c.summary.secret_ref == reference);
        let record = records.next().ok_or(ControlError::NotFound)?;
        if records.next().is_some()
            || record.principal != self.plan.body().principal
            || record.summary.state != CredentialState::Available
            || !matches!(record.summary.kind, NodeCredentialKind::Password {})
        {
            return Err(ControlError::ResourceConflict);
        }
        let raw = self
            .vault
            .read_credential_material(reference, self.deadline)?
            .ok_or(ControlError::NotFound)?;
        let bytes = exact(raw, reference, 1, record.vault_version, max_bytes.min(4096))?;
        let text =
            std::str::from_utf8(bytes.expose()).map_err(|_| ControlError::InvalidConfiguration)?;
        if text.is_empty() || text.contains('\0') {
            return Err(ControlError::InvalidConfiguration);
        }
        self.check_since(observed)?;
        Ok(bytes)
    }
    fn pair(
        &self,
        certificate: &CertificateId,
        key_ref: &SecretRef,
        chain_limit: usize,
        key_limit: usize,
    ) -> Result<(SecretBytes, SecretBytes), ControlError> {
        let now = self.check()?;
        let authorized = self
            .config()
            .listeners
            .iter()
            .filter(|l| l.enabled)
            .any(|l| {
                matches!(&l.security, ServerSecurity::Tls { certificate_ref, private_key_ref, .. }
                if certificate_ref == certificate && private_key_ref == key_ref)
            });
        if !authorized {
            return Err(ControlError::PermissionDenied);
        }
        let asset = self
            .aggregate
            .certificate_assets
            .get(certificate.as_str())
            .ok_or(ControlError::NotFound)?;
        if asset.phase != AssetPhase::Available
            || asset.key_ref != key_ref.as_str()
            || asset.facts.policy != self.policy.fingerprint
        {
            return Err(ControlError::ResourceConflict);
        }
        let chain_ref =
            SecretRef::try_from(asset.chain_ref.clone()).map_err(|_| ControlError::CorruptState)?;
        let chain = exact(
            self.vault
                .read_tls_material(&chain_ref, self.deadline)?
                .ok_or(ControlError::NotFound)?,
            &chain_ref,
            6,
            asset.chain_version,
            chain_limit.min(65536),
        )?;
        let after_chain = self.check_since(now)?;
        let key = exact(
            self.vault
                .read_tls_material(key_ref, self.deadline)?
                .ok_or(ControlError::NotFound)?,
            key_ref,
            2,
            asset.key_version,
            key_limit.min(65536),
        )?;
        let verified_at = self.check_since(after_chain)?;
        let facts = super::validation::verify_checked(
            &chain,
            &key,
            self.policy,
            verified_at,
            self.deadline,
            &|| self.cancel.is_canceled() || (self.external_cancel)(),
        )?;
        if facts != asset.facts {
            return Err(ControlError::ResourceConflict);
        }
        let finished_at = self.check_since(verified_at)?;
        // The verified path can include intermediates with different validity
        // intervals. Leaf metadata alone cannot extend that path proof to a new
        // second. Fail closed rather than retry indefinitely or assume validity.
        if finished_at / 1000 != verified_at / 1000 {
            return Err(ControlError::PlanExpired);
        }
        let seconds = i64::try_from(finished_at / 1000).map_err(|_| ControlError::PlanExpired)?;
        if seconds < facts.not_before || seconds > facts.not_after {
            return Err(ControlError::InvalidConfiguration);
        }
        Ok((chain, key))
    }
    pub fn certificate_chain(
        &self,
        reference: &CertificateId,
        max_bytes: usize,
    ) -> Result<SecretBytes, ControlError> {
        let asset = self
            .aggregate
            .certificate_assets
            .get(reference.as_str())
            .ok_or(ControlError::NotFound)?;
        let key =
            SecretRef::try_from(asset.key_ref.clone()).map_err(|_| ControlError::CorruptState)?;
        self.pair(reference, &key, max_bytes, 65536)
            .map(|pair| pair.0)
    }
    pub fn private_key(
        &self,
        reference: &SecretRef,
        max_bytes: usize,
    ) -> Result<SecretBytes, ControlError> {
        let mut assets = self
            .aggregate
            .certificate_assets
            .values()
            .filter(|a| a.key_ref == reference.as_str());
        let asset = assets.next().ok_or(ControlError::NotFound)?;
        if assets.next().is_some() {
            return Err(ControlError::ResourceConflict);
        }
        let id = CertificateId::new(&asset.id).map_err(|_| ControlError::CorruptState)?;
        self.pair(&id, reference, 65536, max_bytes)
            .map(|pair| pair.1)
    }
}
fn exact(
    raw: TlsRawRecord,
    reference: &SecretRef,
    kind: u8,
    version: u64,
    max_bytes: usize,
) -> Result<SecretBytes, ControlError> {
    if raw.reference != *reference || raw.kind != kind || raw.version != version {
        return Err(ControlError::ResourceConflict);
    }
    if raw.bytes.expose().is_empty() || raw.bytes.expose().len() > max_bytes {
        return Err(ControlError::InvalidConfiguration);
    }
    Ok(raw.bytes)
}

fn never_cancel() -> bool {
    false
}
