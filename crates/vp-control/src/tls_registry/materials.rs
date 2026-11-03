//! Ephemeral plan-bound material access while the caller retains the aggregate
//! writer. No durable proof, lifecycle admission or production selection.
use super::{service::*, *};
use crate::{CancellationToken, Clock, OperationState};
use std::time::Instant;
use vp_product_domain::*;

/// Trusted backend read port. No mutation or unrestricted store escape hatch.
pub trait TlsMaterialVault: Send + Sync {
    /// Retained directory identity for fresh reservation; unsupported by default.
    #[cfg(feature = "experimental-public")]
    fn retained_directory_identity(&self) -> Result<(u64, u64), ControlError> { Err(ControlError::ExecutorUnavailable) }
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
    restoration: Option<&'a crate::RevisionRecord>,
    principal: &'a UserId,
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
        Self::for_aggregate(
            lease.aggregate(),
            vault,
            policy,
            clock,
            expected_version,
            operation,
            deadline,
            cancel,
        )
    }
    /// Explicit experimental staging; public authority remains bound to the
    /// approved artifact digest. Not available in default builds.
    #[cfg(feature = "experimental-public")]
    #[allow(clippy::too_many_arguments)]
    pub fn for_public_staging(
        lease: &'a dyn TlsAssetWriterLease,
        vault: &'a dyn TlsMaterialVault,
        policy: &'a TlsBackendPolicy,
        clock: &'a dyn Clock,
        expected_version: u64,
        operation: &OperationId,
        deadline: Instant,
        cancel: &'a CancellationToken,
        expected_artifact: &crate::ContentDigest,
    ) -> Result<Self, ControlError> {
        Self::for_phase(lease.aggregate(), vault, policy, clock, expected_version, operation,
                        deadline, cancel, OperationState::Staging, None, Some(expected_artifact))
    }
    /// Read-only admission of the current committed revision under the retained
    /// TLS writer. It grants material reads only, never process or bind authority.
    #[cfg(feature = "experimental-public")]
    #[allow(clippy::too_many_arguments)]
    pub fn for_public_committed_restart(
        lease: &'a dyn TlsAssetWriterLease, vault: &'a dyn TlsMaterialVault,
        policy: &'a TlsBackendPolicy, clock: &'a dyn Clock, expected_version: u64,
        expected_artifact: &crate::ContentDigest, deadline: Instant, cancel: &'a CancellationToken,
    ) -> Result<Self, ControlError> {
        let e = lease.aggregate();
        e.require_ordinary_access()?;
        e.state.verify_integrity()?;
        if e.state.version != expected_version || e.state.needs_recovery()
            || e.state.secrets.needs_recovery()
            || e.state.operations.values().any(|op| !op.state.is_terminal()) {
            return Err(ControlError::RecoveryRequired);
        }
        let active = e.state.active().ok_or(ControlError::ResourceConflict)?;
        if &active.artifact_digest != expected_artifact { return Err(ControlError::ResourceConflict); }
        let operation = e.state.operations.get(&active.operation_id).ok_or(ControlError::CorruptState)?;
        let plan = e.state.plans.get(&operation.plan_id).ok_or(ControlError::CorruptState)?;
        plan.verify_integrity()?;
        if operation.state != OperationState::Committed || operation.cancel_requested
            || plan.body().principal != operation.principal || plan.body().target_revision != active.revision
            || plan.body().validation.config_digest != active.config_digest
            || plan.body().validation.release_digest != active.release_digest
            || plan.body().validation.artifact_digest != active.artifact_digest
            || ContentDigest::of("vp.product-config.v1", &active.config)? != active.config_digest
            || ContentDigest::of("vp.release-identity.v1", &active.release)? != active.release_digest {
            return Err(ControlError::ResourceConflict);
        }
        let now = clock.now_ms()?;
        let activation = operation.activation.as_ref().ok_or(ControlError::CorruptState)?;
        let health = operation.health.as_ref().ok_or(ControlError::CorruptState)?;
        let prior = if plan.body().base_revision == vp_product_domain::Revision::ZERO { None } else {
            Some(e.state.revisions.iter().find(|r| r.revision == plan.body().base_revision).ok_or(ControlError::CorruptState)?)
        };
        let minimum = crate::minimum_health_checks(&active.config, prior)?;
        let required = &plan.body().validation.required_health;
        let mut seen = std::collections::BTreeSet::new();
        if activation.operation_id != operation.id || activation.revision != active.revision
            || activation.config_digest != active.config_digest || activation.release_digest != active.release_digest
            || activation.generation == 0 || activation.generation > vp_product_domain::MAX_WIRE_COUNTER
            || health.operation_id != operation.id || health.revision != active.revision
            || health.config_digest != active.config_digest || health.release_digest != active.release_digest
            || health.generation != activation.generation || health.checked_at_ms > now
            || !minimum.is_subset(required)
            || health.checks.iter().any(|r| !required.contains(&r.check) || !seen.insert(&r.check))
            || required.iter().any(|check| !health.checks.iter().any(|r| &r.check == check && r.outcome == crate::CheckOutcome::Passed)) {
            return Err(ControlError::CorruptState);
        }
        let value = Self { aggregate: e, plan, restoration: Some(active), principal: &operation.principal,
            vault, policy, clock, cancel, deadline, admitted_at_ms: now, external_cancel: &never_cancel };
        value.validate_materials(true)?;
        Ok(value)
    }
    #[cfg(feature = "experimental-public")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_public_aggregate(
        aggregate: &'a TlsControlEnvelope, vault: &'a dyn TlsMaterialVault,
        policy: &'a TlsBackendPolicy, clock: &'a dyn Clock, expected_version: u64,
        operation: &OperationId, deadline: Instant, cancel: &'a CancellationToken,
        expected_artifact: &crate::ContentDigest,
    ) -> Result<Self, ControlError> {
        Self::for_phase(aggregate, vault, policy, clock, expected_version, operation,
                        deadline, cancel, OperationState::Staging, None, Some(expected_artifact))
    }
    #[cfg(feature = "experimental-public")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_public_activation(
        aggregate: &'a TlsControlEnvelope, vault: &'a dyn TlsMaterialVault, policy: &'a TlsBackendPolicy,
        clock: &'a dyn Clock, expected_version: u64, operation: &OperationId,
        deadline: Instant, cancel: &'a CancellationToken, expected_artifact: &crate::ContentDigest,
    ) -> Result<Self, ControlError> {
        Self::for_phase(aggregate, vault, policy, clock, expected_version, operation, deadline, cancel,
                        OperationState::Activating, None, Some(expected_artifact))
    }
    #[cfg(feature = "experimental-public")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_public_verification(
        aggregate: &'a TlsControlEnvelope, vault: &'a dyn TlsMaterialVault, policy: &'a TlsBackendPolicy,
        clock: &'a dyn Clock, expected_version: u64, operation: &OperationId,
        deadline: Instant, cancel: &'a CancellationToken, expected_artifact: &crate::ContentDigest,
    ) -> Result<Self, ControlError> {
        Self::for_phase(aggregate, vault, policy, clock, expected_version, operation, deadline, cancel,
                        OperationState::Verifying, None, Some(expected_artifact))
    }
    #[cfg(feature = "experimental-public")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_public_restoration(
        aggregate: &'a TlsControlEnvelope, vault: &'a dyn TlsMaterialVault, policy: &'a TlsBackendPolicy,
        clock: &'a dyn Clock, expected_version: u64, operation: &OperationId,
        previous: &'a crate::RevisionRecord, deadline: Instant, cancel: &'a CancellationToken,
        expected_artifact: &crate::ContentDigest,
    ) -> Result<Self, ControlError> {
        Self::for_phase(aggregate, vault, policy, clock, expected_version, operation, deadline, cancel,
                        OperationState::RollingBack, Some(previous), Some(expected_artifact))
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_aggregate(
        e: &'a TlsControlEnvelope,
        vault: &'a dyn TlsMaterialVault,
        policy: &'a TlsBackendPolicy,
        clock: &'a dyn Clock,
        expected_version: u64,
        operation: &OperationId,
        deadline: Instant,
        cancel: &'a CancellationToken,
    ) -> Result<Self, ControlError> {
        Self::for_phase(
            e,
            vault,
            policy,
            clock,
            expected_version,
            operation,
            deadline,
            cancel,
            OperationState::Staging,
            None,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_activation(
        e: &'a TlsControlEnvelope,
        vault: &'a dyn TlsMaterialVault,
        policy: &'a TlsBackendPolicy,
        clock: &'a dyn Clock,
        expected_version: u64,
        operation: &OperationId,
        deadline: Instant,
        cancel: &'a CancellationToken,
    ) -> Result<Self, ControlError> {
        Self::for_phase(
            e,
            vault,
            policy,
            clock,
            expected_version,
            operation,
            deadline,
            cancel,
            OperationState::Activating,
            None,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_restoration(
        e: &'a TlsControlEnvelope,
        vault: &'a dyn TlsMaterialVault,
        policy: &'a TlsBackendPolicy,
        clock: &'a dyn Clock,
        expected_version: u64,
        operation: &OperationId,
        previous: &'a crate::RevisionRecord,
        deadline: Instant,
        cancel: &'a CancellationToken,
    ) -> Result<Self, ControlError> {
        Self::for_phase(
            e,
            vault,
            policy,
            clock,
            expected_version,
            operation,
            deadline,
            cancel,
            OperationState::RollingBack,
            Some(previous),
            None,
        )
    }
    /// Validate a draft against a cloned, writer-held aggregate. The temporary
    /// plan and operation exist only in memory and grant no mutation authority.
    #[cfg(feature = "experimental-public")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_public_draft(
        aggregate: &TlsControlEnvelope, vault: &dyn TlsMaterialVault, policy: &TlsBackendPolicy,
        clock: &dyn Clock, principal: &UserId, config: &ProductConfig, release: &ReleaseIdentity,
        artifact: &crate::ContentDigest, deadline: Instant,
    ) -> Result<(), ControlError> {
        aggregate.require_admission(aggregate.state.version)?;
        let mut draft = aggregate.clone();
        let mut suffix = 0u32;
        let (plan_id, operation) = loop {
            let p = PlanId::new(format!("internal-preview-plan-{suffix}")).map_err(|_| ControlError::CounterExhausted)?;
            let o = OperationId::new(format!("internal-preview-op-{suffix}")).map_err(|_| ControlError::CounterExhausted)?;
            if !draft.state.plans.contains_key(&p) && !draft.state.operations.contains_key(&o) { break (p, o); }
            suffix = suffix.checked_add(1).filter(|n| *n <= 65536).ok_or(ControlError::CounterExhausted)?;
        };
        let now = clock.now_ms()?;
        let body = crate::PlanBody { schema_version: 1, id: plan_id.clone(), principal: principal.clone(),
            base_revision: draft.state.active_revision, target_revision: draft.state.active_revision.next().ok_or(ControlError::CounterExhausted)?,
            created_at_ms: now, expires_at_ms: now.checked_add(10_000).ok_or(ControlError::CounterExhausted)?,
            config: config.clone(), release: release.clone(), resources: vec![],
            validation: crate::ValidationReceipt { config_digest: crate::ContentDigest::of("vp.product-config.v1", config)?,
                release_digest: crate::ContentDigest::of("vp.release-identity.v1", release)?, artifact_digest: artifact.clone(),
                impact: crate::RestartImpact::ControlledRestart, required_health: Default::default() } };
        let plan = crate::ChangePlan::seal(body)?;
        draft.state.plans.insert(plan_id.clone(), plan);
        draft.state.operations.insert(operation.clone(), crate::Operation { id: operation.clone(), plan_id, principal: principal.clone(), state: OperationState::Staging,
            created_at_ms: now, updated_at_ms: now, snapshot: None, failure: None, health: None, activation: None,
            cancel_requested: false, mutation_started: false });
        let cancel = CancellationToken::default();
        let _admission = TlsMaterialAdmission::<'_>::for_phase(&draft, vault, policy, clock, draft.state.version, &operation,
            deadline.min(Instant::now() + std::time::Duration::from_secs(10)), &cancel, OperationState::Staging, None, Some(artifact))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn for_phase(
        e: &'a TlsControlEnvelope,
        vault: &'a dyn TlsMaterialVault,
        policy: &'a TlsBackendPolicy,
        clock: &'a dyn Clock,
        expected_version: u64,
        operation: &OperationId,
        deadline: Instant,
        cancel: &'a CancellationToken,
        phase: OperationState,
        restoration: Option<&'a crate::RevisionRecord>,
        expected_public_artifact: Option<&crate::ContentDigest>,
    ) -> Result<Self, ControlError> {
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
        if op.state != phase
            || (restoration.is_none() && op.cancel_requested)
            || (phase == OperationState::Staging && op.mutation_started)
            || (phase != OperationState::Staging && (!op.mutation_started || op.snapshot.is_none()))
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
        if let Some(expected) = expected_public_artifact {
            let matches = if let Some(previous) = restoration {
                phase == OperationState::RollingBack && &previous.artifact_digest == expected
            } else {
                (phase == OperationState::Staging || phase == OperationState::Activating || phase == OperationState::Verifying)
                    && &plan.body().validation.artifact_digest == expected
            };
            if !matches { return Err(ControlError::InvalidConfiguration); }
        }
        if plan.body().principal != op.principal
            || plan.body().base_revision != e.state.active_revision
        {
            return Err(ControlError::ResourceConflict);
        }
        let principal = if let Some(previous) = restoration {
            let active = e.state.active().ok_or(ControlError::ResourceConflict)?;
            if ContentDigest::of("vp.context-previous.v1", active)?
                != ContentDigest::of("vp.context-previous.v1", previous)?
            {
                return Err(ControlError::ResourceConflict);
            }
            let previous_op = e
                .state
                .operations
                .get(&previous.operation_id)
                .ok_or(ControlError::CorruptState)?;
            let previous_plan = e
                .state
                .plans
                .get(&previous_op.plan_id)
                .ok_or(ControlError::CorruptState)?;
            previous_plan.verify_integrity()?;
            if previous_op.state != OperationState::Committed
                || previous_plan.body().principal != previous_op.principal
                || previous_plan.body().target_revision != previous.revision
                || previous_plan.body().validation.config_digest != previous.config_digest
                || previous_plan.body().validation.release_digest != previous.release_digest
                || previous_plan.body().validation.artifact_digest != previous.artifact_digest
            {
                return Err(ControlError::CorruptState);
            }
            &previous_op.principal
        } else {
            &plan.body().principal
        };
        let now = clock.now_ms()?;
        let value = Self {
            aggregate: e,
            plan,
            restoration,
            principal,
            vault,
            policy,
            clock,
            cancel,
            deadline,
            admitted_at_ms: now,
            external_cancel: &never_cancel,
        };
        value.validate_materials(expected_public_artifact.is_some())?;
        Ok(value)
    }
    fn validate_materials(&self, public: bool) -> Result<(), ControlError> {
        self.check()?;
        let listeners: Vec<_> = self
            .config()
            .listeners
            .iter()
            .filter(|l| l.enabled)
            .collect();
        if listeners.is_empty() || listeners.len() > 128 {
            return Err(ControlError::InvalidConfiguration);
        }
        if public {
            for listener in listeners {
                if !listener.bind.address.is_ipv4() || listener.bind.address.is_unspecified() || listener.bind.address.is_loopback() {
                    return Err(ControlError::InvalidConfiguration);
                }
                let ServerProtocol::Proxy { protocol, users } = &listener.protocol else { return Err(ControlError::InvalidConfiguration); };
                if !users.iter().any(|u| u.enabled) { return Err(ControlError::InvalidConfiguration); }
                match (protocol, &listener.transport, &listener.security) {
                    (Protocol::Trojan {}, Transport::Tcp {}, ServerSecurity::Tls { certificate_ref, private_key_ref, .. }) => {
                        self.pair(certificate_ref, private_key_ref, 65536, 65536)?;
                        for user in users.iter().filter(|u| u.enabled) { self.password(&user.credential_ref, 4096)?; }
                    }
                    (Protocol::Vless { flow: None }, Transport::Ws { .. }, ServerSecurity::Tls { certificate_ref, private_key_ref, .. }) => {
                        self.pair(certificate_ref, private_key_ref, 65536, 65536)?;
                        for user in users.iter().filter(|u| u.enabled) {
                            self.experimental_server_credential_at(&user.credential_ref, &NodeCredentialKind::Uuid {}, 4096, self.deadline, &|| false)?;
                        }
                    }
                    (Protocol::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }, Transport::Tcp {}, ServerSecurity::None {}) => {
                        for user in users.iter().filter(|u| u.enabled) {
                            self.experimental_server_credential_at(&user.credential_ref, &NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }, 4096, self.deadline, &|| false)?;
                        }
                    }
                    _ => return Err(ControlError::InvalidConfiguration),
                }
            }
        } else {
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
            self.pair(certificate_ref, private_key_ref, 65536, 65536)?;
            if !users.iter().any(|u| u.enabled) {
                return Err(ControlError::InvalidConfiguration);
            }
            for user in users.iter().filter(|u| u.enabled) {
                self.password(&user.credential_ref, 4096)?;
            }
        }
        }
        Ok(())
    }
    fn budget<'b>(
        &'b self,
        deadline: Instant,
        cancel: &'b (dyn Fn() -> bool + Sync),
    ) -> TlsMaterialAdmission<'b> {
        TlsMaterialAdmission {
            aggregate: self.aggregate,
            plan: self.plan,
            restoration: self.restoration,
            principal: self.principal,
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
    /// Typed experimental read, still constrained by the admitted immutable plan.
    /// Existing staging admission remains loopback-Trojan-only; this does not
    /// enable a public listener or bypass the writer-held admission checks.
    pub fn experimental_server_credential_at(
        &self,
        reference: &SecretRef,
        kind: &NodeCredentialKind,
        max_bytes: usize,
        deadline: Instant,
        cancel: &(dyn Fn() -> bool + Sync),
    ) -> Result<SecretBytes, ControlError> {
        let budget = self.budget(deadline, cancel);
        let observed = budget.check()?;
        let mut found = false;
        for listener in budget.config().listeners.iter().filter(|l| l.enabled) {
            if let ServerProtocol::Proxy { protocol, users } = &listener.protocol {
                if users.iter().any(|user| user.enabled && &user.credential_ref == reference) {
                    let allowed = matches!(
                        (protocol, &listener.transport, &listener.security, kind),
                        (Protocol::Vless { flow: None }, Transport::Ws { .. }, ServerSecurity::Tls { .. }, NodeCredentialKind::Uuid {})
                        | (Protocol::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }, Transport::Tcp {}, ServerSecurity::None {}, NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm })
                    );
                    if !allowed { return Err(ControlError::PermissionDenied); }
                    found = true;
                }
            }
        }
        if !found { return Err(ControlError::PermissionDenied); }
        let mut records = budget.aggregate.state.secrets.credentials.values().filter(|c| &c.summary.secret_ref == reference);
        let record = records.next().ok_or(ControlError::NotFound)?;
        if records.next().is_some() || &record.principal != budget.principal
            || record.summary.state != CredentialState::Available || &record.summary.kind != kind {
            return Err(ControlError::ResourceConflict);
        }
        let raw = budget.vault.read_credential_material(reference, budget.deadline)?.ok_or(ControlError::NotFound)?;
        let framed = exact(raw, reference, 1, record.vault_version, max_bytes.min(4096).saturating_add(9))?;
        use vp_product_domain::experimental_credential_frame::{decode, CredentialFrameKind};
        let frame_kind = match kind {
            NodeCredentialKind::Uuid {} => CredentialFrameKind::Uuid,
            NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm } => CredentialFrameKind::ShadowsocksAes128Gcm,
            _ => return Err(ControlError::InvalidConfiguration),
        };
        let bytes = decode(frame_kind, framed.expose()).map_err(|_| ControlError::InvalidConfiguration)?;
        if bytes.expose().len() > max_bytes { return Err(ControlError::InvalidConfiguration); }
        budget.check_since(observed)?;
        Ok(bytes)
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
        self.restoration
            .map_or(&self.plan.body().config, |r| &r.config)
    }
    pub fn release(&self) -> &ReleaseIdentity {
        self.restoration
            .map_or(&self.plan.body().release, |r| &r.release)
    }
    /// Immutable artifact digest bound to the admitted staging or rollback plan.
    pub fn artifact_digest(&self) -> &crate::ContentDigest {
        self.restoration.map_or(&self.plan.body().validation.artifact_digest, |revision| &revision.artifact_digest)
    }
    pub fn aggregate_version(&self) -> u64 {
        self.aggregate.state.version
    }
    fn valid_clock(&self, now: u64, floor: u64) -> Result<u64, ControlError> {
        if now < floor
            || now < self.admitted_at_ms
            || (self.restoration.is_none()
                && (now < self.plan.body().created_at_ms || now >= self.plan.body().expires_at_ms))
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
            || &record.principal != self.principal
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
