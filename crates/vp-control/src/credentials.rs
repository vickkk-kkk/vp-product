use crate::service::{check_revision, take_id};
use crate::*;
use serde::Serialize;
use std::time::{Duration, Instant};
use vp_product_domain::*;
const SECRET_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) fn secret_deadline() -> Instant {
    Instant::now() + SECRET_TIMEOUT
}
pub(crate) fn ensure_secret_write(state: &StoredState) -> Result<(), ControlError> {
    state.verify_integrity()?;
    if state.needs_recovery() {
        return Err(ControlError::RecoveryRequired);
    }
    if state.secrets.actions.len() >= 256 {
        return Err(ControlError::InvalidRequest);
    }
    Ok(())
}
pub(crate) fn prior_secret_action(
    state: &StoredState,
    principal: &UserId,
    method: SecretActionKind,
    key: &IdempotencyKey,
    digest: &ContentDigest,
) -> Result<Option<SecretActionOutcome>, ControlError> {
    state.verify_integrity()?;
    match state
        .secrets
        .actions
        .iter()
        .find(|a| &a.principal == principal && a.method == method && &a.key == key)
    {
        None => Ok(None),
        Some(a) if &a.request_digest == digest => Ok(Some(a.outcome.clone())),
        Some(_) => Err(ControlError::IdempotencyConflict),
    }
}
pub(crate) fn action_failure(outcome: SecretActionOutcome) -> ControlError {
    match outcome {
        SecretActionOutcome::PendingCreate(_) | SecretActionOutcome::PendingRetire(_) => {
            ControlError::RecoveryRequired
        }
        SecretActionOutcome::TokenIssued { .. } => ControlError::SecretResultUnavailable,
        SecretActionOutcome::Failed(error) => error,
        _ => ControlError::CorruptState,
    }
}
pub(crate) fn audit_admin(
    principal: &UserId,
    action: SecurityAuditAction,
    subject: &str,
) -> SecurityAuditEvent {
    SecurityAuditEvent {
        actor: SecurityAuditActor::Administrator {
            id: principal.clone(),
        },
        action,
        subject: subject.into(),
    }
}
pub(crate) fn secret_checkpoint(
    lease: &mut dyn WriterLease,
    mut next: StoredState,
    now: u64,
    audit: SecurityAuditEvent,
) -> Result<(), ControlError> {
    if now > MAX_WIRE_COUNTER || audit.subject.len() > 128 {
        return Err(ControlError::InvalidRequest);
    }
    next.version = lease
        .state()
        .version
        .checked_add(1)
        .ok_or(ControlError::CounterExhausted)?;
    let event = JournalEvent {
        security: Some(audit),
        sequence: next.version,
        at_ms: now,
        operation_id: None,
        state: None,
    };
    lease.persist(next, event)
}
pub(crate) fn next_revision(revision: Revision) -> Result<Revision, ControlError> {
    Revision::new(
        revision
            .get()
            .checked_add(1)
            .ok_or(ControlError::CounterExhausted)?,
    )
    .map_err(|_| ControlError::CounterExhausted)
}
fn credential_result(outcome: SecretActionOutcome) -> Result<CredentialSummary, ControlError> {
    if let SecretActionOutcome::Credential(s) = outcome {
        Ok(s)
    } else {
        Err(action_failure(outcome))
    }
}
impl ControlService {
    pub fn credential_inventory(
        &self,
        principal: &UserId,
    ) -> Result<CredentialInventory, ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        let kinds = self.secret_manager.supported_kinds();
        if kinds.len() > 11
            || kinds
                .iter()
                .enumerate()
                .any(|(i, k)| kinds[..i].contains(k))
        {
            return Err(ControlError::ExecutorFailed);
        }
        Ok(CredentialInventory {
            schema_version: 1,
            supported_kinds: kinds,
            credentials: state
                .secrets
                .credentials
                .values()
                .filter(|r| &r.principal == principal)
                .map(|r| r.summary.clone())
                .collect(),
        })
    }
    pub fn create_credential(
        &self,
        principal: &UserId,
        expected: Revision,
        key: IdempotencyKey,
        payload: CredentialCreatePayload,
    ) -> Result<CredentialSummary, ControlError> {
        if !payload.confirm_generate.is_confirmed() {
            return Err(ControlError::ConfirmationMismatch);
        }
        let digest =
            ContentDigest::of("vp.credential-create.v1", &(principal, expected, &payload))?;
        let mut lease = self.store.writer()?;
        if let Some(result) = prior_secret_action(
            lease.state(),
            principal,
            SecretActionKind::CredentialCreate,
            &key,
            &digest,
        )? {
            return credential_result(result);
        }
        ensure_secret_write(lease.state())?;
        check_revision(expected, lease.state().active_revision)?;
        if lease.state().secrets.credentials.len() >= 128 {
            return Err(ControlError::InvalidRequest);
        }
        if !self
            .secret_manager
            .supported_kinds()
            .contains(&payload.kind)
        {
            return Err(ControlError::ExecutorUnavailable);
        }
        let deadline = secret_deadline();
        let generated = self
            .secret_manager
            .generate_credential(&payload.kind, deadline)?;
        // Unique random ref plus the vault lifetime lock prevent adoption of an
        // unrelated pre-existing record during interrupted provisioning recovery.
        if self
            .secret_manager
            .load_credential(&generated.reference, &payload.kind, None, deadline)?
            .is_some()
        {
            return Err(ControlError::ResourceConflict);
        }
        let mut next = lease.state().clone();
        let id = CredentialId::new(format!("credential-{}", take_id(&mut next)?))
            .map_err(|_| ControlError::CounterExhausted)?;
        let now = self.clock.now_ms()?;
        let record = CredentialRecord {
            summary: CredentialSummary {
                schema_version: 1,
                id: id.clone(),
                revision: Revision::new(1).map_err(|_| ControlError::CounterExhausted)?,
                secret_ref: generated.reference,
                kind: payload.kind,
                created_at: now,
                state: CredentialState::Available,
                display_key: CredentialDisplayKey::Managed,
            },
            principal: principal.clone(),
            vault_version: 1,
        };
        let index = next.secrets.actions.len();
        next.secrets.actions.push(SecretActionRecord {
            principal: principal.clone(),
            method: SecretActionKind::CredentialCreate,
            key,
            request_digest: digest,
            outcome: SecretActionOutcome::PendingCreate(record.clone()),
        });
        secret_checkpoint(
            &mut *lease,
            next,
            now,
            audit_admin(
                principal,
                SecurityAuditAction::CredentialPrepared,
                id.as_str(),
            ),
        )?;
        // Failure is outcome-uncertain. Keep the durable intent; never regenerate
        // a credential for the same action key or publish an unverified ref.
        self.secret_manager
            .put_credential(
                &record.summary.secret_ref,
                &record.summary.kind,
                record.vault_version,
                generated.bytes,
                deadline,
            )
            .map_err(|_| ControlError::RecoveryRequired)?;
        let loaded = self
            .secret_manager
            .load_credential(
                &record.summary.secret_ref,
                &record.summary.kind,
                Some(record.vault_version),
                deadline,
            )?
            .ok_or(ControlError::RecoveryRequired)?;
        drop(loaded);
        self.finish_credential_create(&mut *lease, index, record)
    }
    fn finish_credential_create(
        &self,
        lease: &mut dyn WriterLease,
        index: usize,
        record: CredentialRecord,
    ) -> Result<CredentialSummary, ControlError> {
        let mut next = lease.state().clone();
        if next
            .secrets
            .credentials
            .insert(record.summary.id.clone(), record.clone())
            .is_some()
        {
            return Err(ControlError::CorruptState);
        }
        next.secrets
            .actions
            .get_mut(index)
            .ok_or(ControlError::CorruptState)?
            .outcome = SecretActionOutcome::Credential(record.summary.clone());
        secret_checkpoint(
            lease,
            next,
            self.clock.now_ms()?,
            audit_admin(
                &record.principal,
                SecurityAuditAction::CredentialCreated,
                record.summary.id.as_str(),
            ),
        )?;
        Ok(record.summary)
    }
    pub fn retire_credential(
        &self,
        principal: &UserId,
        id: &CredentialId,
        expected: Revision,
        key: IdempotencyKey,
        payload: CredentialRetirePayload,
    ) -> Result<CredentialSummary, ControlError> {
        if !payload.confirm_retire.is_confirmed() {
            return Err(ControlError::ConfirmationMismatch);
        }
        let digest = ContentDigest::of(
            "vp.credential-retire.v1",
            &(principal, id, expected, &payload),
        )?;
        let mut lease = self.store.writer()?;
        if let Some(result) = prior_secret_action(
            lease.state(),
            principal,
            SecretActionKind::CredentialRetire,
            &key,
            &digest,
        )? {
            return credential_result(result);
        }
        ensure_secret_write(lease.state())?;
        let record = lease
            .state()
            .secrets
            .credentials
            .get(id)
            .filter(|r| &r.principal == principal)
            .cloned()
            .ok_or(ControlError::NotFound)?;
        check_revision(expected, record.summary.revision)?;
        if record.summary.state != CredentialState::Available
            || credential_referenced(lease.state(), &record.summary.secret_ref)?
        {
            return Err(ControlError::ResourceConflict);
        }
        let mut next = lease.state().clone();
        let index = next.secrets.actions.len();
        next.secrets.actions.push(SecretActionRecord {
            principal: principal.clone(),
            method: SecretActionKind::CredentialRetire,
            key,
            request_digest: digest,
            outcome: SecretActionOutcome::PendingRetire(id.clone()),
        });
        secret_checkpoint(
            &mut *lease,
            next,
            self.clock.now_ms()?,
            audit_admin(
                principal,
                SecurityAuditAction::CredentialRetirePrepared,
                id.as_str(),
            ),
        )?;
        self.secret_manager
            .retire_credential(
                &record.summary.secret_ref,
                record.vault_version,
                secret_deadline(),
            )
            .map_err(|_| ControlError::RecoveryRequired)?;
        self.finish_credential_retire(&mut *lease, index, record)
    }
    fn finish_credential_retire(
        &self,
        lease: &mut dyn WriterLease,
        index: usize,
        mut record: CredentialRecord,
    ) -> Result<CredentialSummary, ControlError> {
        let mut next = lease.state().clone();
        record.summary.revision = next_revision(record.summary.revision)?;
        record.summary.state = CredentialState::Retired;
        record.summary.display_key = CredentialDisplayKey::Retired;
        next.secrets
            .credentials
            .insert(record.summary.id.clone(), record.clone());
        next.secrets
            .actions
            .get_mut(index)
            .ok_or(ControlError::CorruptState)?
            .outcome = SecretActionOutcome::Credential(record.summary.clone());
        secret_checkpoint(
            lease,
            next,
            self.clock.now_ms()?,
            audit_admin(
                &record.principal,
                SecurityAuditAction::CredentialRetired,
                record.summary.id.as_str(),
            ),
        )?;
        Ok(record.summary)
    }
    pub(crate) fn recover_secret_intents(
        &self,
        lease: &mut dyn WriterLease,
    ) -> Result<(), ControlError> {
        let pending: Vec<_> = lease
            .state()
            .secrets
            .actions
            .iter()
            .enumerate()
            .filter(|(_, a)| {
                matches!(
                    a.outcome,
                    SecretActionOutcome::PendingCreate(_) | SecretActionOutcome::PendingRetire(_)
                )
            })
            .map(|(i, a)| (i, a.clone()))
            .collect();
        for (index, action) in pending {
            match action.outcome {
                SecretActionOutcome::PendingCreate(record) => {
                    match self.secret_manager.load_credential(
                        &record.summary.secret_ref,
                        &record.summary.kind,
                        Some(record.vault_version),
                        secret_deadline(),
                    )? {
                        Some(bytes) => {
                            drop(bytes);
                            self.finish_credential_create(lease, index, record)?;
                        }
                        None => {
                            let mut next = lease.state().clone();
                            next.secrets.actions[index].outcome =
                                SecretActionOutcome::Failed(ControlError::ExecutorFailed);
                            secret_checkpoint(
                                lease,
                                next,
                                self.clock.now_ms()?,
                                audit_admin(
                                    &action.principal,
                                    SecurityAuditAction::CredentialActionFailed,
                                    record.summary.id.as_str(),
                                ),
                            )?;
                        }
                    }
                }
                SecretActionOutcome::PendingRetire(id) => {
                    let record = lease
                        .state()
                        .secrets
                        .credentials
                        .get(&id)
                        .cloned()
                        .ok_or(ControlError::CorruptState)?;
                    if credential_referenced(lease.state(), &record.summary.secret_ref)? {
                        return Err(ControlError::RecoveryRequired);
                    }
                    // Exact kind/version retirement is itself immutable/idempotent;
                    // no vault snapshot restore or reviving a retired value exists.
                    self.secret_manager.retire_credential(
                        &record.summary.secret_ref,
                        record.vault_version,
                        secret_deadline(),
                    )?;
                    self.finish_credential_retire(lease, index, record)?;
                }
                _ => return Err(ControlError::CorruptState),
            }
        }
        Ok(())
    }
}
fn contains_reference(value: &serde_json::Value, reference: &str) -> bool {
    match value {
        serde_json::Value::String(v) => v == reference,
        serde_json::Value::Array(a) => a.iter().any(|v| contains_reference(v, reference)),
        serde_json::Value::Object(o) => o.values().any(|v| contains_reference(v, reference)),
        _ => false,
    }
}
fn has_reference(value: &impl Serialize, reference: &SecretRef) -> Result<bool, ControlError> {
    Ok(contains_reference(
        &serde_json::to_value(value).map_err(|_| ControlError::CorruptState)?,
        reference.as_str(),
    ))
}
fn credential_referenced(state: &StoredState, reference: &SecretRef) -> Result<bool, ControlError> {
    // Conservatively scan every serialized config field, including disabled
    // users/private-key/obfuscation/source refs and all retained recovery history.
    for revision in &state.revisions {
        if has_reference(&revision.config, reference)? {
            return Ok(true);
        }
    }
    for plan in state.plans.values() {
        if has_reference(&plan.body().config, reference)? {
            return Ok(true);
        }
    }
    for draft in state.drafts.values() {
        if has_reference(&draft.summary.config, reference)? {
            return Ok(true);
        }
    }
    Ok(false)
}
