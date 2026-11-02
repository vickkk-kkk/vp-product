//! Durable draft editing belongs to the shared control service, never HTTP/CLI.
use crate::{
    service::{check_revision, checkpoint, take_id},
    *,
};
use serde::{Deserialize, Serialize};
use vp_product_domain::{
    DraftId, DraftSummary, IdempotencyKey, ListenerId, OperationId, ProductConfig, ReleaseIdentity,
    Revision, ServerListener, UserId,
};

const MAX_DRAFTS: usize = 32;
const MAX_DRAFT_BYTES: usize = 256 * 1024;
const MAX_EDIT_HISTORY: usize = 128;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DraftRecord {
    pub principal: UserId,
    pub summary: DraftSummary,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DraftMutation {
    Create(ProductConfig),
    Replace(ProductConfig),
    Delete {},
    ListenerCreate(ServerListener),
    ListenerReplace(ServerListener),
    ListenerDelete(ListenerId),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DraftRequest {
    pub principal: UserId,
    pub draft_id: Option<DraftId>,
    pub expected_revision: Revision,
    pub idempotency_key: IdempotencyKey,
    pub mutation: DraftMutation,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DraftIdempotencyRecord {
    pub principal: UserId,
    pub method: String,
    pub key: IdempotencyKey,
    pub request_digest: ContentDigest,
    pub result: Option<DraftSummary>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanIdempotencyRecord {
    pub principal: UserId,
    pub key: IdempotencyKey,
    pub request_digest: ContentDigest,
    pub plan_id: vp_product_domain::PlanId,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelRequest {
    pub principal: UserId,
    pub operation_id: OperationId,
    pub expected_revision: Revision,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelIdempotencyRecord {
    pub principal: UserId,
    pub key: IdempotencyKey,
    pub request_digest: ContentDigest,
    pub operation_id: OperationId,
}

fn bounded_config(config: &ProductConfig) -> Result<(), ControlError> {
    let bytes = serde_json::to_vec(config).map_err(|_| ControlError::InvalidConfiguration)?;
    if bytes.len() > MAX_DRAFT_BYTES
        || config.listeners.len() > 128
        || config.nodes.len() > 256
        || config.subscriptions.len() > 128
    {
        return Err(ControlError::InvalidRequest);
    }
    config
        .validate()
        .map_err(|_| ControlError::InvalidConfiguration)
}
pub(crate) fn verify_drafts(state: &StoredState) -> Result<(), ControlError> {
    let mut keys = std::collections::BTreeSet::new();
    for (id, draft) in &state.drafts {
        if id != &draft.summary.id
            || draft.summary.revision == Revision::ZERO
            || draft.summary.base_revision > state.active_revision
        {
            return Err(ControlError::CorruptState);
        }
        bounded_config(&draft.summary.config).map_err(|_| ControlError::CorruptState)?;
    }
    for entry in &state.draft_idempotency {
        if !keys.insert((&entry.principal, entry.method.as_str(), &entry.key)) {
            return Err(ControlError::CorruptState);
        }
        if let Some(draft) = &entry.result {
            bounded_config(&draft.config).map_err(|_| ControlError::CorruptState)?;
        }
    }
    let mut keys = std::collections::BTreeSet::new();
    for entry in &state.plan_idempotency {
        if !keys.insert((&entry.principal, &entry.key)) || !state.plans.contains_key(&entry.plan_id)
        {
            return Err(ControlError::CorruptState);
        }
    }
    let mut keys = std::collections::BTreeSet::new();
    for entry in &state.cancel_idempotency {
        if !keys.insert((&entry.principal, &entry.key))
            || !state.operations.get(&entry.operation_id).is_some_and(|op| {
                op.state == OperationState::Canceled && op.principal == entry.principal
            })
        {
            return Err(ControlError::CorruptState);
        }
    }
    Ok(())
}
impl ControlService {
    /// HTTP cancellation is deliberately queued-only. In-flight cancellation
    /// cannot atomically reserve an idempotency key while run owns the writer.
    /// Never claim a volatile cancellation token is a durable accepted command.
    pub fn cancel_request(
        &self,
        request: CancelRequest,
    ) -> Result<(Operation, Revision, Revision), ControlError> {
        let digest = ContentDigest::of("vp.operation-cancel.v1", &request)?;
        let mut lease = self.store.writer()?;
        lease.state().verify_integrity()?;
        if let Some(prior) = lease
            .state()
            .cancel_idempotency
            .iter()
            .find(|p| p.principal == request.principal && p.key == request.idempotency_key)
        {
            if prior.request_digest != digest {
                return Err(ControlError::IdempotencyConflict);
            }
            let op = lease
                .state()
                .operations
                .get(&prior.operation_id)
                .ok_or(ControlError::CorruptState)?;
            let plan = lease
                .state()
                .plans
                .get(&op.plan_id)
                .ok_or(ControlError::CorruptState)?;
            return Ok((
                op.clone(),
                plan.body().base_revision,
                plan.body().target_revision,
            ));
        }
        let op = lease
            .state()
            .operations
            .get(&request.operation_id)
            .filter(|op| op.principal == request.principal)
            .ok_or(ControlError::NotFound)?;
        let plan = lease
            .state()
            .plans
            .get(&op.plan_id)
            .ok_or(ControlError::CorruptState)?;
        let (base, target) = (plan.body().base_revision, plan.body().target_revision);
        check_revision(request.expected_revision, base)?;
        if !matches!(op.state, OperationState::Queued | OperationState::Canceled) {
            return Err(ControlError::CannotCancel);
        }
        if lease.state().cancel_idempotency.len() >= 256 {
            return Err(ControlError::InvalidRequest);
        }
        let mut next = lease.state().clone();
        let now = self.clock.now_ms()?;
        let op = next
            .operations
            .get_mut(&request.operation_id)
            .ok_or(ControlError::CorruptState)?;
        op.state = OperationState::Canceled;
        op.failure = Some(ControlError::Canceled);
        op.cancel_requested = true;
        op.updated_at_ms = now;
        let result = op.clone();
        next.cancel_idempotency.push(CancelIdempotencyRecord {
            principal: request.principal,
            key: request.idempotency_key,
            request_digest: digest,
            operation_id: request.operation_id.clone(),
        });
        checkpoint(
            &mut *lease,
            next,
            now,
            Some(request.operation_id),
            Some(OperationState::Canceled),
        )?;
        Ok((result, base, target))
    }
    pub fn drafts(&self, principal: &UserId) -> Result<Vec<DraftSummary>, ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        Ok(state
            .drafts
            .values()
            .filter(|d| &d.principal == principal)
            .map(|d| d.summary.clone())
            .collect())
    }
    pub fn draft(&self, id: &DraftId, principal: &UserId) -> Result<DraftSummary, ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        authorized_draft(&state, id, principal).cloned()
    }
    /// Atomic CAS + durable idempotency outcome, including deletion tombstones.
    /// History is bounded by rejecting new writes, never silently evicting retry keys.
    pub fn edit_draft(&self, request: DraftRequest) -> Result<Option<DraftSummary>, ControlError> {
        let digest = ContentDigest::of("vp.draft-edit.v1", &request)?;
        let method = match &request.mutation {
            DraftMutation::Create(_) => "draft_create",
            DraftMutation::Replace(_) => "draft_replace",
            DraftMutation::Delete {} => "draft_delete",
            DraftMutation::ListenerCreate(_) => "listener_create",
            DraftMutation::ListenerReplace(_) => "listener_replace",
            DraftMutation::ListenerDelete(_) => "listener_delete",
        };
        let mut lease = self.store.writer()?;
        lease.state().verify_integrity()?;
        if let Some(prior) = lease.state().draft_idempotency.iter().find(|p| {
            p.principal == request.principal
                && p.method == method
                && p.key == request.idempotency_key
        }) {
            return if prior.request_digest == digest {
                Ok(prior.result.clone())
            } else {
                Err(ControlError::IdempotencyConflict)
            };
        }
        if lease.state().needs_recovery() {
            return Err(ControlError::RecoveryRequired);
        }
        if lease.state().draft_idempotency.len() >= MAX_EDIT_HISTORY {
            return Err(ControlError::InvalidRequest);
        }
        let mut next = lease.state().clone();
        let result = match request.mutation {
            DraftMutation::Create(config) => {
                if request.draft_id.is_some() || next.drafts.len() >= MAX_DRAFTS {
                    return Err(ControlError::InvalidRequest);
                }
                check_revision(request.expected_revision, next.active_revision)?;
                bounded_config(&config)?;
                let id = DraftId::new(format!("draft-{}", take_id(&mut next)?))
                    .map_err(|_| ControlError::CounterExhausted)?;
                let summary = DraftSummary {
                    id: id.clone(),
                    revision: Revision::ZERO
                        .next()
                        .ok_or(ControlError::CounterExhausted)?,
                    base_revision: next.active_revision,
                    config,
                };
                next.drafts.insert(
                    id,
                    DraftRecord {
                        principal: request.principal.clone(),
                        summary: summary.clone(),
                    },
                );
                Some(summary)
            }
            mutation => {
                let id = request
                    .draft_id
                    .as_ref()
                    .ok_or(ControlError::InvalidRequest)?;
                let current = authorized_draft(&next, id, &request.principal)?.clone();
                check_revision(request.expected_revision, current.revision)?;
                if matches!(mutation, DraftMutation::Delete {}) {
                    next.drafts.remove(id);
                    None
                } else {
                    let mut updated = current;
                    match mutation {
                        DraftMutation::Replace(config) => updated.config = config,
                        DraftMutation::ListenerCreate(listener) => {
                            if updated.config.listeners.iter().any(|l| l.id == listener.id) {
                                return Err(ControlError::InvalidConfiguration);
                            }
                            updated.config.listeners.push(listener);
                        }
                        DraftMutation::ListenerReplace(listener) => {
                            let prior = updated
                                .config
                                .listeners
                                .iter_mut()
                                .find(|l| l.id == listener.id)
                                .ok_or(ControlError::NotFound)?;
                            *prior = listener;
                        }
                        DraftMutation::ListenerDelete(listener_id) => {
                            let i = updated
                                .config
                                .listeners
                                .iter()
                                .position(|l| l.id == listener_id)
                                .ok_or(ControlError::NotFound)?;
                            updated.config.listeners.remove(i);
                        }
                        _ => return Err(ControlError::InvalidRequest),
                    }
                    bounded_config(&updated.config)?;
                    updated.revision = updated
                        .revision
                        .next()
                        .ok_or(ControlError::CounterExhausted)?;
                    next.drafts.insert(
                        id.clone(),
                        DraftRecord {
                            principal: request.principal.clone(),
                            summary: updated.clone(),
                        },
                    );
                    Some(updated)
                }
            }
        };
        next.draft_idempotency.push(DraftIdempotencyRecord {
            principal: request.principal,
            method: method.into(),
            key: request.idempotency_key,
            request_digest: digest,
            result: result.clone(),
        });
        // Leave headroom under the store's 32 MiB aggregate bound; preserve
        // durable retry history rather than silently evicting old keys.
        if serde_json::to_vec(&next)
            .map_err(|_| ControlError::InvalidRequest)?
            .len()
            > 24 * 1024 * 1024
        {
            return Err(ControlError::InvalidRequest);
        }
        checkpoint(&mut *lease, next, self.clock.now_ms()?, None, None)?;
        Ok(result)
    }
    pub fn validate_draft(
        &self,
        id: &DraftId,
        principal: &UserId,
        expected_revision: Revision,
        release: &ReleaseIdentity,
    ) -> Result<(), ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        let draft = authorized_draft(&state, id, principal)?;
        check_revision(expected_revision, draft.revision)?;
        check_revision(draft.base_revision, state.active_revision)?;
        bounded_config(&draft.config)?;
        release
            .validate()
            .map_err(|_| ControlError::InvalidConfiguration)?;
        let receipt = self
            .runtime
            .validate(&draft.config, release, state.active())?;
        if receipt.config_digest != ContentDigest::of("vp.product-config.v1", &draft.config)?
            || receipt.release_digest != ContentDigest::of("vp.release-identity.v1", release)?
        {
            return Err(ControlError::InvalidConfiguration);
        }
        crate::service::validate_health_requirements(
            &PlanRequest {
                principal: principal.clone(),
                expected_revision: state.active_revision,
                config: draft.config.clone(),
                release: release.clone(),
                resources: vec![],
                ttl_ms: 300_000,
            },
            &receipt,
            state.active(),
        )?;
        if !self.system.inspect(&[])?.is_empty() {
            return Err(ControlError::ResourceConflict);
        }
        Ok(())
    }
    pub fn plan_draft(
        &self,
        id: &DraftId,
        principal: &UserId,
        expected_revision: Revision,
        key: IdempotencyKey,
        release: ReleaseIdentity,
    ) -> Result<ChangePlan, ControlError> {
        // Replays bind the selected draft ID/release/base, not its subsequent edits.
        let digest = ContentDigest::of(
            "vp.plan-draft.v1",
            &(id, principal, expected_revision, &release),
        )?;
        let mut lease = self.store.writer()?;
        lease.state().verify_integrity()?;
        if let Some(prior) = lease
            .state()
            .plan_idempotency
            .iter()
            .find(|p| &p.principal == principal && p.key == key)
        {
            return if prior.request_digest == digest {
                lease
                    .state()
                    .plans
                    .get(&prior.plan_id)
                    .cloned()
                    .ok_or(ControlError::CorruptState)
            } else {
                Err(ControlError::IdempotencyConflict)
            };
        }
        if lease.state().plan_idempotency.len() >= 128 {
            return Err(ControlError::InvalidRequest);
        }
        let draft = authorized_draft(lease.state(), id, principal)?.clone();
        check_revision(expected_revision, draft.base_revision)?;
        // The plan and retry record must be one durable checkpoint. plan_locked
        // writes into a buffered lease and the real store commits both together.
        let mut buffer = BufferedLease {
            state: lease.state().clone(),
            event: None,
        };
        let plan = self.plan_locked(
            PlanRequest {
                principal: principal.clone(),
                expected_revision,
                config: draft.config,
                release,
                resources: vec![],
                ttl_ms: 300_000,
            },
            &mut buffer,
        )?;
        buffer.state.plan_idempotency.push(PlanIdempotencyRecord {
            principal: principal.clone(),
            key,
            request_digest: digest,
            plan_id: plan.body().id.clone(),
        });
        lease.persist(
            buffer.state,
            buffer.event.ok_or(ControlError::CorruptState)?,
        )?;
        Ok(plan)
    }
    pub fn operation_details(
        &self,
        id: &OperationId,
        principal: &UserId,
    ) -> Result<(Operation, Revision, Revision), ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        let op = state
            .operations
            .get(id)
            .filter(|o| &o.principal == principal)
            .ok_or(ControlError::NotFound)?;
        let plan = state
            .plans
            .get(&op.plan_id)
            .ok_or(ControlError::CorruptState)?;
        Ok((
            op.clone(),
            plan.body().base_revision,
            plan.body().target_revision,
        ))
    }
    /// A read-only use of the existing global writer lease serializes active
    /// probes with apply/recovery. No journal/state is persisted by this read.
    /// Otherwise a snapshot could seize the executor lock between activation
    /// steps and spuriously fail a real transaction. Probe implementations must
    /// bound their work; API permits only one outstanding active snapshot.
    pub fn management_view(&self, principal: &UserId) -> Result<ManagementView, ControlError> {
        let lease = self.store.writer()?;
        let state = lease.state();
        state.verify_integrity()?;
        let desired_revision = state
            .operations
            .values()
            .filter(|op| !op.state.is_terminal())
            .filter_map(|op| {
                state
                    .plans
                    .get(&op.plan_id)
                    .map(|p| p.body().target_revision)
            })
            .max()
            .unwrap_or(state.active_revision);
        let operations = state
            .operations
            .values()
            .filter(|op| &op.principal == principal)
            .map(|op| {
                let plan = state
                    .plans
                    .get(&op.plan_id)
                    .ok_or(ControlError::CorruptState)?;
                Ok((
                    op.clone(),
                    plan.body().base_revision,
                    plan.body().target_revision,
                ))
            })
            .collect::<Result<Vec<_>, ControlError>>()?;
        let (observed, observation_error) = match state.active() {
            _ if state.needs_recovery() => (None, Some(ControlError::RecoveryRequired)),
            None => (None, None),
            Some(active) => {
                let observation = self.runtime.observe_committed(active).and_then(|health| {
                    validate_observation(active, &health, self.clock.now_ms()?)?;
                    // Concurrent plan/apply checkpoints invalidate this projection;
                    // never join an old observation to a newer committed view.
                    let latest = self.store.read()?;
                    if latest.version != state.version {
                        return Err(ControlError::HealthFailed);
                    }
                    Ok(health)
                });
                match observation {
                    Ok(health) => (Some(health), None),
                    Err(error) => (None, Some(error)),
                }
            }
        };
        Ok(ManagementView {
            observed,
            observation_error,
            desired_revision,
            listeners: state
                .active()
                .map(|r| r.config.listeners.clone())
                .unwrap_or_default(),
            operations,
        })
    }
    pub fn active_config(&self) -> Result<(Revision, Option<ProductConfig>), ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        Ok((
            state.active_revision,
            state.active().map(|r| r.config.clone()),
        ))
    }
    pub fn operation_by_idempotency(
        &self,
        key: &IdempotencyKey,
        principal: &UserId,
    ) -> Result<(Operation, Revision, Revision), ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        let record = state
            .idempotency
            .iter()
            .find(|r| &r.principal == principal && &r.key == key && r.method == "plans.apply.v1")
            .ok_or(ControlError::NotFound)?;
        let op = state
            .operations
            .get(&record.operation_id)
            .ok_or(ControlError::CorruptState)?;
        let plan = state
            .plans
            .get(&op.plan_id)
            .ok_or(ControlError::CorruptState)?;
        Ok((
            op.clone(),
            plan.body().base_revision,
            plan.body().target_revision,
        ))
    }
    pub fn queued_operations(&self) -> Result<Vec<OperationId>, ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        Ok(state
            .operations
            .values()
            .filter(|op| op.state == OperationState::Queued)
            .map(|op| op.id.clone())
            .collect())
    }
    pub fn configured_listeners(&self) -> Result<Vec<ServerListener>, ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        Ok(state
            .active()
            .map(|r| r.config.listeners.clone())
            .unwrap_or_default())
    }
}
fn authorized_draft<'a>(
    state: &'a StoredState,
    id: &DraftId,
    principal: &UserId,
) -> Result<&'a DraftSummary, ControlError> {
    state
        .drafts
        .get(id)
        .filter(|d| &d.principal == principal)
        .map(|d| &d.summary)
        .ok_or(ControlError::NotFound)
}
struct BufferedLease {
    state: StoredState,
    event: Option<JournalEvent>,
}
impl WriterLease for BufferedLease {
    fn state(&self) -> &StoredState {
        &self.state
    }
    fn persist(&mut self, next: StoredState, event: JournalEvent) -> Result<(), ControlError> {
        if self.event.is_some() {
            return Err(ControlError::CorruptState);
        }
        self.state = next;
        self.event = Some(event);
        Ok(())
    }
}

/// Internal authorized projection, not serialized directly on the wire.
pub struct ManagementView {
    pub observed: Option<RuntimeHealth>,
    pub observation_error: Option<ControlError>,
    pub desired_revision: Revision,
    pub listeners: Vec<ServerListener>,
    pub operations: Vec<(Operation, Revision, Revision)>,
}

pub(crate) fn validate_observation(
    active: &RevisionRecord,
    health: &RuntimeHealth,
    now: u64,
) -> Result<(), ControlError> {
    if health.operation_id != active.operation_id
        || health.revision != active.revision
        || health.config_digest != active.config_digest
        || health.release_digest != active.release_digest
        || health.generation == 0
        || health.generation > vp_product_domain::MAX_WIRE_COUNTER
        || health.checked_at_ms > now
        || now - health.checked_at_ms > 30_000
    {
        return Err(ControlError::HealthFailed);
    }
    let required = crate::minimum_health_checks(&active.config, None)?;
    let mut seen = std::collections::BTreeSet::new();
    for result in &health.checks {
        if !seen.insert(&result.check)
            || !required.contains(&result.check)
            || result.outcome != CheckOutcome::Passed
        {
            return Err(ControlError::HealthFailed);
        }
    }
    if required.iter().any(|check| !seen.contains(check)) {
        return Err(ControlError::HealthFailed);
    }
    Ok(())
}
