use super::*;
use std::collections::BTreeMap;
use vp_product_compiler::server_v2::{ServerCompilerV2, ServerProfileV2, ServerRecipeV2};
use vp_product_control::{OperationState, RevisionRecord, StoredState};
use vp_product_domain::ReleaseIdentity;

/// Content address of exact serialized public core commit/patchset tuple. Release
/// digest additionally binds every release field. No new digest domain allocated.
pub fn core_digest(release: &ReleaseIdentity) -> Result<ContentDigest, ControlError> {
    let bytes = serde_json::to_vec(&(&release.core_commit, &release.patchset_hash))
        .map_err(|_| ControlError::CorruptState)?;
    Ok(ContentDigest::bytes(&bytes))
}
fn references(j: &Journal) -> Vec<&RecipeIdentity> {
    let mut refs = Vec::with_capacity(5);
    if let Some(o) = &j.operation {
        refs.push(&o.candidate);
        if let Some(p) = &o.previous {
            refs.push(p);
        }
    }
    if let Some(a) = &j.active {
        refs.push(&a.launch.recipe);
    }
    if let Some(p) = &j.prepared {
        refs.push(&p.launch.recipe);
    }
    if let Some(l) = &j.launch_intent {
        refs.push(&l.launch.recipe);
    }
    refs
}
/// Caller supplies bounded immutable bytes already read under retained handles.
/// This function performs no I/O and no material/retirement admission.
pub fn verify_recipes(
    j: &Journal,
    artifacts: &BTreeMap<ContentDigest, Vec<u8>>,
) -> Result<(), ControlError> {
    j.validate()?;
    require(artifacts.len() <= 5)?;
    for r in references(j) {
        let bytes = artifacts
            .get(&r.recipe_digest)
            .ok_or(ControlError::CorruptState)?;
        codec::budget(bytes, MAX_RECIPE_BYTES, 65536, 64, 65536)?;
        require(ContentDigest::bytes(bytes) == r.recipe_digest)?;
        let recipe: ServerRecipeV2 =
            serde_json::from_slice(bytes).map_err(|_| ControlError::CorruptState)?;
        require(
            recipe.listeners.len() <= 128
                && recipe
                    .listeners
                    .iter()
                    .map(|l| l.credentials.len())
                    .sum::<usize>()
                    <= 512,
        )?;
        require(serde_json::to_vec(&recipe).map_err(|_| ControlError::CorruptState)? == *bytes)?;
        require(
            ContentDigest::of("vp.product-config.v1", &recipe.source)? == r.config_digest
                && ContentDigest::of("vp.release-identity.v1", &recipe.release)?
                    == r.release_digest
                && core_digest(&recipe.release)? == j.identity.core_digest,
        )?;
        let compiler = match recipe.profile {
            ServerProfileV2::LoopbackDevelopmentUncertified => {
                ServerCompilerV2::for_loopback_development(recipe.release.clone())
            }
            ServerProfileV2::LoopbackExtendedCoreUncertified => {
                ServerCompilerV2::for_loopback_server_extensions(recipe.release.clone())
            }
            ServerProfileV2::PublicExperimentalUncertified => {
                let targets = recipe.public_targets.clone().ok_or(ControlError::CorruptState)?;
                ServerCompilerV2::for_public_experiment(recipe.release.clone(), targets)
            }
        }
        .map_err(|_| ControlError::CorruptState)?;
        compiler
            .verify_recipe(&recipe)
            .map_err(|_| ControlError::CorruptState)?;
    }
    // No unknown unreferenced bytes get adopted as part of this exact proof.
    require(
        artifacts
            .keys()
            .all(|digest| references(j).iter().any(|r| &r.recipe_digest == digest)),
    )
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pairing {
    /// Structurally paired, never a live health or process ownership assertion.
    Stable,
    Inflight,
    /// Uncertain intent or control recovery: no automatic replay/launch authority.
    RecoverOnly,
    /// Control is terminal, runtime metadata may be cleared by a pure proposal.
    Finalize,
}
fn revision_matches(r: &RecipeIdentity, v: &RevisionRecord) -> bool {
    r.revision_owner_operation == v.operation_id
        && r.revision == v.revision
        && r.config_digest == v.config_digest
        && r.release_digest == v.release_digest
        && r.recipe_digest == v.artifact_digest
}
fn receipts(
    op: &vp_product_control::Operation,
    r: &RecipeIdentity,
    expected_generation: Option<u64>,
    require_activation: bool,
    require_health: bool,
) -> Result<(), ControlError> {
    require(!require_activation || op.activation.is_some())?;
    require(!require_health || op.health.is_some())?;
    if let Some(a) = &op.activation {
        require(
            a.operation_id == r.revision_owner_operation
                && a.revision == r.revision
                && a.config_digest == r.config_digest
                && a.release_digest == r.release_digest
                && a.generation > 0
                && a.generation <= MAX_WIRE_COUNTER
                && expected_generation.is_none_or(|g| g == a.generation),
        )?;
    }
    if let Some(h) = &op.health {
        let a = op.activation.as_ref().ok_or(ControlError::CorruptState)?;
        require(
            h.operation_id == r.revision_owner_operation
                && h.revision == r.revision
                && h.config_digest == r.config_digest
                && h.release_digest == r.release_digest
                && h.generation == a.generation,
        )?;
    }
    Ok(())
}
fn committed_owner(r: &RecipeIdentity, s: &StoredState) -> Result<(), ControlError> {
    let v = s
        .revisions
        .iter()
        .find(|v| v.revision == r.revision)
        .ok_or(ControlError::CorruptState)?;
    require(revision_matches(r, v))?;
    let op = s
        .operations
        .get(&r.revision_owner_operation)
        .ok_or(ControlError::CorruptState)?;
    let plan = s.plans.get(&op.plan_id).ok_or(ControlError::CorruptState)?;
    require(
        op.state == OperationState::Committed
            && op.principal == plan.body().principal
            && plan.body().target_revision == r.revision
            && plan.body().validation.config_digest == r.config_digest
            && plan.body().validation.release_digest == r.release_digest
            && plan.body().validation.artifact_digest == r.recipe_digest,
    )?;
    receipts(op, r, None, true, true)
}
/// Correlate saved ownership history, never authenticate a live child.
fn historical_owned(a: &OwnedRecord, s: &StoredState) -> Result<(), ControlError> {
    let r = &a.launch.recipe;
    committed_owner(r, s)?;
    let owner = s
        .operations
        .get(&r.revision_owner_operation)
        .ok_or(ControlError::CorruptState)?;
    let original = owner
        .activation
        .as_ref()
        .ok_or(ControlError::CorruptState)?;
    if a.launch.transition_operation == r.revision_owner_operation {
        receipts(owner, r, Some(a.launch.generation), true, true)
    } else {
        let transition = s
            .operations
            .get(&a.launch.transition_operation)
            .ok_or(ControlError::CorruptState)?;
        let plan = s
            .plans
            .get(&transition.plan_id)
            .ok_or(ControlError::CorruptState)?;
        require(
            transition.state == OperationState::RolledBack
                && transition.principal == plan.body().principal
                && plan.body().base_revision == r.revision
                && transition.mutation_started
                && transition.snapshot.is_some()
                && a.launch.generation > original.generation,
        )?;
        let historical_candidate = RecipeIdentity {
            revision_owner_operation: transition.id.clone(),
            revision: plan.body().target_revision,
            config_digest: plan.body().validation.config_digest.clone(),
            release_digest: plan.body().validation.release_digest.clone(),
            recipe_digest: plan.body().validation.artifact_digest.clone(),
        };
        receipts(transition, &historical_candidate, None, false, false)?;
        require(
            transition
                .activation
                .as_ref()
                .is_none_or(|v| v.generation < a.launch.generation),
        )
        // The existing control model has no persisted restoration receipt.
        // This checks history linkage, not fresh restoration health/ownership.
    }
}
/// Read-only cross-pairing; neither this enum nor decoded records grant authority
/// to mutate SQL, launch, bind, signal, recover unknown PIDs or read secret bytes.
pub fn pair_control(j: &Journal, s: &StoredState) -> Result<Pairing, ControlError> {
    j.validate()?;
    s.verify_integrity()?;
    let inflight: Vec<_> = s
        .operations
        .values()
        .filter(|o| !o.state.is_terminal() && o.state != OperationState::Queued)
        .collect();
    require(inflight.len() <= 1)?;
    if j.phase == Phase::Idle {
        require(inflight.iter().all(|o| o.state == OperationState::Staging))?;
        match (&j.active, s.active()) {
            (None, None) => require(s.active_revision == Revision::ZERO)?,
            (Some(a), Some(v)) => {
                require(revision_matches(&a.launch.recipe, v))?;
                historical_owned(a, s)?;
            }
            _ => return Err(ControlError::ResourceConflict),
        }
        return Ok(Pairing::Stable);
    }
    let o = j.operation.as_ref().ok_or(ControlError::CorruptState)?;
    require(inflight.iter().all(|v| v.id == o.operation))?;
    let op = s
        .operations
        .get(&o.operation)
        .ok_or(ControlError::CorruptState)?;
    let plan = s.plans.get(&o.plan_id).ok_or(ControlError::CorruptState)?;
    require(
        op.plan_id == o.plan_id
            && op.principal == o.principal
            && plan.body().principal == o.principal
            && plan.hash() == &o.plan_hash
            && plan.body().base_revision == o.base_revision
            && plan.body().target_revision == o.candidate.revision
            && plan.body().validation.config_digest == o.candidate.config_digest
            && plan.body().validation.release_digest == o.candidate.release_digest
            && plan.body().validation.artifact_digest == o.candidate.recipe_digest,
    )?;
    if let Some(p) = &o.previous {
        committed_owner(p, s)?;
        let original = s
            .operations
            .get(&p.revision_owner_operation)
            .and_then(|v| v.activation.as_ref())
            .ok_or(ControlError::CorruptState)?;
        require(original.generation <= o.admitted_high_water)?;
    }
    if let Some(a) = &j.active {
        if o.previous.as_ref() == Some(&a.launch.recipe)
            && a.launch.generation <= o.admitted_high_water
        {
            historical_owned(a, s)?;
        }
    }
    receipts(
        op,
        &o.candidate,
        Some(o.admitted_high_water + 1),
        matches!(
            op.state,
            OperationState::Verifying | OperationState::Committing | OperationState::Committed
        ),
        op.state == OperationState::Committed,
    )?;
    use OperationState as C;
    use Phase as P;
    if op.state == C::Committed {
        require(j.phase == P::CandidateStarted && s.active_revision == o.candidate.revision)?;
        committed_owner(&o.candidate, s)?;
        let a = j.active.as_ref().ok_or(ControlError::CorruptState)?;
        let activation = op.activation.as_ref().ok_or(ControlError::CorruptState)?;
        let health = op.health.as_ref().ok_or(ControlError::CorruptState)?;
        require(
            activation.operation_id == o.operation
                && health.operation_id == o.operation
                && activation.revision == o.candidate.revision
                && health.revision == o.candidate.revision
                && activation.config_digest == o.candidate.config_digest
                && health.config_digest == o.candidate.config_digest
                && activation.release_digest == o.candidate.release_digest
                && health.release_digest == o.candidate.release_digest
                && activation.generation == a.launch.generation
                && health.generation == a.launch.generation,
        )?;
        return Ok(Pairing::Finalize);
    }
    require(s.active_revision == o.base_revision)?;
    if op.state == C::RolledBack || matches!(op.state, C::Failed | C::Canceled) {
        let restored = j.phase == P::Restored;
        let unchanged = j.phase == P::CandidateAbsent
            && match (&j.active, &o.previous) {
                (None, None) => true,
                (Some(a), Some(p)) => a.launch.recipe == *p,
                _ => false,
            };
        require(if op.state == C::RolledBack {
            restored || unchanged
        } else {
            unchanged && !op.mutation_started
        })?;
        return Ok(Pairing::Finalize);
    }
    require(op.state != C::Queued)?;
    let compatible = match j.phase {
        P::CandidateReserved | P::CandidateSpawnObserved => {
            matches!(op.state, C::Staging | C::Canceling | C::RecoveryRequired)
        }
        P::Prepared => matches!(
            op.state,
            C::Staging
                | C::Snapshotting
                | C::ApplyingResources
                | C::Activating
                | C::Canceling
                | C::RollingBack
                | C::RecoveryRequired
        ),
        P::StoppingOld | P::OldStopped | P::ActivatingCandidate => matches!(
            op.state,
            C::Activating | C::RollingBack | C::RecoveryRequired
        ),
        P::CandidateStarted => matches!(
            op.state,
            C::Activating | C::Verifying | C::Committing | C::RollingBack | C::RecoveryRequired
        ),
        P::DiscardingPrepared | P::CandidateAbsent => matches!(
            op.state,
            C::Staging | C::Canceling | C::RollingBack | C::RecoveryRequired
        ),
        P::StoppingCandidate
        | P::RestoreReserved
        | P::RestoreSpawnObserved
        | P::RestorePrepared
        | P::ActivatingRestore
        | P::Restored => matches!(op.state, C::RollingBack | C::RecoveryRequired),
        P::Idle => false,
    };
    require(compatible)?;
    if matches!(
        op.state,
        C::ApplyingResources | C::Activating | C::Verifying | C::Committing | C::RollingBack
    ) {
        require(op.mutation_started && op.snapshot.is_some())?;
    }
    Ok(
        if op.state == C::RecoveryRequired || j.launch_intent.is_some() || j.transition.is_some() {
            Pairing::RecoverOnly
        } else {
            Pairing::Inflight
        },
    )
}

/// A read-only observation of one paired, committed generation whose exact
/// historical process is absent. This does not authorize a spawn, restore,
/// health claim, PID signal, or vault access. A future restart coordinator must
/// retain the writer, journal and live handles and persist every effect first.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RestartObservation {
    pub recipe: RecipeIdentity,
    pub previous_process: ProcessIdentity,
    pub next_generation: u64,
}

#[cfg(target_os = "linux")]
pub(crate) fn inspect_absent_committed_process(
    journal: &Journal,
    state: &StoredState,
) -> Result<RestartObservation, ControlError> {
    if journal.phase != Phase::Idle || pair_control(journal, state)? != Pairing::Stable
        || state.needs_recovery() || state.operations.values().any(|op| !op.state.is_terminal()) {
        return Err(ControlError::RecoveryRequired);
    }
    let old = journal.active.as_ref().ok_or(ControlError::ResourceConflict)?;
    // PID + boot + start ticks are observation only. Never adopt or signal it.
    if old.process.is_present()? { return Err(ControlError::ResourceConflict); }
    let next_generation = journal.high_water.checked_add(1)
        .filter(|n| *n <= MAX_WIRE_COUNTER).ok_or(ControlError::CounterExhausted)?;
    Ok(RestartObservation { recipe: old.launch.recipe.clone(), previous_process: old.process.clone(), next_generation })
}
