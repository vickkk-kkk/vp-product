//! Pure prototype of persist-before-effect restart checkpoints. This module has
//! no storage publisher, process authority, listener, or recovery executor.
use super::*;
use vp_product_control::StoredState;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RestartPhase { Reserved, SpawnObserved, Prepared, Activating, Running, Verified, FailedStopped }

/// Bound to the exact stable prior journal and control snapshot. Neither this
/// value nor its decoded bytes authorize process creation or PID signaling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RestartRecord {
    schema_version: u16,
    base_journal_digest: ContentDigest,
    base_control_digest: ContentDigest,
    previous: OwnedRecord,
    launch: LaunchRecord,
    phase: RestartPhase,
    process: Option<ProcessIdentity>,
    health: Option<RestartHealthRecord>,
    attempt: u32,
    sequence: u64,
}
#[derive(Clone, Debug)]
pub(crate) enum RestartEvent { SpawnObserved(ProcessIdentity), Prepared, Activate, Activated, Verified(RestartHealthRecord), FailedAbsent, Retry { instance: String, session: String } }
/// Historical observation only, never proof of current liveness after reopen.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RestartHealthRecord { pub(super) generation: u64, pub(super) checked_at_ms: u64, pub(super) checks: Vec<vp_product_control::HealthCheck> }
impl RestartRecord {
    /// Caller must independently retain the actual writer, runtime lock and
    /// vault; this pure proposal only checks observations and never spawns.
    pub(crate) fn reserve(journal: &Journal, state: &StoredState, instance: String, session: String) -> Result<Self, ControlError> {
        let observed = pairing::inspect_absent_committed_process(journal, state)?;
        require(token(&instance) && token(&session))?;
        let previous = journal.active.clone().ok_or(ControlError::CorruptState)?;
        require(instance != previous.launch.instance)?;
        let launch = LaunchRecord { recipe: observed.recipe, transition_operation: previous.launch.transition_operation.clone(),
            generation: observed.next_generation, instance, session,
            worker_digest: journal.identity.worker_digest.clone(), worker_protocol_version: journal.identity.worker_protocol_version };
        let value = Self { schema_version: 1, base_journal_digest: ContentDigest::bytes(&journal.encode()?),
            base_control_digest: ContentDigest::of("vp.restart-base-control.v1", state)?, previous, launch,
            phase: RestartPhase::Reserved, process: None, health: None, attempt: 1, sequence: 0 };
        value.validate_base(journal, state)?;
        Ok(value)
    }
    pub(crate) fn validate_base(&self, journal: &Journal, state: &StoredState) -> Result<(), ControlError> {
        journal.validate()?;
        state.verify_integrity()?;
        require(pairing::pair_control(journal, state)? == Pairing::Stable
            && journal.phase == Phase::Idle && !state.needs_recovery()
            && state.operations.values().all(|o| o.state.is_terminal())
            && self.schema_version == 1
            && self.base_journal_digest == ContentDigest::bytes(&journal.encode()?)
            && self.base_control_digest == ContentDigest::of("vp.restart-base-control.v1", state)?
            && journal.active.as_ref() == Some(&self.previous)
            && self.launch.recipe == self.previous.launch.recipe
            && self.launch.transition_operation == self.previous.launch.transition_operation
            && self.attempt > 0 && self.attempt <= 100_000
            && self.launch.generation == journal.high_water.checked_add(u64::from(self.attempt)).ok_or(ControlError::CounterExhausted)?
            && self.launch.generation <= MAX_WIRE_COUNTER
            && self.launch.worker_digest == journal.identity.worker_digest
            && self.launch.worker_protocol_version == journal.identity.worker_protocol_version
            && token(&self.launch.instance) && token(&self.launch.session)
            && self.launch.instance != self.previous.launch.instance)?;
        if let Some(process) = &self.process { process.validate()?; require(process.pid != self.previous.process.pid)?; }
        let prior = u64::from(self.attempt - 1);
        let min = prior.checked_mul(3).ok_or(ControlError::CounterExhausted)?;
        let max = prior.checked_mul(6).ok_or(ControlError::CounterExhausted)?;
        let (lower, upper, has_process) = match self.phase {
            RestartPhase::Reserved => (0, 0, false),
            RestartPhase::SpawnObserved => (1, 1, true),
            RestartPhase::Prepared => (2, 2, true),
            RestartPhase::Activating => (3, 3, true),
            RestartPhase::Running => (4, 4, true),
            RestartPhase::Verified => (5, 5, true),
            RestartPhase::FailedStopped => (2, 5, true),
        };
        require((min + lower..=max + upper).contains(&self.sequence) && self.process.is_some() == has_process)?;
        match (&self.phase, &self.health) {
            (RestartPhase::Verified, Some(health)) => {
                let active = state.active().ok_or(ControlError::CorruptState)?;
                let required = vp_product_control::minimum_health_checks(&active.config, None)?;
                let observed: std::collections::BTreeSet<_> = health.checks.iter().cloned().collect();
                require(health.generation == self.launch.generation && health.checked_at_ms > 0
                    && observed == required && observed.len() == health.checks.len()
                    && health.checks.iter().eq(required.iter()))
            }
            (RestartPhase::Verified, None) | (_, Some(_)) => Err(ControlError::CorruptState),
            _ => Ok(()),
        }
    }
    /// Canonical bounded bytes for a future atomic publisher. No I/O occurs here.
    pub(crate) fn encode(&self, journal: &Journal, state: &StoredState) -> Result<Vec<u8>, ControlError> {
        self.validate_base(journal, state)?;
        let bytes = serde_json::to_vec(self).map_err(|_| ControlError::CorruptState)?;
        codec::budget(&bytes, MAX_JOURNAL_BYTES, 4096, 16, 4096)?;
        Ok(bytes)
    }
    /// Untrusted bytes remain observations; a future coordinator must separately
    /// establish durable ownership and re-check the running process/materials.
    pub(crate) fn decode(bytes: &[u8], journal: &Journal, state: &StoredState) -> Result<Self, ControlError> {
        codec::budget(bytes, MAX_JOURNAL_BYTES, 4096, 16, 4096)?;
        let record: Self = serde_json::from_slice(bytes).map_err(|_| ControlError::CorruptState)?;
        record.validate_base(journal, state)?;
        require(record.encode(journal, state)?.as_slice() == bytes)?;
        Ok(record)
    }
    /// Propose only the next legal state; successful return proves no effect.
    pub(crate) fn propose(&self, event: RestartEvent, journal: &Journal, state: &StoredState) -> Result<Self, ControlError> {
        self.validate_base(journal, state)?;
        let mut next = self.clone();
        match (self.phase, event) {
            (RestartPhase::Reserved, RestartEvent::SpawnObserved(p)) => { next.process = Some(p); next.phase = RestartPhase::SpawnObserved; }
            (RestartPhase::SpawnObserved, RestartEvent::Prepared) => next.phase = RestartPhase::Prepared,
            (RestartPhase::Prepared, RestartEvent::Activate) => next.phase = RestartPhase::Activating,
            (RestartPhase::Activating, RestartEvent::Activated) => next.phase = RestartPhase::Running,
            (RestartPhase::Running, RestartEvent::Verified(health)) => { next.health = Some(health); next.phase = RestartPhase::Verified; }
            (RestartPhase::SpawnObserved | RestartPhase::Prepared | RestartPhase::Activating | RestartPhase::Running, RestartEvent::FailedAbsent) => next.phase = RestartPhase::FailedStopped,
            (RestartPhase::FailedStopped, RestartEvent::Retry { instance, session }) => {
                require(token(&instance) && token(&session) && instance != self.launch.instance && instance != self.previous.launch.instance)?;
                next.attempt = next.attempt.checked_add(1).filter(|v| *v <= 100_000).ok_or(ControlError::CounterExhausted)?;
                next.launch.generation = next.launch.generation.checked_add(1).filter(|v| *v <= MAX_WIRE_COUNTER).ok_or(ControlError::CounterExhausted)?;
                next.launch.instance = instance; next.launch.session = session; next.process = None; next.health = None; next.phase = RestartPhase::Reserved;
            }
            _ => return Err(ControlError::RecoveryRequired),
        }
        next.sequence = next.sequence.checked_add(1).ok_or(ControlError::CounterExhausted)?;
        next.validate_base(journal, state)?;
        Ok(next)
    }
}

/// Isolated experimental checkpoint store. It is not yet connected to the
/// runtime root, installer, process lifecycle or recovery; it cannot launch.
/// The caller must hold the matching control writer and runtime ownership for
/// its entire life. Any uncertain write poisons the handle without cleanup.
pub(crate) struct RestartStore {
    file: vp_product_storage::ReadOnlyBoundFile,
    root: vp_product_storage::BoundDirectory,
    record: RestartRecord,
    poisoned: bool,
}
impl RestartStore {
    const MARKER: &'static str = "restart.intent.json";
    const PENDING: &'static str = "restart.intent.pending";
    pub(crate) fn create(root: vp_product_storage::BoundDirectory, record: RestartRecord,
        journal: &Journal, state: &StoredState) -> Result<Self, ControlError> {
        let bytes = record.encode(journal, state)?;
        let root = root.lock()?;
        root.require_empty()?;
        // On any failure, preserve pending/committed files; never retry blindly.
        root.atomic_file(Self::MARKER, Self::PENDING, &bytes, MAX_JOURNAL_BYTES, false)?;
        let file = root.inspect_file_read_only(Self::MARKER, MAX_JOURNAL_BYTES)?;
        require(file.bytes() == bytes.as_slice() && root.names()? == [Self::MARKER.to_owned()])?;
        RestartRecord::decode(file.bytes(), journal, state)?;
        Ok(Self { file, root, record, poisoned: false })
    }
    /// Inspect only exact canonical saved bytes; never repair pending residue.
    pub(crate) fn open(root: vp_product_storage::BoundDirectory, journal: &Journal,
        state: &StoredState) -> Result<Self, ControlError> {
        let root = root.lock()?;
        require(root.names()? == [Self::MARKER.to_owned()])?;
        let file = root.inspect_file_read_only(Self::MARKER, MAX_JOURNAL_BYTES)?;
        let record = RestartRecord::decode(file.bytes(), journal, state)?;
        Ok(Self { file, root, record, poisoned: false })
    }
    fn unchanged(&self, journal: &Journal, state: &StoredState) -> Result<(), ControlError> {
        if self.poisoned { return Err(ControlError::RecoveryRequired); }
        self.file.revalidate(&self.root)?;
        require(self.root.names()? == [Self::MARKER.to_owned()])?;
        require(self.file.bytes() == self.record.encode(journal, state)?.as_slice())
    }
    pub(crate) fn record(&self, journal: &Journal, state: &StoredState) -> Result<&RestartRecord, ControlError> {
        self.unchanged(journal, state)?;
        Ok(&self.record)
    }
    /// Terminalize only a known child that has been reaped and whose exact
    /// recorded process is absent. This does not permit a retry or a new launch.
    pub(crate) fn confirm_failed_absent(&mut self, journal: &Journal, state: &StoredState,
        runtime: &vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2) -> Result<(), ControlError> {
        let record = self.record(journal, state)?;
        if !matches!(record.phase, RestartPhase::SpawnObserved | RestartPhase::Prepared | RestartPhase::Activating | RestartPhase::Running)
            || runtime.active_generation().is_some() || runtime.prepared_generation().is_some()
            || runtime.generation() != record.launch.generation || runtime.instance().as_str() != record.launch.instance
            || runtime.worker_sha256() != journal.identity.worker_digest.as_str()
            || record.process.as_ref().ok_or(ControlError::RecoveryRequired)?.is_present()? {
            return Err(ControlError::RecoveryRequired);
        }
        self.publish_event(RestartEvent::FailedAbsent, journal, state)
    }
    /// A retry requires both historical processes absent and the exact prior
    /// runtime owner to have no remaining child. It consumes a new generation.
    pub(crate) fn retry_after_failed(&mut self, journal: &Journal, state: &StoredState,
        runtime: &vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2,
        instance: String, session: String) -> Result<(), ControlError> {
        let record = self.record(journal, state)?;
        if record.phase != RestartPhase::FailedStopped || runtime.active_generation().is_some()
            || runtime.prepared_generation().is_some() || runtime.generation() != record.launch.generation
            || runtime.instance().as_str() != record.launch.instance || runtime.worker_sha256() != journal.identity.worker_digest.as_str()
            || record.process.as_ref().ok_or(ControlError::RecoveryRequired)?.is_present()?
            || record.previous.process.is_present()? { return Err(ControlError::RecoveryRequired); }
        self.publish_event(RestartEvent::Retry { instance, session }, journal, state)
    }
    pub(crate) fn advance(&mut self, event: RestartEvent, journal: &Journal, state: &StoredState) -> Result<(), ControlError> {
        if matches!(event, RestartEvent::FailedAbsent | RestartEvent::Retry { .. } | RestartEvent::Verified(_)) { return Err(ControlError::PermissionDenied); }
        self.publish_event(event, journal, state)
    }
    fn publish_verified(&mut self, health: RestartHealthRecord, journal: &Journal, state: &StoredState) -> Result<(), ControlError> {
        self.publish_event(RestartEvent::Verified(health), journal, state)
    }
    fn publish_event(&mut self, event: RestartEvent, journal: &Journal, state: &StoredState) -> Result<(), ControlError> {
        self.advance_using(event, journal, state, |root, bytes| root.atomic_file(Self::MARKER, Self::PENDING, bytes, MAX_JOURNAL_BYTES, true))
    }
    #[cfg(test)]
    pub(super) fn inject_write_failure(&mut self, event: RestartEvent, journal: &Journal, state: &StoredState) -> Result<(), ControlError> {
        self.advance_using(event, journal, state, |_, _| Err(ControlError::StorageUnavailable))
    }
    fn advance_using<F>(&mut self, event: RestartEvent, journal: &Journal, state: &StoredState, publish: F) -> Result<(), ControlError>
    where F: FnOnce(&vp_product_storage::BoundDirectory, &[u8]) -> Result<(), ControlError> {
        let next = self.record.propose(event, journal, state)?;
        let bytes = next.encode(journal, state)?;
        if let Err(error) = self.unchanged(journal, state) { self.poisoned = true; return Err(error); }
        self.poisoned = true; // before first potentially durable mutation
        publish(&self.root, &bytes)?;
        let file = self.root.inspect_file_read_only(Self::MARKER, MAX_JOURNAL_BYTES)?;
        require(file.bytes() == bytes.as_slice() && self.root.names()? == [Self::MARKER.to_owned()])?;
        RestartRecord::decode(file.bytes(), journal, state)?;
        self.file = file; self.record = next; self.poisoned = false;
        Ok(())
    }
}

/// Private stage-only experiment: a trusted caller must retain the real journal
/// and control writer, re-admit materials against that writer, and supply only
/// the immutable approved recipe/inputs. This never binds a listener, commits a
/// revision, claims health or implements crash recovery. Until composition is
/// complete it is not exposed by a management command or release.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_restart_candidate_inner(
    checkpoints: &mut RestartStore, journal: &Journal, state: &StoredState,
    runtime: &mut vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2,
    recipe: vp_product_compiler::server_v2::ServerRecipeV2,
    inputs: vp_product_core_adapter::managed::server_v2::ServerInputsV2,
    timeout: std::time::Duration, cancel: &vp_product_core_adapter::managed::Cancellation,
    before_transfer: impl FnOnce() -> Result<(), ControlError>,
) -> Result<u64, ControlError> {
    use vp_product_core_adapter::managed::Failure;
    let record = checkpoints.record(journal, state)?.clone();
    require(record.phase == RestartPhase::Reserved)?;
    let observed = pairing::inspect_absent_committed_process(journal, state)?;
    require(observed.next_generation <= record.launch.generation
        && runtime.generation().checked_add(1) == Some(record.launch.generation) && runtime.active_generation().is_none()
        && runtime.prepared_generation().is_none() && runtime.instance().as_str() == record.launch.instance
        && runtime.worker_sha256() == journal.identity.worker_digest.as_str()
        && ContentDigest::bytes(&serde_json::to_vec(&recipe).map_err(|_| ControlError::InvalidConfiguration)?) == record.launch.recipe.recipe_digest)?;
    let expected = record.launch.generation;
    let instance = record.launch.instance.clone();
    let spawned = runtime.prepare_with_spawn_observer(recipe, inputs, record.launch.generation - 1, timeout, cancel, |child| {
        if child.generation != expected || child.instance.as_str() != instance { return Err(Failure::ProtocolViolation); }
        let process = ProcessIdentity::observe(child.pid).map_err(|_| Failure::Io)?;
        checkpoints.advance(RestartEvent::SpawnObserved(process), journal, state).map_err(|_| Failure::Io)?;
        before_transfer().map_err(|_| Failure::Io)
    }).map_err(|_| ControlError::RecoveryRequired)?;
    if checkpoints.advance(RestartEvent::Prepared, journal, state).is_err() {
        let _ = runtime.discard_prepared(spawned.generation);
        return Err(ControlError::RecoveryRequired);
    }
    Ok(spawned.generation)
}

/// Materials remain bound to the same retained control and journal owners.
/// This type contains secret bytes and intentionally has no Debug/Clone/Serialize.
pub(crate) struct RestartMaterials<'a> {
    journal: &'a persistence::JournalPersistence,
    lease: &'a dyn vp_product_control::TlsAssetWriterLease,
    recipe: vp_product_compiler::server_v2::ServerRecipeV2,
    inputs: vp_product_core_adapter::managed::server_v2::ServerInputsV2,
    binding: &'a vp_product_control::InstanceBinding,
    vault: &'a dyn vp_product_control::TlsMaterialVault,
    policy: &'a vp_product_control::TlsBackendPolicy,
    clock: &'a dyn vp_product_control::Clock,
    control_cancel: &'a vp_product_control::CancellationToken,
    deadline: std::time::Instant,
}
/// Resolve only the committed exact artifact after revalidating the private
/// vault, TLS chain, typed credentials and live control writer. No spawn/bind.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_restart_materials<'a>(
    journal: &'a persistence::JournalPersistence,
    lease: &'a dyn vp_product_control::TlsAssetWriterLease,
    binding: &'a vp_product_control::InstanceBinding,
    vault: &'a dyn vp_product_control::TlsMaterialVault,
    policy: &'a vp_product_control::TlsBackendPolicy,
    clock: &'a dyn vp_product_control::Clock,
    deadline: std::time::Instant,
    cancel: &'a vp_product_control::CancellationToken,
    core_cancel: &vp_product_core_adapter::managed::Cancellation,
) -> Result<RestartMaterials<'a>, ControlError> {
    journal.assert_unchanged()?;
    let base = journal.last_acknowledged();
    let aggregate = lease.aggregate();
    if aggregate.binding() != binding || binding.digest()? != base.identity.genesis { return Err(ControlError::ResourceConflict); }
    let observed = pairing::inspect_absent_committed_process(base, aggregate.state())?;
    let bytes = journal.referenced_recipe(&observed.recipe.recipe_digest)?;
    let recipe: vp_product_compiler::server_v2::ServerRecipeV2 = serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
    if recipe.profile != vp_product_compiler::server_v2::ServerProfileV2::PublicExperimentalUncertified { return Err(ControlError::InvalidConfiguration); }
    let compiler = vp_product_compiler::server_v2::ServerCompilerV2::for_public_experiment(recipe.release.clone(), recipe.public_targets.clone().ok_or(ControlError::CorruptState)?).map_err(|_| ControlError::InvalidConfiguration)?;
    let admission = vp_product_control::TlsMaterialAdmission::for_public_committed_restart(lease, vault, policy, clock,
        aggregate.state().version, &observed.recipe.recipe_digest, deadline, cancel)?;
    let resolver = vp_product_server_materials::RegistryMaterialResolverV2::new(admission, &recipe, &compiler).map_err(|_| ControlError::InvalidConfiguration)?;
    let inputs = vp_product_core_adapter::managed::material_port_v2::resolve_materials_v2(&recipe, &resolver, deadline, core_cancel).map_err(|_| ControlError::InvalidConfiguration)?;
    if cancel.is_canceled() || core_cancel.is_canceled() { return Err(ControlError::Canceled); }
    if std::time::Instant::now() >= deadline { return Err(ControlError::PlanExpired); }
    journal.assert_unchanged()?;
    Ok(RestartMaterials { journal, lease, recipe, inputs, binding, vault, policy, clock, control_cancel: cancel, deadline })
}
/// Retains the writer/journal and admission inputs across preparation and
/// activation. This is not a health receipt or an externally runnable service.
pub(crate) struct PreparedRestart<'a> {
    journal: &'a persistence::JournalPersistence,
    lease: &'a dyn vp_product_control::TlsAssetWriterLease,
    binding: &'a vp_product_control::InstanceBinding,
    vault: &'a dyn vp_product_control::TlsMaterialVault,
    policy: &'a vp_product_control::TlsBackendPolicy,
    clock: &'a dyn vp_product_control::Clock,
    control_cancel: &'a vp_product_control::CancellationToken,
    deadline: std::time::Instant,
    generation: u64,
}
/// Stage an admitted committed revision only. The passed journal and writer
/// remain borrowed through spawn and material transfer; activation is separate.
pub(crate) fn prepare_restart_candidate<'a>(
    checkpoints: &mut RestartStore,
    runtime: &mut vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2,
    materials: RestartMaterials<'a>, timeout: std::time::Duration,
    cancel: &vp_product_core_adapter::managed::Cancellation,
) -> Result<PreparedRestart<'a>, ControlError> {
    let RestartMaterials { journal, lease, recipe, inputs, binding, vault, policy, clock, control_cancel, deadline } = materials;
    journal.assert_unchanged()?;
    let base = journal.last_acknowledged();
    let state = lease.aggregate().state();
    let artifact = base.active.as_ref().ok_or(ControlError::ResourceConflict)?.launch.recipe.recipe_digest.clone();
    let generation = prepare_restart_candidate_inner(checkpoints, base, state, runtime, recipe, inputs, timeout, cancel, || {
        journal.assert_unchanged()?;
        if lease.aggregate().binding() != binding { return Err(ControlError::ResourceConflict); }
        let _fresh_admission = vp_product_control::TlsMaterialAdmission::for_public_committed_restart(
            lease, vault, policy, clock, state.version, &artifact, deadline, control_cancel)?;
        journal.assert_unchanged()
    })?;
    Ok(PreparedRestart { journal, lease, binding, vault, policy, clock, control_cancel, deadline, generation })
}
/// A running child retains its writer and journal owners until verification.
/// It is not a health receipt and does not update the control revision.
pub(crate) struct StartedRestart<'a> { prepared: PreparedRestart<'a> }
/// Starts the already owned prepared child only after a durable activation
/// intent and fresh material checks. A successful listener snapshot is NOT
/// forwarding/authentication health; no control commit or release is implied.
#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_restart_candidate<'a>(
    checkpoints: &mut RestartStore,
    runtime: &mut vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2,
    prepared: PreparedRestart<'a>, timeout: std::time::Duration,
    cancel: &vp_product_core_adapter::managed::Cancellation,
) -> Result<StartedRestart<'a>, ControlError> {
    prepared.journal.assert_unchanged()?;
    let base = prepared.journal.last_acknowledged();
    let state = prepared.lease.aggregate().state();
    let record = checkpoints.record(base, state)?.clone();
    if record.phase != RestartPhase::Prepared || record.launch.generation != prepared.generation
        || runtime.prepared_generation() != Some(prepared.generation)
        || runtime.active_generation().is_some() || prepared.lease.aggregate().binding() != prepared.binding {
        return Err(ControlError::RecoveryRequired);
    }
    let process = record.process.as_ref().ok_or(ControlError::RecoveryRequired)?;
    if ProcessIdentity::observe(process.pid)? != *process { return Err(ControlError::RecoveryRequired); }
    let _admission = vp_product_control::TlsMaterialAdmission::for_public_committed_restart(
        prepared.lease, prepared.vault, prepared.policy, prepared.clock, state.version,
        &record.launch.recipe.recipe_digest, prepared.deadline, prepared.control_cancel)?;
    prepared.journal.assert_unchanged()?;
    if prepared.control_cancel.is_canceled() || cancel.is_canceled() { return Err(ControlError::Canceled); }
    if timeout.is_zero() || timeout > std::time::Duration::from_secs(30) { return Err(ControlError::InvalidConfiguration); }
    let remaining = prepared.deadline.checked_duration_since(std::time::Instant::now())
        .filter(|d| !d.is_zero()).ok_or(ControlError::PlanExpired)?.min(timeout);
    checkpoints.advance(RestartEvent::Activate, base, state)?;
    struct StopWatch(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for StopWatch { fn drop(&mut self) { self.0.store(true, std::sync::atomic::Ordering::Release); } }
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watch = stop.clone(); let control = prepared.control_cancel.clone(); let bridge = cancel.clone();
    let result = std::thread::scope(|scope| {
        std::thread::Builder::new().name("vp-restart-cancel".into()).spawn_scoped(scope, move || {
            while !watch.load(std::sync::atomic::Ordering::Acquire) {
                if control.is_canceled() { bridge.cancel(); break; }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }).map_err(|_| ControlError::RecoveryRequired)?;
        let _watch = StopWatch(stop);
        runtime.activate_prepared(prepared.generation, remaining, cancel).map_err(|_| ControlError::RecoveryRequired)
    });
    let snapshot = match result {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if runtime.prepared_generation() == Some(prepared.generation) { let _ = runtime.discard_prepared(prepared.generation); }
            return Err(error);
        }
    };
    if prepared.control_cancel.is_canceled() || cancel.is_canceled() || std::time::Instant::now() >= prepared.deadline {
        let _ = runtime.stop_active(prepared.generation, std::time::Duration::from_secs(2));
        return Err(ControlError::RecoveryRequired);
    }
    if snapshot.generation != prepared.generation || !snapshot.listeners_ready || snapshot.forwarding_verified
        || ProcessIdentity::observe(snapshot.pid)? != *process {
        let _ = runtime.stop_active(prepared.generation, std::time::Duration::from_secs(2));
        return Err(ControlError::RecoveryRequired);
    }
    if checkpoints.advance(RestartEvent::Activated, base, state).is_err() {
        let _ = runtime.stop_active(prepared.generation, std::time::Duration::from_secs(2));
        return Err(ControlError::RecoveryRequired);
    }
    Ok(StartedRestart { prepared })
}

/// Validate a single snapshot plus independently supplied probe outcomes.
/// This helper is not process ownership or network evidence by itself.
#[allow(clippy::too_many_arguments)]
pub(super) fn collect_restart_checks(
    recipe: &vp_product_compiler::server_v2::ServerRecipeV2,
    _inputs: &vp_product_core_adapter::managed::server_v2::ServerInputsV2,
    checks: &std::collections::BTreeSet<vp_product_control::HealthCheck>,
    snapshot: &vp_product_core_adapter::managed::WorkerSnapshot, expected_pid: u32,
    generation: u64, deadline: std::time::Instant,
    control_cancel: &vp_product_control::CancellationToken, core_cancel: &vp_product_core_adapter::managed::Cancellation,
    mut probe_check: impl FnMut(&vp_product_control::HealthCheck) -> Result<vp_product_control::CheckOutcome, ControlError>,
) -> Result<Vec<vp_product_control::CheckResult>, ControlError> {
    use vp_product_control::{CheckOutcome, CheckResult, HealthCheck};
    if snapshot.pid != expected_pid || snapshot.generation != generation || !snapshot.listeners_ready
        || snapshot.task_panics != 0 || snapshot.forwarding_verified || !checks.contains(&HealthCheck::Process) {
        return Err(ControlError::HealthFailed);
    }
    if snapshot.listeners.len() != recipe.listeners.len() || recipe.listeners.iter().any(|listener| {
        snapshot.listeners.iter().filter(|bound| bound.tag == listener.id.as_str()
            && bound.port == listener.bind.port && bound.accept_loop_live).count() != 1
    }) { return Err(ControlError::HealthFailed); }
    let mut results = Vec::new();
    for check in checks {
        if control_cancel.is_canceled() || core_cancel.is_canceled() { return Err(ControlError::Canceled); }
        if std::time::Instant::now() >= deadline { return Err(ControlError::PlanExpired); }
        let outcome = match check {
            HealthCheck::Process => CheckOutcome::Passed,
            HealthCheck::ListenerBound(id) if snapshot.listeners.iter().any(|v| &v.tag == id && v.accept_loop_live) => CheckOutcome::Passed,
            HealthCheck::ListenerBound(_) => CheckOutcome::Failed,
            _ => probe_check(check)?,
        };
        if outcome != CheckOutcome::Passed { return Err(ControlError::HealthFailed); }
        results.push(CheckResult { check: check.clone(), outcome });
    }
    Ok(results)
}

/// An ephemeral new-generation observation, not a persisted control receipt.
/// External connectivity is deliberately not represented as verified here.
pub(crate) struct RestartHealthObservation {
    pub generation: u64,
    pub checked_at_ms: u64,
    pub checks: Vec<vp_product_control::CheckResult>,
}
/// Verify the exact owned process, TLS/credentials and target-observed probes.
/// A failed verification stops only this owned worker and preserves a durable
/// failed checkpoint. Until a separate receipt/promotion is implemented, even
/// success cannot replace the committed runtime record or authorize a release.
pub(crate) fn verify_restart_candidate(
    checkpoints: &mut RestartStore,
    runtime: &mut vp_product_core_adapter::managed::host_v2::ManagedRuntimeV2,
    started: &StartedRestart<'_>, probe: &dyn crate::public_stage::PublicProbe,
    core_cancel: &vp_product_core_adapter::managed::Cancellation,
) -> Result<RestartHealthObservation, ControlError> {
    let p = &started.prepared;
    let base = p.journal.last_acknowledged();
    let state = p.lease.aggregate().state();
    p.journal.assert_unchanged()?;
    let owned = checkpoints.record(base, state)?.clone();
    let process = owned.process.as_ref().ok_or(ControlError::RecoveryRequired)?;
    if owned.phase != RestartPhase::Running || owned.launch.generation != p.generation
        || runtime.active_generation() != Some(p.generation) || runtime.prepared_generation().is_some()
        || ProcessIdentity::observe(process.pid)? != *process { return Err(ControlError::RecoveryRequired); }
    let verify = (|| {
        p.journal.assert_unchanged()?;
        let saved = checkpoints.record(base, state)?;
        let process = saved.process.as_ref().ok_or(ControlError::RecoveryRequired)?;
        if saved.phase != RestartPhase::Running || saved.launch.generation != p.generation
            || runtime.active_generation() != Some(p.generation) || runtime.prepared_generation().is_some()
            || ProcessIdentity::observe(process.pid)? != *process { return Err(ControlError::RecoveryRequired); }
        probe.validate_policy(p.policy)?;
        let bytes = p.journal.referenced_recipe(&saved.launch.recipe.recipe_digest)?;
        let recipe: vp_product_compiler::server_v2::ServerRecipeV2 = serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
        let compiler = vp_product_compiler::server_v2::ServerCompilerV2::for_public_experiment(recipe.release.clone(), recipe.public_targets.clone().ok_or(ControlError::CorruptState)?).map_err(|_| ControlError::InvalidConfiguration)?;
        let admission = vp_product_control::TlsMaterialAdmission::for_public_committed_restart(p.lease, p.vault, p.policy,
            p.clock, state.version, &saved.launch.recipe.recipe_digest, p.deadline, p.control_cancel)?;
        let resolver = vp_product_server_materials::RegistryMaterialResolverV2::new(admission, &recipe, &compiler).map_err(|_| ControlError::InvalidConfiguration)?;
        let inputs = vp_product_core_adapter::managed::material_port_v2::resolve_materials_v2(&recipe, &resolver, p.deadline, core_cancel).map_err(|_| ControlError::InvalidConfiguration)?;
        let checks = vp_product_control::minimum_health_checks(&recipe.source, None)?;
        probe.available(&recipe, &checks)?;
        let snapshot = runtime.snapshot(p.generation).map_err(|_| ControlError::HealthFailed)?;
        let results = collect_restart_checks(&recipe, &inputs, &checks, &snapshot, process.pid,
            p.generation, p.deadline, p.control_cancel, core_cancel,
            |check| probe.check_with_runtime(&recipe, &inputs, check, p.generation, p.deadline, runtime))?;
        let after = runtime.snapshot(p.generation).map_err(|_| ControlError::HealthFailed)?;
        if after.pid != process.pid || !after.listeners_ready || after.task_panics != 0 || after.forwarding_verified
            || ProcessIdentity::observe(after.pid)? != *process { return Err(ControlError::HealthFailed); }
        if p.control_cancel.is_canceled() || core_cancel.is_canceled() { return Err(ControlError::Canceled); }
        let _final_admission = vp_product_control::TlsMaterialAdmission::for_public_committed_restart(p.lease, p.vault, p.policy,
            p.clock, state.version, &saved.launch.recipe.recipe_digest, p.deadline, p.control_cancel)?;
        p.journal.assert_unchanged()?;
        Ok(RestartHealthObservation { generation: p.generation, checked_at_ms: p.clock.now_ms()?, checks: results })
    })();
    match verify {
        Ok(observation) => {
            if p.control_cancel.is_canceled() || core_cancel.is_canceled() || std::time::Instant::now() >= p.deadline {
                if runtime.active_generation() == Some(p.generation) { let _ = runtime.stop_active(p.generation, std::time::Duration::from_secs(2)); }
                checkpoints.confirm_failed_absent(base, state, runtime).map_err(|_| ControlError::RecoveryRequired)?;
                return Err(ControlError::RecoveryRequired);
            }
            let health = RestartHealthRecord { generation: observation.generation, checked_at_ms: observation.checked_at_ms,
                checks: observation.checks.iter().map(|r| r.check.clone()).collect() };
            if checkpoints.publish_verified(health, base, state).is_err() {
                if runtime.active_generation() == Some(p.generation) { let _ = runtime.stop_active(p.generation, std::time::Duration::from_secs(2)); }
                return Err(ControlError::RecoveryRequired);
            }
            Ok(observation)
        }
        Err(error) => {
            if runtime.active_generation() == Some(p.generation) { let _ = runtime.stop_active(p.generation, std::time::Duration::from_secs(2)); }
            checkpoints.confirm_failed_absent(base, state, runtime).map_err(|_| ControlError::RecoveryRequired)?;
            Err(error)
        }
    }
}
