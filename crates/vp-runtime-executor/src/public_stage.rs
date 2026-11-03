//! Experimental first-install coordinator. Health requires a target-observed
//! probe. Upgrade, restart recovery, installation and production readiness are
//! not provided by this module.
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use vp_product_compiler::server_v2::ServerCompilerV2;
use vp_product_control::{ControlError, InstanceBinding, RuntimeStageContext, TlsBackendPolicy, TlsMaterialVault};
use vp_product_core_adapter::managed::{Cancellation, Failure, host_v2::ManagedRuntimeV2};
use crate::server_v2_journal::{Event, OperationRecord, Phase, ProcessIdentity, RecipeIdentity, persistence::JournalPersistence};

struct StopWatcher(Arc<AtomicBool>);
impl Drop for StopWatcher {
    fn drop(&mut self) { self.0.store(true, Ordering::Release); }
}

/// Reconcile only a terminal prior operation while the next one is still
/// queued. Ambiguous or live transitions remain recovery-required.
#[allow(dead_code)]
pub(crate) fn finalize_before_next(
    context: &vp_product_control::RuntimePreStageContext<'_>, binding: &InstanceBinding,
    journal: &mut JournalPersistence,
) -> Result<(), ControlError> {
    if journal.is_poisoned() { return Err(ControlError::RecoveryRequired); }
    let state = journal.last_acknowledged();
    if state.phase == Phase::Idle { return Ok(()); }
    journal.persist_finalization(binding, context.runtime_journal_writer())
}

/// Reserve durably before spawning; record the observed process before material
/// transfer; acknowledge preparation only after the worker confirms it. A failed
/// or ambiguous checkpoint is never replayed blindly or treated as absence.
#[allow(dead_code)] // Internal scaffold: no effectful product composition yet.
pub(crate) fn prepare_candidate(
    context: &RuntimeStageContext<'_>, binding: &InstanceBinding,
    journal: &mut JournalPersistence, runtime: &mut ManagedRuntimeV2,
    vault: &dyn TlsMaterialVault, policy: &TlsBackendPolicy,
    compiler: &ServerCompilerV2, session: &str, deadline: Instant,
) -> Result<u64, ControlError> {
    if context.cancellation().is_canceled() { return Err(ControlError::Canceled); }
    let cancel = Cancellation::default();
    let (recipe, inputs) = vp_product_server_materials::resolve_public_stage(context, vault, policy, compiler, deadline, &cancel)?;
    let bytes = serde_json::to_vec(&recipe).map_err(|_| ControlError::InvalidConfiguration)?;
    let lease = context.runtime_journal_writer();
    let digest = journal.store_staged_recipe(&bytes, context.operation(), binding, lease)?;
    let current = journal.last_acknowledged();
    if current.phase != Phase::Idle || runtime.prepared_generation().is_some()
        || runtime.generation() != current.high_water
        || runtime.active_generation() != current.active.as_ref().map(|o| o.launch.generation) {
        return Err(ControlError::RecoveryRequired);
    }
    let plan = context.plan();
    let high_water = current.high_water;
    let operation = OperationRecord {
        operation: context.operation().clone(), plan_id: plan.body().id.clone(),
        plan_hash: plan.hash().clone(), principal: plan.body().principal.clone(),
        base_revision: plan.body().base_revision,
        candidate: RecipeIdentity { revision_owner_operation: context.operation().clone(),
            revision: plan.body().target_revision,
            config_digest: plan.body().validation.config_digest.clone(),
            release_digest: plan.body().validation.release_digest.clone(), recipe_digest: digest },
        previous: current.active.as_ref().map(|v| v.launch.recipe.clone()), admitted_high_water: high_water,
    };
    let instance = runtime.instance().as_str().to_owned();
    if context.cancellation().is_canceled() { return Err(ControlError::Canceled); }
    let timeout = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(ControlError::PlanExpired)?.min(Duration::from_secs(15));
    journal.persist_event(Event::Begin { operation: Box::new(operation), instance: instance.clone(), session: session.to_owned() }, binding, lease)?;
    // The control token may be cancelled while the synchronous host handshake
    // runs. A bounded watcher bridges it to the worker cancellation token.
    let stop = Arc::new(AtomicBool::new(false));
    let source = context.cancellation().clone();
    let bridge = cancel.clone();
    let watch_stop = stop.clone();
    let expected_generation = high_water.checked_add(1).ok_or(ControlError::CounterExhausted)?;
    let result = std::thread::scope(|scope| {
        std::thread::Builder::new().name("vp-stage-cancel".into()).spawn_scoped(scope, move || {
            while !watch_stop.load(Ordering::Acquire) {
                if source.is_canceled() { bridge.cancel(); break; }
                std::thread::sleep(Duration::from_millis(10));
            }
        }).map_err(|_| ControlError::RecoveryRequired)?;
        let stop_on_drop = StopWatcher(stop.clone());
        let result = runtime.prepare_with_spawn_observer(recipe, inputs, high_water, timeout, &cancel, |spawned| {
            if spawned.instance.as_str() != instance || spawned.generation != expected_generation { return Err(Failure::ProtocolViolation); }
            let observed = ProcessIdentity::observe(spawned.pid).map_err(|_| Failure::Io)?;
            journal.persist_event(Event::SpawnObserved(observed), binding, lease).map_err(|_| Failure::Io)
        });
        drop(stop_on_drop);
        result.map_err(|_| ControlError::RecoveryRequired)
    });
    let spawned = result?;
    if journal.persist_event(Event::Prepared, binding, lease).is_err() {
        let _ = runtime.discard_prepared(spawned.generation);
        return Err(ControlError::RecoveryRequired);
    }
    Ok(spawned.generation)
}

/// Cancel only the candidate belonging to this operation, preserving any old
/// generation. Unknown ownership, ambiguous writes, or a live unowned process
/// fail closed; no PID is signalled from persisted data.
#[allow(dead_code)]
pub(crate) fn cleanup_prepared_candidate(
    context: &vp_product_control::RuntimeCleanupContext<'_>, binding: &InstanceBinding,
    journal: &mut JournalPersistence, runtime: &mut ManagedRuntimeV2,
) -> Result<(), ControlError> {
    if journal.is_poisoned() { return Err(ControlError::RecoveryRequired); }
    let state = journal.last_acknowledged();
    if runtime.active_generation() != state.active.as_ref().map(|a| a.launch.generation) {
        return Err(ControlError::RecoveryRequired);
    }
    if let Some(active) = &state.active {
        if !active.process.is_present()? { return Err(ControlError::RecoveryRequired); }
    }
    if state.phase == Phase::Idle {
        return if runtime.prepared_generation().is_none() { Ok(()) } else { Err(ControlError::RecoveryRequired) };
    }
    if state.operation.as_ref().is_none_or(|o| &o.operation != context.operation()) {
        return Err(ControlError::RecoveryRequired);
    }
    let lease = context.runtime_journal_writer();
    match state.phase {
        Phase::CandidateSpawnObserved => {
            let process = &state.launch_intent.as_ref().and_then(|i| i.process.as_ref()).ok_or(ControlError::RecoveryRequired)?;
            if runtime.prepared_generation().is_some() || process.is_present()? { return Err(ControlError::RecoveryRequired); }
            journal.persist_event(Event::FailedChildAbsent, binding, lease)?;
        }
        Phase::Prepared => {
            let prepared = state.prepared.as_ref().ok_or(ControlError::RecoveryRequired)?;
            let generation = prepared.launch.generation;
            let process = prepared.process.clone();
            if runtime.prepared_generation() != Some(generation) || !process.is_present()? { return Err(ControlError::RecoveryRequired); }
            journal.persist_event(Event::Discard, binding, lease)?;
            runtime.discard_prepared(generation).map_err(|_| ControlError::RecoveryRequired)?;
            if process.is_present()? { return Err(ControlError::RecoveryRequired); }
            journal.persist_event(Event::Discarded, binding, lease)?;
        }
        Phase::CandidateAbsent => {
            if runtime.prepared_generation().is_some() { return Err(ControlError::RecoveryRequired); }
        }
        _ => return Err(ControlError::RecoveryRequired),
    }
    let active = journal.last_acknowledged().active.as_ref();
    if runtime.active_generation() != active.map(|a| a.launch.generation)
        || active.is_some_and(|a| !a.process.is_present().unwrap_or(false)) {
        return Err(ControlError::RecoveryRequired);
    }
    Ok(())
}

/// First-install activation scaffold only. Existing active generations are
/// rejected until controlled restart and rollback are implemented. A listener
/// snapshot is not forwarding or authentication health evidence.
#[allow(dead_code)]
pub(crate) fn activate_first_candidate(
    context: &vp_product_control::RuntimeActivationContext<'_>, binding: &InstanceBinding,
    journal: &mut JournalPersistence, runtime: &mut ManagedRuntimeV2,
    vault: &dyn TlsMaterialVault, policy: &TlsBackendPolicy,
    compiler: &ServerCompilerV2, deadline: Instant,
) -> Result<vp_product_control::RuntimeActivation, ControlError> {
    if context.previous().is_some() || journal.last_acknowledged().active.is_some() {
        return Err(ControlError::ExecutorUnavailable);
    }
    let current = journal.last_acknowledged();
    let prepared = current.prepared.as_ref().ok_or(ControlError::RecoveryRequired)?;
    let generation = prepared.launch.generation;
    if current.phase != Phase::Prepared || runtime.prepared_generation() != Some(generation)
        || prepared.launch.transition_operation != *context.operation()
        || ProcessIdentity::observe(prepared.process.pid)? != prepared.process {
        return Err(ControlError::RecoveryRequired);
    }
    let plan = context.plan();
    let recipe = compiler.compile(&plan.body().config, &plan.body().release).map_err(|_| ControlError::InvalidConfiguration)?;
    let admission = context.experimental_public_materials(vault, policy, deadline)?;
    let resolver = vp_product_server_materials::RegistryMaterialResolverV2::new(admission, &recipe, compiler).map_err(|_| ControlError::InvalidConfiguration)?;
    // Revalidate all immutable materials at activation, not just at staging.
    let validated = vp_product_core_adapter::managed::material_port_v2::resolve_materials_v2(&recipe, &resolver, deadline, &Cancellation::default()).map_err(|_| ControlError::InvalidConfiguration)?;
    drop(validated);
    let timeout = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(ControlError::PlanExpired)?.min(Duration::from_secs(15));
    let lease = context.runtime_journal_writer();
    journal.persist_event(Event::Activate, binding, lease)?;
    let snapshot = runtime.activate_prepared(generation, timeout, &Cancellation::default()).map_err(|_| ControlError::RecoveryRequired)?;
    if snapshot.generation != generation || !snapshot.listeners_ready || snapshot.forwarding_verified
        || ProcessIdentity::observe(snapshot.pid)? != journal.last_acknowledged().prepared.as_ref().ok_or(ControlError::RecoveryRequired)?.process {
        return Err(ControlError::RecoveryRequired);
    }
    journal.persist_event(Event::Activated, binding, lease).map_err(|_| ControlError::RecoveryRequired)?;
    Ok(vp_product_control::RuntimeActivation { revision: plan.body().target_revision, operation_id: context.operation().clone(), config_digest: plan.body().validation.config_digest.clone(), release_digest: plan.body().validation.release_digest.clone(), generation })
}

/// Trusted local probe implementation must perform actual protocol exchanges.
/// No implementation is provided by default, so a product cannot claim health
/// by translating a bound socket or a stored receipt into a passing result.
#[allow(dead_code)]
pub(crate) trait PublicProbe: Send + Sync {
    fn validate_policy(&self, policy: &TlsBackendPolicy) -> Result<(), ControlError>;
    fn available(&self, recipe: &vp_product_compiler::server_v2::ServerRecipeV2,
        checks: &std::collections::BTreeSet<vp_product_control::HealthCheck>) -> Result<(), ControlError>;
    fn check(&self, recipe: &vp_product_compiler::server_v2::ServerRecipeV2,
        inputs: &vp_product_core_adapter::managed::server_v2::ServerInputsV2,
        check: &vp_product_control::HealthCheck, generation: u64,
        deadline: Instant) -> Result<vp_product_control::CheckOutcome, ControlError>;
    fn check_with_runtime(&self, recipe: &vp_product_compiler::server_v2::ServerRecipeV2,
        inputs: &vp_product_core_adapter::managed::server_v2::ServerInputsV2,
        check: &vp_product_control::HealthCheck, generation: u64, deadline: Instant,
        _runtime: &mut ManagedRuntimeV2) -> Result<vp_product_control::CheckOutcome, ControlError> {
        self.check(recipe, inputs, check, generation, deadline)
    }
}

/// Verify fresh exact-generation observations and demand actual probe evidence
/// for forwarding, authentication and security identity. No public probe has
/// yet been certified or wired to a production constructor.
#[allow(dead_code)]
pub(crate) fn verify_candidate(
    context: &vp_product_control::RuntimeVerificationContext<'_>,
    journal: &JournalPersistence, runtime: &mut ManagedRuntimeV2,
    vault: &dyn TlsMaterialVault, policy: &TlsBackendPolicy,
    compiler: &ServerCompilerV2, probe: &dyn PublicProbe, deadline: Instant,
) -> Result<vp_product_control::RuntimeHealth, ControlError> {
    use vp_product_control::{CheckOutcome, CheckResult, HealthCheck};
    if journal.is_poisoned() { return Err(ControlError::RecoveryRequired); }
    let saved = journal.last_acknowledged();
    let active = saved.active.as_ref().ok_or(ControlError::HealthFailed)?;
    let activation = context.activation();
    if saved.phase != Phase::CandidateStarted
        || saved.operation.as_ref().is_none_or(|o| &o.operation != context.operation())
        || active.launch.generation != activation.generation
        || active.launch.recipe.config_digest != activation.config_digest
        || active.launch.recipe.release_digest != activation.release_digest
        || runtime.active_generation() != Some(activation.generation)
        || ProcessIdentity::observe(active.process.pid)? != active.process {
        return Err(ControlError::HealthFailed);
    }
    let plan = context.plan();
    let recipe = compiler.compile(&plan.body().config, &plan.body().release).map_err(|_| ControlError::InvalidConfiguration)?;
    let admission = context.experimental_public_materials(vault, policy, deadline)?;
    let resolver = vp_product_server_materials::RegistryMaterialResolverV2::new(admission, &recipe, compiler).map_err(|_| ControlError::InvalidConfiguration)?;
    let inputs = vp_product_core_adapter::managed::material_port_v2::resolve_materials_v2(&recipe, &resolver, deadline, &Cancellation::default()).map_err(|_| ControlError::InvalidConfiguration)?;
    probe.available(&recipe, &plan.body().validation.required_health)?;
    let snapshot = runtime.snapshot(activation.generation).map_err(|_| ControlError::HealthFailed)?;
    if snapshot.pid != active.process.pid || !snapshot.listeners_ready || snapshot.task_panics != 0 || snapshot.forwarding_verified {
        return Err(ControlError::HealthFailed);
    }
    let mut checks = Vec::new();
    for check in &plan.body().validation.required_health {
        if Instant::now() >= deadline { return Err(ControlError::PlanExpired); }
        let outcome = match check {
            HealthCheck::Process => CheckOutcome::Passed,
            HealthCheck::ListenerBound(id) if snapshot.listeners.iter().any(|l| &l.tag == id && l.accept_loop_live) => CheckOutcome::Passed,
            HealthCheck::ListenerBound(_) => CheckOutcome::Failed,
            _ => probe.check_with_runtime(&recipe, &inputs, check, activation.generation, deadline, runtime)?,
        };
        if !matches!(outcome, CheckOutcome::Passed) { return Err(ControlError::HealthFailed); }
        checks.push(CheckResult { check: check.clone(), outcome });
    }
    drop(inputs);
    let after = runtime.snapshot(activation.generation).map_err(|_| ControlError::HealthFailed)?;
    if after.pid != active.process.pid || !after.listeners_ready || after.task_panics != 0
        || ProcessIdentity::observe(active.process.pid)? != active.process { return Err(ControlError::HealthFailed); }
    Ok(vp_product_control::RuntimeHealth { revision: activation.revision, operation_id: activation.operation_id.clone(),
        config_digest: activation.config_digest.clone(), release_digest: activation.release_digest.clone(),
        generation: activation.generation, checked_at_ms: context.now_ms()?, checks, external_connectivity: CheckOutcome::NotChecked })
}

/// Only the first-install failed-activation case: confirm the exact prepared
/// child has exited. No PID is ever signalled or adopted here.
#[allow(dead_code)]
pub(crate) fn observe_failed_first_candidate(
    operation: &vp_product_domain::OperationId, journal: &JournalPersistence, runtime: &ManagedRuntimeV2,
) -> Result<(), ControlError> {
    let state = journal.last_acknowledged();
    if state.phase != Phase::ActivatingCandidate || state.active.is_some()
        || state.operation.as_ref().is_none_or(|o| &o.operation != operation || o.previous.is_some())
        || runtime.active_generation().is_some() || runtime.prepared_generation().is_some() {
        return Err(ControlError::RecoveryRequired);
    }
    let process = &state.prepared.as_ref().ok_or(ControlError::RecoveryRequired)?.process;
    if process.is_present()? { return Err(ControlError::RecoveryRequired); }
    Ok(())
}

/// Stop only the exact first-install candidate under a durable rollback intent.
/// Uncertain in-flight effects are never guessed or retried automatically.
#[allow(dead_code)]
pub(crate) fn stop_first_candidate(
    context: &vp_product_control::RuntimeRestoreContext<'_>, binding: &InstanceBinding,
    journal: &mut JournalPersistence, runtime: &mut ManagedRuntimeV2,
) -> Result<(), ControlError> {
    if context.previous().is_some() || journal.is_poisoned()
        || journal.last_acknowledged().operation.as_ref().is_none_or(|o| &o.operation != context.operation() || o.previous.is_some()) {
        return Err(ControlError::RecoveryRequired);
    }
    let lease = context.runtime_journal_writer();
    match journal.last_acknowledged().phase {
        Phase::ActivatingCandidate => observe_failed_first_candidate(context.operation(), journal, runtime),
        Phase::Prepared => {
            let prepared = journal.last_acknowledged().prepared.as_ref().ok_or(ControlError::RecoveryRequired)?;
            let process = prepared.process.clone(); let generation = prepared.launch.generation;
            if runtime.active_generation().is_some() || runtime.prepared_generation() != Some(generation) || !process.is_present()? { return Err(ControlError::RecoveryRequired); }
            journal.persist_event(Event::Discard, binding, lease)?;
            runtime.discard_prepared(generation).map_err(|_| ControlError::RecoveryRequired)?;
            if process.is_present()? { return Err(ControlError::RecoveryRequired); }
            journal.persist_event(Event::Discarded, binding, lease)
        }
        Phase::CandidateStarted => {
            let active = journal.last_acknowledged().active.as_ref().ok_or(ControlError::RecoveryRequired)?;
            let process = active.process.clone(); let generation = active.launch.generation;
            if runtime.prepared_generation().is_some() || runtime.active_generation() != Some(generation) || !process.is_present()? { return Err(ControlError::RecoveryRequired); }
            journal.persist_event(Event::StopCandidate, binding, lease)?;
            let report = runtime.stop_active(generation, Duration::from_secs(2)).map_err(|_| ControlError::RecoveryRequired)?;
            if !report.process_exited || report.remaining_tasks != 0 || process.is_present()? { return Err(ControlError::RecoveryRequired); }
            journal.persist_event(Event::CandidateStopped, binding, lease)
        }
        Phase::CandidateAbsent => {
            if runtime.active_generation().is_none() && runtime.prepared_generation().is_none() { Ok(()) } else { Err(ControlError::RecoveryRequired) }
        }
        _ => Err(ControlError::RecoveryRequired),
    }
}

/// After resources were restored, durably record the observed absence and the
/// pre-install stopped state. Caller still verifies it and finalizes control.
#[allow(dead_code)]
pub(crate) fn restore_first_stopped(
    context: &vp_product_control::RuntimeRestoreContext<'_>, binding: &InstanceBinding,
    journal: &mut JournalPersistence, runtime: &ManagedRuntimeV2,
) -> Result<(), ControlError> {
    if context.previous().is_some() { return Err(ControlError::ExecutorUnavailable); }
    if journal.last_acknowledged().operation.as_ref().is_none_or(|o| &o.operation != context.operation() || o.previous.is_some())
        || runtime.active_generation().is_some() || runtime.prepared_generation().is_some() {
        return Err(ControlError::RecoveryRequired);
    }
    let lease = context.runtime_journal_writer();
    match journal.last_acknowledged().phase {
        Phase::ActivatingCandidate => {
            observe_failed_first_candidate(context.operation(), journal, runtime)?;
            journal.persist_event(Event::FailedChildAbsent, binding, lease)?;
        }
        Phase::CandidateAbsent => {},
        Phase::Restored => return Ok(()),
        _ => return Err(ControlError::RecoveryRequired),
    }
    if runtime.active_generation().is_some() || runtime.prepared_generation().is_some() { return Err(ControlError::RecoveryRequired); }
    journal.persist_event(Event::RestoreStopped, binding, lease)
}

/// First-install experimental composition; not registered in managementd and
/// cannot be constructed without a trusted concrete probe and admitted journal.
/// Upgrades, crash adoption, installer integration and real probes remain absent.
struct PublicInner { journal: JournalPersistence, runtime: ManagedRuntimeV2 }
#[allow(dead_code)]
pub(crate) struct ExperimentalPublicExecutor {
    inner: std::sync::Mutex<PublicInner>, binding: InstanceBinding,
    vault: Arc<dyn TlsMaterialVault>, policy: TlsBackendPolicy,
    compiler: ServerCompilerV2, probe: Arc<dyn PublicProbe>, session: String,
}
#[allow(dead_code)]
impl ExperimentalPublicExecutor {
    pub(crate) fn new(journal: JournalPersistence, runtime: ManagedRuntimeV2, binding: InstanceBinding,
        vault: Arc<dyn TlsMaterialVault>, policy: TlsBackendPolicy, compiler: ServerCompilerV2,
        probe: Arc<dyn PublicProbe>, session: String) -> Result<Self, ControlError> {
        binding.validate_tls_profile()?;
        if vault.material_binding(Instant::now()+Duration::from_secs(10))? != binding { return Err(ControlError::ResourceConflict); }
        probe.validate_policy(&policy)?;
        if session.is_empty() || session.len() > 64 || !session.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || binding.digest()? != journal.last_acknowledged().identity.genesis
            || runtime.worker_sha256() != journal.last_acknowledged().identity.worker_digest.as_str()
            || journal.is_poisoned() || journal.last_acknowledged().phase != Phase::Idle
            || runtime.generation() != journal.last_acknowledged().high_water
            || runtime.active_generation().is_some() || runtime.prepared_generation().is_some()
            || journal.last_acknowledged().active.is_some() { return Err(ControlError::RecoveryRequired); }
        Ok(Self { inner: std::sync::Mutex::new(PublicInner { journal, runtime }), binding, vault, policy, compiler, probe, session })
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, PublicInner>, ControlError> {
        self.inner.try_lock().map_err(|_| ControlError::RecoveryRequired)
    }
}
impl vp_product_control::RuntimeExecutor for ExperimentalPublicExecutor {
    fn validate_with_context(&self, context: vp_product_control::RuntimePlanContext<'_>) -> Result<vp_product_control::ValidationReceipt, ControlError> {
        if context.previous().is_some() { return Err(ControlError::ExecutorUnavailable); }
        let recipe = self.compiler.compile(context.config(), context.release()).map_err(|_| ControlError::InvalidConfiguration)?;
        if recipe.profile != vp_product_compiler::server_v2::ServerProfileV2::PublicExperimentalUncertified { return Err(ControlError::InvalidConfiguration); }
        let required_health = vp_product_control::minimum_health_checks(context.config(), None)?;
        self.probe.available(&recipe, &required_health)?;
        let digest = vp_product_server_materials::public_recipe_digest(&recipe).map_err(|_| ControlError::InvalidConfiguration)?;
        context.validate_public_materials(self.vault.as_ref(), &self.policy, &digest, Instant::now()+Duration::from_secs(10))?;
        Ok(vp_product_control::ValidationReceipt { config_digest: vp_product_control::ContentDigest::of("vp.product-config.v1", context.config())?,
            release_digest: vp_product_control::ContentDigest::of("vp.release-identity.v1", context.release())?, artifact_digest: digest,
            impact: vp_product_control::RestartImpact::ControlledRestart, required_health })
    }
    fn validate(&self, _: &vp_product_domain::ProductConfig, _: &vp_product_domain::ReleaseIdentity, _: Option<&vp_product_control::RevisionRecord>) -> Result<vp_product_control::ValidationReceipt, ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn reconcile_before_stage(&self, context: vp_product_control::RuntimePreStageContext<'_>) -> Result<(), ControlError> {
        finalize_before_next(&context, &self.binding, &mut self.lock()?.journal)
    }
    fn stage_with_context(&self, context: RuntimeStageContext<'_>) -> Result<(), ControlError> {
        let mut inner = self.lock()?; let PublicInner { journal, runtime } = &mut *inner;
        prepare_candidate(&context, &self.binding, journal, runtime, self.vault.as_ref(), &self.policy, &self.compiler, &self.session, Instant::now()+Duration::from_secs(10))?;
        Ok(())
    }
    fn discard_with_context(&self, context: vp_product_control::RuntimeCleanupContext<'_>) -> Result<(), ControlError> {
        let mut inner = self.lock()?; let PublicInner { journal, runtime } = &mut *inner;
        cleanup_prepared_candidate(&context, &self.binding, journal, runtime)
    }
    fn activate_with_context(&self, context: vp_product_control::RuntimeActivationContext<'_>) -> Result<vp_product_control::RuntimeActivation, ControlError> {
        let mut inner = self.lock()?; let PublicInner { journal, runtime } = &mut *inner;
        activate_first_candidate(&context, &self.binding, journal, runtime, self.vault.as_ref(), &self.policy, &self.compiler, Instant::now()+Duration::from_secs(10))
    }
    fn verify_with_context(&self, context: vp_product_control::RuntimeVerificationContext<'_>) -> Result<vp_product_control::RuntimeHealth, ControlError> {
        let mut inner = self.lock()?; let PublicInner { journal, runtime } = &mut *inner;
        verify_candidate(&context, journal, runtime, self.vault.as_ref(), &self.policy, &self.compiler, self.probe.as_ref(), Instant::now()+Duration::from_secs(60))
    }
    fn stop_candidate_with_context(&self, context: vp_product_control::RuntimeRestoreContext<'_>) -> Result<(), ControlError> {
        let mut inner = self.lock()?; let PublicInner { journal, runtime } = &mut *inner;
        stop_first_candidate(&context, &self.binding, journal, runtime)
    }
    fn restore_previous_with_context(&self, context: vp_product_control::RuntimeRestoreContext<'_>) -> Result<(), ControlError> {
        let mut inner = self.lock()?; let PublicInner { journal, runtime } = &mut *inner;
        restore_first_stopped(&context, &self.binding, journal, runtime)
    }
    fn verify_previous(&self, operation: &vp_product_domain::OperationId, previous: Option<&vp_product_control::RevisionRecord>) -> Result<(), ControlError> {
        let inner = self.lock()?;
        let state = inner.journal.last_acknowledged();
        if previous.is_some() || state.phase != Phase::Restored || state.active.is_some() || state.prepared.is_some()
            || state.operation.as_ref().is_none_or(|o| &o.operation != operation || o.previous.is_some())
            || inner.runtime.active_generation().is_some() || inner.runtime.prepared_generation().is_some() { return Err(ControlError::RecoveryRequired); }
        Ok(())
    }
    fn discard_stage(&self, operation: &vp_product_domain::OperationId) -> Result<(), ControlError> {
        let inner = self.lock()?; let state = inner.journal.last_acknowledged();
        if state.phase == Phase::Restored && state.operation.as_ref().is_some_and(|o| &o.operation == operation)
            && inner.runtime.active_generation().is_none() && inner.runtime.prepared_generation().is_none() { Ok(()) } else { Err(ControlError::RecoveryRequired) }
    }
    fn stage(&self, _: &vp_product_domain::OperationId, _: &vp_product_control::ChangePlan, _: &vp_product_control::CancellationToken) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn activate(&self, _: &vp_product_domain::OperationId, _: &vp_product_control::ChangePlan, _: Option<&vp_product_control::RevisionRecord>) -> Result<vp_product_control::RuntimeActivation, ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn verify(&self, _: &vp_product_domain::OperationId, _: &vp_product_control::ChangePlan) -> Result<vp_product_control::RuntimeHealth, ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn stop_candidate(&self, _: &vp_product_domain::OperationId, _: &vp_product_control::ChangePlan) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
    fn restore_previous(&self, _: &vp_product_domain::OperationId, _: Option<&vp_product_control::RevisionRecord>) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, sync::{Mutex, MutexGuard}, os::unix::fs::PermissionsExt};
    use sha2::{Digest, Sha256};
    use vp_product_control::*;
    use vp_product_domain::*;
    use vp_product_core_adapter::managed::{VerifiedWorker, protocol_v2::WorkerInstanceV2};
    use vp_product_storage::{BoundDirectory, DirectoryIdentity};
    use crate::server_v2_journal::{self as journal, persistence::FreshJournalInspection};

    struct Store(Mutex<TlsControlEnvelope>);
    struct Lease<'a>(MutexGuard<'a, TlsControlEnvelope>);
    impl WriterLease for Lease<'_> {
        fn state(&self) -> &StoredState { self.0.state() }
        fn tls_aggregate(&self) -> Option<&TlsControlEnvelope> { Some(&self.0) }
        fn persist(&mut self, next: StoredState, _: JournalEvent) -> Result<(), ControlError> {
            *self.0 = self.0.with_ordinary_state(next)?; Ok(())
        }
    }
    impl ControlStore for Store {
        fn read(&self) -> Result<StoredState, ControlError> { Ok(self.0.lock().unwrap().state().clone()) }
        fn writer(&self) -> Result<Box<dyn WriterLease + '_>, ControlError> { Ok(Box::new(Lease(self.0.lock().unwrap()))) }
    }
    struct Vault { binding: InstanceBinding, credential: SecretRef }
    impl TlsMaterialVault for Vault {
        fn material_binding(&self, _: Instant) -> Result<InstanceBinding, ControlError> { Ok(self.binding.clone()) }
        fn read_tls_material(&self, _: &SecretRef, _: Instant) -> Result<Option<TlsRawRecord>, ControlError> { Ok(None) }
        fn read_credential_material(&self, reference: &SecretRef, _: Instant) -> Result<Option<TlsRawRecord>, ControlError> {
            if reference != &self.credential { return Ok(None); }
            use vp_product_domain::experimental_credential_frame::{encode, CredentialFrameKind};
            Ok(Some(TlsRawRecord { reference: reference.clone(), kind: 1, version: 1,
                bytes: encode(CredentialFrameKind::ShadowsocksAes128Gcm, b"synthetic-test-password").unwrap() }))
        }
    }
    struct EmptySystem;
    impl SystemExecutor for EmptySystem {
        fn inspect(&self, r: &[ResourceChange]) -> Result<Vec<ResourceObservation>, ControlError> { if r.is_empty() { Ok(vec![]) } else { Err(ControlError::ExecutorUnavailable) } }
        fn capture(&self, _: &OperationId, r: &[ResourceChange]) -> Result<ResourceSnapshot, ControlError> { if r.is_empty() { Ok(ResourceSnapshot { id: "no-host-changes".into(), resources: vec![] }) } else { Err(ControlError::ExecutorUnavailable) } }
        fn apply(&self, _: &OperationId, _: &ChangePlan, _: &ResourceSnapshot) -> Result<(), ControlError> { Ok(()) }
        fn restore(&self, _: &OperationId, _: &ChangePlan, _: &ResourceSnapshot) -> Result<(), ControlError> { Ok(()) }
    }
    struct NoProbe;
    impl PublicProbe for NoProbe {
        fn validate_policy(&self, _: &TlsBackendPolicy) -> Result<(), ControlError> { Ok(()) }
        fn available(&self, _: &vp_product_compiler::server_v2::ServerRecipeV2, _: &std::collections::BTreeSet<HealthCheck>) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
        fn check(&self, _: &vp_product_compiler::server_v2::ServerRecipeV2, _: &vp_product_core_adapter::managed::server_v2::ServerInputsV2, _: &HealthCheck, _: u64, _: Instant) -> Result<CheckOutcome, ControlError> { Err(ControlError::ExecutorUnavailable) }
    }
    struct ProbeNeverPass;
    impl PublicProbe for ProbeNeverPass {
        fn validate_policy(&self, _: &TlsBackendPolicy) -> Result<(), ControlError> { Ok(()) }
        fn available(&self, _: &vp_product_compiler::server_v2::ServerRecipeV2, _: &std::collections::BTreeSet<HealthCheck>) -> Result<(), ControlError> { Ok(()) }
        fn check(&self, _: &vp_product_compiler::server_v2::ServerRecipeV2, _: &vp_product_core_adapter::managed::server_v2::ServerInputsV2, _: &HealthCheck, _: u64, _: Instant) -> Result<CheckOutcome, ControlError> { Err(ControlError::HealthFailed) }
    }
    struct StageRuntime { journal: Mutex<JournalPersistence>, worker: Mutex<ManagedRuntimeV2>, binding: InstanceBinding, vault: Vault, policy: TlsBackendPolicy, mode: u8 }
    impl RuntimeExecutor for StageRuntime {
        fn validate_with_context(&self, c: RuntimePlanContext<'_>) -> Result<ValidationReceipt, ControlError> {
            let receipt = self.validate(c.config(), c.release(), c.previous())?;
            c.validate_public_materials(&self.vault, &self.policy, &receipt.artifact_digest, Instant::now()+Duration::from_secs(10))?;
            Ok(receipt)
        }
        fn reconcile_before_stage(&self, c: vp_product_control::RuntimePreStageContext<'_>) -> Result<(), ControlError> { finalize_before_next(&c, &self.binding, &mut self.journal.lock().unwrap()) }
        fn discard_with_context(&self, c: vp_product_control::RuntimeCleanupContext<'_>) -> Result<(), ControlError> { cleanup_prepared_candidate(&c, &self.binding, &mut self.journal.lock().unwrap(), &mut self.worker.lock().unwrap()) }
        fn validate(&self, c: &ProductConfig, r: &ReleaseIdentity, old: Option<&RevisionRecord>) -> Result<ValidationReceipt, ControlError> {
            let compiler = ServerCompilerV2::for_public_experiment(r.clone(), vec!["8.8.8.8:443".parse().unwrap()]).map_err(|_| ControlError::InvalidConfiguration)?;
            let recipe = compiler.compile(c,r).map_err(|_| ControlError::InvalidConfiguration)?;
            Ok(ValidationReceipt { config_digest: ContentDigest::of("vp.product-config.v1",c)?, release_digest: ContentDigest::of("vp.release-identity.v1",r)?, artifact_digest: vp_product_server_materials::public_recipe_digest(&recipe).map_err(|_| ControlError::InvalidConfiguration)?, impact: RestartImpact::ControlledRestart, required_health: minimum_health_checks(c,old)? })
        }
        fn stage_with_context(&self, c: RuntimeStageContext<'_>) -> Result<(), ControlError> {
            let compiler = ServerCompilerV2::for_public_experiment(c.plan().body().release.clone(), vec!["8.8.8.8:443".parse().unwrap()]).map_err(|_| ControlError::InvalidConfiguration)?;
            let generation = prepare_candidate(&c, &self.binding, &mut self.journal.lock().unwrap(), &mut self.worker.lock().unwrap(), &self.vault, &self.policy, &compiler, "test-session", Instant::now()+Duration::from_secs(10))?;
            assert!(generation >= 1);
            {
                let journal = self.journal.lock().unwrap();
                let saved = journal.last_acknowledged().prepared.as_ref().unwrap();
                assert_eq!(saved.launch.generation, generation);
                assert!(saved.process.pid > 0 && !saved.process.start_ticks.is_empty());
            }
            if self.mode == 2 { c.cancellation().cancel(); }
            if self.mode == 0 { Err(ControlError::ExecutorFailed) } else { Ok(()) }
        }
        fn activate_with_context(&self, c: vp_product_control::RuntimeActivationContext<'_>) -> Result<RuntimeActivation, ControlError> {
            let compiler = ServerCompilerV2::for_public_experiment(c.plan().body().release.clone(), vec!["8.8.8.8:443".parse().unwrap()]).map_err(|_| ControlError::InvalidConfiguration)?;
            activate_first_candidate(&c, &self.binding, &mut self.journal.lock().unwrap(), &mut self.worker.lock().unwrap(), &self.vault, &self.policy, &compiler, Instant::now()+Duration::from_secs(10))
        }
        fn stage(&self, _: &OperationId, _: &ChangePlan, _: &CancellationToken) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
        fn activate(&self, _: &OperationId, _: &ChangePlan, _: Option<&RevisionRecord>) -> Result<RuntimeActivation, ControlError> { Err(ControlError::ExecutorUnavailable) }
        fn verify(&self, _: &OperationId, _: &ChangePlan) -> Result<vp_product_control::RuntimeHealth, ControlError> { Err(ControlError::ExecutorUnavailable) }
        fn stop_candidate_with_context(&self, c: vp_product_control::RuntimeRestoreContext<'_>) -> Result<(), ControlError> { stop_first_candidate(&c, &self.binding, &mut self.journal.lock().unwrap(), &mut self.worker.lock().unwrap()) }
        fn stop_candidate(&self, _: &OperationId, _: &ChangePlan) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
        fn restore_previous_with_context(&self, c: vp_product_control::RuntimeRestoreContext<'_>) -> Result<(), ControlError> { restore_first_stopped(&c, &self.binding, &mut self.journal.lock().unwrap(), &self.worker.lock().unwrap()) }
        fn restore_previous(&self, _: &OperationId, _: Option<&RevisionRecord>) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
        fn verify_previous(&self, _: &OperationId, previous: Option<&RevisionRecord>) -> Result<(), ControlError> { if previous.is_none() && self.journal.lock().unwrap().last_acknowledged().phase == Phase::Restored && self.worker.lock().unwrap().active_generation().is_none() { Ok(()) } else { Err(ControlError::RecoveryRequired) } }
        fn discard_stage(&self, _: &OperationId) -> Result<(), ControlError> { if self.journal.lock().unwrap().last_acknowledged().phase == Phase::Restored { Ok(()) } else { Err(ControlError::RecoveryRequired) } }
    }
    fn run_worker_case(mode: u8) {
        let activate = mode == 1;
        let release = vp_product_core_adapter::inspect_build().unwrap().build.release;
        let worker_path = std::path::PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap()).join("debug/vp-core-server-worker-v2");
        let worker_bytes = std::fs::read(&worker_path).unwrap();
        let worker_hash = format!("{:x}", Sha256::digest(worker_bytes));
        let worker = VerifiedWorker::for_server_v2(&worker_path, &worker_hash, Instant::now()+Duration::from_secs(10), &Cancellation::default()).unwrap();
        let d = ContentDigest::bytes(b"synthetic-genesis");
        let binding = InstanceBinding { binding_version: 1, genesis_id: "a".repeat(32), vault_id: "b".repeat(32), namespace_digest: d.clone(), administrator_commitment: d.clone(), preparation_digest: d.clone(), activation_intent_digest: d.clone(), artifact_set_digest: d, profile: FRESH_TLS_RUNTIME_PROFILE.into() };
        let mut envelope = TlsControlEnvelope::preparing(binding.clone()).unwrap();
        envelope.mark_initialized().unwrap();
        let credential = SecretRef::new("test-secret").unwrap();
        let principal = UserId::new("test-user").unwrap();
        let credential_id = CredentialId::new("test-credential").unwrap();
        let mut state = envelope.state().clone();
        state.secrets.credentials.insert(credential_id.clone(), CredentialRecord { principal: principal.clone(), vault_version: 1, summary: CredentialSummary { schema_version: 1, id: credential_id, revision: Revision::ZERO.next().unwrap(), secret_ref: credential.clone(), kind: NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm }, created_at: 1, state: CredentialState::Available, display_key: CredentialDisplayKey::Managed } });
        state.version += 1;
        envelope = envelope.with_ordinary_state(state).unwrap();
        let store = Arc::new(Store(Mutex::new(envelope)));
        let root = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
        let directory = BoundDirectory::admit(root.path(), DirectoryIdentity::of(&File::open(root.path()).unwrap()).unwrap()).unwrap();
        let identity = journal::Identity { schema_version: journal::SCHEMA, profile: journal::PROFILE.into(), genesis: binding.digest().unwrap(), release_digest: ContentDigest::of("vp.release-identity.v1", &release).unwrap(), core_digest: journal::core_digest(&release).unwrap(), worker_digest: ContentDigest::parse(worker_hash).unwrap(), recipe_version: 2, worker_protocol_version: 3 };
        let fresh = FreshJournalInspection::inspect_empty(directory, identity).unwrap();
        let inspection = fresh.initialize(&TlsControlEnvelope::preparing(binding.clone()).unwrap()).map_err(|e| e.error().clone()).unwrap();
        if mode == 5 || mode == 6 {
            drop(inspection);
            let before = std::fs::read(root.path().join("runtime.journal.json")).unwrap();
            let root2 = BoundDirectory::admit(root.path(), DirectoryIdentity::of(&File::open(root.path()).unwrap()).unwrap()).unwrap();
            let mut vault_binding = binding.clone();
            if mode == 6 { vault_binding.genesis_id = "c".repeat(32); }
            let vault = Arc::new(Vault { binding: vault_binding, credential: credential.clone() });
            let policy = TlsBackendPolicy::new(principal.as_str().into(), vec![vec![1]], "localhost".into()).unwrap();
            let result = crate::experimental_public::attach_existing(root2, store.as_ref(), binding.clone(), vault, policy, worker.clone(), "127.0.0.1".parse().unwrap(), vec!["8.8.8.8:443".parse().unwrap()]);
            assert!(result.is_err());
            assert_eq!(std::fs::read(root.path().join("runtime.journal.json")).unwrap(), before);
            return;
        }
        let persistence = { let lease=store.writer().unwrap(); inspection.promote(&binding, &*lease).unwrap() };
        let config: ProductConfig = serde_json::from_value(serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{"schemaVersion":1,"id":"test-listener","name":"stage-only","enabled":true,"bind":{"address":"192.0.2.1","port":19001},"protocol":{"kind":"proxy","protocol":{"kind":"shadowsocks","method":"aes-128-gcm"},"users":[{"id":"test-user","credentialRef":credential,"enabled":true}]},"transport":{"kind":"tcp"},"security":{"kind":"none"},"requirements":[]}]})).unwrap();
        let managed = ManagedRuntimeV2::with_generation(worker, WorkerInstanceV2::new("test-instance").unwrap(), 0).unwrap();
        if mode == 3 || mode == 4 {
            let compiler = ServerCompilerV2::for_public_experiment(release.clone(), vec!["8.8.8.8:443".parse().unwrap()]).unwrap();
            let executor = Arc::new(ExperimentalPublicExecutor::new(persistence, managed, binding.clone(), Arc::new(Vault { binding: binding.clone(), credential: credential.clone() }), TlsBackendPolicy::new(principal.as_str().into(), vec![vec![1]], "localhost".into()).unwrap(), compiler, if mode == 3 { Arc::new(NoProbe) } else { Arc::new(ProbeNeverPass) }, "test-session".into()).unwrap());
            let control = ControlService::new(store.clone(), executor.clone(), Arc::new(EmptySystem), Arc::new(SystemClock));
            let before = store.read().unwrap();
            if mode == 3 {
                assert!(matches!(control.plan(PlanRequest { principal, expected_revision: Revision::ZERO, config, release, resources: vec![], ttl_ms: 120_000 }), Err(ControlError::ExecutorUnavailable)));
                let after = store.read().unwrap();
                assert_eq!(before.version, after.version);
                assert_eq!(before.plans.len(), after.plans.len());
            } else {
                let plan = control.plan(PlanRequest { principal: principal.clone(), expected_revision: Revision::ZERO, config, release, resources: vec![], ttl_ms: 120_000 }).unwrap();
                let op = control.submit(ApplyRequest { principal, plan_id: plan.body().id.clone(), confirmed_hash: plan.hash().clone(), expected_revision: Revision::ZERO, idempotency_key: IdempotencyKey::new("executor-test").unwrap() }).unwrap();
                assert_eq!(control.run(&op.id, &CancellationToken::default()).unwrap().state, OperationState::RolledBack);
                let inner = executor.lock().unwrap();
                assert_eq!(inner.journal.last_acknowledged().phase, Phase::Restored);
                assert!(inner.runtime.active_generation().is_none() && inner.runtime.prepared_generation().is_none());
            }
            return;
        }
        let runtime = Arc::new(StageRuntime { journal: Mutex::new(persistence), worker: Mutex::new(managed), binding: binding.clone(), vault: Vault { binding, credential: credential.clone() }, policy: TlsBackendPolicy::new(principal.as_str().into(), vec![vec![1]], "localhost".into()).unwrap(), mode });
        let control = ControlService::new(store, runtime.clone(), Arc::new(EmptySystem), Arc::new(SystemClock));
        let plan = control.plan(PlanRequest { principal: principal.clone(), expected_revision: Revision::ZERO, config: config.clone(), release: release.clone(), resources: vec![], ttl_ms: 120_000 }).unwrap();
        let op = control.submit(ApplyRequest { principal: principal.clone(), plan_id: plan.body().id.clone(), confirmed_hash: plan.hash().clone(), expected_revision: Revision::ZERO, idempotency_key: IdempotencyKey::new("stage-test").unwrap() }).unwrap();
        assert_eq!(control.run(&op.id, &CancellationToken::default()).unwrap().state, match mode { 0 => OperationState::Failed, 1 => OperationState::RolledBack, _ => OperationState::Canceled });
        let journal = runtime.journal.lock().unwrap();
        let expected = if activate { Phase::Restored } else { Phase::CandidateAbsent };
        assert_eq!(journal.last_acknowledged().phase, expected);
        assert!(journal.last_acknowledged().prepared.is_none());
        assert_eq!(runtime.worker.lock().unwrap().prepared_generation(), None);
        drop(journal);
        if activate {
            // The next queued plan first finalizes the terminal previous journal,
            // then must consume a fresh generation and roll back independently.
            let next = control.plan(PlanRequest { principal: principal.clone(), expected_revision: Revision::ZERO, config, release, resources: vec![], ttl_ms: 120_000 }).unwrap();
            let next_op = control.submit(ApplyRequest { principal, plan_id: next.body().id.clone(), confirmed_hash: next.hash().clone(), expected_revision: Revision::ZERO, idempotency_key: IdempotencyKey::new("stage-test-next").unwrap() }).unwrap();
            assert_eq!(control.run(&next_op.id, &CancellationToken::default()).unwrap().state, OperationState::RolledBack);
            let journal = runtime.journal.lock().unwrap();
            assert_eq!(journal.last_acknowledged().high_water, 2);
            assert_eq!(journal.last_acknowledged().phase, Phase::Restored);
        }
        // Dropping the runtime kills/reaps any prepared test-only child. No
        // journal result is treated as forwarding or authentication health.
    }
    #[test]
    fn watcher_stop_is_set_even_if_caller_unwinds() {
        let stop = Arc::new(AtomicBool::new(false));
        let seen = stop.clone();
        let result = std::panic::catch_unwind(|| {
            let _guard = StopWatcher(stop.clone());
            panic!("synthetic unwind");
        });
        assert!(result.is_err());
        assert!(seen.load(Ordering::Acquire));
    }
    #[test]
    fn real_worker_preparation_persists_identity_before_material_and_never_binds() { run_worker_case(0); }
    #[test]
    fn unavailable_bind_rolls_back_to_stopped_first_install() { run_worker_case(1); }
    #[test]
    fn canceled_prepared_worker_is_discarded_before_host_mutation() { run_worker_case(2); }
    #[test]
    fn executor_refuses_to_plan_without_real_probe() { run_worker_case(3); }
    #[test]
    fn executor_reaps_and_rolls_back_failed_first_bind() { run_worker_case(4); }
    #[test]
    fn attachment_rejects_loopback_oracle_without_mutating_journal() { run_worker_case(5); }
    #[test]
    fn attachment_rejects_vault_binding_mismatch_without_mutation() { run_worker_case(6); }
}
