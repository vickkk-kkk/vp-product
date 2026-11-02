//! Durable, reference-only managed vp_core RuntimeExecutor bridge.
//! This is an explicitly uncertified loopback-development executor, not a vault,
//! production interoperability harness, route controller or release certificate.
#![forbid(unsafe_code)]
mod durable;
mod ports;
use durable::*;
pub use ports::*;
use std::{
    collections::BTreeSet,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use vp_product_compiler::{Compiler, ExecutionRecipe, RecipeProtocol};
use vp_product_control::RuntimeHealth;
use vp_product_control::*;
use vp_product_core_adapter::managed::{
    Cancellation, Failure, ListenerKind, ListenerSpec, ManagedRuntime, VerifiedWorker,
    WorkerConfig, WorkerSnapshot,
};
use vp_product_domain::*;
use vp_product_storage::{ArtifactStore, FileArtifactStore};

const ACTION_TIMEOUT: Duration = Duration::from_secs(20);
const START_TIMEOUT: Duration = Duration::from_secs(15);
struct Inner {
    runtime: ManagedRuntime,
    journal: Journal,
    owned: Option<RuntimeRecord>,
    poisoned: bool,
}
pub struct ManagedExecutor {
    compiler: Compiler,
    worker: VerifiedWorker,
    durable: Durable,
    #[cfg(target_os = "linux")]
    _bound_root: Option<vp_product_storage::BoundDirectory>,
    artifacts: FileArtifactStore,
    secrets: Arc<dyn ImmutableSecretStore>,
    probes: Arc<dyn ActiveProbe>,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
}
impl ManagedExecutor {
    /// Root must already exist, be absolute/non-symlink and private 0700. Worker
    /// hash and exact release come from local reviewed composition, never HTTP.
    /// Holds an exclusive nonblocking lifetime lock (one runtime owner/process).
    pub fn open(
        root: impl AsRef<Path>,
        release: ReleaseIdentity,
        worker: VerifiedWorker,
        worker_digest: ContentDigest,
        secrets: Arc<dyn ImmutableSecretStore>,
        probes: Arc<dyn ActiveProbe>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ControlError> {
        if worker_digest.as_str() != worker.sha256() {
            return Err(ControlError::InvalidConfiguration);
        }
        let build = vp_product_core_adapter::inspect_build()
            .map_err(|_| ControlError::ExecutorUnavailable)?;
        if !build.runtime_enabled || release != build.build.release {
            return Err(ControlError::InvalidConfiguration);
        }
        let compiler = Compiler::for_loopback_development(release.clone())
            .map_err(|_| ControlError::InvalidConfiguration)?;
        let (durable, journal) = Durable::open(
            root.as_ref(),
            ContentDigest::of("vp.release-identity.v1", &release)?,
            worker_digest,
        )?;
        let artifacts = FileArtifactStore::open(root.as_ref(), 4 * 1024 * 1024)?;
        let runtime = ManagedRuntime::with_generation(worker.clone(), journal.high_water)
            .map_err(map_failure)?;
        let value = Self {
            compiler,
            worker,
            durable,
            #[cfg(target_os = "linux")]
            _bound_root: None,
            artifacts,
            secrets,
            probes,
            clock,
            inner: Mutex::new(Inner {
                runtime,
                journal,
                owned: None,
                poisoned: false,
            }),
        };
        {
            let inner = value.lock()?;
            for record in inner
                .journal
                .active
                .iter()
                .chain(inner.journal.launching.iter())
                .chain(inner.journal.stages.values().flat_map(|stage| {
                    std::iter::once(&stage.candidate).chain(stage.previous.iter())
                }))
            {
                value.recipe(record)?;
                if record.generation > inner.journal.high_water {
                    return Err(ControlError::CorruptState);
                }
            }
        }
        Ok(value)
    }
    fn lock(&self) -> Result<MutexGuard<'_, Inner>, ControlError> {
        let inner = self
            .inner
            .try_lock()
            .map_err(|_| ControlError::RecoveryRequired)?;
        if inner.poisoned {
            return Err(ControlError::RecoveryRequired);
        }
        Ok(inner)
    }
    fn save(&self, inner: &mut Inner, next: Journal) -> Result<(), ControlError> {
        if let Err(error) = self.durable.save(&next) {
            inner.poisoned = true;
            return Err(error);
        }
        inner.journal = next;
        Ok(())
    }
    fn recipe(&self, record: &RuntimeRecord) -> Result<ExecutionRecipe, ControlError> {
        let bytes = self.artifacts.get(&record.recipe_digest)?;
        let recipe: ExecutionRecipe =
            serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
        self.compiler
            .verify_recipe(&recipe)
            .map_err(|_| ControlError::CorruptState)?;
        if record.config_digest != ContentDigest::of("vp.product-config.v1", &recipe.source)?
            || record.release_digest
                != ContentDigest::of("vp.release-identity.v1", &recipe.release)?
        {
            return Err(ControlError::CorruptState);
        }
        Ok(recipe)
    }
    fn bytes(recipe: &ExecutionRecipe) -> Result<Vec<u8>, ControlError> {
        serde_json::to_vec(recipe).map_err(|_| ControlError::InvalidConfiguration)
    }
    fn compile(
        &self,
        config: &ProductConfig,
        release: &ReleaseIdentity,
    ) -> Result<ExecutionRecipe, ControlError> {
        self.compiler
            .compile(config, release)
            .map_err(|_| ControlError::InvalidConfiguration)
    }
    fn record(&self, previous: &RevisionRecord) -> Result<RuntimeRecord, ControlError> {
        let recipe = self.compile(&previous.config, &previous.release)?;
        let digest = self.artifacts.put(&Self::bytes(&recipe)?)?;
        if digest != previous.artifact_digest
            || previous.config_digest
                != ContentDigest::of("vp.product-config.v1", &previous.config)?
            || previous.release_digest
                != ContentDigest::of("vp.release-identity.v1", &previous.release)?
        {
            return Err(ControlError::CorruptState);
        }
        Ok(RuntimeRecord {
            operation: previous.operation_id.clone(),
            revision: previous.revision,
            config_digest: previous.config_digest.clone(),
            release_digest: previous.release_digest.clone(),
            recipe_digest: digest,
            generation: 0,
            process: None,
        })
    }
    fn stage_matches(
        &self,
        inner: &Inner,
        operation: &OperationId,
        plan: &ChangePlan,
    ) -> Result<Stage, ControlError> {
        plan.verify_integrity()?;
        let stage = inner
            .journal
            .stages
            .get(operation)
            .ok_or(ControlError::NotFound)?;
        if stage.plan_hash != *plan.hash()
            || stage.candidate.operation != *operation
            || stage.candidate.revision != plan.body().target_revision
            || stage.candidate.config_digest != plan.body().validation.config_digest
            || stage.candidate.release_digest != plan.body().validation.release_digest
            || stage.candidate.recipe_digest != plan.body().validation.artifact_digest
        {
            return Err(ControlError::CorruptState);
        }
        self.recipe(&stage.candidate)?;
        Ok(stage.clone())
    }
    fn validate_refs(
        &self,
        recipe: &ExecutionRecipe,
        deadline: Instant,
    ) -> Result<(), ControlError> {
        for listener in &recipe.listeners {
            for user in &listener.users {
                within(deadline)?;
                self.secrets
                    .validate_immutable(&user.credential_ref, deadline)?;
                within(deadline)?;
            }
        }
        Ok(())
    }
    fn resolve(
        &self,
        recipe: &ExecutionRecipe,
        deadline: Instant,
    ) -> Result<WorkerConfig, ControlError> {
        let mut listeners = Vec::new();
        for listener in &recipe.listeners {
            let (kind, cipher) = match listener.protocol {
                RecipeProtocol::Vless {} => (ListenerKind::Vless, None),
                RecipeProtocol::Vmess {} => (ListenerKind::Vmess, None),
                RecipeProtocol::Shadowsocks { method } => (
                    ListenerKind::Shadowsocks,
                    Some(cipher_name(method).to_owned()),
                ),
            };
            // ListenerSpec scrubs users on drop, including any early failure.
            let mut spec = ListenerSpec {
                tag: listener.id.as_str().to_owned(),
                kind,
                port: listener.port,
                users: Vec::new(),
                cipher,
            };
            for user in &listener.users {
                within(deadline)?;
                self.secrets
                    .validate_immutable(&user.credential_ref, deadline)?;
                let secret = self
                    .secrets
                    .resolve_immutable(&user.credential_ref, deadline)?;
                within(deadline)?;
                let text = std::str::from_utf8(secret.expose())
                    .map_err(|_| ControlError::InvalidConfiguration)?;
                if text.is_empty() || text.len() > 4096 {
                    return Err(ControlError::InvalidConfiguration);
                }
                if matches!(
                    listener.protocol,
                    RecipeProtocol::Vless {} | RecipeProtocol::Vmess {}
                ) && !canonical_uuid(text)
                {
                    return Err(ControlError::InvalidConfiguration);
                }
                spec.users.push(text.to_owned());
            }
            listeners.push(spec);
        }
        let config = WorkerConfig {
            schema_version: 1,
            bind_address: recipe.bind_address,
            listeners,
        };
        config.validate().map_err(map_failure)?;
        Ok(config)
    }
    /// After a process restart, never reuse saved health. Prove the exact saved
    /// process identity is absent and endpoints released before a new launch.
    fn clear_stale(&self, inner: &mut Inner) -> Result<(), ControlError> {
        if inner.owned.is_some() {
            return Ok(());
        }
        let deadline = Instant::now() + ACTION_TIMEOUT;
        for record in inner
            .journal
            .active
            .iter()
            .chain(inner.journal.launching.iter())
        {
            if let Some(process) = &record.process {
                if process.is_present()? {
                    return Err(ControlError::RecoveryRequired);
                }
                self.probes.stopped(&self.recipe(record)?, deadline)?;
                within(deadline)?;
            } else if inner.journal.active.as_ref() == Some(record) {
                return Err(ControlError::CorruptState);
            }
            // A launching record without a PID is before the durable observer.
            // No Start frame may be sent before that observer's successful fsync.
        }
        if inner.journal.active.is_some() || inner.journal.launching.is_some() {
            let mut next = inner.journal.clone();
            next.active = None;
            next.launching = None;
            self.save(inner, next)?;
        }
        Ok(())
    }
    fn stop_owned(&self, inner: &mut Inner) -> Result<(), ControlError> {
        let Some(record) = inner.owned.clone() else {
            return self.clear_stale(inner);
        };
        let report = inner
            .runtime
            .stop(record.generation, Duration::from_millis(100))
            .map_err(map_failure)?;
        if !report.process_exited || report.remaining_tasks != 0 {
            return Err(ControlError::RecoveryRequired);
        }
        inner.owned = None;
        let mut next = inner.journal.clone();
        next.active = None;
        next.launching = None;
        self.save(inner, next)
    }
    fn launch(
        &self,
        inner: &mut Inner,
        mut record: RuntimeRecord,
    ) -> Result<RuntimeRecord, ControlError> {
        self.clear_stale(inner)?;
        if inner.owned.is_some() {
            return Err(ControlError::RecoveryRequired);
        }
        let recipe = self.recipe(&record)?;
        let config = self.resolve(&recipe, Instant::now() + ACTION_TIMEOUT)?;
        let previous_generation = inner.journal.high_water;
        record.generation = previous_generation
            .checked_add(1)
            .filter(|generation| *generation <= MAX_WIRE_COUNTER)
            .ok_or(ControlError::CounterExhausted)?;
        record.process = None;
        let mut next = inner.journal.clone();
        next.high_water = record.generation;
        next.launching = Some(record.clone());
        self.save(inner, next)?;
        inner.runtime = ManagedRuntime::with_generation(self.worker.clone(), previous_generation)
            .map_err(map_failure)?;
        let mut observed_journal = inner.journal.clone();
        let mut observed_record = record.clone();
        let mut persistence_failed = false;
        let result = inner.runtime.start_with_spawn_observer(
            config,
            previous_generation,
            START_TIMEOUT,
            &Cancellation::default(),
            |pid| {
                observed_record.process =
                    Some(ProcessIdentity::read(pid).map_err(|_| Failure::Io)?);
                observed_journal.launching = Some(observed_record.clone());
                if self.durable.save(&observed_journal).is_err() {
                    persistence_failed = true;
                    return Err(Failure::Io);
                }
                Ok(())
            },
        );
        if persistence_failed {
            inner.poisoned = true;
            return Err(ControlError::StorageUnavailable);
        }
        inner.journal = observed_journal;
        record = observed_record;
        let snapshot = match result {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let mut next = inner.journal.clone();
                next.launching = None;
                self.save(inner, next)?;
                return Err(map_failure(error));
            }
        };
        if snapshot.generation != record.generation {
            inner.poisoned = true;
            return Err(ControlError::RecoveryRequired);
        }
        if record.process != Some(ProcessIdentity::read(snapshot.pid)?) {
            inner.poisoned = true;
            return Err(ControlError::RecoveryRequired);
        }
        inner.owned = Some(record.clone());
        let mut next = inner.journal.clone();
        next.launching = None;
        next.active = Some(record.clone());
        if let Err(error) = self.save(inner, next) {
            // The journal outcome is uncertain, but this exact owned child can
            // still be contained. Reopening must reconcile the durable marker.
            let _ = inner
                .runtime
                .stop(record.generation, Duration::from_millis(100));
            inner.owned = None;
            return Err(error);
        }
        Ok(record)
    }
    fn snapshot(
        &self,
        inner: &mut Inner,
        record: &RuntimeRecord,
        recipe: &ExecutionRecipe,
    ) -> Result<WorkerSnapshot, ControlError> {
        if inner.owned.as_ref() != Some(record) {
            return Err(ControlError::HealthFailed);
        }
        let snapshot = inner
            .runtime
            .snapshot(record.generation)
            .map_err(map_failure)?;
        if !snapshot.listeners_ready
            || snapshot.task_panics != 0
            || snapshot.listeners.len() != recipe.listeners.len()
            || recipe.listeners.iter().any(|listener| {
                snapshot
                    .listeners
                    .iter()
                    .filter(|bound| {
                        bound.tag == listener.id.as_str()
                            && bound.port == listener.port
                            && bound.accept_loop_live
                    })
                    .count()
                    != 1
            })
            || Some(ProcessIdentity::read(snapshot.pid)?) != record.process
        {
            return Err(ControlError::HealthFailed);
        }
        Ok(snapshot)
    }
    fn check_all(
        &self,
        inner: &mut Inner,
        record: &RuntimeRecord,
        recipe: &ExecutionRecipe,
        previous: Option<&ExecutionRecipe>,
        checks: &BTreeSet<HealthCheck>,
    ) -> Result<Vec<CheckResult>, ControlError> {
        self.snapshot(inner, record, recipe)?;
        self.probes.available(recipe, previous, checks)?;
        let deadline = Instant::now() + ACTION_TIMEOUT;
        let mut results = Vec::new();
        for check in checks {
            within(deadline)?;
            let outcome = if *check == HealthCheck::Process {
                CheckOutcome::Passed
            } else {
                let credential = match check {
                    HealthCheck::AuthenticationAccepted(auth) => {
                        Some(self.probe_secret(recipe, auth, deadline)?)
                    }
                    HealthCheck::RetiredAuthenticationRejected(auth) => Some(self.probe_secret(
                        previous.ok_or(ControlError::CorruptState)?,
                        auth,
                        deadline,
                    )?),
                    _ => None,
                };
                let outcome = self.probes.check(
                    ProbeRequest {
                        check,
                        current: recipe,
                        previous,
                        generation: record.generation,
                        credential: credential.as_ref(),
                    },
                    deadline,
                )?;
                within(deadline)?;
                outcome
            };
            results.push(CheckResult {
                check: check.clone(),
                outcome,
            });
        }
        self.snapshot(inner, record, recipe)?;
        Ok(results)
    }
    fn probe_secret(
        &self,
        recipe: &ExecutionRecipe,
        auth: &AuthenticationProbe,
        deadline: Instant,
    ) -> Result<SecretBytes, ControlError> {
        let user = recipe
            .listeners
            .iter()
            .find(|l| l.id.as_str() == auth.listener_id)
            .and_then(|l| l.users.iter().find(|u| u.id.as_str() == auth.user_id))
            .ok_or(ControlError::CorruptState)?;
        if ContentDigest::of("vp.credential-reference.v1", &user.credential_ref)?
            != auth.credential_ref_digest
        {
            return Err(ControlError::CorruptState);
        }
        self.secrets
            .validate_immutable(&user.credential_ref, deadline)?;
        self.secrets
            .resolve_immutable(&user.credential_ref, deadline)
    }
    /// Read-only cross-store startup gate. Call before Ready, reconciliation or
    /// shutdown. Unexplained intents require operator recovery, not adoption.
    pub fn validate_startup_pair(&self, state: &StoredState) -> Result<(), ControlError> {
        state.verify_integrity()?;
        let inner = self.lock()?;
        if inner.journal.launching.is_some()
            || state.operations.values().any(|op| !op.state.is_terminal())
        {
            return Err(ControlError::RecoveryRequired);
        }
        let matches = |record: &RuntimeRecord, revision: &RevisionRecord| {
            record.operation == revision.operation_id
                && record.revision == revision.revision
                && record.config_digest == revision.config_digest
                && record.release_digest == revision.release_digest
                && record.recipe_digest == revision.artifact_digest
        };
        for (id, stage) in &inner.journal.stages {
            let op = state
                .operations
                .get(id)
                .ok_or(ControlError::RecoveryRequired)?;
            let plan = state
                .plans
                .get(&op.plan_id)
                .ok_or(ControlError::RecoveryRequired)?;
            self.stage_matches(&inner, id, plan)?;
            match stage.phase {
                Phase::Candidate if op.state == OperationState::Committed => {
                    if !state.revisions.iter().any(|r| matches(&stage.candidate, r)) {
                        return Err(ControlError::RecoveryRequired);
                    }
                }
                Phase::Discarded if op.state != OperationState::Committed => (),
                _ => return Err(ControlError::RecoveryRequired),
            }
            if let Some(previous) = &stage.previous {
                if previous.revision != plan.body().base_revision
                    || !state.revisions.iter().any(|r| matches(previous, r))
                {
                    return Err(ControlError::RecoveryRequired);
                }
            } else if stage.phase == Phase::Candidate && plan.body().base_revision != Revision::ZERO
            {
                return Err(ControlError::RecoveryRequired);
            }
        }
        for revision in &state.revisions {
            let stage = inner
                .journal
                .stages
                .get(&revision.operation_id)
                .ok_or(ControlError::RecoveryRequired)?;
            if stage.phase != Phase::Candidate || !matches(&stage.candidate, revision) {
                return Err(ControlError::RecoveryRequired);
            }
            // Compile and read existing artifact only: record() would publish.
            let recipe = self.compile(&revision.config, &revision.release)?;
            let bytes = Self::bytes(&recipe)?;
            if ContentDigest::bytes(&bytes) != revision.artifact_digest
                || self.artifacts.get(&revision.artifact_digest)? != bytes
            {
                return Err(ControlError::CorruptState);
            }
        }
        if let Some(active) = &inner.journal.active {
            if !state.active().is_some_and(|r| matches(active, r)) {
                return Err(ControlError::RecoveryRequired);
            }
        }
        Ok(())
    }
    /// Explicit daemon shutdown: stop and reap only the process generation this
    /// executor actually owns, then prove its listener endpoints released. The
    /// control database retains desired configuration for explicit startup reconciliation.
    pub fn shutdown(&self) -> Result<(), ControlError> {
        let mut inner = self.lock()?;
        let recipe = inner
            .owned
            .as_ref()
            .map(|record| self.recipe(record))
            .transpose()?;
        self.stop_owned(&mut inner)?;
        if let Some(recipe) = recipe {
            self.probes
                .stopped(&recipe, Instant::now() + ACTION_TIMEOUT)?;
        }
        Ok(())
    }
    /// Explicit daemon-start reconciliation, invoked only for control's durable
    /// committed record, after control recovery. It verifies freshly; persisted
    /// receipts never imply the runtime is currently healthy. Launches loopback
    /// listeners, never routes, firewall, system proxy or external targets.
    pub fn reconcile_committed(&self, previous: &RevisionRecord) -> Result<(), ControlError> {
        let mut inner = self.lock()?;
        let record = self.record(previous)?;
        let active = match inner.owned.clone() {
            Some(active) if same_revision(&active, &record) => active,
            Some(_) => return Err(ControlError::RecoveryRequired),
            None => self.launch(&mut inner, record)?,
        };
        let recipe = self.recipe(&active)?;
        let checks = minimum_health_checks(&previous.config, None)?;
        let health = self
            .check_all(&mut inner, &active, &recipe, None, &checks)
            .and_then(|results| {
                if results.iter().all(|r| r.outcome == CheckOutcome::Passed) {
                    Ok(())
                } else {
                    Err(ControlError::HealthFailed)
                }
            });
        if let Err(error) = health {
            self.stop_owned(&mut inner)?;
            return Err(error);
        }
        Ok(())
    }
}
fn same_revision(a: &RuntimeRecord, b: &RuntimeRecord) -> bool {
    a.operation == b.operation
        && a.revision == b.revision
        && a.config_digest == b.config_digest
        && a.release_digest == b.release_digest
        && a.recipe_digest == b.recipe_digest
}
fn within(deadline: Instant) -> Result<(), ControlError> {
    if Instant::now() >= deadline {
        Err(ControlError::ExecutorFailed)
    } else {
        Ok(())
    }
}
fn map_failure(failure: Failure) -> ControlError {
    match failure {
        Failure::Unsupported => ControlError::ExecutorUnavailable,
        Failure::InvalidConfig | Failure::WorkerIdentityMismatch => {
            ControlError::InvalidConfiguration
        }
        Failure::Canceled => ControlError::Canceled,
        Failure::StaleGeneration | Failure::CleanupFailed | Failure::RollbackFailed => {
            ControlError::RecoveryRequired
        }
        _ => ControlError::ExecutorFailed,
    }
}
fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn cipher_name(method: ShadowsocksCipher) -> &'static str {
    match method {
        ShadowsocksCipher::Aes128Gcm => "aes-128-gcm",
        ShadowsocksCipher::Aes256Gcm => "aes-256-gcm",
        ShadowsocksCipher::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        ShadowsocksCipher::Xchacha20IetfPoly1305 => "xchacha20-ietf-poly1305",
        ShadowsocksCipher::Blake3Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
        ShadowsocksCipher::Blake3Aes256Gcm2022 => "2022-blake3-aes-256-gcm",
        ShadowsocksCipher::Blake3Chacha20Poly13052022 => "2022-blake3-chacha20-poly1305",
    }
}

impl RuntimeExecutor for ManagedExecutor {
    fn observe_committed(&self, previous: &RevisionRecord) -> Result<RuntimeHealth, ControlError> {
        let mut inner = self.lock()?;
        let active = inner.owned.clone().ok_or(ControlError::HealthFailed)?;
        let recipe = self.recipe(&active)?;
        // Do not call record()/reconcile here: this read must never stage or
        // launch anything, and must match all committed identities exactly.
        if active.operation != previous.operation_id
            || active.revision != previous.revision
            || active.config_digest != previous.config_digest
            || active.release_digest != previous.release_digest
            || active.recipe_digest != previous.artifact_digest
            || recipe.source != previous.config
            || recipe.release != previous.release
        {
            return Err(ControlError::HealthFailed);
        }
        let checks = minimum_health_checks(&previous.config, None)?;
        let results = self.check_all(&mut inner, &active, &recipe, None, &checks)?;
        Ok(RuntimeHealth {
            revision: active.revision,
            operation_id: active.operation,
            config_digest: active.config_digest,
            release_digest: active.release_digest,
            generation: active.generation,
            checked_at_ms: self.clock.now_ms()?,
            checks: results,
            external_connectivity: CheckOutcome::NotChecked,
        })
    }

    fn validate(
        &self,
        config: &ProductConfig,
        release: &ReleaseIdentity,
        previous: Option<&RevisionRecord>,
    ) -> Result<ValidationReceipt, ControlError> {
        let recipe = self.compile(config, release)?;
        let previous_recipe = previous
            .map(|p| self.compile(&p.config, &p.release))
            .transpose()?;
        let deadline = Instant::now() + ACTION_TIMEOUT;
        self.validate_refs(&recipe, deadline)?;
        if let Some(previous) = &previous_recipe {
            self.validate_refs(previous, deadline)?;
        }
        let required_health = minimum_health_checks(config, previous)?;
        self.probes
            .available(&recipe, previous_recipe.as_ref(), &required_health)?;
        within(deadline)?;
        Ok(ValidationReceipt {
            config_digest: ContentDigest::of("vp.product-config.v1", config)?,
            release_digest: ContentDigest::of("vp.release-identity.v1", release)?,
            artifact_digest: ContentDigest::bytes(&Self::bytes(&recipe)?),
            impact: RestartImpact::ControlledRestart,
            required_health,
        })
    }
    fn stage(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
        cancel: &CancellationToken,
    ) -> Result<(), ControlError> {
        plan.verify_integrity()?;
        if cancel.is_canceled() {
            return Err(ControlError::Canceled);
        }
        let mut inner = self.lock()?;
        if inner.journal.stages.contains_key(operation) {
            let stage = self.stage_matches(&inner, operation, plan)?;
            return if stage.phase == Phase::Staged {
                Ok(())
            } else {
                Err(ControlError::RecoveryRequired)
            };
        }
        if inner.journal.stages.len() >= 4096 {
            return Err(ControlError::StorageUnavailable);
        }
        let recipe = self.compile(&plan.body().config, &plan.body().release)?;
        self.validate_refs(&recipe, Instant::now() + ACTION_TIMEOUT)?;
        let digest = self.artifacts.put(&Self::bytes(&recipe)?)?;
        if digest != plan.body().validation.artifact_digest {
            return Err(ControlError::CorruptState);
        }
        if cancel.is_canceled() {
            return Err(ControlError::Canceled);
        }
        let candidate = RuntimeRecord {
            operation: operation.clone(),
            revision: plan.body().target_revision,
            config_digest: plan.body().validation.config_digest.clone(),
            release_digest: plan.body().validation.release_digest.clone(),
            recipe_digest: digest,
            generation: 0,
            process: None,
        };
        let mut next = inner.journal.clone();
        next.stages.insert(
            operation.clone(),
            Stage {
                plan_hash: plan.hash().clone(),
                candidate,
                previous: None,
                phase: Phase::Staged,
            },
        );
        self.save(&mut inner, next)
    }
    fn activate(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
        previous: Option<&RevisionRecord>,
    ) -> Result<RuntimeActivation, ControlError> {
        let mut inner = self.lock()?;
        let mut stage = self.stage_matches(&inner, operation, plan)?;
        if stage.phase == Phase::Candidate {
            let record = inner
                .owned
                .clone()
                .filter(|r| same_revision(r, &stage.candidate))
                .ok_or(ControlError::RecoveryRequired)?;
            self.snapshot(&mut inner, &record, &self.recipe(&record)?)?;
            return Ok(activation(&record));
        }
        if stage.phase != Phase::Staged {
            return Err(ControlError::RecoveryRequired);
        }
        let old = previous.map(|p| self.record(p)).transpose()?;
        if let Some(owned) = &inner.owned {
            if !old.as_ref().is_some_and(|old| same_revision(owned, old)) {
                return Err(ControlError::RecoveryRequired);
            }
        }
        stage.previous = old;
        stage.phase = Phase::Candidate;
        let mut next = inner.journal.clone();
        next.stages.insert(operation.clone(), stage.clone());
        self.save(&mut inner, next)?;
        self.stop_owned(&mut inner)?;
        let record = self.launch(&mut inner, stage.candidate.clone())?;
        stage.candidate = record.clone();
        let mut next = inner.journal.clone();
        next.stages.insert(operation.clone(), stage);
        self.save(&mut inner, next)?;
        Ok(activation(&record))
    }
    fn verify(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
    ) -> Result<RuntimeHealth, ControlError> {
        let mut inner = self.lock()?;
        let stage = self.stage_matches(&inner, operation, plan)?;
        if stage.phase != Phase::Candidate {
            return Err(ControlError::HealthFailed);
        }
        let record = inner
            .owned
            .clone()
            .filter(|record| same_revision(record, &stage.candidate))
            .ok_or(ControlError::HealthFailed)?;
        let recipe = self.recipe(&record)?;
        let previous = stage
            .previous
            .as_ref()
            .map(|p| self.recipe(p))
            .transpose()?;
        let checks = self.check_all(
            &mut inner,
            &record,
            &recipe,
            previous.as_ref(),
            &plan.body().validation.required_health,
        )?;
        Ok(RuntimeHealth {
            revision: record.revision,
            operation_id: operation.clone(),
            config_digest: record.config_digest,
            release_digest: record.release_digest,
            generation: record.generation,
            checked_at_ms: self.clock.now_ms()?,
            checks,
            external_connectivity: CheckOutcome::NotChecked,
        })
    }
    fn stop_candidate(
        &self,
        operation: &OperationId,
        plan: &ChangePlan,
    ) -> Result<(), ControlError> {
        let mut inner = self.lock()?;
        let mut stage = self.stage_matches(&inner, operation, plan)?;
        if matches!(stage.phase, Phase::Restored | Phase::Discarded) {
            return Ok(());
        }
        if let Some(owned) = inner.owned.clone() {
            if owned.operation == *operation {
                if !same_revision(&owned, &stage.candidate) {
                    return Err(ControlError::CorruptState);
                }
                self.stop_owned(&mut inner)?;
            } else if owned.revision != plan.body().base_revision {
                return Err(ControlError::RecoveryRequired);
            }
        } else {
            self.clear_stale(&mut inner)?;
        }
        stage.phase = Phase::Stopped;
        let mut next = inner.journal.clone();
        next.stages.insert(operation.clone(), stage);
        self.save(&mut inner, next)
    }
    fn restore_previous(
        &self,
        operation: &OperationId,
        previous: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        let mut inner = self.lock()?;
        let mut stage = inner
            .journal
            .stages
            .get(operation)
            .cloned()
            .ok_or(ControlError::NotFound)?;
        let old = previous.map(|p| self.record(p)).transpose()?;
        // Resource failure can precede activate; capture previous reference here
        // in that case, before any rollback launch. No control state is changed.
        if stage.previous.is_none() && stage.phase == Phase::Stopped {
            stage.previous = old.clone();
        }
        if stage
            .previous
            .as_ref()
            .zip(old.as_ref())
            .is_some_and(|(a, b)| !same_revision(a, b))
            || stage.previous.is_some() != old.is_some()
        {
            return Err(ControlError::CorruptState);
        }
        if !matches!(stage.phase, Phase::Stopped | Phase::Restored) {
            return Err(ControlError::RecoveryRequired);
        }
        if let Some(old) = old {
            match inner.owned.as_ref() {
                Some(owned) if same_revision(owned, &old) => (),
                Some(_) => return Err(ControlError::RecoveryRequired),
                None => {
                    self.launch(&mut inner, old)?;
                }
            }
        } else {
            if inner.owned.is_some() {
                return Err(ControlError::RecoveryRequired);
            }
            self.clear_stale(&mut inner)?;
        }
        stage.phase = Phase::Restored;
        let mut next = inner.journal.clone();
        next.stages.insert(operation.clone(), stage);
        self.save(&mut inner, next)
    }
    fn verify_previous(
        &self,
        operation: &OperationId,
        previous: Option<&RevisionRecord>,
    ) -> Result<(), ControlError> {
        let mut inner = self.lock()?;
        let stage = inner
            .journal
            .stages
            .get(operation)
            .cloned()
            .ok_or(ControlError::NotFound)?;
        if stage.phase != Phase::Restored {
            return Err(ControlError::RecoveryRequired);
        }
        if let Some(previous) = previous {
            let expected = self.record(previous)?;
            if !stage
                .previous
                .as_ref()
                .is_some_and(|p| same_revision(p, &expected))
            {
                return Err(ControlError::CorruptState);
            }
            let active = inner
                .owned
                .clone()
                .filter(|r| same_revision(r, &expected))
                .ok_or(ControlError::HealthFailed)?;
            let recipe = self.recipe(&active)?;
            let candidate = self.recipe(&stage.candidate)?;
            let candidate_record = RevisionRecord {
                revision: stage.candidate.revision,
                config: candidate.source.clone(),
                release: candidate.release.clone(),
                config_digest: stage.candidate.config_digest.clone(),
                release_digest: stage.candidate.release_digest.clone(),
                artifact_digest: stage.candidate.recipe_digest.clone(),
                operation_id: stage.candidate.operation.clone(),
            };
            let checks = minimum_health_checks(&previous.config, Some(&candidate_record))?;
            let results =
                self.check_all(&mut inner, &active, &recipe, Some(&candidate), &checks)?;
            if results.iter().any(|r| r.outcome != CheckOutcome::Passed) {
                return Err(ControlError::HealthFailed);
            }
        } else {
            if stage.previous.is_some()
                || inner.owned.is_some()
                || inner.runtime.is_running()
                || inner.journal.active.is_some()
                || inner.journal.launching.is_some()
            {
                return Err(ControlError::HealthFailed);
            }
            self.probes.stopped(
                &self.recipe(&stage.candidate)?,
                Instant::now() + ACTION_TIMEOUT,
            )?;
        }
        Ok(())
    }
    fn discard_stage(&self, operation: &OperationId) -> Result<(), ControlError> {
        let mut inner = self.lock()?;
        let Some(mut stage) = inner.journal.stages.get(operation).cloned() else {
            return Ok(());
        };
        if stage.phase == Phase::Discarded {
            return Ok(());
        }
        if !matches!(stage.phase, Phase::Staged | Phase::Restored)
            || inner
                .owned
                .as_ref()
                .is_some_and(|r| r.operation == *operation)
        {
            return Err(ControlError::RecoveryRequired);
        }
        stage.phase = Phase::Discarded;
        let mut next = inner.journal.clone();
        next.stages.insert(operation.clone(), stage);
        self.save(&mut inner, next)
    }
}
fn activation(record: &RuntimeRecord) -> RuntimeActivation {
    RuntimeActivation {
        revision: record.revision,
        operation_id: record.operation.clone(),
        config_digest: record.config_digest.clone(),
        release_digest: record.release_digest.clone(),
        generation: record.generation,
    }
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BoundRuntimeMarker {
    schema_version: u16,
    profile: String,
    genesis: ContentDigest,
    release_digest: ContentDigest,
    worker_digest: ContentDigest,
}

/// Exact immutable pairing for the separately versioned bound runtime profile.
#[cfg(target_os = "linux")]
pub struct BoundRuntimeIdentity {
    pub genesis: ContentDigest,
    pub release: ReleaseIdentity,
    pub worker_digest: ContentDigest,
}
#[cfg(target_os = "linux")]
impl ManagedExecutor {
    /// Never adopts a reservation, legacy journal or partial directory tree.
    /// Root admission is performed by the fresh coordinator; this constructor
    /// retains the root and child leases throughout the executor lifetime.
    pub fn open_bound(
        root: vp_product_storage::BoundDirectory,
        mode: vp_product_storage::BoundOpenMode,
        identity: BoundRuntimeIdentity,
        worker: VerifiedWorker,
        secrets: Arc<dyn ImmutableSecretStore>,
        probes: Arc<dyn ActiveProbe>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ControlError> {
        use vp_product_storage::BoundOpenMode;
        if identity.worker_digest.as_str() != worker.sha256() {
            return Err(ControlError::InvalidConfiguration);
        }
        let build = vp_product_core_adapter::inspect_build()
            .map_err(|_| ControlError::ExecutorUnavailable)?;
        if !build.runtime_enabled || identity.release != build.build.release {
            return Err(ControlError::InvalidConfiguration);
        }
        let compiler = Compiler::for_loopback_development(identity.release.clone())
            .map_err(|_| ControlError::InvalidConfiguration)?;
        let root = root.lock()?;
        let marker = BoundRuntimeMarker {
            schema_version: 2,
            profile: "vp.bound-runtime.v2".into(),
            genesis: identity.genesis.clone(),
            release_digest: ContentDigest::of("vp.release-identity.v1", &identity.release)?,
            worker_digest: identity.worker_digest.clone(),
        };
        match mode {
            BoundOpenMode::CreateFresh => {
                root.require_empty()?;
                let bytes = serde_json::to_vec(&marker).map_err(|_| ControlError::CorruptState)?;
                root.atomic_file(
                    "runtime.journal.json",
                    "runtime.profile.pending",
                    &bytes,
                    16384,
                    false,
                )?;
            }
            BoundOpenMode::OpenExisting => {
                if root.names()? != ["artifacts", "journal", "runtime.journal.json"] {
                    return Err(ControlError::RecoveryRequired);
                }
                let observed: BoundRuntimeMarker =
                    serde_json::from_slice(&root.read("runtime.journal.json", 16384)?)
                        .map_err(|_| ControlError::CorruptState)?;
                if observed != marker {
                    return Err(ControlError::CorruptState);
                }
            }
        }
        // A partial child creation remains visible and refuses a future fresh
        // attempt. OpenExisting never creates missing children or journal state.
        let journal_root = root.child("journal", mode)?;
        let artifact_root = root.child("artifacts", mode)?;
        let artifacts = FileArtifactStore::open_bound(
            artifact_root,
            identity.genesis.clone(),
            mode,
            4 * 1024 * 1024,
        )?;
        let (durable, journal) = Durable::open_bound(
            journal_root,
            identity.genesis,
            mode,
            ContentDigest::of("vp.release-identity.v1", &identity.release)?,
            identity.worker_digest,
        )?;
        let runtime = ManagedRuntime::with_generation(worker.clone(), journal.high_water)
            .map_err(map_failure)?;
        let value = Self {
            compiler,
            worker,
            durable,
            artifacts,
            secrets,
            probes,
            clock,
            _bound_root: Some(root),
            inner: Mutex::new(Inner {
                runtime,
                journal,
                owned: None,
                poisoned: false,
            }),
        };
        {
            let inner = value.lock()?;
            for record in inner
                .journal
                .active
                .iter()
                .chain(inner.journal.launching.iter())
                .chain(inner.journal.stages.values().flat_map(|stage| {
                    std::iter::once(&stage.candidate).chain(stage.previous.iter())
                }))
            {
                value.recipe(record)?;
                if record.generation > inner.journal.high_water {
                    return Err(ControlError::CorruptState);
                }
            }
        }
        Ok(value)
    }
}
