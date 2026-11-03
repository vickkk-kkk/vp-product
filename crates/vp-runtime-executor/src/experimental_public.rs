//! Explicit, experimental attachment to an already paired TLS runtime root.
//! No fresh installer, daemon registration, update/rollback, or release is provided.
//! This profile remains IPv4 exact-target/TCP-only and is not a general VPN.
use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::{Duration, Instant}};
use vp_product_compiler::server_v2::ServerCompilerV2;
use vp_product_control::{ContentDigest, ControlError, ControlStore, InstanceBinding, RuntimeExecutor, TlsBackendPolicy, TlsMaterialVault, WriterLease};
use vp_product_core_adapter::managed::{VerifiedWorker, host_v2::ManagedRuntimeV2, protocol_v2::WorkerInstanceV2};
use vp_product_storage::{BoundDirectory, TlsSqliteStore};
use zeroize::Zeroize;
use crate::{public_oracle::ProbeOracle, public_probe::{OracleProbe, VirtualProbe}, public_stage::{ExperimentalPublicExecutor, PublicProbe},
    server_v2_journal::{self as journal, persistence::{FreshJournalInspection, JournalInspection}}};

/// An attached executor plus its reserved challenge endpoint. The endpoint is
/// not a proxy listener or health proof. Retain the executor for its full worker
/// lifetime; dropping it closes the worker before closing the oracle socket.
pub struct AttachedPublicRuntime { executor: Arc<ExperimentalPublicExecutor>, probe_target: SocketAddr }
impl AttachedPublicRuntime {
    pub fn executor(&self) -> Arc<dyn RuntimeExecutor> { self.executor.clone() }
    pub fn probe_target(&self) -> SocketAddr { self.probe_target }
    /// Persist final metadata for a committed operation. The retained process
    /// record is historical and must not be interpreted as live status.
    pub fn finalize_committed(&self, store: &dyn ControlStore) -> Result<(), ControlError> {
        let lease = store.writer()?;
        self.executor.finalize_committed(&*lease)
    }
}

/// Attach only an already initialized, exactly paired and idle runtime. This
/// binds one explicit challenge IP and reserves an ephemeral port. It performs
/// no service install, firewall change, worker spawn, migration or recovery.
/// All control/vault directory anchoring must finish before this starts a thread.
/// `worker` must have been verified against a trusted release manifest digest.
#[allow(clippy::too_many_arguments)]
pub fn attach_existing(
    root: BoundDirectory, store: &dyn ControlStore, binding: InstanceBinding,
    vault: Arc<dyn TlsMaterialVault>, policy: TlsBackendPolicy, worker: VerifiedWorker,
    oracle_bind: IpAddr, permitted_targets: Vec<SocketAddr>,
) -> Result<AttachedPublicRuntime, ControlError> {
    binding.validate_tls_profile()?;
    if permitted_targets.is_empty() || permitted_targets.len() >= 64 { return Err(ControlError::InvalidConfiguration); }
    if vault.material_binding(Instant::now()+Duration::from_secs(10))? != binding { return Err(ControlError::ResourceConflict); }
    let (release, identity) = identity_for(&binding, &worker)?;
    let inspection = JournalInspection::inspect(root, identity)?;
    let prepared_probe = prepare_probe(oracle_bind, permitted_targets, release, &policy)?;
    attach_inspection(inspection, store, binding, vault, policy, worker, prepared_probe)
}

/// Explicit trusted HTTPS target for real egress, separate from the local
/// in-process authentication challenge. No target or trust is inferred.
pub struct SingleIpProbeConfig { pub target: SocketAddr, pub target_trust: vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust,
    pub target_name: String, pub path: String, pub expected_status: u16 }
impl SingleIpProbeConfig {
    /// Bind public probe policy to an immutable digest for provisioning records.
    pub fn fingerprint(&self) -> Result<ContentDigest, ControlError> {
        use vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust;
        let trust = match &self.target_trust {
            HttpsTargetTrust::PinnedDer(roots) => ContentDigest::of("vp.https-roots.v1", roots)?,
            HttpsTargetTrust::PublicWebPki => ContentDigest::bytes(b"webpki-roots:0.26.11+1.0.11"),
        };
        ContentDigest::of("vp.single-ip-probe.v1", &(&self.target, trust, &self.target_name, &self.path, self.expected_status))
    }
    /// Optional public Cloudflare trace endpoint; the caller must explicitly
    /// include its address in permitted targets before enabling this probe.
    pub fn cloudflare_trace() -> Self {
        Self { target: SocketAddr::from(([1, 1, 1, 1], 443)),
            target_trust: vp_product_core_adapter::managed::probe_client_v2::HttpsTargetTrust::PublicWebPki,
            target_name: "one.one.one.one".into(), path: "/cdn-cgi/trace".into(), expected_status: 200 }
    }
}

/// Attach an already initialized, paired, idle instance with a single-IP probe.
/// This does not install, bind proxy listeners, spawn workers or grant release readiness.
#[allow(clippy::too_many_arguments)]
pub fn attach_existing_single_ip(
    root: BoundDirectory, vault_root: &BoundDirectory, store: &TlsSqliteStore, binding: InstanceBinding,
    vault: Arc<dyn TlsMaterialVault>, policy: TlsBackendPolicy, worker: VerifiedWorker,
    config: SingleIpProbeConfig, permitted_targets: Vec<SocketAddr>,
) -> Result<AttachedPublicRuntime, ControlError> {
    binding.validate_tls_profile()?;
    root.check()?; vault_root.check()?;
    let observed = vault.retained_directory_identity()?; let admitted = vault_root.identity()?;
    if observed != (admitted.device, admitted.inode) { return Err(ControlError::ResourceConflict); }
    store.disjoint_from(vault_root)?; store.disjoint_from(&root)?; vault_root.disjoint(&root)?;
    if vault.material_binding(Instant::now()+Duration::from_secs(10))? != binding { return Err(ControlError::ResourceConflict); }
    let (release, identity) = identity_for(&binding, &worker)?;
    let inspection = JournalInspection::inspect(root, identity)?;
    let prepared_probe = prepare_single_ip(config, permitted_targets, release, &policy)?;
    attach_inspection(inspection, store, binding, vault, policy, worker, prepared_probe)
}

/// A durable, paired fresh journal reservation. An interrupted setup must be
/// inspected as recovery-required; it must never be deleted or retried blindly.
pub struct FreshPublicReservation { inspection: Option<JournalInspection>, binding: InstanceBinding,
    control_identity: vp_product_storage::DirectoryIdentity, vault_identity: (u64, u64) }

/// Reserves a fresh runtime only for an actual writer-held preparing control
/// envelope and an authenticated, already claimed vault. All three retained
/// directory capabilities must be distinct and non-nested.
pub fn reserve_fresh(
    root: BoundDirectory, vault_root: &BoundDirectory, store: &TlsSqliteStore,
    vault: &dyn TlsMaterialVault, binding: InstanceBinding, worker: &VerifiedWorker,
) -> Result<FreshPublicReservation, ControlError> {
    binding.validate_tls_profile()?;
    root.check()?;
    vault_root.check()?;
    let observed = vault.retained_directory_identity()?;
    let admitted = vault_root.identity()?;
    if observed.0 != admitted.device || observed.1 != admitted.inode { return Err(ControlError::ResourceConflict); }
    store.disjoint_from(vault_root)?;
    store.disjoint_from(&root)?;
    vault_root.disjoint(&root)?;
    if vault.material_binding(Instant::now() + Duration::from_secs(10))? != binding { return Err(ControlError::ResourceConflict); }
    let (_, identity) = identity_for(&binding, worker)?;
    let fresh = FreshJournalInspection::inspect_empty(root, identity)?;
    let inspection = store.with_preparing(|envelope| {
        if envelope.binding() != &binding { return Err(ControlError::ResourceConflict); }
        fresh.initialize(envelope).map_err(|failure| failure.error().clone())
    })?;
    Ok(FreshPublicReservation { inspection: Some(inspection), binding, control_identity: store.directory_identity()?, vault_identity: observed })
}

impl FreshPublicReservation {
    /// Single-IP counterpart. The HTTPS target and its trust are explicitly
    /// configured and must be included in the approved exact egress targets.
    #[allow(clippy::too_many_arguments)]
    pub fn attach_single_ip(&mut self, store: &TlsSqliteStore, vault: Arc<dyn TlsMaterialVault>,
        policy: TlsBackendPolicy, worker: VerifiedWorker, config: SingleIpProbeConfig,
        permitted_targets: Vec<SocketAddr>) -> Result<AttachedPublicRuntime, ControlError> {
        if store.directory_identity()? != self.control_identity || vault.retained_directory_identity()? != self.vault_identity { return Err(ControlError::ResourceConflict); }
        if vault.material_binding(Instant::now()+Duration::from_secs(10))? != self.binding { return Err(ControlError::ResourceConflict); }
        let (release, identity) = identity_for(&self.binding, &worker)?;
        if self.inspection.as_ref().ok_or(ControlError::RecoveryRequired)?.identity()? != &identity { return Err(ControlError::ResourceConflict); }
        let prepared_probe = prepare_single_ip(config, permitted_targets, release, &policy)?;
        store.mark_initialized()?;
        let inspection = self.inspection.take().ok_or(ControlError::RecoveryRequired)?;
        attach_inspection(inspection, store, self.binding.clone(), vault, policy, worker, prepared_probe)
    }
    /// Mark the same control store initialized only after the durable runtime
    /// reservation and vault pairing are revalidated. A later attachment error
    /// must be inspected rather than blindly reset.
    #[allow(clippy::too_many_arguments)]
    pub fn attach(&mut self, store: &TlsSqliteStore, vault: Arc<dyn TlsMaterialVault>,
        policy: TlsBackendPolicy, worker: VerifiedWorker, oracle_bind: IpAddr,
        permitted_targets: Vec<SocketAddr>) -> Result<AttachedPublicRuntime, ControlError> {
        if store.directory_identity()? != self.control_identity || vault.retained_directory_identity()? != self.vault_identity { return Err(ControlError::ResourceConflict); }
        if vault.material_binding(Instant::now()+Duration::from_secs(10))? != self.binding { return Err(ControlError::ResourceConflict); }
        let (release, identity) = identity_for(&self.binding, &worker)?;
        if self.inspection.as_ref().ok_or(ControlError::RecoveryRequired)?.identity()? != &identity { return Err(ControlError::ResourceConflict); }
        let prepared_probe = prepare_probe(oracle_bind, permitted_targets, release, &policy)?;
        store.mark_initialized()?;
        let inspection = self.inspection.take().ok_or(ControlError::RecoveryRequired)?;
        attach_inspection(inspection, store, self.binding.clone(), vault, policy, worker, prepared_probe)
    }
}

fn identity_for(binding: &InstanceBinding, worker: &VerifiedWorker) -> Result<(vp_product_domain::ReleaseIdentity, journal::Identity), ControlError> {
    let release = vp_product_core_adapter::inspect_build().map_err(|_| ControlError::ExecutorUnavailable)?.build.release;
    let identity = journal::Identity { schema_version: journal::SCHEMA, profile: journal::PROFILE.into(),
        genesis: binding.digest()?, release_digest: ContentDigest::of("vp.release-identity.v1", &release)?,
        core_digest: journal::core_digest(&release)?, worker_digest: ContentDigest::parse(worker.sha256().to_owned())?,
        recipe_version: 2, worker_protocol_version: 3 };
    Ok((release, identity))
}

struct PreparedProbe { target: SocketAddr, compiler: ServerCompilerV2, probe: Arc<dyn PublicProbe> }
fn prepare_single_ip(config: SingleIpProbeConfig, permitted_targets: Vec<SocketAddr>,
    release: vp_product_domain::ReleaseIdentity, policy: &TlsBackendPolicy) -> Result<PreparedProbe, ControlError> {
    if !permitted_targets.contains(&config.target) { return Err(ControlError::InvalidConfiguration); }
    let compiler = ServerCompilerV2::for_public_experiment(release, permitted_targets).map_err(|_| ControlError::InvalidConfiguration)?;
    let target = config.target;
    let probe = Arc::new(VirtualProbe::new(policy, target, config.target_trust, config.target_name, config.path, config.expected_status)?);
    Ok(PreparedProbe { target, compiler, probe })
}
fn prepare_probe(oracle_bind: IpAddr, mut permitted_targets: Vec<SocketAddr>,
    release: vp_product_domain::ReleaseIdentity, policy: &TlsBackendPolicy) -> Result<PreparedProbe, ControlError> {
    if permitted_targets.is_empty() || permitted_targets.len() >= 64 { return Err(ControlError::InvalidConfiguration); }
    let oracle = Arc::new(ProbeOracle::bind(oracle_bind)?);
    let target = oracle.address();
    if permitted_targets.contains(&target) { return Err(ControlError::InvalidConfiguration); }
    permitted_targets.push(target);
    let compiler = ServerCompilerV2::for_public_experiment(release, permitted_targets).map_err(|_| ControlError::InvalidConfiguration)?;
    let probe = Arc::new(OracleProbe::new(oracle, policy)?);
    Ok(PreparedProbe { target, compiler, probe })
}

#[allow(clippy::too_many_arguments)]
fn attach_inspection(
    inspection: JournalInspection, store: &dyn ControlStore, binding: InstanceBinding,
    vault: Arc<dyn TlsMaterialVault>, policy: TlsBackendPolicy, worker: VerifiedWorker,
    prepared: PreparedProbe,
) -> Result<AttachedPublicRuntime, ControlError> {
    let lease = store.writer()?;
    let persistence = inspection.promote(&binding, &*lease)?;
    if persistence.last_acknowledged().phase != journal::Phase::Idle
        || persistence.last_acknowledged().active.is_some() || lease.state().needs_recovery() { return Err(ControlError::RecoveryRequired); }
    let PreparedProbe { target: oracle_target, compiler, probe } = prepared;
    let mut random = [0u8;16]; getrandom::fill(&mut random).map_err(|_| ControlError::ExecutorUnavailable)?;
    let session = random.iter().map(|b| format!("{b:02x}")).collect::<String>(); random.zeroize();
    let instance = WorkerInstanceV2::new(&session).map_err(|_| ControlError::InvalidConfiguration)?;
    let runtime = ManagedRuntimeV2::with_generation(worker, instance, persistence.last_acknowledged().high_water).map_err(|_| ControlError::RecoveryRequired)?;
    let executor = ExperimentalPublicExecutor::new(persistence, runtime, binding, vault, policy, compiler, probe, session)?;
    Ok(AttachedPublicRuntime { executor: Arc::new(executor), probe_target: oracle_target })
}

/// Read-only evidence for a paired stopped committed revision. This is not
/// permission to launch or proof that the listener or public network is live.
#[derive(Debug)]
pub struct CommittedRestartInspection { pub next_generation: u64, pub listener_count: usize }

/// Re-check disk pairing, old process absence, the exact approved recipe and
/// current vault materials without starting a worker or binding any socket.
/// The caller must later revalidate everything under retained writer handles.
#[allow(clippy::too_many_arguments)]
pub fn inspect_committed_restart(
    root: BoundDirectory, vault_root: &BoundDirectory, store: &TlsSqliteStore,
    vault: &dyn TlsMaterialVault, binding: &InstanceBinding, policy: &TlsBackendPolicy,
    worker: &VerifiedWorker, oracle_target: SocketAddr, clock: &dyn vp_product_control::Clock,
    cancel: &vp_product_control::CancellationToken, deadline: Instant,
) -> Result<CommittedRestartInspection, ControlError> {
    binding.validate_tls_profile()?;
    root.check()?; vault_root.check()?;
    let observed = vault.retained_directory_identity()?;
    let admitted = vault_root.identity()?;
    if observed != (admitted.device, admitted.inode) { return Err(ControlError::ResourceConflict); }
    store.disjoint_from(vault_root)?; store.disjoint_from(&root)?; vault_root.disjoint(&root)?;
    if vault.material_binding(deadline)? != *binding { return Err(ControlError::ResourceConflict); }
    let (_, identity) = identity_for(binding, worker)?;
    let inspection = JournalInspection::inspect(root, identity)?;
    let lease = store.asset_writer()?;
    let persistence = inspection.promote(binding, &lease)?;
    let observed = journal::inspect_absent_committed_process(persistence.last_acknowledged(), lease.state())?;
    let bytes = persistence.referenced_recipe(&observed.recipe.recipe_digest)?;
    let recipe: vp_product_compiler::server_v2::ServerRecipeV2 = serde_json::from_slice(&bytes).map_err(|_| ControlError::CorruptState)?;
    let targets = recipe.public_targets.clone().ok_or(ControlError::CorruptState)?;
    if recipe.profile != vp_product_compiler::server_v2::ServerProfileV2::PublicExperimentalUncertified
        || !targets.contains(&oracle_target) || recipe.listeners.iter().any(|l| l.bind.address == oracle_target.ip()) {
        return Err(ControlError::InvalidConfiguration);
    }
    let compiler = ServerCompilerV2::for_public_experiment(recipe.release.clone(), targets).map_err(|_| ControlError::InvalidConfiguration)?;
    let admission = vp_product_control::TlsMaterialAdmission::for_public_committed_restart(
        &lease, vault, policy, clock, lease.state().version, &observed.recipe.recipe_digest, deadline, cancel)?;
    let resolver = vp_product_server_materials::RegistryMaterialResolverV2::new(admission, &recipe, &compiler).map_err(|_| ControlError::InvalidConfiguration)?;
    let core_cancel = vp_product_core_adapter::managed::Cancellation::default();
    if cancel.is_canceled() { return Err(ControlError::Canceled); }
    let inputs = vp_product_core_adapter::managed::material_port_v2::resolve_materials_v2(&recipe, &resolver, deadline, &core_cancel).map_err(|_| ControlError::InvalidConfiguration)?;
    drop(inputs); // material never leaves this scope or appears in the report
    if cancel.is_canceled() { return Err(ControlError::Canceled); }
    if Instant::now() >= deadline { return Err(ControlError::PlanExpired); }
    Ok(CommittedRestartInspection { next_generation: observed.next_generation, listener_count: recipe.listeners.len() })
}
