//! Journal-only filesystem prerequisite. Public entry points only inspect.
//! Mutating constructors/methods remain crate-private until a real coordinator
//! supplies authenticated vault/control admission. No generic repair or effects.
use super::*;
use std::collections::BTreeMap;
use vp_product_control::{GenesisPhase, InstanceBinding, TlsControlEnvelope, WriterLease};
use vp_product_storage::{BoundDirectory, BoundOpenMode, ReadOnlyBoundFile};

const MARKER: &str = "runtime.journal.json";
const PENDING: &str = "runtime.journal.pending";
const ARTIFACT_BINDING: &str = "artifacts.binding.json";
const MARKER_LIMIT: usize = 16 * 1024;
const MAX_ARTIFACTS: usize = 128;
const MAX_ARTIFACT_TOTAL: usize = 16 * 1024 * 1024;
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ArtifactBinding {
    schema_version: u16,
    genesis: ContentDigest,
    max_bytes: usize,
}
fn artifact_binding(id: &Identity) -> ArtifactBinding {
    // Existing recipe-neutral storage binding1, distinct fresh child root.
    ArtifactBinding {
        schema_version: 1,
        genesis: id.genesis.clone(),
        max_bytes: MAX_RECIPE_BYTES,
    }
}
fn artifact_bytes(id: &Identity) -> Result<Vec<u8>, ControlError> {
    serde_json::to_vec(&artifact_binding(id)).map_err(|_| ControlError::CorruptState)
}
fn names(root: &BoundDirectory, expected: &[&str]) -> Result<(), ControlError> {
    if root.names()? == expected {
        Ok(())
    } else {
        Err(ControlError::RecoveryRequired)
    }
}
/// Retains directory leases and read-only file descriptions. Does not authenticate
/// a vault, promote SQL, admit an instance, recover a child or assert live health.
pub struct JournalInspection {
    // Rust drops fields in declaration order: close every retained file first,
    // then child leases, and release the runtime root lease LAST.
    marker_file: ReadOnlyBoundFile,
    journal_file: ReadOnlyBoundFile,
    binding_file: ReadOnlyBoundFile,
    artifact_files: BTreeMap<ContentDigest, ReadOnlyBoundFile>,
    identity: Identity,
    journal: Journal,
    journal_root: BoundDirectory,
    artifact_root: BoundDirectory,
    root: BoundDirectory,
}
impl JournalInspection {
    /// Exact existing profile only; missing/extra/pending entries never repaired.
    pub fn inspect(root: BoundDirectory, expected: Identity) -> Result<Self, ControlError> {
        expected.validate()?;
        let root = root.lock()?;
        names(&root, &["artifacts", "journal", MARKER])?;
        let marker_file = root.inspect_file_read_only(MARKER, MARKER_LIMIT)?;
        Identity::decode(marker_file.bytes(), &expected)?;
        let journal_root = root.child("journal", BoundOpenMode::OpenExisting)?;
        let artifact_root = root.child("artifacts", BoundOpenMode::OpenExisting)?;
        Self::from_parts(root, journal_root, artifact_root, expected, marker_file)
    }
    fn from_parts(
        root: BoundDirectory,
        journal_root: BoundDirectory,
        artifact_root: BoundDirectory,
        identity: Identity,
        marker_file: ReadOnlyBoundFile,
    ) -> Result<Self, ControlError> {
        names(&journal_root, &[MARKER])?;
        let journal_file = journal_root.inspect_file_read_only(MARKER, MAX_JOURNAL_BYTES)?;
        let journal = Journal::decode(journal_file.bytes(), &identity)?;
        let binding_file = artifact_root.inspect_file_read_only(ARTIFACT_BINDING, MARKER_LIMIT)?;
        let binding: ArtifactBinding =
            serde_json::from_slice(binding_file.bytes()).map_err(|_| ControlError::CorruptState)?;
        require(
            binding == artifact_binding(&identity)
                && binding_file.bytes() == artifact_bytes(&identity)?.as_slice(),
        )?;
        let mut artifact_files = BTreeMap::new();
        // Retain all immutable blobs so added/removed/replaced inventory cannot be
        // silently adopted between inspection and promotion. No GC or cleanup.
        let mut total = 0usize;
        for name in artifact_root.names_bounded(MAX_ARTIFACTS + 1)? {
            if name == ARTIFACT_BINDING {
                continue;
            }
            let digest = ContentDigest::parse(&name).map_err(|_| ControlError::RecoveryRequired)?;
            let remaining = MAX_ARTIFACT_TOTAL
                .checked_sub(total)
                .ok_or(ControlError::CorruptState)?;
            let file =
                artifact_root.inspect_file_read_only(&name, remaining.min(MAX_RECIPE_BYTES))?;
            total = total
                .checked_add(file.bytes().len())
                .ok_or(ControlError::CorruptState)?;
            require(total <= MAX_ARTIFACT_TOTAL && ContentDigest::bytes(file.bytes()) == digest)?;
            artifact_files.insert(digest, file);
        }
        let value = Self {
            root,
            journal_root,
            artifact_root,
            marker_file,
            journal_file,
            binding_file,
            artifact_files,
            identity,
            journal,
        };
        value.check_unchanged()?;
        verify_recipes(&value.journal, &value.referenced_bytes(&value.journal)?)?;
        Ok(value)
    }
    /// Rechecks retained descriptors and their names before returning facts.
    /// Borrowed facts cannot outlive the inspector's retained leases.
    /// ```compile_fail
    /// use vp_product_runtime_executor::server_v2_journal::persistence::JournalInspection;
    /// fn escape(inspected: JournalInspection) {
    ///     let observed = inspected.journal().unwrap();
    ///     drop(inspected);
    ///     assert_eq!(observed.sequence, 0);
    /// }
    /// ```
    pub fn journal(&self) -> Result<&Journal, ControlError> {
        self.check_unchanged()?;
        Ok(&self.journal)
    }
    pub fn identity(&self) -> Result<&Identity, ControlError> {
        self.check_unchanged()?;
        Ok(&self.identity)
    }
    fn referenced_bytes(
        &self,
        journal: &Journal,
    ) -> Result<BTreeMap<ContentDigest, Vec<u8>>, ControlError> {
        // At most five references are admitted by fixed journal slots.
        let mut out = BTreeMap::new();
        let mut add = |r: &RecipeIdentity| -> Result<(), ControlError> {
            let file = self
                .artifact_files
                .get(&r.recipe_digest)
                .ok_or(ControlError::CorruptState)?;
            out.insert(r.recipe_digest.clone(), file.bytes().to_vec());
            Ok(())
        };
        if let Some(o) = &journal.operation {
            add(&o.candidate)?;
            if let Some(p) = &o.previous {
                add(p)?;
            }
        }
        if let Some(a) = &journal.active {
            add(&a.launch.recipe)?;
        }
        if let Some(p) = &journal.prepared {
            add(&p.launch.recipe)?;
        }
        if let Some(l) = &journal.launch_intent {
            add(&l.launch.recipe)?;
        }
        Ok(out)
    }
    fn check_unchanged(&self) -> Result<(), ControlError> {
        names(&self.root, &["artifacts", "journal", MARKER])?;
        self.root.revalidate_child("journal", &self.journal_root)?;
        self.root
            .revalidate_child("artifacts", &self.artifact_root)?;
        names(&self.journal_root, &[MARKER])?;
        self.marker_file.revalidate(&self.root)?;
        self.journal_file.revalidate(&self.journal_root)?;
        self.binding_file.revalidate(&self.artifact_root)?;
        let mut expected: Vec<_> = self
            .artifact_files
            .keys()
            .map(|d| d.as_str().to_owned())
            .collect();
        expected.push(ARTIFACT_BINDING.into());
        expected.sort();
        require(self.artifact_root.names_bounded(MAX_ARTIFACTS + 1)? == expected)?;
        for f in self.artifact_files.values() {
            f.revalidate(&self.artifact_root)?;
        }
        Ok(())
    }
    /// Internal only: authenticating binding provenance and supplying an already
    /// held current control writer remain the future coordinator's obligations.
    #[allow(dead_code)] // No production coordinator is wired to this prerequisite.
    pub(crate) fn promote(
        self,
        authenticated_binding: &InstanceBinding,
        lease: &dyn WriterLease,
    ) -> Result<JournalPersistence, ControlError> {
        self.check_unchanged()?;
        let state = paired_state(&self.identity, authenticated_binding, lease)?;
        let pairing = pair_control(&self.journal, state)?;
        // Persisted uncertainty is inspection evidence, not generic repair input.
        if !matches!(pairing, Pairing::Stable | Pairing::Finalize) {
            return Err(ControlError::RecoveryRequired);
        }
        verify_recipes(&self.journal, &self.referenced_bytes(&self.journal)?)?;
        Ok(JournalPersistence {
            inspection: self,
            poisoned: false,
        })
    }
}
fn paired_state<'a>(
    identity: &Identity,
    binding: &InstanceBinding,
    lease: &'a dyn WriterLease,
) -> Result<&'a vp_product_control::StoredState, ControlError> {
    binding.validate_tls_profile()?;
    require(binding.digest()? == identity.genesis)?;
    let aggregate = lease
        .tls_aggregate()
        .ok_or(ControlError::ExecutorUnavailable)?;
    aggregate.validate()?;
    require(
        aggregate.binding() == binding
            && aggregate.phase() == GenesisPhase::Initialized
            && ContentDigest::of("vp.stage-state.v1", aggregate.state())?
                == ContentDigest::of("vp.stage-state.v1", lease.state())?,
    )?;
    Ok(lease.state())
}
/// A poisoned writer never retries, cleans pending files or rolls back its cached
/// state after uncertain publication. Drop only releases leases; it does not repair.
pub struct JournalPersistence {
    inspection: JournalInspection,
    poisoned: bool,
}
impl JournalPersistence {
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    /// This historical view borrows the same owner that retains all leases.
    /// ```compile_fail
    /// use vp_product_runtime_executor::server_v2_journal::persistence::JournalPersistence;
    /// fn escape(writer: JournalPersistence) {
    ///     let observed = writer.last_acknowledged();
    ///     drop(writer);
    ///     assert_eq!(observed.sequence, 0);
    /// }
    /// ```
    pub fn last_acknowledged(&self) -> &Journal {
        &self.inspection.journal
    }
    /// Revalidate the retained artifact handles before returning exact bytes.
    pub(crate) fn assert_unchanged(&self) -> Result<(), ControlError> {
        if self.poisoned { return Err(ControlError::RecoveryRequired); }
        self.inspection.check_unchanged()
    }
    pub(crate) fn referenced_recipe(&self, digest: &ContentDigest) -> Result<Vec<u8>, ControlError> {
        if self.poisoned { return Err(ControlError::RecoveryRequired); }
        self.inspection.check_unchanged()?;
        self.inspection.referenced_bytes(&self.inspection.journal)?
            .remove(digest).ok_or(ControlError::CorruptState)
    }
    /// Persist only the exact recipe referenced by a sealed plan which is
    /// currently staging under this same admitted control writer. This does not
    /// reserve a generation, spawn a worker, or authorize network effects.
    #[allow(dead_code)] // The experimental coordinator is not yet wired.
    pub(crate) fn store_staged_recipe(
        &mut self, bytes: &[u8], operation: &OperationId,
        binding: &InstanceBinding, lease: &dyn WriterLease,
    ) -> Result<ContentDigest, ControlError> {
        if self.poisoned { return Err(ControlError::RecoveryRequired); }
        let state = paired_state(&self.inspection.identity, binding, lease)?;
        let op = state.operations.get(operation).ok_or(ControlError::NotFound)?;
        let plan = state.plans.get(&op.plan_id).ok_or(ControlError::CorruptState)?;
        plan.verify_integrity()?;
        require(op.state == vp_product_control::OperationState::Staging
            && !op.cancel_requested && !op.mutation_started
            && op.principal == plan.body().principal
            && plan.body().base_revision == state.active_revision)?;
        codec::budget(bytes, MAX_RECIPE_BYTES, 65536, 64, 65536)?;
        let recipe: vp_product_compiler::server_v2::ServerRecipeV2 = serde_json::from_slice(bytes).map_err(|_| ControlError::CorruptState)?;
        let digest = ContentDigest::bytes(bytes);
        require(serde_json::to_vec(&recipe).map_err(|_| ControlError::CorruptState)? == bytes
            && digest == plan.body().validation.artifact_digest
            && recipe.source == plan.body().config && recipe.release == plan.body().release
            && ContentDigest::of("vp.product-config.v1", &recipe.source)? == plan.body().validation.config_digest
            && ContentDigest::of("vp.release-identity.v1", &recipe.release)? == plan.body().validation.release_digest
            && ContentDigest::of("vp.release-identity.v1", &recipe.release)? == self.inspection.identity.release_digest
            && core_digest(&recipe.release)? == self.inspection.identity.core_digest)?;
        use vp_product_compiler::server_v2::{ServerCompilerV2, ServerProfileV2};
        let compiler = match recipe.profile {
            ServerProfileV2::LoopbackDevelopmentUncertified => ServerCompilerV2::for_loopback_development(recipe.release.clone()),
            ServerProfileV2::LoopbackExtendedCoreUncertified => ServerCompilerV2::for_loopback_server_extensions(recipe.release.clone()),
            ServerProfileV2::PublicExperimentalUncertified => ServerCompilerV2::for_public_experiment(recipe.release.clone(), recipe.public_targets.clone().ok_or(ControlError::CorruptState)?),
        }.map_err(|_| ControlError::CorruptState)?;
        compiler.verify_recipe(&recipe).map_err(|_| ControlError::CorruptState)?;
        self.inspection.check_unchanged()?;
        if let Some(existing) = self.inspection.artifact_files.get(&digest) {
            require(existing.bytes() == bytes)?;
            return Ok(digest);
        }
        require(self.inspection.artifact_files.len() < MAX_ARTIFACTS)?;
        let total = self.inspection.artifact_files.values().try_fold(bytes.len(), |n, file| n.checked_add(file.bytes().len())).ok_or(ControlError::CorruptState)?;
        require(total <= MAX_ARTIFACT_TOTAL)?;
        // Any failed publication or verification has an uncertain durable outcome.
        // Preserve evidence and force a fresh inspection instead of blind retries.
        self.poisoned = true;
        self.inspection.artifact_root.atomic_file(digest.as_str(), "artifact.pending", bytes, MAX_RECIPE_BYTES, false)?;
        let file = self.inspection.artifact_root.inspect_file_read_only(digest.as_str(), MAX_RECIPE_BYTES)?;
        require(file.bytes() == bytes)?;
        self.inspection.artifact_files.insert(digest.clone(), file);
        self.inspection.check_unchanged()?;
        self.poisoned = false;
        Ok(digest)
    }
    #[allow(dead_code)] // Future executor supplies real observations, not this module.
    pub(crate) fn persist_event(
        &mut self,
        event: Event,
        binding: &InstanceBinding,
        lease: &dyn WriterLease,
    ) -> Result<(), ControlError> {
        if self.poisoned {
            return Err(ControlError::RecoveryRequired);
        }
        let next = self.inspection.journal.propose(event)?;
        self.persist_next(next, binding, lease)
    }
    #[allow(dead_code)] // Future pre-Staging reconciliation hook is not installed.
    pub(crate) fn persist_finalization(
        &mut self,
        binding: &InstanceBinding,
        lease: &dyn WriterLease,
    ) -> Result<(), ControlError> {
        if self.poisoned {
            return Err(ControlError::RecoveryRequired);
        }
        let state = paired_state(&self.inspection.identity, binding, lease)?;
        let next = self.inspection.journal.finalize(state)?;
        self.persist_next(next, binding, lease)
    }
    fn persist_next(
        &mut self,
        next: Journal,
        binding: &InstanceBinding,
        lease: &dyn WriterLease,
    ) -> Result<(), ControlError> {
        self.persist_next_using(next, binding, lease, |root, bytes| {
            root.atomic_file(MARKER, PENDING, bytes, MAX_JOURNAL_BYTES, true)
        })
    }
    // Fixed production publisher above; injection is private and only used by
    // unit tests to stop at each publication boundary. Not an admission callback.
    fn persist_next_using<F>(
        &mut self,
        next: Journal,
        binding: &InstanceBinding,
        lease: &dyn WriterLease,
        publish: F,
    ) -> Result<(), ControlError>
    where
        F: FnOnce(&BoundDirectory, &[u8]) -> Result<(), ControlError>,
    {
        if self.poisoned {
            return Err(ControlError::RecoveryRequired);
        }
        // Semantic rejection before attempting writes does not poison the handle.
        let state = paired_state(&self.inspection.identity, binding, lease)?;
        let acknowledged = &self.inspection.journal;
        require(
            next.identity == self.inspection.identity
                && acknowledged.sequence.checked_add(1) == Some(next.sequence)
                && next.high_water >= acknowledged.high_water
                && next.high_water <= acknowledged.high_water.saturating_add(1),
        )?;
        pair_control(&next, state)?;
        verify_recipes(&next, &self.inspection.referenced_bytes(&next)?)?;
        let bytes = next.encode()?;
        // Any retained-identity failure or I/O error requires a new inspection;
        // no error allows this object to silently continue after a failed barrier.
        self.poisoned = true;
        self.inspection.check_unchanged()?;
        publish(&self.inspection.journal_root, &bytes)?;
        let file = self
            .inspection
            .journal_root
            .inspect_file_read_only(MARKER, MAX_JOURNAL_BYTES)?;
        require(file.bytes() == bytes.as_slice())?;
        self.inspection.journal_file = file;
        self.inspection.check_unchanged()?;
        self.inspection.journal = next;
        self.poisoned = false;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitializationBarrier {
    MarkerPublished,
    JournalChildCreated,
    ArtifactChildCreated,
    ArtifactBindingPublished,
    JournalPublished,
}
/// Public no-write emptiness inspection; initialization stays internal. A partial
/// initialization never becomes a second fresh attempt or a repair capability.
pub struct FreshJournalInspection {
    identity: Identity,
    poisoned: bool,
    // Partial/poisoned reservations obey the same child-before-root release.
    journal_root: Option<BoundDirectory>,
    artifact_root: Option<BoundDirectory>,
    root: Option<BoundDirectory>,
}
impl FreshJournalInspection {
    pub fn inspect_empty(root: BoundDirectory, identity: Identity) -> Result<Self, ControlError> {
        identity.validate()?;
        let root = root.lock()?;
        root.require_empty()?;
        Ok(Self {
            root: Some(root),
            journal_root: None,
            artifact_root: None,
            identity,
            poisoned: false,
        })
    }
    pub fn identity(&self) -> Result<&Identity, ControlError> {
        self.check_empty()?;
        Ok(&self.identity)
    }
    fn check_empty(&self) -> Result<(), ControlError> {
        if self.poisoned {
            return Err(ControlError::RecoveryRequired);
        }
        self.root
            .as_ref()
            .ok_or(ControlError::RecoveryRequired)?
            .require_empty()
    }
    #[allow(dead_code)] // Fresh coordinator is intentionally not implemented here.
    pub(crate) fn initialize(
        mut self,
        preparing: &TlsControlEnvelope,
    ) -> Result<JournalInspection, InitializationFailure> {
        let result = self.initialize_inner(preparing);
        match result {
            Ok(value) => Ok(value),
            Err(error) => Err(InitializationFailure {
                error,
                reservation: self,
            }),
        }
    }
    fn initialize_inner(
        &mut self,
        preparing: &TlsControlEnvelope,
    ) -> Result<JournalInspection, ControlError> {
        self.initialize_inner_using(preparing, |_| Ok(()))
    }
    fn initialize_inner_using<F>(
        &mut self,
        preparing: &TlsControlEnvelope,
        mut barrier: F,
    ) -> Result<JournalInspection, ControlError>
    where
        F: FnMut(InitializationBarrier) -> Result<(), ControlError>,
    {
        self.check_empty()?;
        preparing.validate()?;
        require(
            preparing.phase() == GenesisPhase::Preparing
                && preparing.binding().digest()? == self.identity.genesis,
        )?;
        let state = preparing.state();
        require(
            state.version == 0
                && state.active_revision == vp_product_domain::Revision::ZERO
                && state.operations.is_empty()
                && state.plans.is_empty()
                && state.revisions.is_empty(),
        )?;
        let empty = Journal::empty(self.identity.clone())?;
        let marker = self.identity.encode()?;
        let journal = empty.encode()?;
        let binding = artifact_bytes(&self.identity)?;
        self.poisoned = true; // precedes the first potentially durable creation.
        let root = self.root.as_ref().ok_or(ControlError::RecoveryRequired)?;
        root.atomic_file(
            MARKER,
            "runtime.profile.pending",
            &marker,
            MARKER_LIMIT,
            false,
        )?;
        barrier(InitializationBarrier::MarkerPublished)?;
        self.journal_root = Some(root.child("journal", BoundOpenMode::CreateFresh)?);
        barrier(InitializationBarrier::JournalChildCreated)?;
        self.artifact_root = Some(root.child("artifacts", BoundOpenMode::CreateFresh)?);
        barrier(InitializationBarrier::ArtifactChildCreated)?;
        self.artifact_root
            .as_ref()
            .ok_or(ControlError::RecoveryRequired)?
            .atomic_file(
                ARTIFACT_BINDING,
                "artifacts.binding.pending",
                &binding,
                MARKER_LIMIT,
                false,
            )?;
        barrier(InitializationBarrier::ArtifactBindingPublished)?;
        self.journal_root
            .as_ref()
            .ok_or(ControlError::RecoveryRequired)?
            .atomic_file(MARKER, PENDING, &journal, MAX_JOURNAL_BYTES, false)?;
        barrier(InitializationBarrier::JournalPublished)?;
        let marker_file = root.inspect_file_read_only(MARKER, MARKER_LIMIT)?;
        JournalInspection::from_parts(
            self.root.take().ok_or(ControlError::RecoveryRequired)?,
            self.journal_root
                .take()
                .ok_or(ControlError::RecoveryRequired)?,
            self.artifact_root
                .take()
                .ok_or(ControlError::RecoveryRequired)?,
            self.identity.clone(),
            marker_file,
        )
    }
}
/// Failed initialization retains any remaining capabilities and poison status.
/// Neither accessor grants retry/cleanup. Dropping never removes residue.
pub struct InitializationFailure {
    error: ControlError,
    reservation: FreshJournalInspection,
}
impl InitializationFailure {
    pub fn error(&self) -> &ControlError {
        &self.error
    }
    pub fn is_poisoned(&self) -> bool {
        self.reservation.poisoned
    }
}
#[cfg(test)]
mod tests;

/// Synthetic unit-test setup only. Does not authorize production writes.
#[cfg(test)]
pub(super) fn synthetic_committed_fixture(
    path: &std::path::Path, identity: Identity, binding: &InstanceBinding,
    journal: &Journal, recipe: &[u8], lease: &dyn WriterLease,
) -> Result<JournalPersistence, ControlError> {
    use std::fs::File;
    use vp_product_storage::DirectoryIdentity;
    let cap = || -> Result<BoundDirectory, ControlError> {
        let file = File::open(path).map_err(|_| ControlError::StorageUnavailable)?;
        BoundDirectory::admit(path, DirectoryIdentity::of(&file)?)
    };
    let fresh = FreshJournalInspection::inspect_empty(cap()?, identity.clone())?;
    let preparing = TlsControlEnvelope::preparing(binding.clone())?;
    drop(fresh.initialize(&preparing).map_err(|e| e.error().clone())?);
    {
        let root = cap()?.lock()?;
        let journal_root = root.child("journal", BoundOpenMode::OpenExisting)?;
        let artifact_root = root.child("artifacts", BoundOpenMode::OpenExisting)?;
        let digest = ContentDigest::bytes(recipe);
        artifact_root.atomic_file(digest.as_str(), "artifact.test.pending", recipe, MAX_RECIPE_BYTES, false)?;
        journal_root.atomic_file(MARKER, PENDING, &journal.encode()?, MAX_JOURNAL_BYTES, true)?;
    }
    JournalInspection::inspect(cap()?, identity)?.promote(binding, lease)
}
