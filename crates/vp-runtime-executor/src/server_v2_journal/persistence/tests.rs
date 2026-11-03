#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Synthetic private-directory tests. No actual vault/process/instance admission.
use super::*;
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};
use vp_product_storage::DirectoryIdentity;
fn digest(v: &str) -> ContentDigest {
    ContentDigest::bytes(v.as_bytes())
}
fn binding() -> InstanceBinding {
    InstanceBinding {
        binding_version: 1,
        genesis_id: "a".repeat(32),
        vault_id: "b".repeat(32),
        namespace_digest: digest("namespace"),
        administrator_commitment: digest("synthetic-administrator"),
        preparation_digest: digest("prepare"),
        activation_intent_digest: digest("intent"),
        artifact_set_digest: digest("artifact-set"),
        profile: vp_product_control::FRESH_TLS_RUNTIME_PROFILE.into(),
    }
}
fn identity() -> Identity {
    Identity {
        schema_version: SCHEMA,
        profile: PROFILE.into(),
        genesis: binding().digest().unwrap(),
        release_digest: digest("release"),
        core_digest: digest("core"),
        worker_digest: digest("worker3"),
        recipe_version: 2,
        worker_protocol_version: 3,
    }
}
fn private() -> tempfile::TempDir {
    let mut b = tempfile::Builder::new();
    b.permissions(fs::Permissions::from_mode(0o700));
    b.tempdir().unwrap()
}
fn cap(path: &Path) -> BoundDirectory {
    let id = DirectoryIdentity::of(&File::open(path).unwrap()).unwrap();
    BoundDirectory::admit(path, id).unwrap()
}
struct Lease {
    aggregate: TlsControlEnvelope,
}
impl Lease {
    fn initialized() -> Self {
        let mut aggregate = TlsControlEnvelope::preparing(binding()).unwrap();
        aggregate.mark_initialized().unwrap();
        Self { aggregate }
    }
}
impl WriterLease for Lease {
    fn state(&self) -> &vp_product_control::StoredState {
        self.aggregate.state()
    }
    fn tls_aggregate(&self) -> Option<&TlsControlEnvelope> {
        Some(&self.aggregate)
    }
    fn persist(
        &mut self,
        _: vp_product_control::StoredState,
        _: vp_product_control::JournalEvent,
    ) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
}
fn initialized(path: &Path) -> JournalInspection {
    let fresh = FreshJournalInspection::inspect_empty(cap(path), identity()).unwrap();
    fresh
        .initialize(&TlsControlEnvelope::preparing(binding()).unwrap())
        .map_err(|e| e.error().clone())
        .unwrap()
}
fn snapshot(path: &Path) -> Vec<(String, u64, u64, i64, i64, u32, Vec<u8>)> {
    fn walk(root: &Path, path: &Path, out: &mut Vec<(String, u64, u64, i64, i64, u32, Vec<u8>)>) {
        let m = fs::symlink_metadata(path).unwrap();
        out.push((
            path.strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.ctime(),
            m.mode(),
            if m.is_file() {
                fs::read(path).unwrap()
            } else {
                vec![]
            },
        ));
        if m.is_dir() {
            let mut children: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            children.sort();
            for p in children {
                walk(root, &p, out);
            }
        }
    }
    let mut out = vec![];
    walk(path, path, &mut out);
    out
}
#[test]
fn exact_inspection_is_read_only_and_holds_all_directory_leases() {
    let d = private();
    drop(initialized(d.path()));
    let before = snapshot(d.path());
    let inspection = JournalInspection::inspect(cap(d.path()), identity()).unwrap();
    assert_eq!(inspection.journal().unwrap().phase, Phase::Idle);
    assert_eq!(inspection.identity().unwrap(), &identity());
    assert!(cap(d.path()).lock().is_err());
    assert_eq!(snapshot(d.path()), before);
    drop(inspection);
    assert_eq!(snapshot(d.path()), before);
}
#[test]
fn wrong_identity_and_legacy_profile_refuse_without_writes() {
    let d = private();
    drop(initialized(d.path()));
    let before = snapshot(d.path());
    for which in 0..5 {
        let mut expected = identity();
        match which {
            0 => expected.genesis = digest("other"),
            1 => expected.worker_digest = digest("other"),
            2 => expected.release_digest = digest("other"),
            3 => expected.core_digest = digest("other"),
            _ => expected.worker_protocol_version = 2,
        }
        assert!(JournalInspection::inspect(cap(d.path()), expected).is_err());
        assert_eq!(snapshot(d.path()), before);
    }
    let marker = d.path().join(MARKER);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    value["schemaVersion"] = 2.into();
    value["profile"] = "vp.bound-runtime.v2".into();
    fs::write(marker, serde_json::to_vec(&value).unwrap()).unwrap();
    let old = snapshot(d.path());
    assert!(JournalInspection::inspect(cap(d.path()), identity()).is_err());
    assert_eq!(snapshot(d.path()), old);
}
#[test]
fn partial_roots_pending_entries_and_changed_binding_are_not_adopted_or_cleaned() {
    for name in [
        "runtime.profile.pending",
        "journal/runtime.journal.pending",
        "artifacts/artifacts.binding.pending",
    ] {
        let d = private();
        drop(initialized(d.path()));
        fs::write(d.path().join(name), b"uncertain").unwrap();
        let before = snapshot(d.path());
        assert!(JournalInspection::inspect(cap(d.path()), identity()).is_err());
        assert!(FreshJournalInspection::inspect_empty(cap(d.path()), identity()).is_err());
        assert_eq!(snapshot(d.path()), before);
    }
    for missing in [
        "runtime.journal.json",
        "journal/runtime.journal.json",
        "artifacts/artifacts.binding.json",
    ] {
        let d = private();
        drop(initialized(d.path()));
        fs::remove_file(d.path().join(missing)).unwrap();
        let before = snapshot(d.path());
        assert!(JournalInspection::inspect(cap(d.path()), identity()).is_err());
        assert_eq!(snapshot(d.path()), before);
    }
    let d = private();
    drop(initialized(d.path()));
    let mut wrong = artifact_binding(&identity());
    wrong.genesis = digest("wrong");
    fs::write(
        d.path().join("artifacts").join(ARTIFACT_BINDING),
        serde_json::to_vec(&wrong).unwrap(),
    )
    .unwrap();
    let before = snapshot(d.path());
    assert!(JournalInspection::inspect(cap(d.path()), identity()).is_err());
    assert_eq!(snapshot(d.path()), before);
}
#[test]
fn promotion_rechecks_current_writer_binding_and_retained_names() {
    let d = private();
    let inspection = initialized(d.path());
    let before = snapshot(d.path());
    let mut wrong = binding();
    wrong.genesis_id = "c".repeat(32);
    assert!(inspection.promote(&wrong, &Lease::initialized()).is_err());
    assert_eq!(snapshot(d.path()), before);
    let inspection = JournalInspection::inspect(cap(d.path()), identity()).unwrap();
    let preparing = Lease {
        aggregate: TlsControlEnvelope::preparing(binding()).unwrap(),
    };
    assert!(inspection.promote(&binding(), &preparing).is_err());
    assert_eq!(snapshot(d.path()), before);
    let inspection = JournalInspection::inspect(cap(d.path()), identity()).unwrap();
    let journal = d.path().join("journal").join(MARKER);
    let bytes = fs::read(&journal).unwrap();
    fs::remove_file(&journal).unwrap();
    fs::write(&journal, bytes).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(inspection
        .promote(&binding(), &Lease::initialized())
        .is_err());
}
#[test]
fn failed_initialization_at_every_durable_boundary_retains_residue_and_poison() {
    for stop in [
        InitializationBarrier::MarkerPublished,
        InitializationBarrier::JournalChildCreated,
        InitializationBarrier::ArtifactChildCreated,
        InitializationBarrier::ArtifactBindingPublished,
        InitializationBarrier::JournalPublished,
    ] {
        let d = private();
        let mut fresh = FreshJournalInspection::inspect_empty(cap(d.path()), identity()).unwrap();
        assert!(fresh
            .initialize_inner_using(&TlsControlEnvelope::preparing(binding()).unwrap(), |at| {
                if at == stop {
                    Err(ControlError::StorageUnavailable)
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(fresh.poisoned);
        assert!(fresh.check_empty().is_err());
        let before = snapshot(d.path());
        drop(fresh);
        assert!(FreshJournalInspection::inspect_empty(cap(d.path()), identity()).is_err());
        assert_eq!(snapshot(d.path()), before);
        assert!(d.path().join(MARKER).exists());
    }
}
#[test]
fn invalid_fresh_pairing_is_nonmutating_and_not_a_repair_retry() {
    let d = private();
    let fresh = FreshJournalInspection::inspect_empty(cap(d.path()), identity()).unwrap();
    let before = snapshot(d.path());
    let failure = fresh
        .initialize(&Lease::initialized().aggregate)
        .err()
        .unwrap();
    assert!(!failure.is_poisoned());
    assert_eq!(snapshot(d.path()), before);
    drop(failure);
    let fresh = FreshJournalInspection::inspect_empty(cap(d.path()), identity()).unwrap();
    fs::write(d.path().join("residue"), b"x").unwrap();
    let before = snapshot(d.path());
    assert!(fresh
        .initialize(&TlsControlEnvelope::preparing(binding()).unwrap())
        .is_err());
    assert_eq!(snapshot(d.path()), before);
}
#[test]
fn publication_failures_before_and_after_rename_poison_without_retry_or_cleanup() {
    // Model every existing atomic_file barrier using private injection. The
    // production publisher is always BoundDirectory::atomic_file, never callback.
    for barrier in 0..7 {
        let d = private();
        let inspection = initialized(d.path());
        let lease = Lease::initialized();
        let mut writer = inspection.promote(&binding(), &lease).unwrap();
        let old = writer.last_acknowledged().clone();
        let mut next = old.clone();
        next.sequence += 1;
        let pending = d.path().join("journal").join(PENDING);
        let destination = d.path().join("journal").join(MARKER);
        let result = writer.persist_next_using(next, &binding(), &lease, |root, bytes| {
            if barrier == 0 {
                return Err(ControlError::StorageUnavailable);
            }
            let mut file = root.create_file(PENDING)?;
            if barrier == 1 {
                return Err(ControlError::StorageUnavailable);
            }
            file.write_all(bytes).unwrap();
            if barrier == 2 {
                return Err(ControlError::StorageUnavailable);
            }
            file.sync_all().unwrap();
            if barrier == 3 {
                return Err(ControlError::StorageUnavailable);
            }
            root.sync()?;
            if barrier == 4 {
                return Err(ControlError::StorageUnavailable);
            }
            fs::rename(&pending, &destination).unwrap();
            if barrier == 5 {
                return Err(ControlError::StorageUnavailable);
            }
            root.sync()?;
            Err(ControlError::StorageUnavailable)
        });
        assert!(result.is_err());
        assert!(writer.is_poisoned());
        assert_eq!(writer.last_acknowledged(), &old);
        let after = snapshot(d.path());
        assert!(writer.persist_finalization(&binding(), &lease).is_err());
        assert_eq!(snapshot(d.path()), after);
        drop(writer);
        assert_eq!(snapshot(d.path()), after);
        if (1..=4).contains(&barrier) {
            assert!(pending.exists());
            assert!(JournalInspection::inspect(cap(d.path()), identity()).is_err());
        }
    }
}
#[test]
fn successful_atomic_publication_replaces_snapshot_only_after_acknowledged_barriers() {
    let d = private();
    let lease = Lease::initialized();
    let mut writer = initialized(d.path()).promote(&binding(), &lease).unwrap();
    let mut next = writer.last_acknowledged().clone();
    next.sequence = 1;
    writer
        .persist_next(next.clone(), &binding(), &lease)
        .unwrap();
    assert!(!writer.is_poisoned());
    assert_eq!(writer.last_acknowledged(), &next);
    assert!(!d.path().join("journal").join(PENDING).exists());
    drop(writer);
    assert_eq!(
        JournalInspection::inspect(cap(d.path()), identity())
            .unwrap()
            .journal()
            .unwrap(),
        &next
    );
}
#[test]
fn invalid_proposal_does_not_write_and_inventory_drift_poisons_before_publication() {
    let d = private();
    let lease = Lease::initialized();
    let mut writer = initialized(d.path()).promote(&binding(), &lease).unwrap();
    let before = snapshot(d.path());
    assert!(writer
        .persist_event(Event::Activate, &binding(), &lease)
        .is_err());
    assert!(!writer.is_poisoned());
    assert_eq!(snapshot(d.path()), before);
    fs::write(d.path().join("journal").join(PENDING), b"unknown").unwrap();
    let before = snapshot(d.path());
    let mut next = writer.last_acknowledged().clone();
    next.sequence = 1;
    assert!(writer.persist_next(next, &binding(), &lease).is_err());
    assert!(writer.is_poisoned());
    assert_eq!(snapshot(d.path()), before);
}

#[test]
fn resource_field_declarations_keep_runtime_root_lease_last() {
    // Rust specifies declaration-order field destruction. This source regression
    // checks that contract directly instead of claiming scheduler-sensitive drop
    // timing proves a concurrent owner could never acquire the root too early.
    let source = include_str!("mod.rs");
    let inspection = source
        .split_once("pub struct JournalInspection {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    let journal_child = inspection.find("journal_root: BoundDirectory,").unwrap();
    let artifact_child = inspection.find("artifact_root: BoundDirectory,").unwrap();
    let root = inspection.rfind("    root: BoundDirectory,").unwrap();
    for field in [
        "marker_file:",
        "journal_file:",
        "binding_file:",
        "artifact_files:",
    ] {
        let position = inspection.find(field).unwrap();
        assert!(position < journal_child && position < artifact_child);
    }
    assert!(journal_child < root && artifact_child < root);
    assert!(inspection.trim_end().ends_with("root: BoundDirectory,"));
    let fresh = source
        .split_once("pub struct FreshJournalInspection {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    let root = fresh.rfind("    root: Option<BoundDirectory>,").unwrap();
    assert!(fresh.find("journal_root:").unwrap() < root);
    assert!(fresh.find("artifact_root:").unwrap() < root);
    assert!(fresh.trim_end().ends_with("root: Option<BoundDirectory>,"));
    // Writable and failed-initialization wrappers contain their entire resource
    // tree in these ordered owners, rather than adding an earlier root handle.
    let writer = source
        .split_once("pub struct JournalPersistence {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    assert!(writer.contains("inspection: JournalInspection,"));
    assert!(!writer.contains("BoundDirectory"));
    let failure = source
        .split_once("pub struct InitializationFailure {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    assert!(failure.contains("reservation: FreshJournalInspection,"));
    assert!(!failure.contains("BoundDirectory"));
}

use vp_product_compiler::server_v2::{ServerCompilerV2, ServerRecipeV2};
use vp_product_domain::*;
fn synthetic_release() -> ReleaseIdentity {
    ReleaseIdentity {
        release_id: ReleaseId::new("journal3-source-test").unwrap(),
        product_version: "0.1-test".into(),
        adapter_version: "0.1-test".into(),
        core_commit: "a".repeat(40),
        patchset_hash: Some("b".repeat(64)),
        build_target: "x86_64-linux".into(),
        toolchain: "unit-only".into(),
        schema_read: CompatibilityRange {
            minimum: 1,
            maximum: 1,
        },
        schema_write: CompatibilityRange {
            minimum: 1,
            maximum: 1,
        },
        abi: VersionPair {
            major: ABI_MAJOR,
            minor: ABI_MINOR,
        },
        api: VersionPair { major: 1, minor: 0 },
        evidence_manifest_hash: None,
    }
}
fn compiled_recipe() -> ServerRecipeV2 {
    let release = synthetic_release();
    let config = ProductConfig {
        schema_version: 1,
        minimum_reader_version: 1,
        nodes: vec![],
        subscriptions: vec![],
        listeners: vec![ServerListener {
            schema_version: 1,
            id: ListenerId::new("listener-1").unwrap(),
            name: "synthetic-journal-test".into(),
            enabled: true,
            bind: BindAddress {
                address: "127.0.0.1".parse().unwrap(),
                port: 19001,
            },
            protocol: ServerProtocol::Proxy {
                protocol: Protocol::Trojan {},
                users: vec![ListenerUser {
                    id: UserId::new("user-1").unwrap(),
                    credential_ref: SecretRef::new("credential-1").unwrap(),
                    enabled: true,
                }],
            },
            transport: Transport::Tcp {},
            security: ServerSecurity::Tls {
                certificate_ref: CertificateId::new("cert-1").unwrap(),
                private_key_ref: SecretRef::new("key-1").unwrap(),
                alpn: vec![],
            },
            requirements: vec![CapabilityKey::TrojanTls],
        }],
    };
    ServerCompilerV2::for_loopback_development(release.clone())
        .unwrap()
        .compile(&config, &release)
        .unwrap()
}

fn nonempty_fixture(path: &Path) -> (Identity, Journal, Vec<u8>) {
    let recipe = compiled_recipe();
    let bytes = serde_json::to_vec(&recipe).unwrap();
    let mut id = identity();
    id.release_digest = ContentDigest::of("vp.release-identity.v1", &recipe.release).unwrap();
    id.core_digest = core_digest(&recipe.release).unwrap();
    let fresh = FreshJournalInspection::inspect_empty(cap(path), id.clone()).unwrap();
    drop(
        fresh
            .initialize(&TlsControlEnvelope::preparing(binding()).unwrap())
            .map_err(|e| e.error().clone())
            .unwrap(),
    );
    let associated = RecipeIdentity {
        revision_owner_operation: OperationId::new("original-operation").unwrap(),
        revision: Revision::ZERO.next().unwrap(),
        config_digest: ContentDigest::of("vp.product-config.v1", &recipe.source).unwrap(),
        release_digest: id.release_digest.clone(),
        recipe_digest: ContentDigest::bytes(&bytes),
    };
    let mut journal = Journal::empty(id.clone()).unwrap();
    journal.sequence = 1;
    journal.high_water = 1;
    journal.active = Some(OwnedRecord {
        launch: LaunchRecord {
            recipe: associated.clone(),
            transition_operation: associated.revision_owner_operation.clone(),
            generation: 1,
            instance: "synthetic-instance-1".into(),
            session: "synthetic-session".into(),
            worker_digest: id.worker_digest.clone(),
            worker_protocol_version: 3,
        },
        process: ProcessIdentity {
            pid: 12345,
            start_ticks: "1".into(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        },
    });
    // Seed a reference-only artifact and historical journal fixture directly;
    // this is not an implemented artifact publication or process-admission API.
    let artifact = path
        .join("artifacts")
        .join(associated.recipe_digest.as_str());
    fs::write(&artifact, &bytes).unwrap();
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path.join("journal").join(MARKER), journal.encode().unwrap()).unwrap();
    (id, journal, bytes)
}
#[test]
fn nonempty_reference_recipe_inspection_is_exact_and_read_only() {
    let d = private();
    let (id, journal, _) = nonempty_fixture(d.path());
    let before = snapshot(d.path());
    let inspection = JournalInspection::inspect(cap(d.path()), id).unwrap();
    assert_eq!(inspection.journal().unwrap(), &journal);
    assert_eq!(inspection.artifact_files.len(), 1);
    assert_eq!(snapshot(d.path()), before);
    drop(inspection);
    assert_eq!(snapshot(d.path()), before);
}
#[test]
fn event_generated_journal_cannot_relabel_reference_recipe_config_identity() {
    let d = private();
    let (id, journal, _) = nonempty_fixture(d.path());
    let previous = journal.active.as_ref().unwrap().launch.recipe.clone();
    let mut candidate = previous.clone();
    candidate.revision = candidate.revision.next().unwrap();
    candidate.revision_owner_operation = OperationId::new("candidate-operation").unwrap();
    candidate.config_digest = digest("wrong-config-association");
    let next = journal
        .propose(Event::Begin {
            operation: Box::new(OperationRecord {
                operation: candidate.revision_owner_operation.clone(),
                plan_id: PlanId::new("candidate-plan").unwrap(),
                plan_hash: digest("synthetic-plan"),
                principal: UserId::new("candidate-owner").unwrap(),
                base_revision: previous.revision,
                candidate,
                previous: Some(previous),
                admitted_high_water: 1,
            }),
            instance: "synthetic-instance-2".into(),
            session: "synthetic-session".into(),
        })
        .unwrap();
    fs::write(
        d.path().join("journal").join(MARKER),
        next.encode().unwrap(),
    )
    .unwrap();
    let before = snapshot(d.path());
    assert!(
        JournalInspection::inspect(cap(d.path()), id).is_err(),
        "recipe bytes cannot be relabeled by an otherwise-valid journal transition"
    );
    assert_eq!(snapshot(d.path()), before);
}

#[test]
fn staged_recipe_is_durable_idempotent_and_rejects_wrong_bytes() {
    use vp_product_control::{ChangePlan, Operation, OperationState, PlanBody, RestartImpact, ValidationReceipt};
    let d = private();
    let recipe = compiled_recipe();
    let bytes = serde_json::to_vec(&recipe).unwrap();
    let digest = ContentDigest::bytes(&bytes);
    let mut id = identity();
    id.release_digest = ContentDigest::of("vp.release-identity.v1", &recipe.release).unwrap();
    id.core_digest = core_digest(&recipe.release).unwrap();
    let fresh = FreshJournalInspection::inspect_empty(cap(d.path()), id.clone()).unwrap();
    let inspection = fresh.initialize(&TlsControlEnvelope::preparing(binding()).unwrap()).map_err(|e| e.error().clone()).unwrap();
    let mut persistence = inspection.promote(&binding(), &Lease::initialized()).unwrap();
    let operation = OperationId::new("staging-operation").unwrap();
    let plan_id = PlanId::new("staging-plan").unwrap();
    let principal = UserId::new("staging-user").unwrap();
    let body = PlanBody { schema_version: 1, id: plan_id.clone(), principal: principal.clone(), base_revision: Revision::ZERO, target_revision: Revision::ZERO.next().unwrap(), created_at_ms: 1, expires_at_ms: 10000, config: recipe.source.clone(), release: recipe.release.clone(), validation: ValidationReceipt { config_digest: ContentDigest::of("vp.product-config.v1", &recipe.source).unwrap(), release_digest: id.release_digest.clone(), artifact_digest: digest.clone(), impact: RestartImpact::ControlledRestart, required_health: Default::default() }, resources: vec![] };
    let hash = ContentDigest::of("vp.change-plan.v1", &body).unwrap();
    let plan: ChangePlan = serde_json::from_value(serde_json::json!({"body":body,"hash":hash})).unwrap();
    let mut lease = Lease::initialized();
    let mut state = lease.aggregate.state().clone();
    state.plans.insert(plan_id.clone(), plan);
    state.operations.insert(operation.clone(), Operation { id: operation.clone(), plan_id, principal, state: OperationState::Staging, created_at_ms: 1, updated_at_ms: 1, snapshot: None, failure: None, health: None, activation: None, cancel_requested: false, mutation_started: false });
    state.version += 1;
    lease.aggregate = lease.aggregate.with_ordinary_state(state).unwrap();
    assert!(persistence.store_staged_recipe(b"bad", &operation, &binding(), &lease).is_err());
    assert_eq!(persistence.store_staged_recipe(&bytes, &operation, &binding(), &lease).unwrap(), digest);
    assert_eq!(persistence.store_staged_recipe(&bytes, &operation, &binding(), &lease).unwrap(), digest);
    assert_eq!(fs::read(d.path().join("artifacts").join(digest.as_str())).unwrap(), bytes);
    // Synthetic control state and current test process: exercises persistence
    // ordering only, not ownership of a real service worker.
    let plan = lease.state().plans.values().next().unwrap();
    let candidate = RecipeIdentity { revision_owner_operation: operation.clone(), revision: plan.body().target_revision, config_digest: plan.body().validation.config_digest.clone(), release_digest: plan.body().validation.release_digest.clone(), recipe_digest: digest };
    let record = OperationRecord { operation: operation.clone(), plan_id: plan.body().id.clone(), plan_hash: plan.hash().clone(), principal: plan.body().principal.clone(), base_revision: plan.body().base_revision, candidate, previous: None, admitted_high_water: 0 };
    persistence.persist_event(Event::Begin { operation: Box::new(record), instance: "test-instance".into(), session: "test-session".into() }, &binding(), &lease).unwrap();
    assert_eq!(persistence.last_acknowledged().phase, Phase::CandidateReserved);
    persistence.persist_event(Event::SpawnObserved(ProcessIdentity::observe(std::process::id()).unwrap()), &binding(), &lease).unwrap();
    persistence.persist_event(Event::Prepared, &binding(), &lease).unwrap();
    assert!(!persistence.is_poisoned());
    drop(persistence);
    let inspection = JournalInspection::inspect(cap(d.path()), id).unwrap();
    assert_eq!(inspection.artifact_files.len(), 1);
    assert_eq!(inspection.journal().unwrap().phase, Phase::Prepared);
}
