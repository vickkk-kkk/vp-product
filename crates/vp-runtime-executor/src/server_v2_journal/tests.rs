#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Synthetic in-memory records only: no filesystem, worker, vault or network.
use super::*;
use std::collections::BTreeMap;
use vp_product_compiler::server_v2::{ServerCompilerV2, ServerRecipeV2};
use vp_product_domain::*;

fn digest(s: &str) -> ContentDigest {
    ContentDigest::bytes(s.as_bytes())
}
fn operation(s: &str) -> OperationId {
    OperationId::new(s).unwrap()
}
fn revision(n: u64) -> Revision {
    (0..n).fold(Revision::ZERO, |r, _| r.next().unwrap())
}
fn identity() -> Identity {
    Identity {
        schema_version: 3,
        profile: PROFILE.into(),
        genesis: digest("genesis"),
        release_digest: digest("release"),
        core_digest: digest("core"),
        worker_digest: digest("worker3"),
        recipe_version: 2,
        worker_protocol_version: 3,
    }
}
fn recipe(owner: &str, n: u64) -> RecipeIdentity {
    RecipeIdentity {
        revision_owner_operation: operation(owner),
        revision: revision(n),
        config_digest: digest(&format!("config-{n}")),
        release_digest: identity().release_digest,
        recipe_digest: digest(&format!("recipe-{n}")),
    }
}
fn launch(r: RecipeIdentity, transition: &str, generation: u64) -> LaunchRecord {
    LaunchRecord {
        recipe: r,
        transition_operation: operation(transition),
        generation,
        instance: format!("instance-{generation}"),
        session: "session-1".into(),
        worker_digest: identity().worker_digest,
        worker_protocol_version: 3,
    }
}
fn process(generation: u64) -> ProcessIdentity {
    ProcessIdentity {
        pid: 1000 + generation as u32,
        start_ticks: (100 + generation).to_string(),
        boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
    }
}
fn owned(r: RecipeIdentity, transition: &str, generation: u64) -> OwnedRecord {
    OwnedRecord {
        launch: launch(r, transition, generation),
        process: process(generation),
    }
}
fn fixture(phase: Phase) -> Journal {
    let previous = recipe("old-operation", 1);
    let candidate = recipe("new-operation", 2);
    let old = owned(previous.clone(), "old-operation", 3);
    let new = owned(candidate.clone(), "new-operation", 4);
    let restored = owned(previous.clone(), "new-operation", 5);
    let mut j = Journal::empty(identity()).unwrap();
    j.phase = phase;
    j.sequence = 20;
    j.high_water = 4;
    if phase != Phase::Idle {
        j.operation = Some(OperationRecord {
            operation: operation("new-operation"),
            plan_id: PlanId::new("new-plan").unwrap(),
            plan_hash: digest("plan"),
            principal: UserId::new("new-owner").unwrap(),
            base_revision: revision(1),
            candidate,
            previous: Some(previous),
            admitted_high_water: 3,
        });
    }
    use Phase::*;
    match phase {
        Idle => {
            j.active = Some(old);
            j.high_water = 3;
        }
        CandidateReserved | CandidateSpawnObserved => {
            j.active = Some(old);
            j.launch_intent = Some(LaunchIntent {
                role: Role::Candidate,
                launch: new.launch,
                process: (phase == CandidateSpawnObserved).then_some(new.process),
            });
        }
        Prepared | StoppingOld | DiscardingPrepared => {
            j.active = Some(old);
            j.prepared = Some(new);
            let action = match phase {
                StoppingOld => Some(Action::StopOld),
                DiscardingPrepared => Some(Action::DiscardPrepared),
                _ => None,
            };
            if let Some(action) = action {
                j.transition = Some(TransitionIntent {
                    action,
                    transition_operation: operation("new-operation"),
                    generation: if action == Action::StopOld { 3 } else { 4 },
                });
            }
        }
        OldStopped | ActivatingCandidate => {
            j.prepared = Some(new);
            if phase == ActivatingCandidate {
                j.transition = Some(TransitionIntent {
                    action: Action::ActivateCandidate,
                    transition_operation: operation("new-operation"),
                    generation: 4,
                });
            }
        }
        CandidateStarted | StoppingCandidate => {
            j.active = Some(new);
            if phase == StoppingCandidate {
                j.transition = Some(TransitionIntent {
                    action: Action::StopCandidate,
                    transition_operation: operation("new-operation"),
                    generation: 4,
                });
            }
        }
        CandidateAbsent => {}
        RestoreReserved | RestoreSpawnObserved => {
            j.high_water = 5;
            j.launch_intent = Some(LaunchIntent {
                role: Role::RestorePrevious,
                launch: restored.launch,
                process: (phase == RestoreSpawnObserved).then_some(restored.process),
            });
        }
        RestorePrepared | ActivatingRestore => {
            j.high_water = 5;
            j.prepared = Some(restored);
            if phase == ActivatingRestore {
                j.transition = Some(TransitionIntent {
                    action: Action::ActivateRestore,
                    transition_operation: operation("new-operation"),
                    generation: 5,
                });
            }
        }
        Restored => {
            j.high_water = 5;
            j.active = Some(restored);
        }
    }
    j
}
const PHASES: [Phase; 16] = [
    Phase::Idle,
    Phase::CandidateReserved,
    Phase::CandidateSpawnObserved,
    Phase::Prepared,
    Phase::StoppingOld,
    Phase::OldStopped,
    Phase::ActivatingCandidate,
    Phase::CandidateStarted,
    Phase::StoppingCandidate,
    Phase::DiscardingPrepared,
    Phase::CandidateAbsent,
    Phase::RestoreReserved,
    Phase::RestoreSpawnObserved,
    Phase::RestorePrepared,
    Phase::ActivatingRestore,
    Phase::Restored,
];

#[test]
fn every_reviewed_phase_is_valid_and_canonically_roundtrips() {
    for phase in PHASES {
        let j = fixture(phase);
        assert_eq!(j.validate(), Ok(()), "{phase:?}");
        let bytes = j.encode().unwrap();
        assert_eq!(
            Journal::decode(&bytes, &j.identity).unwrap(),
            j,
            "{phase:?}"
        );
    }
    let empty = Journal::empty(identity()).unwrap();
    assert_eq!(
        Journal::decode(&empty.encode().unwrap(), &empty.identity).unwrap(),
        empty
    );
}

#[test]
fn operation_and_optional_slot_presence_matrix_is_exhaustive() {
    for phase in PHASES {
        let reference = fixture(phase);
        for mask in 0_u8..32 {
            let mut j = reference.clone();
            j.operation = (mask & 1 != 0).then(|| fixture(Phase::Prepared).operation.unwrap());
            j.active = (mask & 2 != 0).then(|| {
                reference
                    .active
                    .clone()
                    .unwrap_or_else(|| fixture(Phase::Prepared).active.unwrap())
            });
            j.prepared = (mask & 4 != 0).then(|| {
                reference
                    .prepared
                    .clone()
                    .unwrap_or_else(|| fixture(Phase::Prepared).prepared.unwrap())
            });
            j.launch_intent = (mask & 8 != 0).then(|| {
                reference
                    .launch_intent
                    .clone()
                    .unwrap_or_else(|| fixture(Phase::CandidateReserved).launch_intent.unwrap())
            });
            j.transition = (mask & 16 != 0).then(|| {
                reference
                    .transition
                    .clone()
                    .unwrap_or_else(|| fixture(Phase::StoppingOld).transition.unwrap())
            });
            let exact = j == reference;
            let legal_missing_old =
                matches!(phase, Phase::DiscardingPrepared | Phase::CandidateAbsent)
                    && j.active.is_none()
                    && {
                        let mut without_old = reference.clone();
                        without_old.active = None;
                        j == without_old
                    };
            let legal_retained_old = phase == Phase::CandidateAbsent && j.active.is_some() && {
                let mut with_old = reference.clone();
                with_old.active = fixture(Phase::Prepared).active;
                j == with_old
            };
            assert_eq!(
                j.validate().is_ok(),
                exact
                    || legal_missing_old
                    || legal_retained_old
                    || (phase == Phase::Idle && mask == 0),
                "phase={phase:?}, mask={mask:05b}"
            );
        }
    }
}

#[test]
fn every_nonidle_phase_requires_operation_and_exact_recipe_owner() {
    for phase in PHASES.into_iter().filter(|p| *p != Phase::Idle) {
        let mut j = fixture(phase);
        j.operation = None;
        assert!(j.validate().is_err(), "{phase:?}");
        let mut j = fixture(phase);
        j.operation
            .as_mut()
            .unwrap()
            .candidate
            .revision_owner_operation = operation("wrong-owner");
        assert!(j.validate().is_err(), "{phase:?}");
        let mut j = fixture(phase);
        j.operation
            .as_mut()
            .unwrap()
            .previous
            .as_mut()
            .unwrap()
            .revision_owner_operation = operation("new-operation");
        assert!(j.validate().is_err(), "{phase:?}");
    }
}

#[test]
fn exact_process_identity_and_nonaliasing_are_mandatory() {
    let bad_processes = [
        ProcessIdentity {
            pid: 0,
            ..process(4)
        },
        ProcessIdentity {
            start_ticks: "001".into(),
            ..process(4)
        },
        ProcessIdentity {
            start_ticks: "18446744073709551616".into(),
            ..process(4)
        },
        ProcessIdentity {
            boot_id: "not-a-boot-id".into(),
            ..process(4)
        },
        ProcessIdentity {
            boot_id: "01234567-89AB-cdef-0123-456789abcdef".into(),
            ..process(4)
        },
    ];
    for process in bad_processes {
        let mut j = fixture(Phase::Prepared);
        j.prepared.as_mut().unwrap().process = process;
        assert!(j.validate().is_err());
    }
    let mut j = fixture(Phase::Prepared);
    j.prepared.as_mut().unwrap().process.pid = j.active.as_ref().unwrap().process.pid;
    assert!(j.validate().is_err());
    let mut j = fixture(Phase::Prepared);
    j.prepared.as_mut().unwrap().launch.instance =
        j.active.as_ref().unwrap().launch.instance.clone();
    assert!(j.validate().is_err());
    let mut j = fixture(Phase::CandidateReserved);
    j.launch_intent.as_mut().unwrap().process = Some(process(4));
    assert!(j.validate().is_err());
    let mut j = fixture(Phase::CandidateSpawnObserved);
    j.launch_intent.as_mut().unwrap().process = None;
    assert!(j.validate().is_err());
}

#[test]
fn identity_generation_role_and_transition_mutations_fail_closed() {
    for phase in PHASES {
        let mut j = fixture(phase);
        j.identity.schema_version = 2;
        assert!(j.validate().is_err());
        let mut j = fixture(phase);
        j.identity.profile = "vp.bound-runtime.v2".into();
        assert!(j.validate().is_err());
        let mut j = fixture(phase);
        j.identity.worker_protocol_version = 2;
        assert!(j.validate().is_err());
        let mut j = fixture(phase);
        j.identity.recipe_version = 1;
        assert!(j.validate().is_err());
        let mut j = fixture(phase);
        j.high_water = 0;
        assert!(j.validate().is_err());
        let mut j = fixture(phase);
        j.sequence = MAX_WIRE_COUNTER + 1;
        assert!(j.validate().is_err());
    }
    for phase in PHASES
        .into_iter()
        .filter(|p| !matches!(p, Phase::Idle | Phase::CandidateAbsent))
    {
        let mut j = fixture(phase);
        j.high_water += 1;
        assert!(
            j.validate().is_err(),
            "unreachable unused reservation in {phase:?}"
        );
    }
    for phase in [
        Phase::CandidateReserved,
        Phase::CandidateSpawnObserved,
        Phase::RestoreReserved,
        Phase::RestoreSpawnObserved,
    ] {
        let mut j = fixture(phase);
        let intent = j.launch_intent.as_mut().unwrap();
        intent.role = if intent.role == Role::Candidate {
            Role::RestorePrevious
        } else {
            Role::Candidate
        };
        assert!(j.validate().is_err());
    }
    for phase in [
        Phase::StoppingOld,
        Phase::ActivatingCandidate,
        Phase::StoppingCandidate,
        Phase::DiscardingPrepared,
        Phase::ActivatingRestore,
    ] {
        let mut j = fixture(phase);
        j.transition.as_mut().unwrap().generation += 1;
        assert!(j.validate().is_err());
        let mut j = fixture(phase);
        j.transition.as_mut().unwrap().transition_operation = operation("wrong-operation");
        assert!(j.validate().is_err());
    }
}

#[test]
fn codec_refuses_wrong_genesis_old_profiles_unknown_duplicate_and_noncanonical_bytes() {
    let j = fixture(Phase::Prepared);
    let bytes = j.encode().unwrap();
    for change in 0..4 {
        let mut expected = j.identity.clone();
        match change {
            0 => expected.genesis = digest("other-genesis"),
            1 => expected.worker_digest = digest("other-worker"),
            2 => expected.core_digest = digest("other-core"),
            _ => expected.release_digest = digest("other-release"),
        }
        assert!(Journal::decode(&bytes, &expected).is_err());
    }
    let text = String::from_utf8(bytes.clone()).unwrap();
    let duplicate = format!("{{\"schemaVersion\":3,{}", &text[1..]);
    assert!(Journal::decode(duplicate.as_bytes(), &j.identity).is_err());
    let unknown = format!("{{\"unknown\":true,{}", &text[1..]);
    assert!(Journal::decode(unknown.as_bytes(), &j.identity).is_err());
    assert!(Journal::decode(format!(" {text}").as_bytes(), &j.identity).is_err());
    assert!(Journal::decode(format!("{text}\n").as_bytes(), &j.identity).is_err());
    assert!(Journal::decode(&bytes[..bytes.len() - 1], &j.identity).is_err());
    assert!(Journal::decode(&vec![b' '; MAX_JOURNAL_BYTES + 1], &j.identity).is_err());
    assert!(Journal::decode(b"{}", &j.identity).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["schemaVersion"] = 2.into();
    assert!(Journal::decode(&serde_json::to_vec(&value).unwrap(), &j.identity).is_err());
}

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
fn recipe_journal() -> (Journal, BTreeMap<ContentDigest, Vec<u8>>) {
    let recipe = compiled_recipe();
    let bytes = serde_json::to_vec(&recipe).unwrap();
    let recipe_digest = ContentDigest::bytes(&bytes);
    let release_digest = ContentDigest::of("vp.release-identity.v1", &recipe.release).unwrap();
    let config_digest = ContentDigest::of("vp.product-config.v1", &recipe.source).unwrap();
    let mut j = fixture(Phase::CandidateStarted);
    j.identity.release_digest = release_digest.clone();
    j.identity.core_digest = core_digest(&recipe.release).unwrap();
    let exact = RecipeIdentity {
        revision_owner_operation: operation("new-operation"),
        revision: revision(2),
        config_digest,
        release_digest: release_digest.clone(),
        recipe_digest: recipe_digest.clone(),
    };
    j.active.as_mut().unwrap().launch.recipe = exact.clone();
    let o = j.operation.as_mut().unwrap();
    o.candidate = exact.clone();
    let mut previous = exact;
    previous.revision = revision(1);
    previous.revision_owner_operation = operation("old-operation");
    o.previous = Some(previous);
    (j, BTreeMap::from([(recipe_digest, bytes)]))
}
#[test]
fn recipe_associations_recompile_exact_bytes_and_refuse_tampering() {
    let (j, artifacts) = recipe_journal();
    assert!(verify_recipes(&j, &artifacts).is_ok());
    assert!(verify_recipes(&j, &BTreeMap::new()).is_err());
    let mut wrong = artifacts.clone();
    wrong.values_mut().next().unwrap().push(b' ');
    assert!(verify_recipes(&j, &wrong).is_err());
    let mut wrong = j.clone();
    wrong
        .operation
        .as_mut()
        .unwrap()
        .previous
        .as_mut()
        .unwrap()
        .config_digest = digest("wrong-config");
    assert!(verify_recipes(&wrong, &artifacts).is_err());
    let mut wrong = j.clone();
    wrong.active.as_mut().unwrap().launch.recipe.release_digest = digest("wrong-release");
    assert!(verify_recipes(&wrong, &artifacts).is_err());
    let mut wrong = artifacts;
    *wrong.values_mut().next().unwrap() = vec![b' '; MAX_RECIPE_BYTES + 1];
    assert!(verify_recipes(&j, &wrong).is_err());
}

fn events_for(j: &Journal) -> Vec<Event> {
    vec![
        Event::Begin {
            operation: Box::new(fixture(Phase::Prepared).operation.unwrap()),
            instance: "instance-4".into(),
            session: "session-1".into(),
        },
        Event::SpawnObserved(process(j.high_water)),
        Event::Prepared,
        Event::StopOld,
        Event::OldStopped,
        Event::Activate,
        Event::Activated,
        Event::StopCandidate,
        Event::CandidateStopped,
        Event::Discard,
        Event::Discarded,
        Event::FailedChildAbsent,
        Event::Restore {
            instance: "restore-instance".into(),
            session: "session-1".into(),
        },
        Event::RestoreStopped,
    ]
}
#[test]
fn transition_phase_event_matrix_rejects_every_unlisted_edge() {
    for phase in PHASES {
        let j = fixture(phase);
        let before = j.clone();
        for (index, event) in events_for(&j).into_iter().enumerate() {
            use Phase::*;
            let legal = match index {
                0 => phase == Idle,
                1 => matches!(phase, CandidateReserved | RestoreReserved),
                2 => matches!(phase, CandidateSpawnObserved | RestoreSpawnObserved),
                3 => phase == Prepared,
                4 => phase == StoppingOld,
                5 => matches!(phase, OldStopped | RestorePrepared),
                6 => matches!(phase, ActivatingCandidate | ActivatingRestore),
                7 => phase == CandidateStarted,
                8 => phase == StoppingCandidate,
                9 => matches!(phase, Prepared | OldStopped),
                10 => phase == DiscardingPrepared,
                11 => matches!(
                    phase,
                    CandidateSpawnObserved
                        | RestoreSpawnObserved
                        | ActivatingCandidate
                        | ActivatingRestore
                        | RestorePrepared
                ),
                12 => phase == CandidateAbsent,
                _ => false,
            };
            let result = j.propose(event);
            assert_eq!(result.is_ok(), legal, "phase={phase:?} event={index}");
            if let Ok(next) = result {
                assert_eq!(next.sequence, j.sequence + 1);
                assert!(next.validate().is_ok());
            }
            assert_eq!(j, before, "proposals never mutate the input");
        }
    }
}
#[test]
fn pure_lifecycle_retains_old_during_prepare_and_restores_original_owner_with_new_generation() {
    let idle = fixture(Phase::Idle);
    let op = fixture(Phase::Prepared).operation.unwrap();
    let reserved = idle
        .propose(Event::Begin {
            operation: Box::new(op),
            instance: "instance-4".into(),
            session: "session-1".into(),
        })
        .unwrap();
    assert_eq!(reserved.high_water, 4);
    assert_eq!(reserved.active, idle.active);
    assert!(
        reserved.propose(Event::Prepared).is_err(),
        "PID observer precedes preparation"
    );
    assert!(
        reserved.propose(Event::FailedChildAbsent).is_err(),
        "unknown launch cannot be declared absent"
    );
    let prepared = reserved
        .propose(Event::SpawnObserved(process(4)))
        .unwrap()
        .propose(Event::Prepared)
        .unwrap();
    assert_eq!(prepared.active, idle.active);
    assert!(
        prepared.propose(Event::Activate).is_err(),
        "cannot overlap bound old and new"
    );
    let stopping = prepared.propose(Event::StopOld).unwrap();
    assert!(
        stopping.propose(Event::Activate).is_err(),
        "stop intent is not exit proof"
    );
    let activating = stopping
        .propose(Event::OldStopped)
        .unwrap()
        .propose(Event::Activate)
        .unwrap();
    assert!(
        activating.propose(Event::Activate).is_err(),
        "one-use activation cannot replay"
    );
    let active = activating.propose(Event::Activated).unwrap();
    assert!(active.prepared.is_none());
    assert_eq!(active.active.as_ref().unwrap().launch.generation, 4);
    let absent = active
        .propose(Event::StopCandidate)
        .unwrap()
        .propose(Event::CandidateStopped)
        .unwrap();
    let restore = absent
        .propose(Event::Restore {
            instance: "instance-5".into(),
            session: "session-1".into(),
        })
        .unwrap();
    assert_eq!(restore.high_water, 5);
    let intent = restore.launch_intent.as_ref().unwrap();
    assert_eq!(
        intent.launch.transition_operation,
        operation("new-operation")
    );
    assert_eq!(
        intent.launch.recipe.revision_owner_operation,
        operation("old-operation")
    );
    let restored = restore
        .propose(Event::SpawnObserved(process(5)))
        .unwrap()
        .propose(Event::Prepared)
        .unwrap()
        .propose(Event::Activate)
        .unwrap()
        .propose(Event::Activated)
        .unwrap();
    assert_eq!(restored.phase, Phase::Restored);
    assert_eq!(
        restored.active.as_ref().unwrap().launch.recipe,
        idle.active.as_ref().unwrap().launch.recipe
    );
    assert_ne!(
        restored.active.as_ref().unwrap().process,
        idle.active.as_ref().unwrap().process
    );
}
#[test]
fn stopped_base_compensation_does_not_invent_previous_material_or_generation() {
    let idle = Journal::empty(identity()).unwrap();
    let mut op = fixture(Phase::Prepared).operation.unwrap();
    op.base_revision = Revision::ZERO;
    op.previous = None;
    op.admitted_high_water = 0;
    op.candidate.revision = revision(1);
    let reserved = idle
        .propose(Event::Begin {
            operation: Box::new(op),
            instance: "instance-1".into(),
            session: "session-1".into(),
        })
        .unwrap();
    let prepared = reserved
        .propose(Event::SpawnObserved(process(1)))
        .unwrap()
        .propose(Event::Prepared)
        .unwrap();
    assert!(prepared.active.is_none());
    let activated = prepared
        .propose(Event::Activate)
        .unwrap()
        .propose(Event::Activated)
        .unwrap();
    let absent = activated
        .propose(Event::StopCandidate)
        .unwrap()
        .propose(Event::CandidateStopped)
        .unwrap();
    assert!(absent
        .propose(Event::Restore {
            instance: "invented".into(),
            session: "session-1".into()
        })
        .is_err());
    let restored = absent.propose(Event::RestoreStopped).unwrap();
    assert_eq!(restored.phase, Phase::Restored);
    assert!(restored.active.is_none());
    assert_eq!(restored.high_water, 1);
}
#[test]
fn counters_are_checked_without_wrap_and_failed_attempts_burn_generations() {
    let mut idle = fixture(Phase::Idle);
    idle.high_water = MAX_WIRE_COUNTER;
    idle.sequence = MAX_WIRE_COUNTER;
    let mut op = fixture(Phase::Prepared).operation.unwrap();
    op.admitted_high_water = MAX_WIRE_COUNTER;
    assert_eq!(
        idle.propose(Event::Begin {
            operation: Box::new(op),
            instance: "no-launch".into(),
            session: "session-1".into()
        }),
        Err(ControlError::CounterExhausted)
    );
    let mut j = fixture(Phase::Prepared);
    j.sequence = MAX_WIRE_COUNTER;
    assert_eq!(
        j.propose(Event::StopOld),
        Err(ControlError::CounterExhausted)
    );
    let observed = fixture(Phase::CandidateSpawnObserved);
    let absent = observed.propose(Event::FailedChildAbsent).unwrap();
    assert_eq!(absent.high_water, observed.high_water);
    assert!(
        absent.active.is_some(),
        "failed new preparation retained old active"
    );
    assert!(absent
        .propose(Event::Restore {
            instance: "unneeded".into(),
            session: "session-1".into()
        })
        .is_err());
}

fn paired_fixture(
    phase: Phase,
    state: vp_product_control::OperationState,
) -> (Journal, vp_product_control::StoredState) {
    use vp_product_control::{
        ChangePlan, HealthCheck, Operation, OperationState, PlanBody, ResourceSnapshot,
        RestartImpact, RevisionRecord, StoredState, ValidationReceipt,
    };
    let compiled = compiled_recipe();
    let bytes = serde_json::to_vec(&compiled).unwrap();
    let exact = |mut r: RecipeIdentity| {
        r.config_digest = ContentDigest::of("vp.product-config.v1", &compiled.source).unwrap();
        r.release_digest = ContentDigest::of("vp.release-identity.v1", &compiled.release).unwrap();
        r.recipe_digest = ContentDigest::bytes(&bytes);
        r
    };
    let mut j = fixture(phase);
    j.identity.release_digest =
        ContentDigest::of("vp.release-identity.v1", &compiled.release).unwrap();
    j.identity.core_digest = core_digest(&compiled.release).unwrap();
    if let Some(o) = &mut j.operation {
        o.candidate = exact(o.candidate.clone());
        o.previous = o.previous.take().map(exact);
    }
    if let Some(a) = &mut j.active {
        a.launch.recipe = exact(a.launch.recipe.clone());
    }
    if let Some(p) = &mut j.prepared {
        p.launch.recipe = exact(p.launch.recipe.clone());
    }
    if let Some(l) = &mut j.launch_intent {
        l.launch.recipe = exact(l.launch.recipe.clone());
    }
    let mut stored = StoredState::default();
    for (id, plan_id, principal, target, op_state, generation) in [
        (
            "old-operation",
            "old-plan",
            "old-owner",
            1,
            OperationState::Committed,
            3,
        ),
        (
            "new-operation",
            "new-plan",
            "new-owner",
            2,
            state.clone(),
            4,
        ),
    ] {
        let record = exact(recipe(id, target));
        let body = PlanBody {
            schema_version: 1,
            id: PlanId::new(plan_id).unwrap(),
            principal: UserId::new(principal).unwrap(),
            base_revision: revision(target - 1),
            target_revision: revision(target),
            created_at_ms: 100,
            expires_at_ms: 1000,
            config: compiled.source.clone(),
            release: compiled.release.clone(),
            validation: ValidationReceipt {
                config_digest: record.config_digest.clone(),
                release_digest: record.release_digest.clone(),
                artifact_digest: record.recipe_digest.clone(),
                impact: RestartImpact::ControlledRestart,
                required_health: std::collections::BTreeSet::from([HealthCheck::Process]),
            },
            resources: vec![],
        };
        let hash = ContentDigest::of("vp.change-plan.v1", &body).unwrap();
        let plan: ChangePlan =
            serde_json::from_value(serde_json::json!({"body":body,"hash":hash})).unwrap();
        plan.verify_integrity().unwrap();
        if id == "new-operation" {
            if let Some(o) = &mut j.operation {
                o.plan_hash = plan.hash().clone();
            }
        }
        let committed = op_state == OperationState::Committed;
        let mutation = committed
            || matches!(
                op_state,
                OperationState::ApplyingResources
                    | OperationState::Activating
                    | OperationState::Verifying
                    | OperationState::Committing
                    | OperationState::RollingBack
                    | OperationState::RolledBack
                    | OperationState::RecoveryRequired
            );
        let has_activation = committed
            || matches!(
                op_state,
                OperationState::Verifying | OperationState::Committing
            );
        let op = Operation {
            id: operation(id),
            plan_id: plan.body().id.clone(),
            principal: plan.body().principal.clone(),
            state: op_state,
            created_at_ms: 100,
            updated_at_ms: 200,
            snapshot: mutation.then_some(ResourceSnapshot {
                id: "snapshot".into(),
                resources: vec![],
            }),
            failure: None,
            cancel_requested: false,
            mutation_started: mutation,
            activation: has_activation.then_some(vp_product_control::RuntimeActivation {
                revision: record.revision,
                operation_id: operation(id),
                config_digest: record.config_digest.clone(),
                release_digest: record.release_digest.clone(),
                generation,
            }),
            health: committed.then_some(vp_product_control::RuntimeHealth {
                revision: record.revision,
                operation_id: operation(id),
                config_digest: record.config_digest.clone(),
                release_digest: record.release_digest.clone(),
                generation,
                checked_at_ms: 200,
                checks: vec![],
                external_connectivity: vp_product_control::CheckOutcome::NotChecked,
            }),
        };
        if committed {
            stored.revisions.push(RevisionRecord {
                revision: record.revision,
                config: compiled.source.clone(),
                release: compiled.release.clone(),
                config_digest: record.config_digest,
                release_digest: record.release_digest,
                artifact_digest: record.recipe_digest,
                operation_id: operation(id),
            });
        }
        stored.plans.insert(plan.body().id.clone(), plan);
        stored.operations.insert(op.id.clone(), op);
    }
    stored.active_revision = if state == OperationState::Committed {
        revision(2)
    } else {
        revision(1)
    };
    stored.verify_integrity().unwrap();
    j.validate().unwrap();
    (j, stored)
}
#[test]
fn pairing_control_phase_matrix_and_uncertainty_classification() {
    use vp_product_control::OperationState as C;
    let states = [
        C::Queued,
        C::Staging,
        C::Snapshotting,
        C::ApplyingResources,
        C::Activating,
        C::Verifying,
        C::Committing,
        C::Committed,
        C::Canceling,
        C::Canceled,
        C::RollingBack,
        C::RolledBack,
        C::Failed,
        C::RecoveryRequired,
    ];
    for phase in PHASES.into_iter().filter(|p| *p != Phase::Idle) {
        for state in states.clone() {
            let (j, s) = paired_fixture(phase, state.clone());
            use Phase as P;
            let compatible = match state {
                C::Committed => phase == P::CandidateStarted,
                C::RolledBack => phase == P::Restored,
                C::Failed | C::Canceled | C::Queued => false,
                _ => match phase {
                    P::CandidateReserved | P::CandidateSpawnObserved => {
                        matches!(state, C::Staging | C::Canceling | C::RecoveryRequired)
                    }
                    P::Prepared => matches!(
                        state,
                        C::Staging
                            | C::Snapshotting
                            | C::ApplyingResources
                            | C::Activating
                            | C::Canceling
                            | C::RollingBack
                            | C::RecoveryRequired
                    ),
                    P::StoppingOld | P::OldStopped | P::ActivatingCandidate => {
                        matches!(state, C::Activating | C::RollingBack | C::RecoveryRequired)
                    }
                    P::CandidateStarted => matches!(
                        state,
                        C::Activating
                            | C::Verifying
                            | C::Committing
                            | C::RollingBack
                            | C::RecoveryRequired
                    ),
                    P::DiscardingPrepared | P::CandidateAbsent => matches!(
                        state,
                        C::Staging | C::Canceling | C::RollingBack | C::RecoveryRequired
                    ),
                    P::StoppingCandidate
                    | P::RestoreReserved
                    | P::RestoreSpawnObserved
                    | P::RestorePrepared
                    | P::ActivatingRestore
                    | P::Restored => matches!(state, C::RollingBack | C::RecoveryRequired),
                    P::Idle => false,
                },
            };
            let pair = pair_control(&j, &s);
            assert_eq!(
                pair.is_ok(),
                compatible,
                "phase={phase:?} control={state:?}"
            );
            if compatible {
                let expected = if state.is_terminal() {
                    Pairing::Finalize
                } else if state == C::RecoveryRequired
                    || j.launch_intent.is_some()
                    || j.transition.is_some()
                {
                    Pairing::RecoverOnly
                } else {
                    Pairing::Inflight
                };
                assert_eq!(pair.unwrap(), expected);
            }
        }
    }
}
#[test]
fn committed_control_finalizes_lazily_without_rewriting_control_or_claiming_health() {
    use vp_product_control::OperationState as C;
    let (j, s) = paired_fixture(Phase::CandidateStarted, C::Committed);
    assert_eq!(pair_control(&j, &s), Ok(Pairing::Finalize));
    let state_before = serde_json::to_vec(&s).unwrap();
    let next = j.finalize(&s).unwrap();
    assert_eq!(next.phase, Phase::Idle);
    assert!(next.operation.is_none());
    assert_eq!(next.active, j.active);
    assert_eq!(next.high_water, j.high_water);
    assert_eq!(next.sequence, j.sequence + 1);
    assert_eq!(serde_json::to_vec(&s).unwrap(), state_before);
    assert_eq!(pair_control(&next, &s), Ok(Pairing::Stable));
    assert!(
        next.finalize(&s).is_err(),
        "stable no-op is not a second terminal transition"
    );
    let (j, s) = paired_fixture(Phase::CandidateStarted, C::Verifying);
    assert!(
        j.finalize(&s).is_err(),
        "runtime receipt cannot commit control"
    );
}
#[test]
fn pairing_rejects_wrong_plan_actor_owner_revision_health_and_unrelated_inflight() {
    use vp_product_control::OperationState as C;
    let (j, s) = paired_fixture(Phase::CandidateStarted, C::Committed);
    let mut wrong = j.clone();
    wrong.operation.as_mut().unwrap().plan_hash = digest("wrong");
    assert!(pair_control(&wrong, &s).is_err());
    let mut wrong = j.clone();
    wrong.operation.as_mut().unwrap().principal = UserId::new("other-actor").unwrap();
    assert!(pair_control(&wrong, &s).is_err());
    let mut wrong = s.clone();
    wrong
        .operations
        .get_mut(&operation("new-operation"))
        .unwrap()
        .health
        .as_mut()
        .unwrap()
        .generation = 999;
    assert!(pair_control(&j, &wrong).is_err());
    let mut wrong = s.clone();
    wrong
        .operations
        .get_mut(&operation("new-operation"))
        .unwrap()
        .activation
        .as_mut()
        .unwrap()
        .operation_id = operation("old-operation");
    assert!(pair_control(&j, &wrong).is_err());
    let mut wrong = s.clone();
    wrong.active_revision = revision(1);
    assert!(pair_control(&j, &wrong).is_err());
    let (j, mut s) = paired_fixture(Phase::Prepared, C::Staging);
    let mut other = s.operations[&operation("new-operation")].clone();
    other.id = operation("unrelated");
    s.operations.insert(other.id.clone(), other);
    assert!(pair_control(&j, &s).is_err());
}

#[test]
fn marker_codec_refuses_other_profiles_versions_bindings_and_noncanonical_forms() {
    let id = identity();
    let bytes = id.encode().unwrap();
    assert_eq!(Identity::decode(&bytes, &id), Ok(id.clone()));
    for mutation in 0..8 {
        let mut other = id.clone();
        match mutation {
            0 => other.schema_version = 1,
            1 => other.schema_version = 2,
            2 => other.profile = "vp.bound-runtime.v2".into(),
            3 => other.genesis = digest("different"),
            4 => other.release_digest = digest("different"),
            5 => other.worker_digest = digest("different"),
            6 => other.recipe_version = 1,
            _ => other.worker_protocol_version = 2,
        }
        assert!(Identity::decode(&serde_json::to_vec(&other).unwrap(), &id).is_err());
    }
    let text = String::from_utf8(bytes).unwrap();
    for bad in [
        format!(" {text}"),
        format!("{{\"schemaVersion\":3,{}", &text[1..]),
        format!("{{\"extra\":0,{}", &text[1..]),
        text.replace("vp.bound-server-runtime.v3", "vp.bound-server-runtime.v4"),
    ] {
        assert!(Identity::decode(bad.as_bytes(), &id).is_err());
    }
    assert!(Identity::decode(&vec![b' '; 16385], &id).is_err());
}
#[test]
fn lexical_budgets_bound_depth_strings_tokens_and_numerical_aliases() {
    let too_many = format!("[{}]", vec!["0"; 129].join(","));
    assert!(codec::budget(too_many.as_bytes(), 1024, 1024, 64, 1024).is_err());
    assert!(codec::budget(&[b'['; 65], 1024, 1024, 64, 1024).is_err());
    assert!(codec::budget(
        format!("\"{}\"", "a".repeat(1025)).as_bytes(),
        2048,
        1024,
        64,
        1024
    )
    .is_err());
    assert!(codec::budget(br#"[0,0,0,0]"#, 1024, 1024, 64, 2).is_err());
    let j = fixture(Phase::Prepared);
    let text = String::from_utf8(j.encode().unwrap()).unwrap();
    for bad in [
        text.replace("\"highWater\":4", "\"highWater\":4.0"),
        text.replace("instance-4", "instance-\\u0034"),
        text.replace("\"highWater\":4", "\"highWater\":18446744073709551616"),
    ] {
        assert!(Journal::decode(bad.as_bytes(), &j.identity).is_err());
    }
}
#[test]
fn recomputed_artifact_hash_does_not_hide_noncanonical_or_uncompiled_recipe() {
    let (j, artifacts) = recipe_journal();
    let original = artifacts.values().next().unwrap();
    let mut wrong: ServerRecipeV2 = serde_json::from_slice(original).unwrap();
    wrong.listeners[0].bind.port += 1;
    let bytes = serde_json::to_vec(&wrong).unwrap();
    let digest = ContentDigest::bytes(&bytes);
    let mut changed = j.clone();
    changed.active.as_mut().unwrap().launch.recipe.recipe_digest = digest.clone();
    let operation = changed.operation.as_mut().unwrap();
    operation.candidate.recipe_digest = digest.clone();
    operation.previous.as_mut().unwrap().recipe_digest = digest.clone();
    assert!(
        verify_recipes(&changed, &BTreeMap::from([(digest, bytes)])).is_err(),
        "compiler must reconstruct exact recipe"
    );
    let mut extra = artifacts;
    extra.insert(
        ContentDigest::bytes(b"unreferenced"),
        b"unreferenced".to_vec(),
    );
    assert!(
        verify_recipes(&j, &extra).is_err(),
        "unknown artifacts are not silently adopted"
    );
}

#[test]
fn historical_committed_receipts_and_idle_generation_are_exact() {
    use vp_product_control::OperationState as C;
    for phase in [Phase::Idle, Phase::CandidateReserved, Phase::Prepared] {
        let (j, s) = paired_fixture(
            phase,
            if phase == Phase::Idle {
                C::Queued
            } else {
                C::Staging
            },
        );
        assert!(pair_control(&j, &s).is_ok());
        for mutation in 0..8 {
            let mut bad = s.clone();
            let owner = bad.operations.get_mut(&operation("old-operation")).unwrap();
            match mutation {
                0 => owner.activation.as_mut().unwrap().operation_id = operation("wrong"),
                1 => owner.activation.as_mut().unwrap().revision = revision(2),
                2 => owner.activation.as_mut().unwrap().config_digest = digest("wrong"),
                3 => owner.activation.as_mut().unwrap().release_digest = digest("wrong"),
                4 => owner.health.as_mut().unwrap().operation_id = operation("wrong"),
                5 => owner.health.as_mut().unwrap().revision = revision(2),
                6 => owner.health.as_mut().unwrap().config_digest = digest("wrong"),
                _ => owner.health.as_mut().unwrap().release_digest = digest("wrong"),
            }
            assert!(
                pair_control(&j, &bad).is_err(),
                "{phase:?} receipt field {mutation}"
            );
        }
        let mut bad = s.clone();
        bad.operations
            .get_mut(&operation("old-operation"))
            .unwrap()
            .health
            .as_mut()
            .unwrap()
            .generation += 1;
        assert!(pair_control(&j, &bad).is_err());
        let mut bad = j.clone();
        bad.active.as_mut().unwrap().launch.generation = 2;
        bad.validate().unwrap();
        assert!(
            pair_control(&bad, &s).is_err(),
            "owned generation must equal original receipts"
        );
    }
}

#[test]
fn retained_previous_checks_historical_transition_before_finalization() {
    use vp_product_control::OperationState as C;
    for phase in [
        Phase::CandidateReserved,
        Phase::Prepared,
        Phase::CandidateAbsent,
    ] {
        let (mut j, s) = paired_fixture(phase, C::Staging);
        if j.active.is_none() {
            j.active = paired_fixture(Phase::Prepared, C::Staging).0.active;
        }
        j.validate().unwrap();
        assert!(pair_control(&j, &s).is_ok());
        j.active.as_mut().unwrap().launch.transition_operation =
            operation("missing-historical-launch");
        j.validate().unwrap();
        assert!(pair_control(&j, &s).is_err(), "{phase:?}");
    }
    let (mut j, mut s) = paired_fixture(Phase::CandidateAbsent, C::Canceled);
    let mut old = paired_fixture(Phase::Prepared, C::Staging)
        .0
        .active
        .unwrap();
    old.launch.generation = 4;
    old.launch.transition_operation = operation("prior-recovery");
    j.active = Some(old);
    j.high_water = 5;
    j.operation.as_mut().unwrap().admitted_high_water = 4;
    let mut prior = s.operations[&operation("new-operation")].clone();
    prior.id = operation("prior-recovery");
    prior.state = C::RolledBack;
    prior.mutation_started = true;
    prior.snapshot = Some(vp_product_control::ResourceSnapshot {
        id: "prior-snapshot".into(),
        resources: vec![],
    });
    s.operations.insert(prior.id.clone(), prior);
    j.validate().unwrap();
    s.verify_integrity().unwrap();
    assert_eq!(pair_control(&j, &s), Ok(Pairing::Finalize));
    assert_eq!(
        pair_control(&j.finalize(&s).unwrap(), &s),
        Ok(Pairing::Stable)
    );
    let mut bad = s.clone();
    bad.operations
        .get_mut(&operation("prior-recovery"))
        .unwrap()
        .state = C::Failed;
    assert!(pair_control(&j, &bad).is_err());
    assert!(j.finalize(&bad).is_err());
    let mut bad = s.clone();
    let prior = bad
        .operations
        .get_mut(&operation("prior-recovery"))
        .unwrap();
    prior.plan_id = PlanId::new("old-plan").unwrap();
    prior.principal = UserId::new("old-owner").unwrap();
    assert!(
        pair_control(&j, &bad).is_err(),
        "rollback base must equal retained revision"
    );
    let mut bad = j.clone();
    bad.active.as_mut().unwrap().launch.generation = 3;
    assert!(
        pair_control(&bad, &s).is_err(),
        "restoration generation must be newer than original"
    );
}

#[test]
fn verifying_and_committing_require_candidate_activation_and_rollback_checks_present_receipts() {
    use vp_product_control::OperationState as C;
    for state in [C::Verifying, C::Committing] {
        let (j, s) = paired_fixture(Phase::CandidateStarted, state);
        assert!(pair_control(&j, &s).is_ok());
        assert!(
            s.operations[&operation("new-operation")].health.is_none(),
            "Committing precedes durable health"
        );
        let mut missing = s.clone();
        missing
            .operations
            .get_mut(&operation("new-operation"))
            .unwrap()
            .activation = None;
        assert!(pair_control(&j, &missing).is_err());
        let mut wrong = s.clone();
        wrong
            .operations
            .get_mut(&operation("new-operation"))
            .unwrap()
            .activation
            .as_mut()
            .unwrap()
            .generation += 1;
        assert!(pair_control(&j, &wrong).is_err());
    }
    let (_, receipt_state) = paired_fixture(Phase::CandidateStarted, C::Committed);
    let original = &receipt_state.operations[&operation("new-operation")];
    let (j, mut s) = paired_fixture(Phase::Restored, C::RollingBack);
    let current = s.operations.get_mut(&operation("new-operation")).unwrap();
    current.activation = original.activation.clone();
    current.health = original.health.clone();
    assert!(
        pair_control(&j, &s).is_ok(),
        "historical candidate receipt stays generation4, restored active is5"
    );
    for health in [false, true] {
        let mut bad = s.clone();
        let op = bad.operations.get_mut(&operation("new-operation")).unwrap();
        if health {
            op.health.as_mut().unwrap().generation = 5;
        } else {
            op.activation.as_mut().unwrap().generation = 5;
        }
        assert!(
            pair_control(&j, &bad).is_err(),
            "must not relabel receipt as restored generation"
        );
    }
}

#[test]
fn terminal_reconciliation_must_precede_next_durable_staging_checkpoint() {
    use vp_product_control::OperationState as C;
    let (j, mut s) = paired_fixture(Phase::CandidateStarted, C::Committed);
    let mut next = s.operations[&operation("new-operation")].clone();
    next.id = operation("later-operation");
    next.state = C::Queued;
    next.activation = None;
    next.health = None;
    next.mutation_started = false;
    next.snapshot = None;
    s.operations.insert(next.id.clone(), next);
    let finalized = j.finalize(&s).unwrap();
    s.operations
        .get_mut(&operation("later-operation"))
        .unwrap()
        .state = C::Staging;
    assert!(
        j.finalize(&s).is_err(),
        "unrelated Staging is not authority to finalize previous op"
    );
    assert_eq!(pair_control(&finalized, &s), Ok(Pairing::Stable));
}

#[test]
fn absent_previous_process_still_requires_historical_generation_before_admission() {
    use vp_product_control::OperationState as C;
    for phase in [
        Phase::OldStopped,
        Phase::CandidateStarted,
        Phase::CandidateAbsent,
        Phase::RestorePrepared,
    ] {
        let state = if matches!(phase, Phase::CandidateAbsent | Phase::RestorePrepared) {
            C::RollingBack
        } else {
            C::Activating
        };
        let (j, mut s) = paired_fixture(phase, state);
        assert!(pair_control(&j, &s).is_ok());
        let previous = s.operations.get_mut(&operation("old-operation")).unwrap();
        previous.activation.as_mut().unwrap().generation = 99;
        previous.health.as_mut().unwrap().generation = 99;
        s.verify_integrity().unwrap();
        assert!(
            pair_control(&j, &s).is_err(),
            "{phase:?}: original generation cannot exceed admitted high-water"
        );
    }
}

#[test]
fn experimental_public_recipe_is_content_addressed_and_recompiled() {
    let mut recipe = compiled_recipe();
    recipe.source.listeners[0].bind.address = "192.168.1.5".parse().unwrap();
    recipe = ServerCompilerV2::for_public_experiment(recipe.release.clone(), vec!["8.8.8.8:443".parse().unwrap()])
        .unwrap().compile(&recipe.source, &recipe.release).unwrap();
    let bytes = serde_json::to_vec(&recipe).unwrap();
    let digest = ContentDigest::bytes(&bytes);
    let (mut j, _) = recipe_journal();
    let mut id = j.active.as_ref().unwrap().launch.recipe.clone();
    id.config_digest = ContentDigest::of("vp.product-config.v1", &recipe.source).unwrap();
    id.release_digest = ContentDigest::of("vp.release-identity.v1", &recipe.release).unwrap();
    id.recipe_digest = digest.clone();
    j.identity.release_digest = id.release_digest.clone();
    j.identity.core_digest = core_digest(&recipe.release).unwrap();
    j.active.as_mut().unwrap().launch.recipe = id.clone();
    let op = j.operation.as_mut().unwrap();
    op.candidate = id.clone();
    id.revision = revision(1);
    id.revision_owner_operation = operation("old-operation");
    op.previous = Some(id);
    let artifacts = BTreeMap::from([(digest, bytes)]);
    assert!(verify_recipes(&j, &artifacts).is_ok());
    let mut corrupt = artifacts;
    corrupt.values_mut().next().unwrap().push(b' ');
    assert!(verify_recipes(&j, &corrupt).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn real_process_observation_has_birth_and_boot_identity() {
    let first = ProcessIdentity::observe(std::process::id()).unwrap();
    let second = ProcessIdentity::observe(std::process::id()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.pid, std::process::id());
    first.validate().unwrap();
    assert!(ProcessIdentity::observe(0).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn restart_observation_requires_paired_committed_absent_process_and_never_mutates() {
    use vp_product_control::OperationState as C;
    let (j, s) = paired_fixture(Phase::CandidateStarted, C::Committed);
    let mut j = j.finalize(&s).unwrap();
    let state_before = serde_json::to_vec(&s).unwrap();
    j.active.as_mut().unwrap().process = ProcessIdentity::observe(std::process::id()).unwrap();
    assert_eq!(pairing::inspect_absent_committed_process(&j, &s), Err(ControlError::ResourceConflict));
    j.active.as_mut().unwrap().process.pid = u32::MAX;
    let bytes_before = j.encode().unwrap();
    let observed = pairing::inspect_absent_committed_process(&j, &s).unwrap();
    assert_eq!(observed.next_generation, j.high_water + 1);
    assert_eq!(observed.recipe, j.active.as_ref().unwrap().launch.recipe);
    assert_eq!(j.encode().unwrap(), bytes_before);
    assert_eq!(serde_json::to_vec(&s).unwrap(), state_before);
    let mut corrupted = s.clone();
    corrupted.active_revision = Revision::ZERO;
    assert!(pairing::inspect_absent_committed_process(&j, &corrupted).is_err());
    let (inflight, state) = paired_fixture(Phase::Prepared, C::Staging);
    assert!(pairing::inspect_absent_committed_process(&inflight, &state).is_err());
}

#[cfg(all(target_os = "linux", feature = "experimental-public"))]
#[test]
fn restart_proposals_are_ordered_bound_to_original_state_and_never_prove_effects() {
    use super::restart_v4::{RestartEvent as E, RestartHealthRecord, RestartRecord};
    use vp_product_control::OperationState as C;
    let (j, s) = paired_fixture(Phase::CandidateStarted, C::Committed);
    let mut j = j.finalize(&s).unwrap();
    j.active.as_mut().unwrap().process.pid = u32::MAX;
    let reserved = RestartRecord::reserve(&j, &s, "restart-instance".into(), "restart-session".into()).unwrap();
    let encoded = reserved.encode(&j, &s).unwrap();
    assert_eq!(RestartRecord::decode(&encoded, &j, &s).unwrap(), reserved);
    let mut whitespace = encoded.clone(); whitespace.push(b' ');
    assert!(RestartRecord::decode(&whitespace, &j, &s).is_err());
    let mut bad: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    bad["unexpected"] = serde_json::json!(true);
    assert!(RestartRecord::decode(&serde_json::to_vec(&bad).unwrap(), &j, &s).is_err());
    bad.as_object_mut().unwrap().remove("unexpected"); bad["sequence"] = serde_json::json!(2);
    assert!(RestartRecord::decode(&serde_json::to_vec(&bad).unwrap(), &j, &s).is_err());
    assert!(reserved.propose(E::Prepared, &j, &s).is_err());
    let seen = reserved.propose(E::SpawnObserved(process(12)), &j, &s).unwrap();
    assert!(seen.propose(E::Activate, &j, &s).is_err());
    let prepared = seen.propose(E::Prepared, &j, &s).unwrap();
    let activating = prepared.propose(E::Activate, &j, &s).unwrap();
    let running = activating.propose(E::Activated, &j, &s).unwrap();
    assert!(running.propose(E::Activated, &j, &s).is_err());
    let checks: Vec<_> = vp_product_control::minimum_health_checks(&s.active().unwrap().config, None).unwrap().into_iter().collect();
    let bad = RestartHealthRecord { generation: j.high_water + 1, checked_at_ms: 123, checks: vec![] };
    assert!(running.propose(E::Verified(bad), &j, &s).is_err());
    let health = RestartHealthRecord { generation: j.high_water + 1, checked_at_ms: 123, checks };
    let verified = running.propose(E::Verified(health), &j, &s).unwrap();
    let verified_bytes = verified.encode(&j, &s).unwrap();
    assert_eq!(RestartRecord::decode(&verified_bytes, &j, &s).unwrap(), verified);
    let mut changed = j.clone(); changed.sequence += 1;
    assert!(running.validate_base(&changed, &s).is_err());
    let mut changed = s.clone(); changed.version += 1;
    assert!(running.validate_base(&j, &changed).is_err());
    let mut duplicate = process(12); duplicate.pid = u32::MAX;
    assert!(reserved.propose(E::SpawnObserved(duplicate), &j, &s).is_err());
}

#[cfg(all(target_os = "linux", feature = "experimental-public"))]
#[test]
fn restart_checkpoint_store_persists_exact_order_and_refuses_residue() {
    use super::restart_v4::{RestartEvent as E, RestartRecord, RestartStore};
    use std::{fs::File, os::unix::fs::PermissionsExt};
    use vp_product_control::OperationState as C;
    use vp_product_storage::{BoundDirectory, DirectoryIdentity};
    let (j, s) = paired_fixture(Phase::CandidateStarted, C::Committed);
    let mut j = j.finalize(&s).unwrap();
    j.active.as_mut().unwrap().process.pid = u32::MAX;
    let temp = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
    let cap = || BoundDirectory::admit(temp.path(), DirectoryIdentity::of(&File::open(temp.path()).unwrap()).unwrap()).unwrap();
    let reserved = RestartRecord::reserve(&j, &s, "restart-instance".into(), "restart-session".into()).unwrap();
    let mut saved = RestartStore::create(cap(), reserved, &j, &s).unwrap();
    assert!(saved.advance(E::Prepared, &j, &s).is_err());
    assert!(saved.advance(E::Verified(super::restart_v4::RestartHealthRecord { generation: j.high_water + 1, checked_at_ms: 123, checks: vec![] }), &j, &s).is_err());
    assert!(saved.advance(E::FailedAbsent, &j, &s).is_err());
    saved.advance(E::SpawnObserved(process(12)), &j, &s).unwrap();
    assert!(saved.advance(E::FailedAbsent, &j, &s).is_err());
    saved.advance(E::Prepared, &j, &s).unwrap();
    let expected = saved.record(&j, &s).unwrap().clone();
    drop(saved);
    let reopened = RestartStore::open(cap(), &j, &s).unwrap();
    assert_eq!(reopened.record(&j, &s).unwrap(), &expected);
    drop(reopened);
    std::fs::write(temp.path().join("restart.intent.pending"), b"uncertain").unwrap();
    assert!(RestartStore::open(cap(), &j, &s).is_err());
}

#[cfg(all(target_os = "linux", feature = "experimental-public"))]
#[test]
fn restart_checkpoint_uncertain_write_poison_and_external_tamper_fail_closed() {
    use super::restart_v4::{RestartEvent as E, RestartRecord, RestartStore};
    use std::{fs::File, os::unix::fs::PermissionsExt};
    use vp_product_control::OperationState as C;
    use vp_product_storage::{BoundDirectory, DirectoryIdentity};
    let (j, s) = paired_fixture(Phase::CandidateStarted, C::Committed);
    let mut j = j.finalize(&s).unwrap(); j.active.as_mut().unwrap().process.pid = u32::MAX;
    for inject_failure in [true, false] {
        let temp = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
        let cap = || BoundDirectory::admit(temp.path(), DirectoryIdentity::of(&File::open(temp.path()).unwrap()).unwrap()).unwrap();
        let record = RestartRecord::reserve(&j, &s, "restart-instance".into(), "restart-session".into()).unwrap();
        let mut saved = RestartStore::create(cap(), record, &j, &s).unwrap();
        assert!(RestartStore::open(cap(), &j, &s).is_err(), "root lease excludes a second writer");
        if inject_failure {
            assert!(saved.inject_write_failure(E::SpawnObserved(process(12)), &j, &s).is_err());
        } else {
            std::fs::write(temp.path().join("restart.intent.json"), b"corrupt").unwrap();
            assert!(saved.advance(E::SpawnObserved(process(12)), &j, &s).is_err());
        }
        assert!(matches!(saved.record(&j, &s), Err(ControlError::RecoveryRequired)));
        assert!(saved.advance(E::SpawnObserved(process(12)), &j, &s).is_err());
    }
}

#[cfg(all(target_os = "linux", feature = "experimental-public"))]
#[test]
fn restart_checkpoint_prepares_real_worker_without_binding_or_health_claim() {
    use super::restart_v4::{activate_restart_candidate, admit_restart_materials, prepare_restart_candidate, prepare_restart_candidate_inner, RestartRecord, RestartStore};
    use sha2::{Digest, Sha256};
    use std::{fs::File, os::unix::fs::PermissionsExt, time::{Duration, Instant}};
    use vp_product_control::OperationState as C;
    use vp_product_core_adapter::managed::{Cancellation, VerifiedWorker, host_v2::ManagedRuntimeV2,
        protocol_v2::WorkerInstanceV2, server_v2::ServerInputsV2};
    use vp_product_storage::{BoundDirectory, DirectoryIdentity};
    use vp_product_control::{TlsAssetWriterLease, TlsControlEnvelope, TlsAssetMutation, WriterLease, JournalEvent,
        TlsMaterialVault, TlsRawRecord, TlsBackendPolicy, InstanceBinding, FRESH_TLS_RUNTIME_PROFILE};
    struct Lease(TlsControlEnvelope);
    impl WriterLease for Lease {
        fn state(&self) -> &vp_product_control::StoredState { self.0.state() }
        fn tls_aggregate(&self) -> Option<&TlsControlEnvelope> { Some(&self.0) }
        fn persist(&mut self, _: vp_product_control::StoredState, _: JournalEvent) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
    }
    impl TlsAssetWriterLease for Lease {
        fn aggregate(&self) -> &TlsControlEnvelope { &self.0 }
        fn persist_asset(&mut self, _: TlsAssetMutation) -> Result<(), ControlError> { Err(ControlError::ExecutorUnavailable) }
    }
    struct Vault(InstanceBinding);
    impl TlsMaterialVault for Vault {
        fn material_binding(&self, _: Instant) -> Result<InstanceBinding, ControlError> { Ok(self.0.clone()) }
        fn read_tls_material(&self, _: &SecretRef, _: Instant) -> Result<Option<TlsRawRecord>, ControlError> { Ok(None) }
        fn read_credential_material(&self, r: &SecretRef, _: Instant) -> Result<Option<TlsRawRecord>, ControlError> {
            use vp_product_domain::experimental_credential_frame::{encode, CredentialFrameKind};
            Ok(Some(TlsRawRecord { reference: r.clone(), kind: 1, version: 1,
                bytes: encode(CredentialFrameKind::ShadowsocksAes128Gcm, b"synthetic-test-password").unwrap() }))
        }
    }
    let path = std::path::PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap()).join("debug/vp-core-server-worker-v2");
    let sha = format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap()));
    let worker = VerifiedWorker::for_server_v2(path, &sha, Instant::now()+Duration::from_secs(10), &Cancellation::default()).unwrap();
    let release = vp_product_core_adapter::inspect_build().unwrap().build.release;
    let config: ProductConfig = serde_json::from_value(serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{"schemaVersion":1,"id":"restart-test-listener","name":"prepare-only","enabled":true,"bind":{"address":"192.0.2.1","port":19001},"protocol":{"kind":"proxy","protocol":{"kind":"shadowsocks","method":"aes-128-gcm"},"users":[{"id":"restart-user","credentialRef":"secret:restart-secret","enabled":true}]},"transport":{"kind":"tcp"},"security":{"kind":"none"},"requirements":[]}]})).unwrap();
    let compiler = ServerCompilerV2::for_public_experiment(release.clone(), vec!["8.8.8.8:443".parse().unwrap()]).unwrap();
    let recipe = compiler.compile(&config, &release).unwrap();
    let config_digest = ContentDigest::of("vp.product-config.v1", &config).unwrap();
    let release_digest = ContentDigest::of("vp.release-identity.v1", &release).unwrap();
    let recipe_digest = ContentDigest::bytes(&serde_json::to_vec(&recipe).unwrap());
    let (j, mut s) = paired_fixture(Phase::CandidateStarted, C::Committed);
    let mut j = j.finalize(&s).unwrap();
    for plan in s.plans.values_mut() {
        let mut body = plan.body().clone(); body.config = config.clone(); body.release = release.clone();
        body.validation.config_digest = config_digest.clone(); body.validation.release_digest = release_digest.clone(); body.validation.artifact_digest = recipe_digest.clone();
        body.validation.required_health = vp_product_control::minimum_health_checks(&config, None).unwrap();
        let hash = ContentDigest::of("vp.change-plan.v1", &body).unwrap();
        *plan = serde_json::from_value(serde_json::json!({"body":body,"hash":hash})).unwrap();
    }
    for revision in &mut s.revisions {
        revision.config = config.clone(); revision.release = release.clone(); revision.config_digest = config_digest.clone();
        revision.release_digest = release_digest.clone(); revision.artifact_digest = recipe_digest.clone();
    }
    for op in s.operations.values_mut() {
        if let Some(a) = &mut op.activation { a.config_digest = config_digest.clone(); a.release_digest = release_digest.clone(); }
        if let Some(h) = &mut op.health { h.config_digest = config_digest.clone(); h.release_digest = release_digest.clone();
            h.checks = vp_product_control::minimum_health_checks(&config, None).unwrap().into_iter().map(|check| vp_product_control::CheckResult { check, outcome: vp_product_control::CheckOutcome::Passed }).collect(); }
    }
    j.identity.release_digest = release_digest.clone(); j.identity.core_digest = core_digest(&release).unwrap();
    j.identity.worker_digest = ContentDigest::parse(sha).unwrap();
    let old = j.active.as_mut().unwrap(); old.launch.recipe.config_digest = config_digest;
    old.launch.recipe.release_digest = release_digest; old.launch.recipe.recipe_digest = recipe_digest;
    old.launch.worker_digest = j.identity.worker_digest.clone(); old.process.pid = u32::MAX;
    s.version = 1;
    let credential_id = CredentialId::new("restart-credential").unwrap();
    s.secrets.credentials.insert(credential_id.clone(), vp_product_control::CredentialRecord {
        principal: UserId::new("new-owner").unwrap(), vault_version: 1,
        summary: CredentialSummary { schema_version: 1, id: credential_id, revision: Revision::ZERO.next().unwrap(),
            secret_ref: SecretRef::new("restart-secret").unwrap(), kind: NodeCredentialKind::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm },
            created_at: 1, state: CredentialState::Available, display_key: CredentialDisplayKey::Managed },
    });
    let d = ContentDigest::bytes(b"synthetic-genesis");
    let binding = InstanceBinding { binding_version: 1, genesis_id: "a".repeat(32), vault_id: "b".repeat(32),
        namespace_digest: d.clone(), administrator_commitment: d.clone(), preparation_digest: d.clone(),
        activation_intent_digest: d.clone(), artifact_set_digest: d, profile: FRESH_TLS_RUNTIME_PROFILE.into() };
    j.identity.genesis = binding.digest().unwrap();
    assert_eq!(pair_control(&j, &s), Ok(Pairing::Stable));
    let mut envelope = TlsControlEnvelope::preparing(binding.clone()).unwrap(); envelope.mark_initialized().unwrap();
    let lease = Lease(envelope.with_ordinary_state(s.clone()).unwrap());
    let journal_dir = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
    let persistence = super::persistence::synthetic_committed_fixture(journal_dir.path(), j.identity.clone(), &binding, &j, &serde_json::to_vec(&recipe).unwrap(), &lease).unwrap();
    let vault = Vault(binding.clone());
    let policy = TlsBackendPolicy::new("new-owner".into(), vec![vec![1]], "localhost".into()).unwrap();
    for mode in ["before-material", "cancel-before-bind", "bind-failure"] {
        let root = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
        let cap = BoundDirectory::admit(root.path(), DirectoryIdentity::of(&File::open(root.path()).unwrap()).unwrap()).unwrap();
        let record = RestartRecord::reserve(&j, &s, "restart-real-worker".into(), "restart-session".into()).unwrap();
        let mut checkpoints = RestartStore::create(cap, record, &j, &s).unwrap();
        let mut runtime = ManagedRuntimeV2::with_generation(worker.clone(), WorkerInstanceV2::new("restart-real-worker").unwrap(), j.high_water).unwrap();
        let inputs = ServerInputsV2 { credentials: BTreeMap::from([(SecretRef::new("restart-secret").unwrap(), SecretBytes::new(b"synthetic-test-password".to_vec()))]), certificate_chains: BTreeMap::new(), private_keys: BTreeMap::new() };
        let result = if mode == "before-material" {
            prepare_restart_candidate_inner(&mut checkpoints, &j, &s, &mut runtime, recipe.clone(), inputs,
                Duration::from_secs(10), &Cancellation::default(), || Err(ControlError::ResourceConflict))
        } else {
            drop(inputs);
            let control_cancel = vp_product_control::CancellationToken::default();
            let core_cancel = Cancellation::default();
            let admitted = admit_restart_materials(&persistence, &lease, &binding, &vault, &policy,
                &vp_product_control::SystemClock, Instant::now()+Duration::from_secs(15), &control_cancel, &core_cancel).unwrap();
            let prepared = prepare_restart_candidate(&mut checkpoints, &mut runtime, admitted, Duration::from_secs(10), &core_cancel).unwrap();
            let saved = serde_json::to_value(checkpoints.record(&j, &s).unwrap()).unwrap();
            assert_eq!(saved["phase"], "prepared");
            assert_eq!(runtime.prepared_generation(), Some(j.high_water + 1));
            assert!(checkpoints.confirm_failed_absent(&j, &s, &runtime).is_err(), "a live prepared child cannot be called absent");
            if mode == "cancel-before-bind" { control_cancel.cancel(); }
            // Test-net address is deliberately not assigned locally. Cancellation
            // must not bind; otherwise binding must fail after durable intent.
            assert!(activate_restart_candidate(&mut checkpoints, &mut runtime, prepared, Duration::from_secs(5), &core_cancel).is_err());
            let after = serde_json::to_value(checkpoints.record(&j, &s).unwrap()).unwrap();
            if mode == "cancel-before-bind" {
                assert_eq!(after["phase"], "prepared");
                assert_eq!(runtime.prepared_generation(), Some(j.high_water + 1));
                runtime.discard_prepared(j.high_water + 1).unwrap();
            } else { assert_eq!(after["phase"], "activating"); }
            assert_eq!(runtime.prepared_generation(), None); assert_eq!(runtime.active_generation(), None);
            Ok(j.high_water + 1)
        };
        let saved = serde_json::to_value(checkpoints.record(&j, &s).unwrap()).unwrap();
        let pid = saved["process"]["pid"].as_u64().unwrap();
        assert!(pid > 0); assert_eq!(runtime.active_generation(), None);
        if mode == "before-material" {
            assert!(result.is_err()); assert_eq!(saved["phase"], "spawn_observed");
            assert_eq!(runtime.prepared_generation(), None);
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        } else {
            assert_eq!(result.unwrap(), j.high_water + 1);
            assert_eq!(saved["phase"], if mode == "cancel-before-bind" { "prepared" } else { "activating" });
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        }
        checkpoints.confirm_failed_absent(&j, &s, &runtime).unwrap();
        let terminal = serde_json::to_value(checkpoints.record(&j, &s).unwrap()).unwrap();
        assert_eq!(terminal["phase"], "failed_stopped");
        assert!(checkpoints.confirm_failed_absent(&j, &s, &runtime).is_err());
        if mode == "bind-failure" {
            assert!(checkpoints.retry_after_failed(&j, &s, &runtime, "restart-real-worker".into(), "retry-session".into()).is_err());
            checkpoints.retry_after_failed(&j, &s, &runtime, "restart-retry-worker".into(), "retry-session".into()).unwrap();
            let retry = serde_json::to_value(checkpoints.record(&j, &s).unwrap()).unwrap();
            assert_eq!(retry["phase"], "reserved"); assert_eq!(retry["attempt"], 2);
            assert_eq!(retry["launch"]["generation"], j.high_water + 2);
            let mut retried = ManagedRuntimeV2::with_generation(worker.clone(), WorkerInstanceV2::new("restart-retry-worker").unwrap(), j.high_water + 1).unwrap();
            let control_cancel = vp_product_control::CancellationToken::default();
            let core_cancel = Cancellation::default();
            let admitted = admit_restart_materials(&persistence, &lease, &binding, &vault, &policy,
                &vp_product_control::SystemClock, Instant::now()+Duration::from_secs(15), &control_cancel, &core_cancel).unwrap();
            let prepared = prepare_restart_candidate(&mut checkpoints, &mut retried, admitted, Duration::from_secs(10), &core_cancel).unwrap();
            assert_eq!(retried.prepared_generation(), Some(j.high_water + 2));
            drop(prepared);
            retried.discard_prepared(j.high_water + 2).unwrap();
            checkpoints.confirm_failed_absent(&j, &s, &retried).unwrap();
            assert_eq!(serde_json::to_value(checkpoints.record(&j, &s).unwrap()).unwrap()["phase"], "failed_stopped");
        }
    }
}

#[cfg(all(target_os = "linux", feature = "experimental-public"))]
#[test]
fn restart_health_never_infers_forwarding_from_a_bound_listener() {
    use super::restart_v4::collect_restart_checks;
    use std::{collections::{BTreeMap, BTreeSet}, time::{Duration, Instant}};
    use vp_product_control::{CancellationToken, CheckOutcome, HealthCheck};
    use vp_product_core_adapter::managed::{Cancellation, WorkerSnapshot, protocol::BoundListener, server_v2::ServerInputsV2};
    let recipe = compiled_recipe();
    let inputs = ServerInputsV2 { credentials: BTreeMap::new(), certificate_chains: BTreeMap::new(), private_keys: BTreeMap::new() };
    let checks = BTreeSet::from([HealthCheck::Process, HealthCheck::ListenerBound("listener-1".into()), HealthCheck::Forwarding("listener-1".into())]);
    let mut snapshot = WorkerSnapshot { generation: 3, pid: 42, listeners_ready: true,
        listeners: vec![BoundListener { tag: "listener-1".into(), port: 19001, accept_loop_live: true }],
        active_tasks: 1, task_panics: 0, forwarding_verified: false, probe_ledger: None };
    let control = CancellationToken::default(); let core = Cancellation::default();
    let deadline = Instant::now() + Duration::from_secs(2);
    assert!(collect_restart_checks(&recipe, &inputs, &checks, &snapshot, 42, 3, deadline, &control, &core, |_| Ok(CheckOutcome::NotChecked)).is_err());
    assert!(collect_restart_checks(&recipe, &inputs, &checks, &snapshot, 42, 3, deadline, &control, &core, |_| Ok(CheckOutcome::Failed)).is_err());
    assert_eq!(collect_restart_checks(&recipe, &inputs, &checks, &snapshot, 42, 3, deadline, &control, &core, |_| Ok(CheckOutcome::Passed)).unwrap().len(), 3);
    snapshot.forwarding_verified = true;
    assert!(collect_restart_checks(&recipe, &inputs, &checks, &snapshot, 42, 3, deadline, &control, &core, |_| Ok(CheckOutcome::Passed)).is_err());
    snapshot.forwarding_verified = false; snapshot.listeners[0].accept_loop_live = false;
    assert!(collect_restart_checks(&recipe, &inputs, &checks, &snapshot, 42, 3, deadline, &control, &core, |_| Ok(CheckOutcome::Passed)).is_err());
    snapshot.listeners[0].accept_loop_live = true; snapshot.listeners[0].port += 1;
    assert!(collect_restart_checks(&recipe, &inputs, &checks, &snapshot, 42, 3, deadline, &control, &core, |_| Ok(CheckOutcome::Passed)).is_err());
    snapshot.listeners[0].port -= 1;
    control.cancel();
    assert!(matches!(collect_restart_checks(&recipe, &inputs, &checks, &snapshot, 42, 3, deadline, &control, &core, |_| Ok(CheckOutcome::Passed)), Err(ControlError::Canceled)));
}
