//! Opt-in, pure journal3 codec and proposal validator. No durable store, process
//! authority, worker implementation or production constructor is provided here.
//! Accepted bytes never authorize an effect. Callers must independently retain
//! admitted storage/control capabilities and prove effect outcomes.
use serde::{Deserialize, Serialize};
use vp_product_control::{ContentDigest, ControlError};
use vp_product_domain::{OperationId, PlanId, Revision, UserId, MAX_WIRE_COUNTER};
mod codec;
mod pairing;
#[cfg(all(target_os = "linux", feature = "experimental-public"))]
mod restart_v4;
#[cfg(all(target_os = "linux", feature = "server-v2-journal-storage"))]
pub mod persistence;
mod transitions;
pub use pairing::{core_digest, pair_control, verify_recipes, Pairing};
#[cfg(target_os = "linux")]
pub(crate) use pairing::inspect_absent_committed_process;
pub use transitions::Event;

pub const SCHEMA: u16 = 3;
pub const PROFILE: &str = "vp.bound-server-runtime.v3";
pub const DOMAIN: &str = "vp.bound-server-runtime-journal.v3";
/// This fixed-slot format needs far less than the reserved 8MiB ceiling.
pub const MAX_JOURNAL_BYTES: usize = 64 * 1024;
pub const MAX_RECIPE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Identity {
    pub schema_version: u16,
    pub profile: String,
    pub genesis: ContentDigest,
    pub release_digest: ContentDigest,
    pub core_digest: ContentDigest,
    pub worker_digest: ContentDigest,
    pub recipe_version: u16,
    pub worker_protocol_version: u16,
}
impl Identity {
    pub fn encode(&self) -> Result<Vec<u8>, ControlError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ControlError::CorruptState)?;
        codec::budget(&bytes, 16 * 1024, 1024, 4, 128)?;
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], expected: &Self) -> Result<Self, ControlError> {
        expected.validate()?;
        codec::budget(bytes, 16 * 1024, 1024, 4, 128)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|_| ControlError::CorruptState)?;
        value.validate()?;
        require(value == *expected && value.encode()?.as_slice() == bytes)?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), ControlError> {
        require(
            self.schema_version == SCHEMA
                && self.profile == PROFILE
                && self.recipe_version == 2
                && self.worker_protocol_version == 3,
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecipeIdentity {
    pub revision_owner_operation: OperationId,
    pub revision: Revision,
    pub config_digest: ContentDigest,
    pub release_digest: ContentDigest,
    pub recipe_digest: ContentDigest,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: String,
    pub boot_id: String,
}
impl ProcessIdentity {
    /// A snapshot of Linux process birth and boot identity, not a live handle
    /// and never permission to adopt or terminate a process after restart.
    #[cfg(target_os = "linux")]
    pub(crate) fn observe(pid: u32) -> Result<Self, ControlError> {
        let identity = crate::durable::ProcessIdentity::read(pid)?.as_server_v2();
        identity.validate()?;
        Ok(identity)
    }
    /// Conservative birth-identity observation. Missing or replaced PID means
    /// this exact process is absent; unreadable state remains uncertain.
    #[cfg(target_os = "linux")]
    pub(crate) fn is_present(&self) -> Result<bool, ControlError> {
        match std::fs::metadata(format!("/proc/{}", self.pid)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(ControlError::RecoveryRequired),
            Ok(_) => Ok(Self::observe(self.pid)? == *self),
        }
    }
    fn validate(&self) -> Result<(), ControlError> {
        require(
            self.pid > 0
                && !self.start_ticks.is_empty()
                && self.start_ticks.len() <= 20
                && self.start_ticks.bytes().all(|b| b.is_ascii_digit())
                && self.start_ticks.parse::<u64>().is_ok()
                && (self.start_ticks == "0" || !self.start_ticks.starts_with('0'))
                && self.boot_id.len() == 36
                && self.boot_id.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }
                }),
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LaunchRecord {
    pub recipe: RecipeIdentity,
    pub transition_operation: OperationId,
    pub generation: u64,
    pub instance: String,
    pub session: String,
    pub worker_digest: ContentDigest,
    pub worker_protocol_version: u16,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OwnedRecord {
    pub launch: LaunchRecord,
    /// Mandatory observation, never permission to adopt or signal after restart.
    pub process: ProcessIdentity,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Candidate,
    RestorePrevious,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LaunchIntent {
    pub role: Role,
    pub launch: LaunchRecord,
    pub process: Option<ProcessIdentity>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    StopOld,
    ActivateCandidate,
    StopCandidate,
    DiscardPrepared,
    ActivateRestore,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TransitionIntent {
    pub action: Action,
    pub transition_operation: OperationId,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Idle,
    CandidateReserved,
    CandidateSpawnObserved,
    Prepared,
    StoppingOld,
    OldStopped,
    ActivatingCandidate,
    CandidateStarted,
    StoppingCandidate,
    DiscardingPrepared,
    CandidateAbsent,
    RestoreReserved,
    RestoreSpawnObserved,
    RestorePrepared,
    ActivatingRestore,
    Restored,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OperationRecord {
    pub operation: OperationId,
    pub plan_id: PlanId,
    pub plan_hash: ContentDigest,
    pub principal: UserId,
    pub base_revision: Revision,
    pub candidate: RecipeIdentity,
    pub previous: Option<RecipeIdentity>,
    /// High-water at operation admission: restores/candidates must be newer.
    pub admitted_high_water: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Journal {
    pub identity: Identity,
    pub sequence: u64,
    pub high_water: u64,
    pub phase: Phase,
    pub operation: Option<OperationRecord>,
    pub active: Option<OwnedRecord>,
    pub prepared: Option<OwnedRecord>,
    pub launch_intent: Option<LaunchIntent>,
    pub transition: Option<TransitionIntent>,
}
fn require(ok: bool) -> Result<(), ControlError> {
    if ok {
        Ok(())
    } else {
        Err(ControlError::CorruptState)
    }
}
fn token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
impl Journal {
    pub fn empty(identity: Identity) -> Result<Self, ControlError> {
        identity.validate()?;
        Ok(Self {
            identity,
            sequence: 0,
            high_water: 0,
            phase: Phase::Idle,
            operation: None,
            active: None,
            prepared: None,
            launch_intent: None,
            transition: None,
        })
    }
    fn check_launch(&self, l: &LaunchRecord) -> Result<(), ControlError> {
        require(
            l.generation > 0
                && l.generation <= self.high_water
                && token(&l.instance)
                && token(&l.session)
                && l.worker_digest == self.identity.worker_digest
                && l.worker_protocol_version == self.identity.worker_protocol_version
                && l.recipe.release_digest == self.identity.release_digest
                && l.recipe.revision != Revision::ZERO,
        )
    }
    fn owned(&self, r: &OwnedRecord) -> Result<(), ControlError> {
        self.check_launch(&r.launch)?;
        r.process.validate()
    }
    pub fn validate(&self) -> Result<(), ControlError> {
        self.identity.validate()?;
        require(
            self.sequence <= MAX_WIRE_COUNTER
                && self.high_water <= self.sequence
                && self.high_water <= MAX_WIRE_COUNTER,
        )?;
        for r in [&self.active, &self.prepared].into_iter().flatten() {
            self.owned(r)?;
        }
        if let Some(l) = &self.launch_intent {
            self.check_launch(&l.launch)?;
            if let Some(p) = &l.process {
                p.validate()?;
            }
        }
        // No aliasing between independently owned or possibly launched children.
        let mut records = Vec::with_capacity(3);
        if let Some(a) = &self.active {
            records.push((&a.launch, Some(&a.process)));
        }
        if let Some(p) = &self.prepared {
            records.push((&p.launch, Some(&p.process)));
        }
        if let Some(l) = &self.launch_intent {
            records.push((&l.launch, l.process.as_ref()));
        }
        for (i, (a, ap)) in records.iter().enumerate() {
            for (b, bp) in records.iter().skip(i + 1) {
                require(
                    a.generation != b.generation
                        && a.instance != b.instance
                        && !matches!((ap,bp),(Some(x),Some(y)) if x.pid == y.pid),
                )?;
            }
        }
        if self.phase == Phase::Idle {
            return require(
                self.operation.is_none()
                    && self.prepared.is_none()
                    && self.launch_intent.is_none()
                    && self.transition.is_none(),
            );
        }
        let o = self.operation.as_ref().ok_or(ControlError::CorruptState)?;
        require(
            o.candidate.revision_owner_operation == o.operation
                && o.candidate.revision
                    == o.base_revision.next().ok_or(ControlError::CorruptState)?
                && o.candidate.release_digest == self.identity.release_digest
                && o.admitted_high_water < self.high_water,
        )?;
        match &o.previous {
            Some(p) => require(
                p.revision == o.base_revision
                    && p.revision != Revision::ZERO
                    && p.release_digest == self.identity.release_digest
                    && p.revision_owner_operation != o.operation,
            )?,
            None => require(o.base_revision == Revision::ZERO)?,
        }
        let previous = |a: &OwnedRecord| {
            o.previous.as_ref() == Some(&a.launch.recipe)
                && a.launch.generation <= o.admitted_high_water
        };
        let candidate = |a: &OwnedRecord| {
            a.launch.recipe == o.candidate
                && a.launch.transition_operation == o.operation
                && a.launch.generation == o.admitted_high_water.saturating_add(1)
                && a.launch.generation == self.high_water
        };
        let restored = |a: &OwnedRecord| {
            o.previous.as_ref() == Some(&a.launch.recipe)
                && a.launch.transition_operation == o.operation
                && a.launch.generation > o.admitted_high_water.saturating_add(1)
                && a.launch.generation == self.high_water
        };
        let active_previous = self.active.as_ref().is_some_and(previous);
        let active_base = match (&self.active, &o.previous) {
            (None, None) => true,
            (Some(a), Some(_)) => previous(a),
            _ => false,
        };
        let candidate_prepared = self.prepared.as_ref().is_some_and(candidate);
        let restore_prepared = self.prepared.as_ref().is_some_and(restored);
        let no_l = self.launch_intent.is_none();
        let no_t = self.transition.is_none();
        let no_p = self.prepared.is_none();
        let no_a = self.active.is_none();
        let intent = |action, record: Option<&OwnedRecord>| {
            self.transition.as_ref().zip(record).is_some_and(|(t, r)| {
                t.action == action
                    && t.transition_operation == o.operation
                    && t.generation == r.launch.generation
            })
        };
        let launch = |role, observed| {
            self.launch_intent.as_ref().is_some_and(|l| {
                let target = match role {
                    Role::Candidate => Some(&o.candidate),
                    Role::RestorePrevious => o.previous.as_ref(),
                };
                l.role == role
                    && l.process.is_some() == observed
                    && target == Some(&l.launch.recipe)
                    && l.launch.transition_operation == o.operation
                    && match role {
                        Role::Candidate => {
                            l.launch.generation == o.admitted_high_water.saturating_add(1)
                        }
                        Role::RestorePrevious => {
                            l.launch.generation > o.admitted_high_water.saturating_add(1)
                        }
                    }
                    && l.launch.generation == self.high_water
            })
        };
        use Phase::*;
        require(match self.phase {
            Idle => false,
            CandidateReserved => active_base && no_p && no_t && launch(Role::Candidate, false),
            CandidateSpawnObserved => active_base && no_p && no_t && launch(Role::Candidate, true),
            Prepared => active_base && candidate_prepared && no_l && no_t,
            StoppingOld => {
                active_previous
                    && candidate_prepared
                    && no_l
                    && intent(Action::StopOld, self.active.as_ref())
            }
            OldStopped => no_a && candidate_prepared && no_l && no_t,
            ActivatingCandidate => {
                no_a && candidate_prepared
                    && no_l
                    && intent(Action::ActivateCandidate, self.prepared.as_ref())
            }
            CandidateStarted => self.active.as_ref().is_some_and(candidate) && no_p && no_l && no_t,
            StoppingCandidate => {
                self.active.as_ref().is_some_and(candidate)
                    && no_p
                    && no_l
                    && intent(Action::StopCandidate, self.active.as_ref())
            }
            DiscardingPrepared => {
                (no_a || active_previous)
                    && candidate_prepared
                    && no_l
                    && intent(Action::DiscardPrepared, self.prepared.as_ref())
            }
            CandidateAbsent => (no_a || active_previous) && no_p && no_l && no_t,
            RestoreReserved => no_a && no_p && no_t && launch(Role::RestorePrevious, false),
            RestoreSpawnObserved => no_a && no_p && no_t && launch(Role::RestorePrevious, true),
            RestorePrepared => no_a && restore_prepared && no_l && no_t,
            ActivatingRestore => {
                no_a && restore_prepared
                    && no_l
                    && intent(Action::ActivateRestore, self.prepared.as_ref())
            }
            Restored => {
                no_p && no_l
                    && no_t
                    && match (&self.active, &o.previous) {
                        (None, None) => true,
                        (Some(a), Some(_)) => restored(a),
                        _ => false,
                    }
            }
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, ControlError> {
        codec::encode(self)
    }
    pub fn decode(bytes: &[u8], expected: &Identity) -> Result<Self, ControlError> {
        codec::decode(bytes, expected)
    }
}
#[cfg(test)]
mod tests;
