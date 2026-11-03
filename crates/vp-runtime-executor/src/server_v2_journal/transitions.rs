use super::*;
/// Proposals based on caller-reported observations, NOT proof of an effect.
/// No event writes a journal or touches a child. Persist-before-effect and live
/// ownership are obligations of a future effectful executor, not this module.
#[derive(Clone, Debug)]
pub enum Event {
    Begin {
        // Keep the in-memory event small; this is not a persisted/wire field.
        operation: Box<OperationRecord>,
        instance: String,
        session: String,
    },
    SpawnObserved(ProcessIdentity),
    Prepared,
    StopOld,
    OldStopped,
    Activate,
    Activated,
    StopCandidate,
    CandidateStopped,
    Discard,
    Discarded,
    /// Exact owned launch/activation child has been proven terminated by caller.
    /// Missing/unknown launch PID cannot use this event.
    FailedChildAbsent,
    Restore {
        instance: String,
        session: String,
    },
    /// Previous=None, candidate absence established: no invented prior material.
    RestoreStopped,
}
impl Journal {
    pub fn propose(&self, event: Event) -> Result<Self, ControlError> {
        self.validate()?;
        let mut n = self.clone();
        n.sequence = n
            .sequence
            .checked_add(1)
            .filter(|v| *v <= MAX_WIRE_COUNTER)
            .ok_or(ControlError::CounterExhausted)?;
        use Phase::*;
        match event {
            Event::Begin {
                operation,
                instance,
                session,
            } if self.phase == Idle => {
                require(operation.admitted_high_water == self.high_water)?;
                n.high_water = next_generation(self.high_water)?;
                n.launch_intent = Some(LaunchIntent {
                    role: Role::Candidate,
                    process: None,
                    launch: LaunchRecord {
                        recipe: operation.candidate.clone(),
                        transition_operation: operation.operation.clone(),
                        generation: n.high_water,
                        instance,
                        session,
                        worker_digest: n.identity.worker_digest.clone(),
                        worker_protocol_version: 3,
                    },
                });
                n.operation = Some(*operation);
                n.phase = CandidateReserved;
            }
            Event::SpawnObserved(process)
                if matches!(self.phase, CandidateReserved | RestoreReserved) =>
            {
                n.launch_intent
                    .as_mut()
                    .ok_or(ControlError::CorruptState)?
                    .process = Some(process);
                n.phase = if self.phase == CandidateReserved {
                    CandidateSpawnObserved
                } else {
                    RestoreSpawnObserved
                };
            }
            Event::Prepared
                if matches!(self.phase, CandidateSpawnObserved | RestoreSpawnObserved) =>
            {
                let l = n.launch_intent.take().ok_or(ControlError::CorruptState)?;
                n.prepared = Some(OwnedRecord {
                    launch: l.launch,
                    process: l.process.ok_or(ControlError::CorruptState)?,
                });
                n.phase = if self.phase == CandidateSpawnObserved {
                    Prepared
                } else {
                    RestorePrepared
                };
            }
            Event::StopOld if self.phase == Prepared && self.active.is_some() => {
                n.set_intent(Action::StopOld, true)?;
                n.phase = StoppingOld;
            }
            Event::OldStopped if self.phase == StoppingOld => {
                n.active = None;
                n.transition = None;
                n.phase = OldStopped;
            }
            Event::Activate
                if (self.phase == Prepared && self.active.is_none())
                    || self.phase == OldStopped
                    || self.phase == RestorePrepared =>
            {
                let restore = self.phase == RestorePrepared;
                n.set_intent(
                    if restore {
                        Action::ActivateRestore
                    } else {
                        Action::ActivateCandidate
                    },
                    false,
                )?;
                n.phase = if restore {
                    ActivatingRestore
                } else {
                    ActivatingCandidate
                };
            }
            Event::Activated if matches!(self.phase, ActivatingCandidate | ActivatingRestore) => {
                n.active = n.prepared.take();
                n.transition = None;
                n.phase = if self.phase == ActivatingRestore {
                    Restored
                } else {
                    CandidateStarted
                };
            }
            Event::StopCandidate if self.phase == CandidateStarted => {
                n.set_intent(Action::StopCandidate, true)?;
                n.phase = StoppingCandidate;
            }
            Event::CandidateStopped if self.phase == StoppingCandidate => {
                n.active = None;
                n.transition = None;
                n.phase = CandidateAbsent;
            }
            Event::Discard if matches!(self.phase, Prepared | OldStopped) => {
                n.set_intent(Action::DiscardPrepared, false)?;
                n.phase = DiscardingPrepared;
            }
            Event::Discarded if self.phase == DiscardingPrepared => {
                n.prepared = None;
                n.transition = None;
                n.phase = CandidateAbsent;
            }
            Event::FailedChildAbsent
                if matches!(
                    self.phase,
                    CandidateSpawnObserved
                        | RestoreSpawnObserved
                        | ActivatingCandidate
                        | ActivatingRestore
                        | RestorePrepared
                ) =>
            {
                n.launch_intent = None;
                n.prepared = None;
                n.transition = None;
                n.phase = CandidateAbsent;
            }
            Event::Restore { instance, session }
                if self.phase == CandidateAbsent && self.active.is_none() =>
            {
                let o = n.operation.as_ref().ok_or(ControlError::CorruptState)?;
                let recipe = o.previous.clone().ok_or(ControlError::ResourceConflict)?;
                n.high_water = next_generation(self.high_water)?;
                n.launch_intent = Some(LaunchIntent {
                    role: Role::RestorePrevious,
                    process: None,
                    launch: LaunchRecord {
                        recipe,
                        transition_operation: o.operation.clone(),
                        generation: n.high_water,
                        instance,
                        session,
                        worker_digest: n.identity.worker_digest.clone(),
                        worker_protocol_version: 3,
                    },
                });
                n.phase = RestoreReserved;
            }
            Event::RestoreStopped
                if self.phase == CandidateAbsent
                    && self.active.is_none()
                    && self
                        .operation
                        .as_ref()
                        .is_some_and(|o| o.previous.is_none()) =>
            {
                n.phase = Restored;
            }
            _ => return Err(ControlError::RecoveryRequired),
        }
        n.validate()?;
        Ok(n)
    }
    fn set_intent(&mut self, action: Action, active: bool) -> Result<(), ControlError> {
        let record = if active {
            self.active.as_ref()
        } else {
            self.prepared.as_ref()
        }
        .ok_or(ControlError::CorruptState)?;
        self.transition = Some(TransitionIntent {
            action,
            transition_operation: self
                .operation
                .as_ref()
                .ok_or(ControlError::CorruptState)?
                .operation
                .clone(),
            generation: record.launch.generation,
        });
        Ok(())
    }
    /// Pure terminal reconciliation. Control pairing must report Finalize; no
    /// process adoption or current-health claim follows from clearing metadata.
    pub fn finalize(&self, state: &vp_product_control::StoredState) -> Result<Self, ControlError> {
        require(pair_control(self, state)? == Pairing::Finalize)?;
        let mut n = self.clone();
        n.sequence = next_generation(self.sequence)?;
        n.operation = None;
        n.phase = Phase::Idle;
        n.validate()?;
        Ok(n)
    }
}
fn next_generation(v: u64) -> Result<u64, ControlError> {
    v.checked_add(1)
        .filter(|v| *v <= MAX_WIRE_COUNTER)
        .ok_or(ControlError::CounterExhausted)
}
