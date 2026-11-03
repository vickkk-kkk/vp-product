//! V2 process ownership, not a control transaction/rollback engine. Preparing a
//! second child never stops the active child. The caller's existing durable
//! controller orders prepare -> stop old -> activate; rollback resolves immutable
//! old references again and consumes a fresh generation, never cached plaintext.
use super::{
    protocol_v2::{
        self, CommandV2, FrameReaderV2, ResponseV2, SecretFrameV2, WorkerInstanceV2,
        MAX_REQUEST_FRAME_V2, MAX_RESPONSE_FRAME_V2, VERSION_V2,
    },
    sealed_executable_v2::SealedExecutableV2,
    server_v2::ServerInputsV2,
    Cancellation, Failure, StopReport, VerifiedWorker, WorkerSnapshot,
};
use std::{
    process::Child,
    sync::mpsc,
    thread::JoinHandle,
    time::{Duration, Instant},
};
use vp_product_compiler::server_v2::{ServerCompilerV2, ServerProfileV2, ServerRecipeV2};
use vp_product_domain::MAX_WIRE_COUNTER;

#[derive(Clone, Debug)]
pub struct SpawnedProcessV2 {
    pub pid: u32,
    pub instance: WorkerInstanceV2,
    pub generation: u64,
}
/// The observer must durably record PID + OS start ticks/boot ID using the same
/// ownership mechanism as v1, before returning Ok. Callback IO must be bounded.
/// No PID-only adoption/recovery or OS-process killing by guessed PID is exposed.
struct ProcessV2 {
    child: Child,
    writer: Option<mpsc::SyncSender<SecretFrameV2>>,
    responses: mpsc::Receiver<Result<ResponseV2, Failure>>,
    pumps: Vec<JoinHandle<()>>,
}
impl ProcessV2 {
    fn spawn(
        worker: &VerifiedWorker,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<Self, Failure> {
        let executable = SealedExecutableV2::capture(worker, deadline, cancel)?;
        let child = executable.spawn(&["--stdio-server-v2"], deadline, cancel)?;
        let (send_frames, frames) = mpsc::sync_channel::<SecretFrameV2>(1);
        let (send_responses, responses) = mpsc::sync_channel(4);
        // Install the owning guard before pipe extraction or spawning any pump.
        let mut process = Self {
            child,
            writer: Some(send_frames),
            responses,
            pumps: Vec::new(),
        };
        let mut input = process.child.stdin.take().ok_or(Failure::Io)?;
        let output = process.child.stdout.take().ok_or(Failure::Io)?;
        let errors = send_responses.clone();
        let writer = std::thread::Builder::new()
            .name("vp-v2-write".into())
            .spawn(move || {
                while let Ok(frame) = frames.recv() {
                    if frame.write_to(&mut input).is_err() {
                        let _ = errors.try_send(Err(Failure::Io));
                        break;
                    }
                }
            })
            .map_err(|_| Failure::Io)?;
        process.pumps.push(writer);
        let reader = std::thread::Builder::new()
            .name("vp-v2-read".into())
            .spawn(move || {
                let mut reader = FrameReaderV2::new(output);
                loop {
                    let response = match reader.read_frame(MAX_RESPONSE_FRAME_V2) {
                        Ok(Some(frame)) => {
                            serde_json::from_slice(&frame).map_err(|_| Failure::ProtocolViolation)
                        }
                        Ok(None) => {
                            let _ = send_responses.try_send(Err(Failure::WorkerExited));
                            break;
                        }
                        Err(_) => {
                            let _ = send_responses.try_send(Err(Failure::ProtocolViolation));
                            break;
                        }
                    };
                    if send_responses.try_send(response).is_err() {
                        break;
                    }
                }
            })
            .map_err(|_| Failure::Io)?;
        process.pumps.push(reader);
        Ok(process)
    }
    fn receive(&mut self, deadline: Instant, cancel: &Cancellation) -> Result<ResponseV2, Failure> {
        loop {
            check(deadline, cancel)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Failure::Timeout)?;
            match self
                .responses
                .recv_timeout(remaining.min(Duration::from_millis(20)))
            {
                Ok(Ok(ResponseV2::FailedServerV2 { failure })) => return Err(failure),
                Ok(response) => return response,
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Failure::WorkerExited),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
    fn request(
        &mut self,
        frame: SecretFrameV2,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<ResponseV2, Failure> {
        check(deadline, cancel)?;
        self.writer
            .as_ref()
            .ok_or(Failure::WorkerExited)?
            .try_send(frame)
            .map_err(|_| Failure::Busy)?;
        self.receive(deadline, cancel)
    }
    fn close(&mut self, deadline: Instant) -> Result<bool, Failure> {
        self.writer.take();
        loop {
            if self
                .child
                .try_wait()
                .map_err(|_| Failure::CleanupFailed)?
                .is_some()
            {
                self.join();
                return Ok(false);
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if self.child.kill().is_err()
            && self
                .child
                .try_wait()
                .map_err(|_| Failure::CleanupFailed)?
                .is_none()
        {
            return Err(Failure::CleanupFailed);
        }
        self.child.wait().map_err(|_| Failure::CleanupFailed)?;
        self.join();
        Ok(true)
    }
    fn join(&mut self) {
        for pump in self.pumps.drain(..) {
            let _ = pump.join();
        }
    }
}
impl Drop for ProcessV2 {
    fn drop(&mut self) {
        self.writer.take();
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        self.join();
    }
}
fn valid_probe_ledger(value: &Option<super::ProbeLedgerObservation>, required: bool) -> bool {
    match (value, required) {
        (None, false) => true,
        (Some(ledger), true) => ledger.version == 1 && ledger.token_hashes.len() <= 64
            && ledger.token_hashes.iter().all(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && ledger.token_hashes.windows(2).all(|w| w[0] < w[1]),
        _ => false,
    }
}
#[cfg(test)]
mod probe_ledger_tests {
    use super::*;
    #[test]
    fn public_snapshots_require_bounded_canonical_ledger() {
        assert!(!valid_probe_ledger(&None, true)); assert!(valid_probe_ledger(&None, false));
        let mut ledger = super::super::ProbeLedgerObservation { version: 1, token_hashes: vec!["a".repeat(64)], saturated: false };
        assert!(valid_probe_ledger(&Some(ledger.clone()), true));
        assert!(!valid_probe_ledger(&Some(ledger.clone()), false));
        ledger.token_hashes.push("a".repeat(64)); assert!(!valid_probe_ledger(&Some(ledger.clone()), true));
        ledger.token_hashes = vec!["A".repeat(64)]; assert!(!valid_probe_ledger(&Some(ledger.clone()), true));
        ledger.token_hashes = (0..65).map(|n| format!("{n:064x}")).collect(); assert!(!valid_probe_ledger(&Some(ledger.clone()), true));
        ledger.token_hashes.truncate(64); ledger.saturated = true;
        assert!(valid_probe_ledger(&Some(ledger), true)); // consumers reject saturation as evidence
    }
}
struct OwnedServerV2 {
    process: ProcessV2,
    generation: u64,
    listeners: Vec<(String, u16)>,
    public_experiment: bool,
}
impl OwnedServerV2 {
    fn valid_snapshot(&self, snapshot: &WorkerSnapshot, require_ready: bool) -> bool {
        valid_probe_ledger(&snapshot.probe_ledger, self.public_experiment) && snapshot.generation == self.generation
            && snapshot.pid == self.process.child.id()
            && !snapshot.forwarding_verified
            && snapshot.listeners.len() == self.listeners.len()
            && self.listeners.iter().all(|(tag, port)| {
                snapshot
                    .listeners
                    .iter()
                    .filter(|l| &l.tag == tag && l.port == *port)
                    .count()
                    == 1
            })
            && (!require_ready
                || (snapshot.listeners_ready
                    && snapshot.task_panics == 0
                    && snapshot.listeners.iter().all(|l| l.accept_loop_live)))
    }
}
fn check(deadline: Instant, cancel: &Cancellation) -> Result<(), Failure> {
    if cancel.is_canceled() {
        Err(Failure::Canceled)
    } else if Instant::now() >= deadline {
        Err(Failure::Timeout)
    } else {
        Ok(())
    }
}
fn deadline(timeout: Duration) -> Result<Instant, Failure> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        Err(Failure::InvalidConfig)
    } else {
        Ok(Instant::now() + timeout)
    }
}

pub struct ManagedRuntimeV2 {
    worker: VerifiedWorker,
    instance: WorkerInstanceV2,
    high_water: u64,
    prepared: Option<OwnedServerV2>,
    active: Option<OwnedServerV2>,
}
impl ManagedRuntimeV2 {
    /// Briefly starts the sealed worker only to verify its protocol/build and
    /// test-fixture marker, then kills/reaps it. No config, listener or secret.
    pub fn probe_worker(worker: &VerifiedWorker, timeout: Duration, cancel: &Cancellation) -> Result<(), Failure> {
        let deadline = deadline(timeout)?;
        let build = crate::inspect_build().map_err(|_| Failure::WorkerIdentityMismatch)?;
        let mut process = ProcessV2::spawn(worker, deadline, cancel)?;
        match process.receive(deadline, cancel)? {
            ResponseV2::HelloServerV2 { version, pid, release, max_request_bytes, test_fixture }
                if version == VERSION_V2 && pid == process.child.id() && release == build.build.release
                    && max_request_bytes == MAX_REQUEST_FRAME_V2 && test_fixture == cfg!(feature = "local-probe-test") => Ok(()),
            _ => Err(Failure::WorkerIdentityMismatch),
        }
        // ProcessV2 drop closes the pipe and reaps the exact owned child.
    }
    pub fn with_generation(
        worker: VerifiedWorker,
        instance: WorkerInstanceV2,
        last_generation: u64,
    ) -> Result<Self, Failure> {
        if last_generation > MAX_WIRE_COUNTER {
            return Err(Failure::StaleGeneration);
        }
        Ok(Self {
            worker,
            instance,
            high_water: last_generation,
            prepared: None,
            active: None,
        })
    }
    pub fn generation(&self) -> u64 {
        self.high_water
    }
    /// Exact verified executable identity, not proof that the worker is alive.
    pub fn worker_sha256(&self) -> &str { self.worker.sha256() }
    pub fn active_generation(&self) -> Option<u64> {
        self.active.as_ref().map(|v| v.generation)
    }
    pub fn prepared_generation(&self) -> Option<u64> {
        self.prepared.as_ref().map(|v| v.generation)
    }
    pub fn instance(&self) -> &WorkerInstanceV2 {
        &self.instance
    }
    pub fn is_running(&mut self) -> bool {
        self.active.as_mut().is_some_and(|v| {
            v.process
                .child
                .try_wait()
                .is_ok_and(|status| status.is_none())
        })
    }
    /// Material is sent only after exact v2 Hello/negotiation and the durable PID
    /// observer. Prepared means certificate/key and protocol inputs validated;
    /// it does NOT mean bound, forwarded, activated or applied.
    pub fn prepare_with_spawn_observer<F>(
        &mut self,
        recipe: ServerRecipeV2,
        inputs: ServerInputsV2,
        expected_high_water: u64,
        timeout: Duration,
        cancel: &Cancellation,
        observer: F,
    ) -> Result<SpawnedProcessV2, Failure>
    where
        F: FnOnce(&SpawnedProcessV2) -> Result<(), Failure>,
    {
        if expected_high_water != self.high_water {
            return Err(Failure::StaleGeneration);
        }
        if self.prepared.is_some() {
            return Err(Failure::Busy);
        }
        let deadline = deadline(timeout)?;
        check(deadline, cancel)?;
        let build = crate::inspect_build().map_err(|_| Failure::WorkerIdentityMismatch)?;
        let compiler = match recipe.profile {
            ServerProfileV2::LoopbackDevelopmentUncertified => {
                ServerCompilerV2::for_loopback_development(build.build.release.clone())
            }
            ServerProfileV2::LoopbackExtendedCoreUncertified => {
                ServerCompilerV2::for_loopback_server_extensions(build.build.release.clone())
            }
            ServerProfileV2::PublicExperimentalUncertified => {
                #[cfg(feature = "experimental-public")]
                { ServerCompilerV2::for_public_experiment(build.build.release.clone(), recipe.public_targets.clone().ok_or(Failure::InvalidConfig)?) }
                #[cfg(not(feature = "experimental-public"))]
                { return Err(Failure::InvalidConfig); }
            },
        }
        .map_err(|_| Failure::InvalidConfig)?;
        compiler
            .verify_recipe(&recipe)
            .map_err(|_| Failure::InvalidConfig)?;
        let generation = self
            .high_water
            .checked_add(1)
            .filter(|g| *g <= MAX_WIRE_COUNTER)
            .ok_or(Failure::StaleGeneration)?;
        // Two-pass bounded encoding includes JSON escaping before allocating the
        // frame. This preflight cannot stop or mutate an existing generation.
        let frame = protocol_v2::encode_prepare(
            &self.instance,
            generation,
            &recipe,
            &inputs,
            timeout.as_millis() as u64,
        )?;
        check(deadline, cancel)?;
        let listeners = recipe
            .listeners
            .iter()
            .map(|l| (l.id.as_str().to_owned(), l.bind.port))
            .collect();
        self.high_water = generation; // every launch attempt consumes a durable slot
        let mut process = ProcessV2::spawn(&self.worker, deadline, cancel)?;
        match process.receive(deadline, cancel)? {
            ResponseV2::HelloServerV2 {
                version,
                pid,
                release,
                max_request_bytes,
                test_fixture,
            } if version == VERSION_V2
                && pid == process.child.id()
                && release == build.build.release
                && max_request_bytes == MAX_REQUEST_FRAME_V2
                && test_fixture == cfg!(feature = "local-probe-test") => {}
            _ => return Err(Failure::WorkerIdentityMismatch),
        }
        match process.request(
            protocol_v2::encode_control(CommandV2::Negotiate, &self.instance, 0, None)?,
            deadline,
            cancel,
        )? {
            ResponseV2::NegotiatedServerV2 {
                version,
                instance,
                pid,
            } if version == VERSION_V2
                && instance == self.instance
                && pid == process.child.id() => {}
            _ => return Err(Failure::ProtocolViolation),
        }
        let spawned = SpawnedProcessV2 {
            pid: process.child.id(),
            instance: self.instance.clone(),
            generation,
        };
        observer(&spawned)?;
        check(deadline, cancel)?;
        match process.request(frame, deadline, cancel)? {
            ResponseV2::PreparedServerV2 {
                instance,
                generation: observed,
                pid,
            } if instance == self.instance
                && observed == generation
                && pid == process.child.id() => {}
            _ => return Err(Failure::ProtocolViolation),
        }
        check(deadline, cancel)?;
        self.prepared = Some(OwnedServerV2 {
            process,
            generation,
            listeners,
            public_experiment: recipe.profile == ServerProfileV2::PublicExperimentalUncertified || cfg!(feature = "local-probe-test"),
        });
        Ok(spawned)
    }
    pub fn activate_prepared(
        &mut self,
        generation: u64,
        timeout: Duration,
        cancel: &Cancellation,
    ) -> Result<WorkerSnapshot, Failure> {
        if self.prepared_generation() != Some(generation) {
            return Err(Failure::StaleGeneration);
        }
        if self.active.is_some() {
            return Err(Failure::Busy);
        } // caller controls old-generation stop
        let deadline = deadline(timeout)?;
        let mut candidate = self.prepared.take().ok_or(Failure::WorkerExited)?;
        let response = candidate.process.request(
            protocol_v2::encode_control(CommandV2::Activate, &self.instance, generation, None)?,
            deadline,
            cancel,
        )?;
        let snapshot = match response {
            ResponseV2::StartedServerV2 { instance, snapshot }
                if instance == self.instance && candidate.valid_snapshot(&snapshot, true) =>
            {
                snapshot
            }
            _ => return Err(Failure::ProtocolViolation),
        };
        check(deadline, cancel)?;
        self.active = Some(candidate);
        Ok(snapshot)
    }
    pub fn snapshot(&mut self, generation: u64) -> Result<WorkerSnapshot, Failure> {
        if self.active_generation() != Some(generation) {
            return Err(Failure::StaleGeneration);
        }
        let active = self.active.as_mut().ok_or(Failure::WorkerExited)?;
        let response = active.process.request(
            protocol_v2::encode_control(CommandV2::Snapshot, &self.instance, generation, None)?,
            Instant::now() + Duration::from_secs(2),
            &Cancellation::default(),
        );
        let result = match response {
            Ok(ResponseV2::SnapshotServerV2 { instance, snapshot })
                if instance == self.instance && active.valid_snapshot(&snapshot, false) =>
            {
                Ok(snapshot)
            }
            Ok(_) => Err(Failure::ProtocolViolation),
            Err(error) => Err(error),
        };
        if result.is_err() {
            self.active.take();
        }
        result
    }
    pub fn stop_active(&mut self, generation: u64, drain: Duration) -> Result<StopReport, Failure> {
        if self.active_generation() != Some(generation) {
            return Err(Failure::StaleGeneration);
        }
        if drain > Duration::from_secs(5) {
            return Err(Failure::InvalidConfig);
        }
        let mut active = self.active.take().ok_or(Failure::WorkerExited)?;
        let deadline = Instant::now() + drain + Duration::from_secs(3);
        let response = active.process.request(
            protocol_v2::encode_control(
                CommandV2::Stop,
                &self.instance,
                generation,
                Some(drain.as_millis() as u64),
            )?,
            deadline,
            &Cancellation::default(),
        );
        let forced = active.process.close(deadline)?;
        match response {
            Ok(ResponseV2::StoppedServerV2 {
                instance,
                mut report,
            }) if instance == self.instance
                && report.generation == generation
                && report.remaining_tasks == 0 =>
            {
                report.process_exited = true;
                if forced {
                    report.drained = false;
                }
                Ok(report)
            }
            _ => Err(Failure::CleanupFailed),
        }
    }
    pub fn discard_prepared(&mut self, generation: u64) -> Result<(), Failure> {
        if self.prepared_generation() != Some(generation) {
            return Err(Failure::StaleGeneration);
        }
        let mut prepared = self.prepared.take().ok_or(Failure::WorkerExited)?;
        if prepared
            .process
            .child
            .try_wait()
            .map_err(|_| Failure::CleanupFailed)?
            .is_some()
        {
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let response = prepared.process.request(
            protocol_v2::encode_control(CommandV2::Discard, &self.instance, generation, None)?,
            deadline,
            &Cancellation::default(),
        );
        prepared.process.close(deadline)?;
        match response {
            Ok(ResponseV2::DiscardedServerV2 {
                instance,
                generation: observed,
                pid,
            }) if instance == self.instance
                && observed == generation
                && pid == prepared.process.child.id() =>
            {
                Ok(())
            }
            _ => Err(Failure::CleanupFailed),
        }
    }
}
