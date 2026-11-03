//! Real Linux worker-process lifecycle, deliberately separate from certification.
//! Start/stop/replace are blocking bounded host operations: invoke off UI threads.
//! A verified child process isolates global core state and non-cancelable library
//! tasks. This is vp_core itself, not an alternate proxy engine.
#[cfg(feature = "experimental-public")]
pub mod probe_client_v2;
pub mod protocol;
mod sealed_executable;
pub use protocol::{
    BoundListener, Failure, ListenerKind, ListenerSpec, ProbeLedgerObservation, StopReport, WorkerConfig, WorkerSnapshot,
};
use protocol::{Request, Response, MAX_FRAME, PROTOCOL_VERSION};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_canceled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
#[derive(Clone)]
pub struct VerifiedWorker {
    path: PathBuf,
    sha256: String,
}
impl VerifiedWorker {
    /// The trusted digest comes from the reviewed release manifest, not an API caller.
    /// Compatibility entry point with a ten-second cooperative acquisition deadline.
    /// Linux >=6.3 and executable sealed memfd support are required; no path fallback.
    pub fn new(path: impl AsRef<Path>, expected_sha256: &str) -> Result<Self, Failure> {
        Self::with_deadline(
            path,
            expected_sha256,
            Instant::now() + Duration::from_secs(10),
            &Cancellation::default(),
        )
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

struct Process {
    child: Child,
    writer: Option<mpsc::SyncSender<Zeroizing<Vec<u8>>>>,
    responses: mpsc::Receiver<Result<Response, Failure>>,
    pumps: Vec<JoinHandle<()>>,
}
impl Process {
    fn spawn(
        worker: &VerifiedWorker,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<Self, Failure> {
        let executable = sealed_executable::SealedExecutable::capture(worker, deadline, cancel)?;
        let mut child = executable.spawn(&["--stdio-v1"], deadline, cancel)?;
        let mut input = child.stdin.take().ok_or(Failure::Io)?;
        let output = child.stdout.take().ok_or(Failure::Io)?;
        let (send_frames, frames) = mpsc::sync_channel::<Zeroizing<Vec<u8>>>(1);
        let (send_responses, responses) = mpsc::sync_channel(8);
        let errors = send_responses.clone();
        let writer = std::thread::spawn(move || {
            while let Ok(frame) = frames.recv() {
                if input.write_all(&frame).and_then(|_| input.flush()).is_err() {
                    let _ = errors.try_send(Err(Failure::Io));
                    break;
                }
            }
        });
        let reader = std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            loop {
                let result = match protocol::read_frame(&mut reader) {
                    Ok(Some(bytes)) => {
                        serde_json::from_slice(&bytes).map_err(|_| Failure::ProtocolViolation)
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
                if send_responses.try_send(result).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            writer: Some(send_frames),
            responses,
            pumps: vec![writer, reader],
        })
    }
    fn receive(&mut self, deadline: Instant, cancel: &Cancellation) -> Result<Response, Failure> {
        loop {
            if cancel.is_canceled() {
                return Err(Failure::Canceled);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Failure::Timeout)?;
            match self
                .responses
                .recv_timeout(remaining.min(Duration::from_millis(20)))
            {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Failure::WorkerExited),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
    fn request(
        &mut self,
        request: &Request,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<Response, Failure> {
        let mut frame =
            Zeroizing::new(serde_json::to_vec(request).map_err(|_| Failure::InvalidConfig)?);
        if frame.len() >= MAX_FRAME {
            return Err(Failure::InvalidConfig);
        }
        frame.push(b'\n');
        self.writer
            .as_ref()
            .ok_or(Failure::WorkerExited)?
            .try_send(frame)
            .map_err(|_| Failure::Busy)?;
        match self.receive(deadline, cancel)? {
            Response::Failed { failure } => Err(failure),
            response => Ok(response),
        }
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
                self.join_pumps();
                return Ok(false);
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.child.kill().map_err(|_| Failure::CleanupFailed)?;
        self.child.wait().map_err(|_| Failure::CleanupFailed)?;
        self.join_pumps();
        Ok(true)
    }
    fn join_pumps(&mut self) {
        for pump in self.pumps.drain(..) {
            let _ = pump.join();
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.writer.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.join_pumps();
    }
}

/// Rollback is a truthful outcome, not a successful application of the candidate.
#[derive(Clone, Debug)]
pub struct ReplaceFailure {
    pub candidate_error: Failure,
    pub rollback_error: Option<Failure>,
    pub restored: Option<WorkerSnapshot>,
}
pub struct ManagedRuntime {
    worker: VerifiedWorker,
    process: Option<Process>,
    active_config: Option<Zeroizing<Vec<u8>>>,
    generation: u64,
}
impl ManagedRuntime {
    pub fn new(worker: VerifiedWorker) -> Self {
        Self {
            worker,
            process: None,
            active_config: None,
            generation: 0,
        }
    }
    /// Seed from the durable runtime journal after a daemon restart. No old
    /// process is adopted and the next launch consumes exactly last_generation+1.
    pub fn with_generation(worker: VerifiedWorker, last_generation: u64) -> Result<Self, Failure> {
        if last_generation > vp_product_domain::MAX_WIRE_COUNTER {
            return Err(Failure::StaleGeneration);
        }
        Ok(Self {
            worker,
            process: None,
            active_config: None,
            generation: last_generation,
        })
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn is_running(&mut self) -> bool {
        self.process.as_mut().is_some_and(|process| {
            process
                .child
                .try_wait()
                .is_ok_and(|status| status.is_none())
        })
    }
    pub fn start(
        &mut self,
        config: WorkerConfig,
        expected_generation: u64,
        timeout: Duration,
        cancel: &Cancellation,
    ) -> Result<WorkerSnapshot, Failure> {
        self.start_with_spawn_observer(config, expected_generation, timeout, cancel, |_| Ok(()))
    }
    /// The observer runs after verified Hello, before any Start request/listener
    /// action. Persist the PID plus OS birth marker here before returning Ok.
    /// An observer error/panic drops the owning process guard and kills/reaps it.
    /// The callback must itself have bounded IO; it runs on the host caller.
    pub fn start_with_spawn_observer<F>(
        &mut self,
        config: WorkerConfig,
        expected_generation: u64,
        timeout: Duration,
        cancel: &Cancellation,
        observer: F,
    ) -> Result<WorkerSnapshot, Failure>
    where
        F: FnOnce(u32) -> Result<(), Failure>,
    {
        if expected_generation != self.generation {
            return Err(Failure::StaleGeneration);
        }
        if self.process.is_some() {
            return Err(Failure::Busy);
        }
        config.validate()?;
        if cancel.is_canceled() {
            return Err(Failure::Canceled);
        }
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(Failure::InvalidConfig);
        }
        let saved =
            Zeroizing::new(serde_json::to_vec(&config).map_err(|_| Failure::InvalidConfig)?);
        if saved.len() > MAX_FRAME - 512 {
            return Err(Failure::InvalidConfig);
        }
        let core = config.to_core_json()?;
        vp_config::parse_and_validate(&core, vp_config::Format::Json)
            .map_err(|_| Failure::InvalidConfig)?;
        let generation = self
            .generation
            .checked_add(1)
            .filter(|generation| *generation <= vp_product_domain::MAX_WIRE_COUNTER)
            .ok_or(Failure::StaleGeneration)?;
        let deadline = Instant::now() + timeout;
        // Allocate on every launch attempt, including a failed candidate. A
        // restored worker must never reuse that candidate generation.
        self.generation = generation;
        let mut process = Process::spawn(&self.worker, deadline, cancel)?;
        let build = crate::inspect_build().map_err(|_| Failure::WorkerIdentityMismatch)?;
        match process.receive(deadline, cancel)? {
            Response::Hello {
                version,
                core_commit,
                patchset_hash,
            } if version == PROTOCOL_VERSION
                && core_commit == build.build.release.core_commit
                && Some(patchset_hash.as_str()) == build.build.release.patchset_hash.as_deref() => {
            }
            _ => return Err(Failure::WorkerIdentityMismatch),
        }
        observer(process.child.id())?;
        if cancel.is_canceled() {
            return Err(Failure::Canceled);
        }
        if Instant::now() >= deadline {
            return Err(Failure::Timeout);
        }
        let request = Request::Start {
            version: PROTOCOL_VERSION,
            generation,
            config,
            startup_ms: timeout.as_millis().min(30_000) as u64,
        };
        let snapshot = match process.request(&request, deadline, cancel)? {
            Response::Started { snapshot }
                if snapshot.generation == generation
                    && snapshot.pid == process.child.id()
                    && snapshot.listeners_ready
                    && !snapshot.listeners.is_empty()
                    && snapshot.task_panics == 0 =>
            {
                snapshot
            }
            _ => return Err(Failure::ProtocolViolation),
        };
        if cancel.is_canceled() {
            return Err(Failure::Canceled);
        }
        let mut normalized: WorkerConfig =
            serde_json::from_slice(&saved).map_err(|_| Failure::InvalidConfig)?;
        for listener in &mut normalized.listeners {
            if listener.port == 0 {
                listener.port = snapshot
                    .listeners
                    .iter()
                    .find(|bound| bound.tag == listener.tag)
                    .ok_or(Failure::ProtocolViolation)?
                    .port;
            }
        }
        self.generation = generation;
        self.active_config = Some(Zeroizing::new(
            serde_json::to_vec(&normalized).map_err(|_| Failure::InvalidConfig)?,
        ));
        self.process = Some(process);
        Ok(snapshot)
    }
    pub fn snapshot(&mut self, expected_generation: u64) -> Result<WorkerSnapshot, Failure> {
        if expected_generation != self.generation {
            return Err(Failure::StaleGeneration);
        }
        let process = self.process.as_mut().ok_or(Failure::WorkerExited)?;
        let result = match process.request(
            &Request::Snapshot {
                generation: self.generation,
            },
            Instant::now() + Duration::from_secs(2),
            &Cancellation::default(),
        ) {
            Ok(Response::Snapshot { snapshot })
                if snapshot.generation == self.generation && snapshot.pid == process.child.id() =>
            {
                Ok(snapshot)
            }
            Ok(_) => Err(Failure::ProtocolViolation),
            Err(error) => Err(error),
        };
        if result.is_err() {
            // An unobservable/untrusted worker cannot remain secretly active.
            self.process.take();
            self.active_config = None;
        }
        result
    }
    pub fn stop(
        &mut self,
        expected_generation: u64,
        drain: Duration,
    ) -> Result<StopReport, Failure> {
        if expected_generation != self.generation {
            return Err(Failure::StaleGeneration);
        }
        if drain > Duration::from_secs(5) {
            return Err(Failure::InvalidConfig);
        }
        let Some(mut process) = self.process.take() else {
            return Ok(StopReport {
                generation: self.generation,
                drained: true,
                forced_tasks: 0,
                remaining_tasks: 0,
                process_exited: true,
            });
        };
        let deadline = Instant::now() + drain + Duration::from_secs(3);
        let response = process.request(
            &Request::Stop {
                generation: self.generation,
                drain_ms: drain.as_millis() as u64,
            },
            deadline,
            &Cancellation::default(),
        );
        let forced_process = process.close(deadline)?;
        self.active_config = None;
        match response {
            Ok(Response::Stopped { mut report }) if report.generation == self.generation => {
                report.process_exited = true;
                if forced_process {
                    report.drained = false;
                }
                Ok(report)
            }
            _ => Err(Failure::CleanupFailed), // child was still killed+waited, never a fake graceful stop
        }
    }
    pub fn replace(
        &mut self,
        config: WorkerConfig,
        expected_generation: u64,
        timeout: Duration,
        cancel: &Cancellation,
    ) -> Result<WorkerSnapshot, ReplaceFailure> {
        let early = |error| ReplaceFailure {
            candidate_error: error,
            rollback_error: None,
            restored: None,
        };
        if expected_generation != self.generation {
            return Err(early(Failure::StaleGeneration));
        }
        config.validate().map_err(early)?;
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(early(Failure::InvalidConfig));
        }
        let compiled = config.to_core_json().map_err(early)?;
        vp_config::parse_and_validate(&compiled, vp_config::Format::Json)
            .map_err(|_| early(Failure::InvalidConfig))?;
        if cancel.is_canceled() {
            return Err(early(Failure::Canceled));
        }
        let previous = self
            .active_config
            .as_ref()
            .map(|bytes| Zeroizing::new(bytes.to_vec()));
        if self.process.is_some() {
            if let Err(error) = self.stop(expected_generation, Duration::from_millis(100)) {
                // Do not pretend a failed cleanup left the previous generation
                // intact or safely restored. Recovery needs explicit evidence.
                return Err(ReplaceFailure {
                    candidate_error: error,
                    rollback_error: Some(Failure::CleanupFailed),
                    restored: None,
                });
            }
        }
        match self.start(config, self.generation, timeout, cancel) {
            Ok(snapshot) => Ok(snapshot),
            Err(candidate_error) => {
                // The previous stopped state is restored by the failed candidate's
                // process guard; no fictitious previous worker is required.
                let Some(previous) = previous else {
                    return Err(ReplaceFailure {
                        candidate_error,
                        rollback_error: None,
                        restored: None,
                    });
                };
                let restored = serde_json::from_slice::<WorkerConfig>(&previous)
                    .map_err(|_| Failure::InvalidConfig)
                    .and_then(|old| {
                        self.start(old, self.generation, timeout, &Cancellation::default())
                    });
                match restored {
                    Ok(snapshot) => Err(ReplaceFailure {
                        candidate_error,
                        rollback_error: None,
                        restored: Some(snapshot),
                    }),
                    Err(rollback_error) => Err(ReplaceFailure {
                        candidate_error,
                        rollback_error: Some(rollback_error),
                        restored: None,
                    }),
                }
            }
        }
    }
}

#[cfg(feature = "managed-server-v2")]
pub mod server_v2;

#[cfg(feature = "managed-server-v2")]
pub mod host_v2;
#[cfg(feature = "managed-server-v2")]
pub mod material_port_v2;
#[cfg(feature = "managed-server-v2")]
pub mod protocol_v2;
#[cfg(feature = "managed-server-v2")]
pub mod server_worker_v2;

#[cfg(all(test, feature = "managed-server-v2"))]
mod v2_test_support;

#[cfg(feature = "managed-server-v2")]
mod sealed_executable_v2;
