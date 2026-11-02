//! In-process mobile generation controller. Uses only vp_core's data plane.
//! No worker process, provider download, global router or host route changes.
mod config;
#[allow(unsafe_code)]
mod fd;
#[allow(unsafe_code)]
pub mod ffi;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    os::fd::OwnedFd,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex, MutexGuard,
    },
    thread::JoinHandle,
    time::Duration,
};
use vp_core::task_scope::{DestinationPolicy, TaskScope};
use vp_product_domain::*;
const COMMAND_CAP: usize = 16;
const IDEMPOTENCY_CAP: usize = 256;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
fn now() -> u64 {
    vp_common::now_millis()
}
fn observation() -> HealthObservation {
    HealthObservation {
        status: ObservationStatus::NotRun,
        observed_at: None,
        evidence_id: None,
        detail_key: None,
    }
}
fn passed(g: Revision, kind: &str) -> HealthObservation {
    HealthObservation {
        status: ObservationStatus::Passed,
        observed_at: Some(now()),
        evidence_id: EvidenceId::new(format!("mobile-{}-{kind}", g.get())).ok(),
        detail_key: None,
    }
}
struct Events {
    items: VecDeque<RuntimeEvent>,
    capacity: usize,
}
struct Shared {
    snapshot: Mutex<RuntimeSnapshot>,
    events: Mutex<Events>,
    changed: Condvar,
    finished: AtomicBool,
    stop: AtomicBool,
}
impl Shared {
    fn new(capacity: usize) -> Self {
        static INSTANCE: AtomicU64 = AtomicU64::new(0);
        let instance_id = format!(
            "mobile-{}-{}-{}",
            std::process::id(),
            now(),
            INSTANCE.fetch_add(1, Ordering::Relaxed)
        );
        let at = now();
        Self {
            snapshot: Mutex::new(RuntimeSnapshot {
                schema_version: SCHEMA_VERSION,
                instance_id,
                generation: Revision::ZERO,
                sequence: Revision::ZERO,
                observed_at: at,
                valid_until: at + 30_000,
                desired: ConnectionIntent::Disconnected {},
                phase: RuntimePhase::Idle,
                config_revision: None,
                desired_revision: None,
                node_id: None,
                operation_id: None,
                health: RuntimeHealth {
                    core: observation(),
                    takeover: observation(),
                    tunnel: observation(),
                    dns: observation(),
                    ipv4: observation(),
                    ipv6: observation(),
                    forwarding: observation(),
                    required_probes: vec![],
                },
                error: None,
            }),
            events: Mutex::new(Events {
                items: VecDeque::new(),
                capacity,
            }),
            changed: Condvar::new(),
            finished: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        }
    }
    fn update(&self, g: Revision, change: impl FnOnce(&mut RuntimeSnapshot)) {
        let mut s = lock(&self.snapshot);
        if s.generation != g {
            return;
        }
        change(&mut s);
        self.emit(&mut s);
    }
    fn emit(&self, s: &mut RuntimeSnapshot) {
        let Some(seq) = s.sequence.next() else {
            self.stop.store(true, Ordering::Release);
            return;
        };
        s.sequence = seq;
        s.observed_at = now();
        s.valid_until = s.observed_at + 30_000;
        let mut e = lock(&self.events);
        let payload = if e.items.len() >= e.capacity {
            e.items.clear();
            RuntimeEventPayload::ResyncRequired {
                last_retained_sequence: seq,
            }
        } else {
            RuntimeEventPayload::Snapshot {
                snapshot: Box::new(s.clone()),
            }
        };
        e.items.push_back(RuntimeEvent {
            schema_version: SCHEMA_VERSION,
            instance_id: s.instance_id.clone(),
            generation: s.generation,
            sequence: seq,
            operation_id: s.operation_id.clone(),
            revision: s.config_revision,
            payload,
        });
        self.changed.notify_all();
    }
    fn snapshot(&self) -> RuntimeSnapshot {
        let mut s = lock(&self.snapshot).clone();
        s.observed_at = now();
        s.valid_until = s.observed_at + 30_000;
        s
    }
    fn finish(&self) {
        self.finished.store(true, Ordering::Release);
        self.changed.notify_all();
    }
}
struct Idempotency {
    digest: [u8; 32],
    result: Value,
}
struct Gate {
    accepted: HashMap<IdempotencyKey, Idempotency>,
}
enum Work {
    Connect {
        generation: Revision,
        input: Box<config::Connect>,
    },
    Disconnect {
        generation: Revision,
    },
}
pub struct Handle {
    shared: Arc<Shared>,
    gate: Mutex<Gate>,
    sender: tokio::sync::mpsc::Sender<Work>,
    thread: Mutex<Option<JoinHandle<()>>>,
    active: AtomicU64,
    closing: AtomicBool,
    event_reader: AtomicBool,
}
impl Handle {
    fn create(
        fd: OwnedFd,
        mtu: u16,
        capacity: usize,
        callbacks: ffi::Callbacks,
    ) -> Result<Self, i32> {
        let shared = Arc::new(Shared::new(capacity));
        let (sender, rx) = tokio::sync::mpsc::channel(COMMAND_CAP);
        let own = shared.clone();
        let thread = std::thread::Builder::new()
            .name("vp-mobile-controller".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                        .map_err(|_| ())?;
                    runtime.block_on(run(own.clone(), rx, fd, mtu, callbacks));
                    // Drop every driver task, including third-party QUIC/ipstack internal tasks,
                    // before declaring the controller finished or freeing host callbacks.
                    drop(runtime);
                    let generation = lock(&own.snapshot).generation;
                    own.update(generation, |s| {
                        if s.phase == RuntimePhase::Stopping {
                            s.phase = RuntimePhase::Idle;
                            s.config_revision = None;
                            s.node_id = None;
                        }
                    });
                    Ok::<(), ()>(())
                }));
                if !matches!(result, Ok(Ok(()))) {
                    let g = lock(&own.snapshot).generation;
                    own.update(g, |s| {
                        s.phase = RuntimePhase::Failed;
                        s.error = Some(ProductError::new(ErrorCode::Internal, ErrorStage::Start));
                    });
                }
                own.finish();
            })
            .map_err(|_| ffi::INTERNAL)?;
        Ok(Self {
            shared,
            gate: Mutex::new(Gate {
                accepted: HashMap::new(),
            }),
            sender,
            thread: Mutex::new(Some(thread)),
            active: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            event_reader: AtomicBool::new(false),
        })
    }
    fn request(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let mut cmd: CommandEnvelope<Value> =
            serde_json::from_slice(input).map_err(|_| ffi::INVALID_ARGUMENT)?;
        // Decode the ORIGINAL bytes into the exact method payload before Value
        // can collapse duplicate object keys. No controller/FD action is queued
        // until this strict pass succeeds (also required if preflight was skipped).
        let mut migration_error = None;
        let strict = match cmd.method {
            CommandMethod::Connect => {
                serde_json::from_slice::<CommandEnvelope<config::Connect>>(input).map(|typed| {
                    migration_error = typed.payload.validate_version().err();
                })
            }
            CommandMethod::Snapshot
            | CommandMethod::Disconnect
            | CommandMethod::OperationCancel => {
                serde_json::from_slice::<CommandEnvelope<EmptyPayload>>(input).map(|_| ())
            }
            _ => Ok(()),
        };
        if strict.is_err() {
            config::erase_json(&mut cmd.payload);
            return Err(ffi::INVALID_ARGUMENT);
        }
        if let Some(error) = migration_error {
            config::erase_json(&mut cmd.payload);
            return serde_json::to_vec(&FailureEnvelope {
                schema_version: SCHEMA_VERSION,
                request_id: cmd.request_id,
                operation_id: None,
                error,
            })
            .map_err(|_| ffi::INTERNAL);
        }
        let result = self.dispatch(&cmd);
        config::erase_json(&mut cmd.payload);
        serde_json::to_vec(&result).map_err(|_| ffi::INTERNAL)
    }
    fn dispatch(&self, cmd: &CommandEnvelope<Value>) -> Value {
        let failure = |code, stage| {
            json!(FailureEnvelope {
                schema_version: SCHEMA_VERSION,
                request_id: cmd.request_id.clone(),
                operation_id: None,
                error: ProductError::new(code, stage)
            })
        };
        if let Err(error) = cmd.validate_metadata() {
            return json!(FailureEnvelope {
                schema_version: SCHEMA_VERSION,
                request_id: cmd.request_id.clone(),
                operation_id: None,
                error
            });
        }
        if cmd.method == CommandMethod::Snapshot {
            if cmd.payload != json!({}) {
                return failure(ErrorCode::ConfigUnknownField, ErrorStage::Decode);
            }
            return json!(SuccessEnvelope {
                schema_version: SCHEMA_VERSION,
                request_id: cmd.request_id.clone(),
                operation_id: None,
                result: self.shared.snapshot()
            });
        }
        if !matches!(
            cmd.method,
            CommandMethod::Connect | CommandMethod::Disconnect | CommandMethod::OperationCancel
        ) {
            return failure(ErrorCode::ConfigUnsupported, ErrorStage::Validate);
        }
        let Some(key) = cmd.idempotency_key.as_ref() else {
            return failure(ErrorCode::ConfigInvalid, ErrorStage::Validate);
        };
        let mut fingerprint =
            serde_json::to_vec(&(cmd.method, cmd.expected_revision, &cmd.payload))
                .unwrap_or_default();
        let digest: [u8; 32] = Sha256::digest(&fingerprint).into();
        use zeroize::Zeroize;
        fingerprint.zeroize();
        let mut gate = lock(&self.gate);
        if let Some(old) = gate.accepted.get(key) {
            if old.digest != digest {
                return failure(ErrorCode::IdempotencyConflict, ErrorStage::Validate);
            }
            let mut result = old.result.clone();
            result["requestId"] = json!(cmd.request_id);
            return result;
        }
        if gate.accepted.len() >= IDEMPOTENCY_CAP {
            return failure(ErrorCode::QueueFull, ErrorStage::Apply);
        }
        if self.shared.finished.load(Ordering::Acquire) {
            return failure(ErrorCode::Closed, ErrorStage::Apply);
        }
        let mut snapshot = lock(&self.shared.snapshot);
        if cmd.expected_revision != Some(snapshot.generation) {
            return failure(ErrorCode::RevisionConflict, ErrorStage::Apply);
        }
        let Some(generation) = snapshot.generation.next() else {
            return failure(ErrorCode::Internal, ErrorStage::Apply);
        };
        let Ok(permit) = self.sender.try_reserve() else {
            return failure(ErrorCode::QueueFull, ErrorStage::Apply);
        };
        let work = match cmd.method {
            CommandMethod::Connect => {
                if snapshot.phase != RuntimePhase::Idle {
                    return failure(ErrorCode::ConfigInvalid, ErrorStage::Start);
                }
                let input: config::Connect = match serde_json::from_value(cmd.payload.clone()) {
                    Ok(v) => v,
                    Err(_) => return failure(ErrorCode::ConfigInvalid, ErrorStage::Decode),
                };
                // Preflight is optional at this low-level ABI boundary. Repeat the pure
                // full mapper before committing a generation or touching the device.
                if let Err(error) = input.build() {
                    return json!(FailureEnvelope {
                        schema_version: SCHEMA_VERSION,
                        request_id: cmd.request_id.clone(),
                        operation_id: None,
                        error
                    });
                }
                snapshot.desired = ConnectionIntent::Connected {
                    node_id: input.node.id.clone(),
                };
                snapshot.node_id = Some(input.node.id.clone());
                snapshot.desired_revision = Some(input.config_revision);
                snapshot.phase = RuntimePhase::Preparing;
                Work::Connect {
                    generation,
                    input: Box::new(input),
                }
            }
            _ => {
                if cmd.payload != json!({}) {
                    return failure(ErrorCode::ConfigUnknownField, ErrorStage::Decode);
                }
                snapshot.desired = ConnectionIntent::Disconnected {};
                snapshot.phase = RuntimePhase::Stopping;
                Work::Disconnect { generation }
            }
        };
        let operation_id = OperationId::new(format!("mobile-op-{}", generation.get())).ok();
        snapshot.generation = generation;
        snapshot.operation_id = operation_id.clone();
        self.shared.emit(&mut snapshot);
        permit.send(work);
        let result = json!(SuccessEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: cmd.request_id.clone(),
            operation_id,
            result: json!({"accepted":true,"generation":generation})
        });
        gate.accepted.insert(
            key.clone(),
            Idempotency {
                digest,
                result: result.clone(),
            },
        );
        result
    }
    fn next_event(&self, timeout: Duration) -> Result<Vec<u8>, i32> {
        if self.event_reader.swap(true, Ordering::AcqRel) {
            return Err(ffi::BUSY);
        }
        struct Reset<'a>(&'a AtomicBool);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release)
            }
        }
        let _reset = Reset(&self.event_reader);
        let end = std::time::Instant::now() + timeout;
        let mut events = lock(&self.shared.events);
        loop {
            if let Some(e) = events.items.pop_front() {
                return serde_json::to_vec(&e).map_err(|_| ffi::INTERNAL);
            }
            if self.shared.finished.load(Ordering::Acquire) || self.closing.load(Ordering::Acquire)
            {
                return Err(ffi::CLOSED);
            }
            let left = end.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err(ffi::TIMEOUT);
            }
            let (next, _) = self
                .shared
                .changed
                .wait_timeout(events, left)
                .unwrap_or_else(|e| e.into_inner());
            events = next;
        }
    }
    fn close(&self) -> i32 {
        self.closing.store(true, Ordering::Release);
        self.shared.stop.store(true, Ordering::Release);
        self.shared.changed.notify_all();
        if self.active.load(Ordering::Acquire) != 0 {
            return ffi::BUSY;
        }
        let end = std::time::Instant::now() + Duration::from_millis(5000);
        while !self.shared.finished.load(Ordering::Acquire) {
            if std::time::Instant::now() >= end {
                return ffi::TIMEOUT;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if let Some(thread) = lock(&self.thread).take() {
            if thread.join().is_err() {
                return ffi::INTERNAL;
            }
        }
        ffi::OK
    }
}
struct Router {
    outbound: Arc<dyn vp_core::Outbound>,
}
#[async_trait::async_trait]
impl vp_core::Router for Router {
    async fn pick(&self, _: &vp_core::Session) -> vp_core::Resolution {
        vp_core::Resolution {
            outbound: self.outbound.clone(),
            via: "mobile-selected".into(),
            rule: None,
        }
    }
}
async fn run(
    shared: Arc<Shared>,
    mut commands: tokio::sync::mpsc::Receiver<Work>,
    fd: OwnedFd,
    mtu: u16,
    callbacks: ffi::Callbacks,
) {
    let mut fd = Some(fd);
    let mut scope: Option<Arc<TaskScope>> = None;
    let stats = Arc::new(vp_common::Stats::default());
    let counts = Arc::new(fd::PacketCounts::default());
    let mut active_generation = None;
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    let mut last_forwarded = (0, 0);
    loop {
        tokio::select! {
         _=interval.tick()=>{
          if shared.stop.load(Ordering::Acquire){break}
          if let (Some(g),Some(scope))=(active_generation,scope.as_ref()){
           if callbacks.failures()>0 {shared.update(g,|s|{s.phase=RuntimePhase::Failed;s.error=Some(ProductError::new(ErrorCode::PermissionDenied,ErrorStage::Start));});break}
           if !scope.snapshot().healthy() || counts.failed.load(Ordering::Acquire){shared.update(g,|s|{s.phase=RuntimePhase::Failed;s.error=Some(ProductError::new(ErrorCode::Internal,ErrorStage::Verify));});break}
           let traffic=stats.snapshot();let read=counts.read.load(Ordering::Relaxed);let written=counts.written.load(Ordering::Relaxed);
           if read>0 && written>0 && traffic.upload>0 && traffic.download>0 {
            let changed=(traffic.upload,traffic.download)!=last_forwarded;
            if changed {last_forwarded=(traffic.upload,traffic.download);shared.update(g,|s|{s.phase=RuntimePhase::Connected;s.health.core=passed(g,"core");s.health.takeover=passed(g,"takeover");s.health.tunnel=passed(g,"tun");s.health.forwarding=passed(g,"relay");});}
            else {let expired={let s=lock(&shared.snapshot);s.phase==RuntimePhase::Connected&&s.health.forwarding.observed_at.is_some_and(|at|now().saturating_sub(at)>=30_000)};if expired{shared.update(g,|s|s.phase=RuntimePhase::Degraded);}}
           }
          }
         },
         command=commands.recv()=>match command{
          None=>break,
          Some(Work::Disconnect{generation})=>{if let Some(scope)=scope.take(){let report=scope.shutdown(Duration::from_millis(100),Duration::from_secs(1)).await;if report.remaining_tasks!=0 {shared.update(generation,|s|{s.phase=RuntimePhase::Failed;s.error=Some(ProductError::new(ErrorCode::Timeout,ErrorStage::Stop));});break}}
           // Idle is published after full runtime drop by thread epilogue below.
           shared.update(generation,|s|{s.phase=RuntimePhase::Stopping;});break
          },
          Some(Work::Connect{generation,input})=>{
           if lock(&shared.snapshot).generation!=generation{continue}
           let built=input.build();let config::Built{outbound,user_dns,bootstrap_servers}=match built{Ok(v)=>v,Err(error)=>{shared.update(generation,|s|{s.phase=RuntimePhase::Failed;s.error=Some(error);});break}};
           let host=callbacks.with_bootstrap(bootstrap_servers,input.node.endpoint.host.clone());let new_scope=TaskScope::with_host_network(DestinationPolicy::Unrestricted,Some(Arc::new(host)));
           let Some(fd)=fd.take() else{break};let device=match fd::Device::new(fd,mtu as usize,counts.clone()){Ok(d)=>d,Err(_)=>{shared.update(generation,|s|{s.phase=RuntimePhase::Failed;s.error=Some(ProductError::new(ErrorCode::PermissionDenied,ErrorStage::Start));});break}};
           let ctx=vp_core::inbound::InboundCtx{router:Arc::new(Router{outbound}),stats:stats.clone(),conns:Arc::new(vp_core::ConnTable::new())};
           let cfg=vp_tun::TunConfig{mtu,dns_hijack:true,..Default::default()};
           new_scope.run(async move{vp_core::task_scope::spawn_listener("android-tun",async move{vp_tun::run_with_device_proxy_dns(cfg,"android-tun".into(),ctx,user_dns,device).await});}).await;
           scope=Some(new_scope);active_generation=Some(generation);shared.update(generation,|s|{s.phase=RuntimePhase::Verifying;s.config_revision=Some(input.config_revision);s.health.core=passed(generation,"core");});
          }
         }
        }
    }
    if let Some(scope) = scope {
        let _ = scope.shutdown(Duration::ZERO, Duration::from_secs(1)).await;
    }
}
