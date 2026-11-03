//! Dedicated v2 child executable implementation; no v1 request/config path.
use super::{
    protocol_v2::{
        self, CommandV2, FrameReaderV2, RequestV2, ResponseV2, WorkerInstanceV2,
        MAX_REQUEST_FRAME_V2, PREPARED_LEASE_SECONDS_V2, VERSION_V2,
    },
    server_v2::{ManagedServerV2, PreparedServerV2},
    Failure,
};
use std::time::Duration;
#[derive(Clone, Copy)]
enum InputStateV2 {
    Open,
    Eof,
    Failed(Failure),
}
fn report_input_end(state: InputStateV2) {
    if let InputStateV2::Failed(error) = state {
        failed(error);
    }
}
struct Prepared {
    value: PreparedServerV2,
    startup_ms: u64,
    expires: tokio::time::Instant,
}
fn respond(response: ResponseV2) -> Result<(), Failure> {
    protocol_v2::encode_response(&response)?
        .write_to(&mut std::io::stdout().lock())
        .map_err(|_| Failure::Io)
}
fn failed(failure: Failure) {
    let _ = respond(ResponseV2::FailedServerV2 { failure });
}
async fn run(
    mut input: tokio::sync::mpsc::Receiver<Result<RequestV2, Failure>>,
    mut closed: tokio::sync::watch::Receiver<InputStateV2>,
) {
    let mut instance: Option<WorkerInstanceV2> = None;
    let mut prepared: Option<Prepared> = None;
    let mut active: Option<ManagedServerV2> = None;
    let mut generation = 0;
    loop {
        if !matches!(*closed.borrow(), InputStateV2::Open) {
            report_input_end(*closed.borrow());
            break;
        }
        let expiry = prepared.as_ref().map(|value| value.expires);
        let request = tokio::select! {biased;
            _=closed.changed()=>{report_input_end(*closed.borrow());break;},
            _=async {if let Some(expiry)=expiry {tokio::time::sleep_until(expiry).await;}else{std::future::pending::<()>().await;}}=>{failed(Failure::Timeout);break;},
            request=input.recv()=>match request {Some(Ok(request))=>request,Some(Err(error))=>{failed(error);break;},None=>break},
        };
        if request.validate_shape().is_err() {
            failed(Failure::ProtocolViolation);
            break;
        }
        if instance.is_none() {
            if request.kind != CommandV2::Negotiate {
                failed(Failure::ProtocolViolation);
                break;
            }
            let identity = request.instance;
            if respond(ResponseV2::NegotiatedServerV2 {
                version: VERSION_V2,
                instance: identity.clone(),
                pid: std::process::id(),
            })
            .is_err()
            {
                break;
            }
            instance = Some(identity);
            continue;
        }
        if instance.as_ref() != Some(&request.instance) || request.kind == CommandV2::Negotiate {
            failed(Failure::ProtocolViolation);
            break;
        }
        let identity = request.instance;
        match request.kind {
            CommandV2::Prepare => {
                if prepared.is_some() || active.is_some() || generation != 0 {
                    failed(Failure::Busy);
                    break;
                }
                let Some(start) = request.start_server_v2 else {
                    failed(Failure::ProtocolViolation);
                    break;
                };
                let (recipe, inputs, startup_ms) = match start.into_materialized() {
                    Ok(value) => value,
                    Err(error) => {
                        failed(error);
                        break;
                    }
                };
                // Parsing/identity construction is bounded and cannot bind. A
                // blocking crypto task is contained by this child process; EOF
                // does not wait forever for a noncancelable library operation.
                let preparing =
                    tokio::task::spawn_blocking(move || PreparedServerV2::prepare(&recipe, inputs));
                let result = tokio::select! {biased;_ = closed.changed()=>{report_input_end(*closed.borrow());break;},result=preparing=>result};
                let value = match result {
                    Ok(Ok(value)) => value,
                    Ok(Err(error)) => {
                        failed(error);
                        break;
                    }
                    Err(_) => {
                        failed(Failure::StartupFailed);
                        break;
                    }
                };
                if !matches!(*closed.borrow(), InputStateV2::Open) {
                    report_input_end(*closed.borrow());
                    break;
                }
                generation = request.generation;
                prepared = Some(Prepared {
                    value,
                    startup_ms,
                    expires: tokio::time::Instant::now()
                        + Duration::from_secs(PREPARED_LEASE_SECONDS_V2),
                });
                if respond(ResponseV2::PreparedServerV2 {
                    instance: identity,
                    generation,
                    pid: std::process::id(),
                })
                .is_err()
                {
                    break;
                }
            }
            CommandV2::Activate => {
                if request.generation != generation {
                    failed(Failure::StaleGeneration);
                    continue;
                }
                let Some(value) = prepared.take() else {
                    failed(Failure::Busy);
                    continue;
                };
                let result = tokio::select! {biased;
                    _=closed.changed()=>{report_input_end(*closed.borrow());break;},
                    result=ManagedServerV2::start_prepared(value.value,Duration::from_millis(value.startup_ms))=>result,
                };
                match result {
                    Ok(server) => {
                        let snapshot = server.snapshot(generation);
                        active = Some(server);
                        if respond(ResponseV2::StartedServerV2 {
                            instance: identity,
                            snapshot,
                        })
                        .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        failed(error);
                        break;
                    }
                }
            }
            CommandV2::Snapshot => {
                if request.generation != generation {
                    failed(Failure::StaleGeneration);
                    continue;
                }
                let Some(server) = active.as_ref() else {
                    failed(Failure::Busy);
                    continue;
                };
                if respond(ResponseV2::SnapshotServerV2 {
                    instance: identity,
                    snapshot: server.snapshot(generation),
                })
                .is_err()
                {
                    break;
                }
            }
            CommandV2::Stop => {
                if request.generation != generation {
                    failed(Failure::StaleGeneration);
                    continue;
                }
                let Some(server) = active.take() else {
                    failed(Failure::Busy);
                    continue;
                };
                let result = tokio::select! {biased;_ = closed.changed()=>{report_input_end(*closed.borrow());break;},result=server.shutdown(generation,Duration::from_millis(request.drain_ms.unwrap_or(0)))=>result};
                match result {
                    Ok(report) => {
                        let _ = respond(ResponseV2::StoppedServerV2 {
                            instance: identity,
                            report,
                        });
                    }
                    Err(error) => failed(error),
                }
                break;
            }
            CommandV2::Discard => {
                if request.generation != generation || prepared.is_none() || active.is_some() {
                    failed(Failure::StaleGeneration);
                    continue;
                }
                prepared.take();
                let _ = respond(ResponseV2::DiscardedServerV2 {
                    instance: identity,
                    generation,
                    pid: std::process::id(),
                });
                break;
            }
            CommandV2::Negotiate => {
                failed(Failure::ProtocolViolation);
                break;
            }
        }
    }
    drop(prepared);
    if let Some(server) = active {
        let _ = server.shutdown(generation, Duration::ZERO).await;
    }
}
/// Invoked only by the separately registered required-feature v2 binary.
/// It has no filesystem config argument, network management API or plugin input.
pub fn main_v2() {
    if std::env::args().skip(1).collect::<Vec<_>>().as_slice() != ["--stdio-server-v2"] {
        std::process::exit(64);
    }
    if !cfg!(target_os = "linux") {
        std::process::exit(69);
    }
    let build = match crate::inspect_build() {
        Ok(build) => build,
        Err(_) => std::process::exit(70),
    };
    if respond(ResponseV2::HelloServerV2 {
        version: VERSION_V2,
        pid: std::process::id(),
        release: build.build.release,
        max_request_bytes: MAX_REQUEST_FRAME_V2,
        test_fixture: cfg!(feature = "local-probe-test"),
    })
    .is_err()
    {
        return;
    }
    let (send, receive) = tokio::sync::mpsc::channel(1);
    let (closed, closed_receiver) = tokio::sync::watch::channel(InputStateV2::Open);
    let reader = std::thread::Builder::new()
        .name("vp-v2-stdin".into())
        .spawn(move || {
            // Constant inherited pipe only; no user path. Avoid std Stdin's global
            // nonzeroizing buffered storage for material-bearing request bytes.
            let input = match std::fs::File::open("/proc/self/fd/0") {
                Ok(input) => input,
                Err(_) => {
                    let _ = closed.send(InputStateV2::Eof);
                    return;
                }
            };
            let mut input = FrameReaderV2::new(input);
            loop {
                let request = match input.read_frame(MAX_REQUEST_FRAME_V2) {
                    Ok(Some(frame)) => protocol_v2::decode_request(&frame),
                    Ok(None) => {
                        let _ = closed.send(InputStateV2::Eof);
                        return;
                    }
                    Err(_) => Err(Failure::ProtocolViolation),
                };
                let request = match request {
                    Ok(request) => request,
                    Err(error) => {
                        let _ = closed.send(InputStateV2::Failed(error));
                        return;
                    }
                };
                // Never block EOF/failure observation behind a full command queue.
                if send.try_send(Ok(request)).is_err() {
                    let _ = closed.send(InputStateV2::Failed(Failure::ProtocolViolation));
                    return;
                }
            }
        });
    if reader.is_err() {
        return;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return,
    };
    runtime.block_on(run(receive, closed_receiver));
    runtime.shutdown_timeout(Duration::from_millis(250));
    // Returning the executable's main is the final containment boundary even if
    // a noncancelable library/background operation remains in this process.
}
