//! Private stdio worker. No user-supplied path, plugin, route, service or shell API.
use std::io::{BufReader, Write};
use std::time::Duration;
use vp_app::managed::ManagedApp;
use vp_product_core_adapter::managed::protocol::{
    self, Failure, Request, Response, PROTOCOL_VERSION,
};
use vp_product_core_adapter::managed::{BoundListener, StopReport, WorkerSnapshot};

fn respond(value: &Response) -> Result<(), ()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, value).map_err(|_| ())?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|_| ())
}
fn snapshot(app: &ManagedApp, generation: u64) -> WorkerSnapshot {
    let tasks = app.task_snapshot();
    WorkerSnapshot {
        generation,
        pid: std::process::id(),
        listeners_ready: app.listeners_ready(),
        listeners: app
            .app()
            .listen_ports
            .iter()
            .map(|(tag, port)| BoundListener {
                tag: tag.clone(),
                port: *port,
                accept_loop_live: tasks.listeners.contains(tag),
            })
            .collect(),
        active_tasks: tasks.task_count(),
        task_panics: tasks.panics,
        forwarding_verified: false,
    }
}
async fn run(
    mut input: tokio::sync::mpsc::Receiver<Result<Request, Failure>>,
    mut parent_closed: tokio::sync::watch::Receiver<bool>,
) {
    let mut app: Option<ManagedApp> = None;
    let mut generation = 0;
    loop {
        if *parent_closed.borrow() {
            break;
        }
        let request = tokio::select! { biased;
            _ = parent_closed.changed() => break,
            request = input.recv() => match request { Some(request) => request, None => break },
        };
        let request = match request {
            Ok(request) => request,
            Err(failure) => {
                let _ = respond(&Response::Failed { failure });
                break;
            }
        };
        match request {
            Request::Start {
                version,
                generation: requested,
                config,
                startup_ms,
            } => {
                if app.is_some()
                    || version != PROTOCOL_VERSION
                    || requested == 0
                    || startup_ms == 0
                    || startup_ms > 30_000
                {
                    let _ = respond(&Response::Failed {
                        failure: Failure::InvalidConfig,
                    });
                    break;
                }
                let config = match config.to_core_json() {
                    Ok(config) => config,
                    Err(failure) => {
                        let _ = respond(&Response::Failed { failure });
                        break;
                    }
                };
                let directory = std::env::temp_dir();
                let started = tokio::select! { biased;
                    _ = parent_closed.changed() => break,
                    started = ManagedApp::start_with_policy(&config, vp_config::Format::Json, &directory,
                        Duration::from_millis(startup_ms), Duration::from_secs(1),
                        vp_core::task_scope::DestinationPolicy::LoopbackIpOnly) => started,
                };
                match started {
                    Ok(started) => {
                        generation = requested;
                        let observed = snapshot(&started, generation);
                        app = Some(started);
                        if respond(&Response::Started { snapshot: observed }).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let failure = match error {
                            vp_common::Error::Io(io)
                                if io.kind() == std::io::ErrorKind::AddrInUse =>
                            {
                                Failure::BindFailed
                            }
                            vp_common::Error::Config(_) => Failure::InvalidConfig,
                            vp_common::Error::Unsupported(_) => Failure::Unsupported,
                            _ => Failure::StartupFailed,
                        };
                        let _ = respond(&Response::Failed { failure });
                        break;
                    }
                }
            }
            Request::Snapshot {
                generation: requested,
            } => {
                if requested != generation {
                    let _ = respond(&Response::Failed {
                        failure: Failure::StaleGeneration,
                    });
                    continue;
                }
                let response = match &app {
                    Some(app) => Response::Snapshot {
                        snapshot: snapshot(app, generation),
                    },
                    None => Response::Failed {
                        failure: Failure::WorkerExited,
                    },
                };
                if respond(&response).is_err() {
                    break;
                }
            }
            Request::Stop {
                generation: requested,
                drain_ms,
            } => {
                if requested != generation || drain_ms > 5_000 {
                    let _ = respond(&Response::Failed {
                        failure: Failure::StaleGeneration,
                    });
                    continue;
                }
                let Some(app) = app.take() else {
                    let _ = respond(&Response::Failed {
                        failure: Failure::WorkerExited,
                    });
                    break;
                };
                let report = app
                    .shutdown(Duration::from_millis(drain_ms), Duration::from_secs(1))
                    .await;
                let _ = respond(&Response::Stopped {
                    report: StopReport {
                        generation,
                        drained: report.drained,
                        forced_tasks: report.forced_tasks,
                        remaining_tasks: report.remaining_tasks,
                        process_exited: false,
                    },
                });
                break; // process lifetime is the final containment boundary
            }
        }
    }
    if let Some(app) = app {
        let _ = app.shutdown(Duration::ZERO, Duration::from_secs(1)).await;
    }
}
fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.as_slice() != ["--stdio-v1"] {
        std::process::exit(64);
    }
    let build = match vp_product_core_adapter::inspect_build() {
        Ok(build) => build,
        Err(_) => std::process::exit(70),
    };
    let Some(patchset_hash) = build.build.release.patchset_hash else {
        std::process::exit(70);
    };
    if respond(&Response::Hello {
        version: PROTOCOL_VERSION,
        core_commit: build.build.release.core_commit,
        patchset_hash,
    })
    .is_err()
    {
        return;
    }
    let (send, receive) = tokio::sync::mpsc::channel(2);
    let (closed, closed_receiver) = tokio::sync::watch::channel(false);
    std::thread::spawn(move || {
        let input = std::io::stdin();
        let mut reader = BufReader::new(input.lock());
        loop {
            let request = match protocol::read_frame(&mut reader) {
                Ok(Some(bytes)) => {
                    serde_json::from_slice(&bytes).map_err(|_| Failure::InvalidConfig)
                }
                Ok(None) => break,
                Err(_) => Err(Failure::ProtocolViolation),
            };
            if send.blocking_send(request).is_err() {
                break;
            }
        }
        let _ = closed.send(true);
    });
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
    // Returning main exits the process, including any noncancelable library task.
}
