#![cfg(feature = "managed-runtime")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::OnceLock;
use std::time::Duration;
use vp_product_core_adapter::managed::{
    Cancellation, Failure, ListenerKind, ListenerSpec, ManagedRuntime, VerifiedWorker, WorkerConfig,
};

fn worker() -> VerifiedWorker {
    static WORKER: OnceLock<VerifiedWorker> = OnceLock::new();
    WORKER
        .get_or_init(|| {
            let path = std::path::Path::new(env!("CARGO_BIN_EXE_vp-core-managed-worker"));
            let mut file = std::fs::File::open(path).unwrap();
            let mut hash = Sha256::new();
            let mut buf = [0; 65536];
            loop {
                let count = file.read(&mut buf).unwrap();
                if count == 0 {
                    break;
                }
                hash.update(&buf[..count]);
            }
            VerifiedWorker::new(path, &format!("{:x}", hash.finalize())).unwrap()
        })
        .clone()
}
fn config(port: u16) -> WorkerConfig {
    WorkerConfig {
        schema_version: 1,
        bind_address: Ipv4Addr::LOCALHOST.into(),
        listeners: vec![ListenerSpec {
            tag: "mixed".into(),
            kind: ListenerKind::Mixed,
            port,
            users: vec![],
            cipher: None,
        }],
    }
}
fn start(
    runtime: &mut ManagedRuntime,
    config: WorkerConfig,
) -> vp_product_core_adapter::managed::WorkerSnapshot {
    runtime
        .start(
            config,
            runtime.generation(),
            Duration::from_secs(15),
            &Cancellation::default(),
        )
        .unwrap()
}
fn socks_echo(proxy: u16) {
    let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target = echo.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = echo.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = [0; 19];
        stream.read_exact(&mut bytes).unwrap();
        stream.write_all(&bytes).unwrap();
    });
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.to_be_bytes());
    client.write_all(&request).unwrap();
    let mut response = [0; 10];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response[..2], &[5, 0]);
    client.write_all(b"vp-managed-loopback").unwrap();
    let mut echoed = [0; 19];
    client.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"vp-managed-loopback");
    drop(client);
    server.join().unwrap();
}
#[test]
fn actual_core_socks_echo_snapshot_and_verified_process_stop() {
    let mut runtime = ManagedRuntime::new(worker());
    let started = start(&mut runtime, config(0));
    let port = started.listeners[0].port;
    assert!(started.listeners_ready);
    assert!(!started.forwarding_verified);
    assert!(runtime.is_running());
    socks_echo(port);
    let observed = runtime.snapshot(started.generation).unwrap();
    assert_eq!(observed.pid, started.pid);
    assert!(observed.listeners_ready);
    let stopped = runtime
        .stop(started.generation, Duration::from_millis(100))
        .unwrap();
    assert!(stopped.process_exited);
    assert_eq!(stopped.remaining_tasks, 0);
    assert!(!runtime.is_running());
    let _rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
}
#[test]
fn failed_second_bind_leaves_no_first_listener_or_process() {
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let free = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free);
    let mut candidate = config(port);
    candidate.listeners.push(ListenerSpec {
        tag: "second".into(),
        kind: ListenerKind::Vless,
        port: occupied.local_addr().unwrap().port(),
        users: vec!["00000000-0000-0000-0000-000000000001".into()],
        cipher: None,
    });
    let mut runtime = ManagedRuntime::new(worker());
    let error = runtime
        .start(
            candidate,
            0,
            Duration::from_secs(15),
            &Cancellation::default(),
        )
        .unwrap_err();
    assert_eq!(error, Failure::BindFailed);
    assert!(!runtime.is_running());
    let _rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
}
#[test]
fn failing_replacement_restores_previous_port_with_new_generation() {
    let mut runtime = ManagedRuntime::new(worker());
    let old = start(&mut runtime, config(0));
    let old_port = old.listeners[0].port;
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let result = runtime
        .replace(
            config(occupied.local_addr().unwrap().port()),
            old.generation,
            Duration::from_secs(15),
            &Cancellation::default(),
        )
        .unwrap_err();
    assert_eq!(result.candidate_error, Failure::BindFailed);
    assert!(result.rollback_error.is_none());
    let restored = result.restored.unwrap();
    assert!(restored.generation > old.generation + 1);
    assert_eq!(restored.listeners[0].port, old_port);
    socks_echo(old_port);
    runtime
        .stop(restored.generation, Duration::from_millis(100))
        .unwrap();
}
#[test]
fn stale_generation_cannot_stop_or_replace_current_worker() {
    let mut runtime = ManagedRuntime::new(worker());
    let observed = start(&mut runtime, config(0));
    assert_eq!(
        runtime.stop(0, Duration::ZERO).unwrap_err(),
        Failure::StaleGeneration
    );
    assert_eq!(
        runtime
            .replace(
                config(0),
                0,
                Duration::from_secs(15),
                &Cancellation::default()
            )
            .unwrap_err()
            .candidate_error,
        Failure::StaleGeneration
    );
    assert!(
        runtime
            .snapshot(observed.generation)
            .unwrap()
            .listeners_ready
    );
    runtime.stop(observed.generation, Duration::ZERO).unwrap();
}
#[test]
fn cancellation_and_deadline_never_leave_hidden_running_worker() {
    let mut runtime = ManagedRuntime::new(worker());
    let canceled = Cancellation::default();
    canceled.cancel();
    assert_eq!(
        runtime
            .start(config(0), 0, Duration::from_secs(1), &canceled)
            .unwrap_err(),
        Failure::Canceled
    );
    assert_eq!(runtime.generation(), 0);
    assert!(!runtime.is_running());
    assert_eq!(
        runtime
            .start(
                config(0),
                0,
                Duration::from_nanos(1),
                &Cancellation::default()
            )
            .unwrap_err(),
        Failure::Timeout
    );
    assert!(!runtime.is_running());
}
#[test]
fn dropping_owner_closes_process_and_listener() {
    let port = {
        let mut runtime = ManagedRuntime::new(worker());
        start(&mut runtime, config(0)).listeners[0].port
    };
    let _rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
}
#[test]
fn worker_digest_and_loopback_policy_fail_closed() {
    assert!(matches!(
        VerifiedWorker::new(
            env!("CARGO_BIN_EXE_vp-core-managed-worker"),
            &"0".repeat(64)
        ),
        Err(Failure::WorkerIdentityMismatch)
    ));
    let mut cfg = config(0);
    cfg.bind_address = Ipv4Addr::UNSPECIFIED.into();
    assert_eq!(cfg.validate().unwrap_err(), Failure::InvalidConfig);
    let invalid =
        br#"{"schemaVersion":1,"bindAddress":"127.0.0.1","listeners":[],"tun":{"enable":true}}"#;
    assert!(serde_json::from_slice::<WorkerConfig>(invalid).is_err());
    let oversized = vec![b'x'; vp_product_core_adapter::managed::protocol::MAX_FRAME + 1];
    assert!(
        vp_product_core_adapter::managed::protocol::read_frame(&mut std::io::Cursor::new(
            oversized
        ))
        .is_err()
    );
}

#[test]
fn failed_restore_is_explicit_not_a_successful_rollback() {
    let mut runtime = ManagedRuntime::new(worker());
    let old = start(&mut runtime, config(0));
    let old_port = old.listeners[0].port;
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (captured, receiver) = std::sync::mpsc::sync_channel(1);
    let blocker = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, old_port)) {
                captured.send(listener).unwrap();
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "previous port was never released"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let result = runtime
        .replace(
            config(occupied.local_addr().unwrap().port()),
            old.generation,
            Duration::from_secs(15),
            &Cancellation::default(),
        )
        .unwrap_err();
    let held = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    blocker.join().unwrap();
    assert_eq!(result.candidate_error, Failure::BindFailed);
    assert_eq!(result.rollback_error, Some(Failure::BindFailed));
    assert!(result.restored.is_none());
    assert!(!runtime.is_running());
    drop(held);
}

#[test]
fn invalid_replacement_deadline_does_not_stop_existing_worker() {
    let mut runtime = ManagedRuntime::new(worker());
    let old = start(&mut runtime, config(0));
    let error = runtime
        .replace(
            config(0),
            old.generation,
            Duration::ZERO,
            &Cancellation::default(),
        )
        .unwrap_err();
    assert_eq!(error.candidate_error, Failure::InvalidConfig);
    assert_eq!(runtime.snapshot(old.generation).unwrap().pid, old.pid);
    runtime.stop(old.generation, Duration::ZERO).unwrap();
}

#[test]
fn journal_generation_seed_is_consumed_exactly_once() {
    let mut runtime = ManagedRuntime::with_generation(worker(), 41).unwrap();
    assert_eq!(runtime.generation(), 41);
    let observed = start(&mut runtime, config(0));
    assert_eq!(observed.generation, 42);
    runtime.stop(42, Duration::ZERO).unwrap();
    assert!(matches!(
        ManagedRuntime::with_generation(worker(), u64::MAX),
        Err(Failure::StaleGeneration)
    ));
}

#[test]
fn parent_process_crash_closes_worker_via_pipe_eof() {
    const DRIVER: &str = "VP_MANAGED_CRASH_DRIVER";
    if std::env::var(DRIVER).as_deref() == Ok("yes") {
        let mut runtime = ManagedRuntime::new(worker());
        let observed = start(&mut runtime, config(0));
        println!("VP_CHILD={}:{}", observed.pid, observed.listeners[0].port);
        std::io::stdout().flush().unwrap();
        // Deliberately bypass ALL Rust Drop guards, like a daemon crash.
        std::process::exit(23);
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "parent_process_crash_closes_worker_via_pipe_eof",
            "--nocapture",
        ])
        .env(DRIVER, "yes")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let marker = stdout
        .lines()
        .find_map(|line| line.strip_prefix("VP_CHILD="))
        .unwrap();
    let (pid, port) = marker.split_once(':').unwrap();
    let pid: u32 = pid.parse().unwrap();
    let port: u16 = port.parse().unwrap();
    assert!(pid > 1 && pid != std::process::id());
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let ended = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |stat| {
            stat.split_once(") ")
                .is_some_and(|(_, tail)| tail.starts_with("Z "))
        });
        if ended && TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = std::process::Command::new("/bin/kill")
                .args(["-KILL", &pid.to_string()])
                .status();
            panic!("worker survived parent crash or retained listener");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn spawn_observer_precedes_listener_action_and_failure_reaps_child() {
    let verified = worker();
    assert_eq!(verified.sha256().len(), 64);
    let mut runtime = ManagedRuntime::new(verified);
    let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let mut child = 0;
    let failure = runtime
        .start_with_spawn_observer(
            config(port),
            0,
            Duration::from_secs(15),
            &Cancellation::default(),
            |pid| {
                child = pid;
                // Worker Hello does not bind listeners; journal failures must stop
                // here without ever exposing even a transient listener.
                let unbound = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
                drop(unbound);
                Err(Failure::Io)
            },
        )
        .unwrap_err();
    assert_eq!(failure, Failure::Io);
    assert!(child > 1);
    assert!(!std::path::Path::new(&format!("/proc/{child}")).exists());
    assert!(!runtime.is_running());
    assert_eq!(runtime.generation(), 1);
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
}

#[test]
fn authenticated_vless_cannot_bypass_worker_destination_policy() {
    let mut runtime = ManagedRuntime::new(worker());
    let mut cfg = config(0);
    cfg.listeners = vec![ListenerSpec {
        tag: "vless-policy".into(),
        kind: ListenerKind::Vless,
        port: 0,
        users: vec!["11111111-1111-1111-1111-111111111111".into()],
        cipher: None,
    }];
    let observed = start(&mut runtime, cfg);
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    let port = target.local_addr().unwrap().port();
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, observed.listeners[0].port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut header = vec![0];
    header.extend_from_slice(&[0x11; 16]);
    header.extend_from_slice(&[0, 1]);
    header.extend_from_slice(&port.to_be_bytes());
    header.extend_from_slice(&[2, 9]);
    header.extend_from_slice(b"localhost");
    header.extend_from_slice(b"must-not-reach-loopback-via-name");
    client.write_all(&header).unwrap();
    match client.read(&mut [0; 1]) {
        Ok(n) => assert_eq!(n, 0),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    runtime.stop(observed.generation, Duration::ZERO).unwrap();
}
