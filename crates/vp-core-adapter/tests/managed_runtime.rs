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
#[cfg(target_os = "linux")]
fn parent_process_crash_closes_worker_via_pipe_eof() {
    use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
    use std::{
        io::BufRead,
        process::{Child, Stdio},
        time::Instant,
    };
    const DRIVER: &str = "VP_MANAGED_CRASH_DRIVER";
    // Capture start time and parent identity while the retained driver is alive.
    // A later numeric PID reuse is never a signal target.
    fn identity(pid: u32) -> Option<(u64, u32, char)> {
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => panic!("cannot inspect owned process: {e}"),
        };
        let fields: Vec<_> = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        Some((
            fields[19].parse().unwrap(),
            fields[1].parse().unwrap(),
            fields[0].chars().next().unwrap(),
        ))
    }
    if std::env::var(DRIVER).as_deref() == Ok("yes") {
        let mut runtime = ManagedRuntime::new(worker());
        let observed = start(&mut runtime, config(0));
        let (ticks, parent, _) = identity(observed.pid).unwrap();
        assert_eq!(parent, std::process::id());
        println!(
            "VP_CHILD={}:{}:{ticks}",
            observed.pid, observed.listeners[0].port
        );
        std::io::stdout().flush().unwrap();
        // Parent first retains a verified pidfd, then authorizes this synthetic
        // driver crash. No existing process or external PID is admitted.
        let mut go = [0];
        if std::io::stdin().read_exact(&mut go).is_err() || go != [1] {
            // Pre-pidfd parent failure closes stdin. Abort cooperatively while
            // this driver still owns the actual ManagedRuntime/Child handles.
            let stopped = runtime.stop(observed.generation, Duration::ZERO).unwrap();
            assert!(stopped.process_exited && stopped.remaining_tasks == 0);
            eprintln!("VP_ABORT_REAPED={}:{ticks}", observed.pid);
            std::process::exit(24);
        }
        std::process::exit(23);
    }
    struct Driver(Child);
    impl Drop for Driver {
        fn drop(&mut self) {
            // EOF requests explicit runtime stop/reap before authorization.
            // This also covers marker parsing/timeout and pidfd acquisition errors.
            drop(self.0.stdin.take());
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if matches!(self.0.try_wait(), Ok(Some(_))) {
                    return;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            eprintln!("VP_DRIVER_COOPERATIVE_ABORT_TIMEOUT: forcing retained driver cleanup");
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    struct OwnedWorker {
        fd: rustix::fd::OwnedFd,
        armed: bool,
    }
    impl Drop for OwnedWorker {
        fn drop(&mut self) {
            if self.armed {
                let _ = pidfd_send_signal(&self.fd, Signal::KILL);
            }
        }
    }
    let mut driver = Driver(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "parent_process_crash_closes_worker_via_pipe_eof",
                "--nocapture",
            ])
            .env(DRIVER, "yes")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = driver.0.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let lines = std::io::BufReader::new(stdout.take(4096)).lines();
        for line in lines {
            let line = line.unwrap();
            if let Some(marker) = line.strip_prefix("VP_CHILD=") {
                let _ = sender.send(marker.to_owned());
                return;
            }
        }
    });
    let marker = receiver.recv_timeout(Duration::from_secs(20)).unwrap();
    reader.join().unwrap();
    let fields: Vec<_> = marker.split(':').collect();
    assert_eq!(fields.len(), 3);
    let pid: u32 = fields[0].parse().unwrap();
    let port: u16 = fields[1].parse().unwrap();
    let ticks: u64 = fields[2].parse().unwrap();
    assert!(pid > 1 && pid != std::process::id());
    if std::env::var("VP_MANAGED_ABORT_BEFORE_PIDFD").as_deref() == Ok("yes") {
        // Separate negative fixture: no worker pidfd is acquired and no crash
        // authorization is sent. Closing stdin must make the owner stop/reap.
        drop(driver.0.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = driver.0.try_wait().unwrap() {
                assert_eq!(status.code(), Some(24));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "cooperative driver abort did not finish"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut acknowledgment = String::new();
        driver
            .0
            .stderr
            .take()
            .unwrap()
            .take(4096)
            .read_to_string(&mut acknowledgment)
            .unwrap();
        assert!(acknowledgment
            .lines()
            .any(|line| line == format!("VP_ABORT_REAPED={pid}:{ticks}")));
        assert!(identity(pid).is_none_or(|(current, _, state)| current != ticks || state == 'Z'));
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
        return;
    }
    let expected_parent = driver.0.id();
    let before = identity(pid).expect("owned worker exited before pidfd acquisition");
    assert_eq!((before.0, before.1), (ticks, expected_parent));
    let fd = pidfd_open(
        Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(),
        PidfdFlags::empty(),
    )
    .unwrap();
    let after = identity(pid).expect("owned worker exited during pidfd acquisition");
    assert_eq!((after.0, after.1), (ticks, expected_parent));
    // Arm cleanup only after identity was verified on both sides of pidfd_open.
    let mut owned = OwnedWorker { fd, armed: true };
    driver.0.stdin.take().unwrap().write_all(&[1]).unwrap();
    let driver_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = driver.0.try_wait().unwrap() {
            assert_eq!(status.code(), Some(23));
            break;
        }
        assert!(
            Instant::now() < driver_deadline,
            "owned driver did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let ended = identity(pid)
            .is_none_or(|(current_ticks, _, state)| current_ticks != ticks || state == 'Z');
        if ended && TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            owned.armed = false;
            break;
        }
        assert!(
            Instant::now() < deadline,
            "worker survived parent crash or retained listener"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[cfg(target_os = "linux")]
fn parent_process_abort_before_pidfd_cooperatively_reaps_worker() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "parent_process_crash_closes_worker_via_pipe_eof",
            "--nocapture",
        ])
        .env("VP_MANAGED_ABORT_BEFORE_PIDFD", "yes")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cooperative pre-pidfd abort fixture failed"
    );
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
