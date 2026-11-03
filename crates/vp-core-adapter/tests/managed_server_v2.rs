//! Real subprocess fixtures, not independent interoperability certification.
//! Synthetic in-memory identities only; no generated key/credential files.
#![cfg(all(feature = "managed-server-v2", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{mpsc, OnceLock},
    thread::JoinHandle,
    time::{Duration, Instant},
};
use vp_product_compiler::server_v2::{ServerCompilerV2, ServerRecipeV2};
use vp_product_core_adapter::managed::{
    host_v2::{ManagedRuntimeV2, SpawnedProcessV2},
    protocol_v2::{ResponseV2, WorkerInstanceV2, MAX_REQUEST_FRAME_V2, MAX_RESPONSE_FRAME_V2},
    server_v2::ServerInputsV2,
    Cancellation, Failure, VerifiedWorker,
};
use vp_product_domain::*;
const UUID: &[u8] = b"12345678-1234-1234-1234-123456789abc";
const WAIT: Duration = Duration::from_secs(10);
fn verified(path: &str) -> VerifiedWorker {
    let mut file = std::fs::File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    VerifiedWorker::for_server_v2(
        path,
        &format!("{:x}", hash.finalize()),
        Instant::now() + WAIT,
        &Cancellation::default(),
    )
    .unwrap()
}
fn worker() -> VerifiedWorker {
    static WORKER: OnceLock<VerifiedWorker> = OnceLock::new();
    WORKER
        .get_or_init(|| verified(env!("CARGO_BIN_EXE_vp-core-server-worker-v2")))
        .clone()
}
fn runtime(name: &str, generation: u64) -> ManagedRuntimeV2 {
    ManagedRuntimeV2::with_generation(worker(), WorkerInstanceV2::new(name).unwrap(), generation)
        .unwrap()
}
fn port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn config(port: u16, tls: bool) -> ProductConfig {
    serde_json::from_value(json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{
        "schemaVersion":1,"id":"fixture-listener","name":"ipc-fixture","enabled":true,"bind":{"address":"127.0.0.1","port":port},
        "protocol":{"kind":"proxy","protocol":if tls {json!({"kind":"trojan"})} else {json!({"kind":"vless","flow":null})},
        "users":[{"id":"fixture-user","credentialRef":"secret:fixture-credential","enabled":true}]},"transport":{"kind":"tcp"},
        "security":if tls {json!({"kind":"tls","certificateRef":"fixture-certificate","privateKeyRef":"secret:fixture-key","alpn":[]})} else {json!({"kind":"none"})},"requirements":[]
    }]})).unwrap()
}
fn recipe(source: &ProductConfig) -> ServerRecipeV2 {
    let release = vp_product_core_adapter::inspect_build()
        .unwrap()
        .build
        .release;
    ServerCompilerV2::for_loopback_server_extensions(release.clone())
        .unwrap()
        .compile(source, &release)
        .unwrap()
}
fn inputs(tls: bool) -> ServerInputsV2 {
    let mut inputs = ServerInputsV2::default();
    inputs.credentials.insert(
        SecretRef::new("fixture-credential").unwrap(),
        SecretBytes::new(if tls {
            b"synthetic-test-password".to_vec()
        } else {
            UUID.to_vec()
        }),
    );
    inputs
}
fn prepare(runtime: &mut ManagedRuntimeV2, port: u16) -> SpawnedProcessV2 {
    runtime
        .prepare_with_spawn_observer(
            recipe(&config(port, false)),
            inputs(false),
            runtime.generation(),
            WAIT,
            &Cancellation::default(),
            |_| Ok(()),
        )
        .unwrap()
}
fn activate(runtime: &mut ManagedRuntimeV2, generation: u64) {
    let snapshot = runtime
        .activate_prepared(generation, WAIT, &Cancellation::default())
        .unwrap();
    assert!(snapshot.listeners_ready);
    assert!(!snapshot.forwarding_verified);
}
fn assert_reaped(pid: u32) {
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "owned child was not reaped"
    );
}
fn vless_forward(proxy: u16) {
    let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    echo.set_nonblocking(true).unwrap();
    let target = echo.local_addr().unwrap().port();
    let task = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            match echo.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "target was not reached");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = [0; b"v2-coalesced-req".len()];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"v2-coalesced-req");
        stream.write_all(b"target-only-ack!").unwrap();
    });
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut header = vec![0];
    header.extend_from_slice(&[
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc,
    ]);
    header.extend_from_slice(&[0, 1]);
    header.extend_from_slice(&target.to_be_bytes());
    header.extend_from_slice(&[1, 127, 0, 0, 1]);
    header.extend_from_slice(b"v2-coalesced-req");
    client.write_all(&header).unwrap();
    let mut reply = [0; 2 + b"target-only-ack!".len()];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply[..2], &[0, 0]);
    assert_eq!(&reply[2..], b"target-only-ack!");
    drop(client);
    task.join().unwrap();
}
fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::new();
    for chunk in der.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | (chunk.get(2).copied().unwrap_or(0) as u32);
        encoded.extend_from_slice(&[
            B64[((n >> 18) & 63) as usize],
            B64[((n >> 12) & 63) as usize],
            if chunk.len() > 1 {
                B64[((n >> 6) & 63) as usize]
            } else {
                b'='
            },
            if chunk.len() > 2 {
                B64[(n & 63) as usize]
            } else {
                b'='
            },
        ]);
    }
    let mut out = format!("-----BEGIN {label}-----\n").into_bytes();
    for line in encoded.chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    out
}
fn identity(input: &mut ServerInputsV2, cert: &rcgen::CertifiedKey, key: &rcgen::CertifiedKey) {
    input.certificate_chains.insert(
        CertificateId::new("fixture-certificate").unwrap(),
        SecretBytes::new(pem("CERTIFICATE", cert.cert.der().as_ref())),
    );
    input.private_keys.insert(
        SecretRef::new("fixture-key").unwrap(),
        SecretBytes::new(pem("PRIVATE KEY", &key.key_pair.serialize_der())),
    );
}

#[test]
fn v2_prepare_is_no_bind_then_actual_forward_and_stop_reaps_process() {
    let port = port();
    let mut runtime = runtime("owner-first", 0);
    let prepared = prepare(&mut runtime, port);
    assert_eq!(prepared.generation, 1);
    assert_eq!(runtime.active_generation(), None);
    assert!(!runtime.is_running());
    drop(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap());
    activate(&mut runtime, 1);
    vless_forward(port);
    let snapshot = runtime.snapshot(1).unwrap();
    assert_eq!(snapshot.pid, prepared.pid);
    assert!(!snapshot.forwarding_verified);
    let stop = runtime.stop_active(1, Duration::ZERO).unwrap();
    assert!(stop.process_exited);
    assert_eq!(stop.remaining_tasks, 0);
    assert_reaped(prepared.pid);
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
}
#[test]
fn v2_prepare_second_generation_does_not_replace_old_or_bypass_controller_order() {
    let port = port();
    let mut runtime = runtime("owner-two-phase", 10);
    let old = prepare(&mut runtime, port);
    activate(&mut runtime, old.generation);
    let candidate = prepare(&mut runtime, port);
    assert_eq!(candidate.generation, 12);
    assert_eq!(runtime.active_generation(), Some(11));
    assert_eq!(
        runtime
            .activate_prepared(12, WAIT, &Cancellation::default())
            .unwrap_err(),
        Failure::Busy
    );
    vless_forward(port);
    assert_eq!(
        runtime.stop_active(12, Duration::ZERO).unwrap_err(),
        Failure::StaleGeneration
    );
    runtime.stop_active(11, Duration::ZERO).unwrap();
    assert_reaped(old.pid);
    activate(&mut runtime, 12);
    vless_forward(port);
    runtime.stop_active(12, Duration::ZERO).unwrap();
    assert_reaped(candidate.pid);
}
#[test]
fn v2_prepare_missing_or_mismatched_identity_reaps_candidate_preserves_active() {
    let port = port();
    let mut runtime = runtime("owner-identity", 0);
    let old = prepare(&mut runtime, port);
    activate(&mut runtime, old.generation);
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let wrong = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    for mismatched in [false, true] {
        let mut materials = inputs(true);
        if mismatched {
            identity(&mut materials, &cert, &wrong);
        }
        let mut pid = 0;
        let error = runtime
            .prepare_with_spawn_observer(
                recipe(&config(port, true)),
                materials,
                runtime.generation(),
                WAIT,
                &Cancellation::default(),
                |p| {
                    pid = p.pid;
                    Ok(())
                },
            )
            .unwrap_err();
        assert_eq!(error, Failure::InvalidConfig);
        assert_reaped(pid);
        assert_eq!(runtime.active_generation(), Some(old.generation));
        assert_eq!(runtime.prepared_generation(), None);
        vless_forward(port);
    }
    assert_eq!(runtime.generation(), 3);
    runtime.stop_active(old.generation, Duration::ZERO).unwrap();
}
#[test]
fn v2_partial_bind_failure_reaps_all_candidate_listeners() {
    let free = port();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut source = config(free, false);
    let mut second = source.listeners[0].clone();
    second.id = ListenerId::new("fixture-second").unwrap();
    second.bind.port = occupied.local_addr().unwrap().port();
    source.listeners.push(second);
    let mut runtime = runtime("owner-bind-failure", 0);
    let prepared = runtime
        .prepare_with_spawn_observer(
            recipe(&source),
            inputs(false),
            0,
            WAIT,
            &Cancellation::default(),
            |_| Ok(()),
        )
        .unwrap();
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, free)).is_ok());
    assert_eq!(
        runtime
            .activate_prepared(1, WAIT, &Cancellation::default())
            .unwrap_err(),
        Failure::BindFailed
    );
    assert_reaped(prepared.pid);
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, free)).is_ok());
    assert!(!runtime.is_running());
}
#[test]
fn v2_observer_failure_cancel_and_discard_consume_highwater_without_harming_old() {
    let port = port();
    let mut runtime = runtime("owner-cancel", 20);
    let old = prepare(&mut runtime, port);
    activate(&mut runtime, old.generation);
    let mut pid = 0;
    let error = runtime
        .prepare_with_spawn_observer(
            recipe(&config(port, false)),
            inputs(false),
            21,
            WAIT,
            &Cancellation::default(),
            |p| {
                pid = p.pid;
                Err(Failure::Io)
            },
        )
        .unwrap_err();
    assert_eq!(error, Failure::Io);
    assert_reaped(pid);
    assert_eq!(runtime.generation(), 22);
    vless_forward(port);
    let cancel = Cancellation::default();
    let error = runtime
        .prepare_with_spawn_observer(
            recipe(&config(port, false)),
            inputs(false),
            22,
            WAIT,
            &cancel,
            |p| {
                pid = p.pid;
                cancel.cancel();
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error, Failure::Canceled);
    assert_reaped(pid);
    assert_eq!(runtime.generation(), 23);
    vless_forward(port);
    let prepared = prepare(&mut runtime, port);
    runtime.discard_prepared(prepared.generation).unwrap();
    assert_reaped(prepared.pid);
    vless_forward(port);
    runtime.stop_active(old.generation, Duration::ZERO).unwrap();
    let prepared = prepare(&mut runtime, port);
    let cancel = Cancellation::default();
    cancel.cancel();
    assert_eq!(
        runtime
            .activate_prepared(prepared.generation, WAIT, &cancel)
            .unwrap_err(),
        Failure::Canceled
    );
    assert_reaped(prepared.pid);
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
}
#[test]
fn v2_instance_ownership_and_v1_binary_mismatch_are_fail_closed() {
    let port_a = port();
    let mut a = runtime("owner-a", 0);
    let old = prepare(&mut a, port_a);
    activate(&mut a, 1);
    let mut b = runtime("owner-b", 0);
    let other = prepare(&mut b, port());
    activate(&mut b, 1);
    drop(b);
    assert_reaped(other.pid);
    vless_forward(port_a);
    let mut v1 = ManagedRuntimeV2::with_generation(
        verified(env!("CARGO_BIN_EXE_vp-core-managed-worker")),
        WorkerInstanceV2::new("wrong-worker").unwrap(),
        0,
    )
    .unwrap();
    assert!(v1
        .prepare_with_spawn_observer(
            recipe(&config(port(), false)),
            inputs(false),
            0,
            WAIT,
            &Cancellation::default(),
            |_| panic!("v1 worker reached material observer")
        )
        .is_err());
    assert_eq!(v1.generation(), 1);
    vless_forward(port_a);
    a.stop_active(old.generation, Duration::ZERO).unwrap();
}

// Responses contain metadata only. Bounded reader/pump prevents a broken worker
// from hanging test execution indefinitely; guard always owns kill+wait cleanup.
struct RawWorker {
    child: Child,
    input: Option<ChildStdin>,
    responses: mpsc::Receiver<Vec<u8>>,
    reader: Option<JoinHandle<()>>,
}
impl RawWorker {
    fn new() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vp-core-server-worker-v2"))
            .arg("--stdio-server-v2")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let output = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::sync_channel(8);
        let reader = std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            loop {
                let mut line = Vec::new();
                let count = reader
                    .by_ref()
                    .take((MAX_RESPONSE_FRAME_V2 + 1) as u64)
                    .read_until(b'\n', &mut line)
                    .unwrap();
                if count == 0 {
                    break;
                }
                assert!(line.len() <= MAX_RESPONSE_FRAME_V2);
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let raw = Self {
            child,
            input,
            responses: rx,
            reader: Some(reader),
        };
        assert!(matches!(
            raw.response(),
            ResponseV2::HelloServerV2 { version: 2, .. }
        ));
        raw
    }
    fn write(&mut self, bytes: &[u8]) {
        self.input.as_mut().unwrap().write_all(bytes).unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
    }
    fn json(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        self.write(&bytes);
    }
    fn line(&self) -> Vec<u8> {
        self.responses
            .recv_timeout(WAIT)
            .expect("worker response deadline")
    }
    fn response(&self) -> ResponseV2 {
        serde_json::from_slice(&self.line()).unwrap()
    }
    fn negotiate(&mut self) {
        self.json(control("negotiate_server_v2", 0));
        assert!(matches!(
            self.response(),
            ResponseV2::NegotiatedServerV2 { version: 2, .. }
        ));
    }
    fn prepare(&mut self, port: u16) {
        self.json(prepare_frame(port));
        assert!(matches!(
            self.response(),
            ResponseV2::PreparedServerV2 { generation: 1, .. }
        ));
    }
    fn eof_and_wait(&mut self) {
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "EOF child did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}
impl Drop for RawWorker {
    fn drop(&mut self) {
        self.input.take();
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
fn control(kind: &str, generation: u64) -> Value {
    json!({"version":2,"kind":kind,"instance":"raw-fixture","generation":generation})
}
fn prepare_frame(port: u16) -> Value {
    json!({"version":2,"kind":"prepare_server_v2","instance":"raw-fixture","generation":1,"startServerV2":{"schemaVersion":2,"recipeJson":serde_json::to_string(&recipe(&config(port,false))).unwrap(),"startupMs":5000,"materials":[{"kind":"credential","reference":"secret:fixture-credential","value":UUID.to_vec()}]}})
}
#[test]
fn v2_real_worker_rejects_wrong_versions_duplicate_fields_and_material_without_echo() {
    let marker = "NEVER-ECHO-SYNTHETIC-MATERIAL";
    let mut unknown = prepare_frame(port());
    unknown["startServerV2"]["materials"][0]["unexpected"] = json!(marker);
    let mut duplicate = prepare_frame(port());
    let record = duplicate["startServerV2"]["materials"][0].clone();
    duplicate["startServerV2"]["materials"]
        .as_array_mut()
        .unwrap()
        .push(record);
    let duplicate_bytes = serde_json::to_string(&prepare_frame(port()))
        .unwrap()
        .replacen(
            "\"schemaVersion\":2",
            "\"schemaVersion\":2,\"schemaVersion\":2",
            1,
        );
    for bytes in [
        format!(
            "{{\"version\":1,\"kind\":\"start\",\"generation\":1,\"password\":\"{marker}\"}}\n"
        )
        .into_bytes(),
        format!("{duplicate_bytes}\n").into_bytes(),
        format!("{unknown}\n").into_bytes(),
        format!("{duplicate}\n").into_bytes(),
    ] {
        let mut raw = RawWorker::new();
        raw.negotiate();
        raw.write(&bytes);
        let response = raw.line();
        assert!(!String::from_utf8_lossy(&response).contains(marker));
        assert!(matches!(
            serde_json::from_slice::<ResponseV2>(&response).unwrap(),
            ResponseV2::FailedServerV2 { .. }
        ));
        raw.eof_and_wait();
    }
}
#[test]
fn v2_real_worker_rejects_oversize_truncated_frames_and_cross_instance() {
    let mut raw = RawWorker::new();
    raw.negotiate();
    let mut mismatch = control("snapshot_server_v2", 1);
    mismatch["instance"] = json!("another-owner");
    raw.json(mismatch);
    assert!(matches!(
        raw.response(),
        ResponseV2::FailedServerV2 {
            failure: Failure::ProtocolViolation
        }
    ));
    raw.eof_and_wait();
    let mut raw = RawWorker::new();
    raw.negotiate();
    raw.write(b"{\"version\":2");
    raw.input.take();
    assert!(matches!(raw.response(), ResponseV2::FailedServerV2 { .. }));
    raw.eof_and_wait();
    let mut raw = RawWorker::new();
    raw.negotiate();
    let oversized = vec![b' '; MAX_REQUEST_FRAME_V2 + 1];
    let _ = raw.input.as_mut().unwrap().write_all(&oversized);
    assert!(matches!(
        raw.response(),
        ResponseV2::FailedServerV2 {
            failure: Failure::ProtocolViolation
        }
    ));
    raw.eof_and_wait();
}
#[test]
fn v2_real_worker_eof_before_prepare_after_prepare_and_activation_boundary_reaps() {
    for phase in 0..4 {
        let port = port();
        let mut raw = RawWorker::new();
        raw.negotiate();
        if phase > 0 {
            raw.prepare(port);
            assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
        }
        if phase > 1 {
            raw.json(control("activate_server_v2", 1));
        }
        if phase > 2 {
            assert!(matches!(raw.response(), ResponseV2::StartedServerV2 { .. }));
            vless_forward(port);
        }
        raw.eof_and_wait();
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    }
}
#[test]
fn v2_host_process_crash_bypasses_drop_but_child_eof_cleans_listener() {
    const DRIVER: &str = "VP_SERVER_V2_CRASH_DRIVER";
    if std::env::var(DRIVER).as_deref() == Ok("yes") {
        let mut runtime = runtime("crash-owner", 0);
        let port = port();
        let prepared = prepare(&mut runtime, port);
        activate(&mut runtime, 1);
        println!("VP_V2_CHILD={}:{}", prepared.pid, port);
        std::io::stdout().flush().unwrap();
        std::process::exit(23);
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "v2_host_process_crash_bypasses_drop_but_child_eof_cleans_listener",
            "--nocapture",
        ])
        .env(DRIVER, "yes")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let marker = stdout
        .lines()
        .find_map(|l| l.strip_prefix("VP_V2_CHILD="))
        .unwrap();
    let (pid, port) = marker.split_once(':').unwrap();
    let pid: u32 = pid.parse().unwrap();
    let port: u16 = port.parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let ended = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |s| {
            s.split_once(") ")
                .is_some_and(|(_, tail)| tail.starts_with("Z "))
        });
        if ended && TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "child survived parent EOF");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn v2_tls_material_prepares_without_bind_and_plaintext_handshake_is_rejected() {
    let port = port();
    let mut runtime = runtime("owner-tls", 0);
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut materials = inputs(true);
    identity(&mut materials, &cert, &cert);
    let child = runtime
        .prepare_with_spawn_observer(
            recipe(&config(port, true)),
            materials,
            0,
            WAIT,
            &Cancellation::default(),
            |_| Ok(()),
        )
        .unwrap();
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    activate(&mut runtime, child.generation);
    let mut plaintext = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    plaintext
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    plaintext.write_all(b"not-a-tls-handshake\r\n").unwrap();
    let mut byte = [0; 1];
    match plaintext.read(&mut byte) {
        Ok(0) => {}
        Err(e) => assert!(matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
        )),
        Ok(_) => {
            // A TLS fatal alert is rejection, not application acceptance.
            assert_eq!(byte[0], 21, "unexpected non-alert TLS response");
        }
    };
    assert!(runtime.snapshot(child.generation).unwrap().listeners_ready);
    runtime
        .stop_active(child.generation, Duration::ZERO)
        .unwrap();
    assert_reaped(child.pid);
}
fn socks_peer(proxy: u16, password: &str, target: u16) -> TcpStream {
    let mut io = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy)).unwrap();
    io.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    io.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    io.write_all(&[5, 1, 2]).unwrap();
    let mut method = [0; 2];
    io.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 2]);
    let username = b"fixture-user";
    let mut frame = vec![1, username.len() as u8];
    frame.extend_from_slice(username);
    frame.push(password.len() as u8);
    frame.extend_from_slice(password.as_bytes());
    frame.extend_from_slice(&[5, 1, 0, 1, 127, 0, 0, 1]);
    frame.extend_from_slice(&target.to_be_bytes());
    frame.extend_from_slice(b"proof");
    io.write_all(&frame).unwrap();
    io
}
#[test]
fn v2_typed_socks_tuple_forwards_and_invalid_retired_credentials_never_reach_target() {
    let port = port();
    let mut source = config(port, false);
    let ServerProtocol::Proxy { protocol, .. } = &mut source.listeners[0].protocol else {
        unreachable!()
    };
    *protocol = Protocol::Socks5 {};
    source.listeners[0].requirements = vec![CapabilityKey::SocksAuth];
    let mut runtime = runtime("owner-socks-rotation", 0);
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    let target_port = target.local_addr().unwrap().port();
    for (version, password, invalid) in [
        (1, "synthetic-one", "synthetic-wrong"),
        (2, "synthetic-two", "synthetic-one"),
    ] {
        let reference = SecretRef::new(&format!("fixture-version-{version}")).unwrap();
        let ServerProtocol::Proxy { users, .. } = &mut source.listeners[0].protocol else {
            unreachable!()
        };
        users[0].credential_ref = reference.clone();
        let mut materials = ServerInputsV2::default();
        materials.credentials.insert(
            reference,
            SecretBytes::new(
                serde_json::to_vec(
                    &json!({"schemaVersion":1,"username":"fixture-user","password":password}),
                )
                .unwrap(),
            ),
        );
        let child = runtime
            .prepare_with_spawn_observer(
                recipe(&source),
                materials,
                runtime.generation(),
                WAIT,
                &Cancellation::default(),
                |_| Ok(()),
            )
            .unwrap();
        activate(&mut runtime, child.generation);
        let mut rejected = socks_peer(port, invalid, target_port);
        let mut auth = [0; 2];
        rejected.read_exact(&mut auth).unwrap();
        assert_eq!(auth, [1, 1]);
        let mut byte = [0; 1];
        assert!(matches!(rejected.read(&mut byte), Ok(0) | Err(_)));
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let mut accepted = socks_peer(port, password, target_port);
        accepted.read_exact(&mut auth).unwrap();
        assert_eq!(auth, [1, 0]);
        let mut response = [0; 10];
        accepted.read_exact(&mut response).unwrap();
        assert_eq!(&response[..2], &[5, 0]);
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut target_io = loop {
            match target.accept() {
                Ok((io, _)) => break io,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        };
        target_io
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut proof = [0; 5];
        target_io.read_exact(&mut proof).unwrap();
        assert_eq!(&proof, b"proof");
        target_io.write_all(b"actual-target-ack").unwrap();
        let mut ack = [0; b"actual-target-ack".len()];
        accepted.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"actual-target-ack");
        drop(accepted);
        drop(target_io);
        runtime
            .stop_active(child.generation, Duration::ZERO)
            .unwrap();
        assert_reaped(child.pid);
    }
}

#[test]
fn v2_real_worker_rejects_unversioned_and_duplicate_tuple_payloads_before_bind() {
    let port = port();
    let mut source = config(port, false);
    let ServerProtocol::Proxy { protocol, .. } = &mut source.listeners[0].protocol else {
        unreachable!()
    };
    *protocol = Protocol::Socks5 {};
    source.listeners[0].requirements = vec![CapabilityKey::SocksAuth];
    let mut runtime = runtime("owner-invalid-tuples", 0);
    for payload in [b"fixture-user:synthetic-password".as_slice(),br#"{"schemaVersion":2,"username":"fixture-user","password":"synthetic-password"}"#,br#"{"schemaVersion":1,"username":"fixture-user","password":"one","password":"two"}"#,br#"{"schemaVersion":1,"username":"fixture-user","password":"synthetic-password","unexpected":"NEVER-ECHO"}"#] {
        let mut materials=ServerInputsV2::default();materials.credentials.insert(SecretRef::new("fixture-credential").unwrap(),SecretBytes::new(payload.to_vec()));let mut pid=0;assert_eq!(runtime.prepare_with_spawn_observer(recipe(&source),materials,runtime.generation(),WAIT,&Cancellation::default(),|child|{pid=child.pid;Ok(())}).unwrap_err(),Failure::InvalidConfig);assert_reaped(pid);assert!(TcpListener::bind((Ipv4Addr::LOCALHOST,port)).is_ok());
    }
    assert_eq!(runtime.generation(), 4);
}
#[test]
fn v2_stop_aborts_active_old_generation_sessions_and_releases_target_socket() {
    let port = port();
    let mut runtime = runtime("owner-active-session", 0);
    let child = prepare(&mut runtime, port);
    activate(&mut runtime, child.generation);
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    let target_port = target.local_addr().unwrap().port();
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut header = vec![0];
    header.extend_from_slice(&[
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc,
    ]);
    header.extend_from_slice(&[0, 1]);
    header.extend_from_slice(&target_port.to_be_bytes());
    header.extend_from_slice(&[1, 127, 0, 0, 1]);
    header.extend_from_slice(b"session-proof");
    client.write_all(&header).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut target_io = loop {
        match target.accept() {
            Ok((io, _)) => break io,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("{e}"),
        }
    };
    target_io
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut proof = [0; b"session-proof".len()];
    target_io.read_exact(&mut proof).unwrap();
    assert_eq!(&proof, b"session-proof");
    target_io.write_all(b"ack").unwrap();
    let mut reply = [0; 5];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, &[0, 0, b'a', b'c', b'k']);
    let report = runtime
        .stop_active(child.generation, Duration::ZERO)
        .unwrap();
    assert_eq!(report.remaining_tasks, 0);
    assert!(report.process_exited);
    assert_reaped(child.pid);
    for mut peer in [client, target_io] {
        match peer.read(&mut [0; 1]) {
            Ok(n) => assert_eq!(n, 0),
            Err(e) => assert!(matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            )),
        }
    }
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
}

#[test]
fn v2_quic_candidates_validate_material_before_udp_bind_then_stop_owned_endpoint() {
    // Construction/readiness and ownership only, explicitly not QUIC peer auth.
    for tuic in [true, false] {
        let reserved = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reserved.local_addr().unwrap().port();
        let mut source = config(port, true);
        let ServerProtocol::Proxy { protocol, .. } = &mut source.listeners[0].protocol else {
            unreachable!()
        };
        *protocol = if tuic {
            Protocol::Tuic {
                congestion_control: CongestionControl::Cubic,
                udp_relay_mode: TuicUdpRelayMode::Native,
            }
        } else {
            Protocol::Hysteria2 {
                obfuscation_ref: None,
            }
        };
        source.listeners[0].transport = Transport::Quic {};
        source.listeners[0].requirements = vec![if tuic {
            CapabilityKey::Tuic
        } else {
            CapabilityKey::Hysteria2
        }];
        let ServerSecurity::Tls { alpn, .. } = &mut source.listeners[0].security else {
            unreachable!()
        };
        *alpn = vec!["h3".into()];
        let mut materials = inputs(true);
        if tuic {
            materials.credentials.insert(SecretRef::new("fixture-credential").unwrap(),SecretBytes::new(br#"{"schemaVersion":1,"uuid":"12345678-1234-1234-1234-123456789abc","password":"synthetic-tuic-password"}"#.to_vec()));
        }
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        identity(&mut materials, &cert, &cert);
        let mut runtime = runtime(if tuic { "owner-tuic" } else { "owner-hy2" }, 0);
        let child = runtime
            .prepare_with_spawn_observer(
                recipe(&source),
                materials,
                0,
                WAIT,
                &Cancellation::default(),
                |_| Ok(()),
            )
            .unwrap();
        // The reservation remains held across actual child prepare: any UDP bind
        // during material validation would fail instead of returning Prepared.
        drop(reserved);
        activate(&mut runtime, child.generation);
        assert!(std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_err());
        runtime
            .stop_active(child.generation, Duration::ZERO)
            .unwrap();
        assert_reaped(child.pid);
        assert!(std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    }
}

#[cfg(feature = "experimental-public")]
#[test]
fn public_v2_worker_prepares_then_reaps_on_unavailable_bind() {
    let unavailable = TcpListener::bind(("192.0.2.1", 19001)).unwrap_err();
    assert_eq!(unavailable.kind(), std::io::ErrorKind::AddrNotAvailable);
    let release = vp_product_core_adapter::inspect_build().unwrap().build.release;
    let compiler = ServerCompilerV2::for_public_experiment(release.clone(), vec!["8.8.8.8:443".parse().unwrap()]).unwrap();
    let mut source = config(19001, true);
    source.listeners[0].bind.address = "192.0.2.1".parse().unwrap();
    let recipe = compiler.compile(&source, &release).unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut materials = inputs(true);
    identity(&mut materials, &cert, &cert);
    let mut runtime = runtime("public-unavailable-bind", 0);
    let prepared = runtime.prepare_with_spawn_observer(recipe, materials, 0, WAIT, &Cancellation::default(), |_| Ok(())).unwrap();
    assert_eq!(runtime.activate_prepared(prepared.generation, WAIT, &Cancellation::default()).unwrap_err(), Failure::BindFailed);
    assert_eq!(runtime.active_generation(), None);
    drop(runtime);
    assert_reaped(prepared.pid);
}

#[cfg(feature = "experimental-public")]
#[test]
fn challenge_client_exercises_three_protocols_against_local_oracle() {
    use vp_product_core_adapter::managed::probe_client_v2::challenge;
    let async_rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for mode in 0..3 {
        eprintln!("probe mode={mode}");
        let p = port();
        let mut source = if mode == 0 { config(p, true) } else { config(p, false) };
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut material = inputs(mode == 0);
        if mode == 1 {
            source.listeners[0].transport = Transport::Ws { path: "/probe".into(), host: None, early_data: None };
            source.listeners[0].security = config(p, true).listeners[0].security.clone();
        } else if mode == 2 {
            let ServerProtocol::Proxy { protocol, .. } = &mut source.listeners[0].protocol else { unreachable!() };
            *protocol = Protocol::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm };
            material.credentials.insert(SecretRef::new("fixture-credential").unwrap(), SecretBytes::new(b"synthetic-ss-password".to_vec()));
        }
        if mode < 2 { identity(&mut material, &certificate, &certificate); }
        let recipe = recipe(&source);
        let listener = recipe.listeners[0].clone();
        let mut runtime = runtime(&format!("probe-mode-{mode}"), 0);
        let child = runtime.prepare_with_spawn_observer(recipe, material, 0, WAIT, &Cancellation::default(), |_| Ok(())).unwrap();
        activate(&mut runtime, child.generation);
        let oracle = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        oracle.set_nonblocking(true).unwrap();
        let target = oracle.local_addr().unwrap();
        let roots = vec![certificate.cert.der().to_vec()];
        let wrong = SecretBytes::new(if mode == 1 { b"22345678-1234-1234-1234-123456789abc".to_vec() } else { b"invalid-password".to_vec() });
        let invalid_token = [7u8; 32];
        let mut mismatched = source.listeners[0].clone();
        mismatched.bind.port = mismatched.bind.port.saturating_add(1);
        assert!(matches!(async_rt.block_on(challenge(&listener, &mismatched, target, &wrong, &roots, "localhost", &invalid_token, Duration::from_secs(1))), Err(Failure::InvalidConfig)));
        let failed = async_rt.block_on(challenge(&listener, &source.listeners[0], target, &wrong, &roots, "localhost", &invalid_token, Duration::from_millis(500)));
        assert!(!matches!(failed, Ok(true)));
        assert_eq!(oracle.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        if mode < 2 {
            let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let wrong_roots = vec![other.cert.der().to_vec()];
            let cert_error = async_rt.block_on(challenge(&listener, &source.listeners[0], target, &wrong, &wrong_roots, "localhost", &invalid_token, Duration::from_secs(2)));
            assert!(cert_error.is_err());
        }
        let valid_token = [9u8;32];
        let server = std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(3);
            let (mut io, _) = loop {
                match oracle.accept() { Ok(value) => break value, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until => std::thread::sleep(Duration::from_millis(5)), Err(e) => panic!("oracle accept: {e}") }
            };
            io.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut received = [0;32]; io.read_exact(&mut received).unwrap(); assert_eq!(received, valid_token);
            io.write_all(b"VP-ORACLE-OK").unwrap();
        });
        let correct = SecretBytes::new(match mode { 0 => b"synthetic-test-password".to_vec(), 1 => UUID.to_vec(), _ => b"synthetic-ss-password".to_vec() });
        assert!(async_rt.block_on(challenge(&listener, &source.listeners[0], target, &correct, &roots, "localhost", &valid_token, Duration::from_secs(3))).unwrap());
        server.join().unwrap();
        runtime.stop_active(child.generation, Duration::ZERO).unwrap();
        assert_reaped(child.pid);
    }
}
