//! Candidate-only tests. Requires the reviewed v2 feature + rcgen dev dependency.
//! No execution/evidence is claimed until the assigned Cargo/loopback lane runs.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vp_product_domain::*;

fn unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn config(port: u16, tls: bool) -> ProductConfig {
    ProductConfig {
        schema_version: 1,
        minimum_reader_version: 1,
        nodes: vec![],
        subscriptions: vec![],
        listeners: vec![ServerListener {
            schema_version: 1,
            id: ListenerId::new("fixture-listener").unwrap(),
            name: "source-only-fixture".into(),
            enabled: true,
            bind: BindAddress {
                address: "127.0.0.1".parse().unwrap(),
                port,
            },
            protocol: ServerProtocol::Proxy {
                protocol: if tls {
                    Protocol::Trojan {}
                } else {
                    Protocol::Vless { flow: None }
                },
                users: vec![ListenerUser {
                    id: UserId::new("fixture-user").unwrap(),
                    credential_ref: SecretRef::new("fixture-credential").unwrap(),
                    enabled: true,
                }],
            },
            transport: Transport::Tcp {},
            security: if tls {
                ServerSecurity::Tls {
                    certificate_ref: CertificateId::new("fixture-certificate").unwrap(),
                    private_key_ref: SecretRef::new("fixture-key").unwrap(),
                    alpn: vec![],
                }
            } else {
                ServerSecurity::None {}
            },
            requirements: if tls {
                vec![CapabilityKey::TrojanTls]
            } else {
                vec![]
            },
        }],
    }
}
fn recipe(config: &ProductConfig) -> ServerRecipeV2 {
    let release = crate::inspect_build().unwrap().build.release;
    ServerCompilerV2::for_loopback_development(release.clone())
        .unwrap()
        .compile(config, &release)
        .unwrap()
}
fn inputs(tls: bool) -> ServerInputsV2 {
    let mut inputs = ServerInputsV2::default();
    inputs.credentials.insert(
        SecretRef::new("fixture-credential").unwrap(),
        SecretBytes::new(if tls {
            b"synthetic-test-password".to_vec()
        } else {
            b"12345678-1234-1234-1234-123456789abc".to_vec()
        }),
    );
    inputs
}
// Test-only PEM encoder avoids rcgen's optional pem dependency and preserves
// the product's exact serde pin. Identities still undergo real rustls parsing.
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
fn identity(
    inputs: &mut ServerInputsV2,
    certificate: &rcgen::CertifiedKey,
    key: &rcgen::CertifiedKey,
) {
    inputs.certificate_chains.insert(
        CertificateId::new("fixture-certificate").unwrap(),
        SecretBytes::new(pem("CERTIFICATE", certificate.cert.der().as_ref())),
    );
    inputs.private_keys.insert(
        SecretRef::new("fixture-key").unwrap(),
        SecretBytes::new(pem("PRIVATE KEY", &key.key_pair.serialize_der())),
    );
}
#[test]
fn missing_certificate_key_and_unrequested_secret_fail_before_bind() {
    let port = unused_port();
    let recipe = recipe(&config(port, true));
    let mut inputs = inputs(true);
    assert!(matches!(
        prepare(&recipe, &inputs),
        Err(Failure::InvalidConfig)
    ));
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    identity(&mut inputs, &cert, &cert);
    let removed = inputs
        .private_keys
        .remove(&SecretRef::new("fixture-key").unwrap())
        .unwrap();
    assert!(matches!(
        prepare(&recipe, &inputs),
        Err(Failure::InvalidConfig)
    ));
    inputs
        .private_keys
        .insert(SecretRef::new("fixture-key").unwrap(), removed);
    inputs.credentials.insert(
        SecretRef::new("unrequested").unwrap(),
        SecretBytes::new(b"test-only".to_vec()),
    );
    assert!(matches!(
        prepare(&recipe, &inputs),
        Err(Failure::InvalidConfig)
    ));
    assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok());
    assert_eq!(format!("{inputs:?}"), "ServerInputsV2([REDACTED])");
}
#[test]
fn mismatched_private_key_and_plaintext_recipe_tampering_are_rejected() {
    let port = unused_port();
    let recipe = recipe(&config(port, true));
    let mut inputs = inputs(true);
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    identity(&mut inputs, &first, &other);
    assert!(matches!(
        prepare(&recipe, &inputs),
        Err(Failure::InvalidConfig)
    ));
    assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok());
    let mut value = serde_json::to_value(&recipe).unwrap();
    value["listeners"][0]["security"]["privateKeyPem"] =
        serde_json::json!("test-only forbidden field");
    assert!(serde_json::from_value::<ServerRecipeV2>(value).is_err());
}
#[tokio::test]
async fn material_failure_leaves_previous_generation_and_sessions_owned() {
    let old_port = unused_port();
    let old_recipe = recipe(&config(old_port, false));
    let old = ManagedServerV2::start(&old_recipe, inputs(false), Duration::from_secs(2))
        .await
        .unwrap();
    let mut held = tokio::net::TcpStream::connect(("127.0.0.1", old_port))
        .await
        .unwrap();
    held.write_all(&[0]).await.unwrap(); // incomplete VLESS request, not a fake forwarding probe
    let candidate = recipe(&config(unused_port(), true));
    assert!(matches!(
        ManagedServerV2::start(&candidate, inputs(true), Duration::from_secs(2)).await,
        Err(Failure::InvalidConfig)
    ));
    assert!(old.snapshot(1).listeners_ready);
    assert!(!old.snapshot(1).forwarding_verified);
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", old_port))
        .await
        .is_ok());
    let report = old.shutdown(1, Duration::ZERO).await.unwrap();
    assert_eq!(report.remaining_tasks, 0);
    let mut byte = [0; 1];
    let closed = tokio::time::timeout(Duration::from_secs(2), held.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0) | Err(_)));
    assert!(tokio::net::TcpListener::bind(("127.0.0.1", old_port))
        .await
        .is_ok());
}
#[tokio::test]
async fn later_bind_failure_reaps_candidate_listeners_without_false_readiness() {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_port = unused_port();
    let mut config = config(first_port, false);
    let mut second = config.listeners[0].clone();
    second.id = ListenerId::new("fixture-second").unwrap();
    second.bind.port = occupied.local_addr().unwrap().port();
    config.listeners.push(second);
    let candidate = recipe(&config);
    assert!(matches!(
        ManagedServerV2::start(&candidate, inputs(false), Duration::from_secs(2)).await,
        Err(Failure::BindFailed)
    ));
    assert!(tokio::net::TcpListener::bind(("127.0.0.1", first_port))
        .await
        .is_ok());
    assert!(
        tokio::net::TcpListener::bind(occupied.local_addr().unwrap())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn dropping_pending_start_guard_cancels_owned_listener() {
    // Exercise the exact guard used when a Start future is dropped by its caller;
    // this is a cancellation ownership fixture, not a whole worker IPC test.
    let scope = TaskScope::with_destination_policy(DestinationPolicy::LoopbackIpOnly);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let owned = scope.clone();
    let task = tokio::spawn(async move {
        let _guard = StartGuard {
            scope: owned.clone(),
            armed: true,
        };
        owned
            .run(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                vp_core::task_scope::spawn_listener("cancel-fixture", async move {
                    let _listener = listener;
                    std::future::pending::<()>().await;
                });
                ready_tx.send(address).unwrap();
                std::future::pending::<()>().await;
            })
            .await;
    });
    let address = ready_rx.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let report = scope.shutdown(Duration::ZERO, Duration::from_secs(1)).await;
    assert_eq!(report.remaining_tasks, 0);
    assert!(tokio::net::TcpListener::bind(address).await.is_ok());
}

#[test]
fn extended_socks_factory_accepts_only_versioned_tuple_and_rejects_duplicate_identity() {
    let mut source = config(unused_port(), false);
    let ServerProtocol::Proxy { protocol, users } = &mut source.listeners[0].protocol else {
        unreachable!()
    };
    *protocol = Protocol::Socks5 {};
    users.push(ListenerUser {
        id: UserId::new("fixture-other").unwrap(),
        credential_ref: SecretRef::new("fixture-other-credential").unwrap(),
        enabled: true,
    });
    source.listeners[0].requirements = vec![CapabilityKey::SocksAuth];
    let release = crate::inspect_build().unwrap().build.release;
    let recipe = ServerCompilerV2::for_loopback_server_extensions(release.clone())
        .unwrap()
        .compile(&source, &release)
        .unwrap();
    let mut inputs = inputs(false);
    inputs.credentials.insert(
        SecretRef::new("fixture-other-credential").unwrap(),
        SecretBytes::new(
            br#"{"schemaVersion":1,"username":"fixture-other","password":"synthetic-password"}"#
                .to_vec(),
        ),
    );
    assert!(matches!(
        prepare(&recipe, &inputs),
        Err(Failure::InvalidConfig)
    )); // raw UUID is not a tuple
    inputs.credentials.insert(
        SecretRef::new("fixture-credential").unwrap(),
        SecretBytes::new(
            br#"{"schemaVersion":1,"username":"fixture-user","password":"synthetic-password"}"#
                .to_vec(),
        ),
    );
    assert_eq!(prepare(&recipe, &inputs).unwrap().len(), 1);
    inputs.credentials.insert(
        SecretRef::new("fixture-other-credential").unwrap(),
        SecretBytes::new(
            br#"{"schemaVersion":1,"username":"fixture-user","password":"different-password"}"#
                .to_vec(),
        ),
    );
    assert!(matches!(
        prepare(&recipe, &inputs),
        Err(Failure::InvalidConfig)
    ));
}

#[tokio::test]
async fn product_socks_recipe_forwards_to_real_target_and_rejects_invalid_and_retired_credentials()
{
    // Authored RFC1929 peer, not independent-library certification. Every socket
    // and synthetic credential is test-scoped, memory-only and loopback-bound.
    tokio::time::timeout(Duration::from_secs(8),async {
        let port=unused_port();let mut source=config(port,false);
        let ServerProtocol::Proxy {protocol,..}=&mut source.listeners[0].protocol else {unreachable!()};
        *protocol=Protocol::Socks5 {};source.listeners[0].requirements=vec![CapabilityKey::SocksAuth];
        let release=crate::inspect_build().unwrap().build.release;
        let target=Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        let target_port=target.local_addr().unwrap().port();
        for (generation,password,invalid) in [(1,"fixture-version-one","wrong-fixture"),(2,"fixture-version-two","fixture-version-one")] {
            let reference=SecretRef::new(&format!("fixture-version-{generation}")).unwrap();
            let mut generation_source=source.clone();
            let ServerProtocol::Proxy {users,..}=&mut generation_source.listeners[0].protocol else {unreachable!()};
            users[0].credential_ref=reference.clone();
            let recipe=ServerCompilerV2::for_loopback_server_extensions(release.clone()).unwrap().compile(&generation_source,&release).unwrap();
            let mut values=ServerInputsV2::default();
            values.credentials.insert(reference,SecretBytes::new(serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"username":"fixture-user","password":password})).unwrap()));
            let server=ManagedServerV2::start(&recipe,values,Duration::from_secs(2)).await.unwrap();
            assert!(!server.snapshot(generation).forwarding_verified);
            let mut rejected=socks_peer(port,invalid,target_port).await;
            let mut auth=[0;2];rejected.read_exact(&mut auth).await.unwrap();assert_eq!(auth,[1,1]);
            let mut byte=[0;1];assert!(matches!(rejected.read(&mut byte).await,Ok(0)|Err(_)));
            assert!(tokio::time::timeout(Duration::from_millis(20),target.accept()).await.is_err(),"rejected credential reached target");
            let listener=target.clone();
            let receiver=tokio::spawn(async move {
                let (mut io,_)=listener.accept().await.unwrap();let mut proof=[0;5];io.read_exact(&mut proof).await.unwrap();assert_eq!(&proof,b"proof");io.write_all(b"target-ack").await.unwrap();
            });
            let mut accepted=socks_peer(port,password,target_port).await;
            accepted.read_exact(&mut auth).await.unwrap();assert_eq!(auth,[1,0]);
            let mut response=[0;10];accepted.read_exact(&mut response).await.unwrap();assert_eq!(&response[..2],&[5,0]);
            let mut ack=[0;10];accepted.read_exact(&mut ack).await.unwrap();assert_eq!(&ack,b"target-ack");
            receiver.await.unwrap();drop(accepted);
            assert_eq!(server.shutdown(generation,Duration::ZERO).await.unwrap().remaining_tasks,0);
            assert!(tokio::net::TcpListener::bind(("127.0.0.1",port)).await.is_ok());
        }
    }).await.unwrap();
}
async fn socks_peer(port: u16, password: &str, target: u16) -> tokio::net::TcpStream {
    let mut io = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    io.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0; 2];
    io.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let username = b"fixture-user";
    let mut frame = vec![1, username.len() as u8];
    frame.extend_from_slice(username);
    frame.push(password.len() as u8);
    frame.extend_from_slice(password.as_bytes());
    // Coalesce target request after auth so the negative test detects processing
    // target bytes before authentication rather than merely checking an error.
    frame.extend_from_slice(&[5, 1, 0, 1, 127, 0, 0, 1]);
    frame.extend_from_slice(&target.to_be_bytes());
    frame.extend_from_slice(b"proof");
    io.write_all(&frame).await.unwrap();
    io
}

#[cfg(not(feature = "experimental-public"))]
#[test]
fn unimplemented_public_profile_is_rejected_before_activation() {
    let mut candidate = recipe(&config(19001, false));
    candidate.profile = ServerProfileV2::PublicExperimentalUncertified;
    candidate.public_targets = Some(vec!["8.8.8.8:443".parse().unwrap()]);
    assert!(matches!(prepare(&candidate, &inputs(false)), Err(Failure::InvalidConfig)));
}

#[cfg(feature = "experimental-public")]
#[test]
fn public_preparation_checks_grant_and_tls_material_before_bind() {
    let release = crate::inspect_build().unwrap().build.release;
    let compiler = ServerCompilerV2::for_public_experiment(release.clone(), vec!["8.8.8.8:443".parse().unwrap()]).unwrap();
    let mut source = config(19001, true);
    source.listeners[0].bind.address = "192.168.1.5".parse().unwrap();
    let recipe = compiler.compile(&source, &release).unwrap();
    assert!(matches!(PreparedServerV2::prepare(&recipe, inputs(true)), Err(Failure::InvalidConfig)));
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut material = inputs(true);
    identity(&mut material, &cert, &cert);
    assert!(PreparedServerV2::prepare(&recipe, material).is_ok());
    let mut tampered = recipe;
    tampered.public_targets = Some(vec!["127.0.0.1:443".parse().unwrap()]);
    let mut material = inputs(true);
    identity(&mut material, &cert, &cert);
    assert!(matches!(PreparedServerV2::prepare(&tampered, material), Err(Failure::InvalidConfig)));
}

#[cfg(feature = "experimental-public")]
#[test]
fn public_activation_bind_failure_stays_fail_closed_in_child() {
    const CHILD: &str = "VP_PUBLIC_ACTIVATION_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("managed::server_v2::tests::public_activation_bind_failure_stays_fail_closed_in_child")
            .arg("--test-threads=1").env(CHILD, "1").status().unwrap();
        assert!(status.success());
        return;
    }
    let release = crate::inspect_build().unwrap().build.release;
    let compiler = ServerCompilerV2::for_public_experiment(release.clone(), vec!["8.8.8.8:443".parse().unwrap()]).unwrap();
    let mut source = config(19001, true);
    // Documentation-only TEST-NET-1 address is intentionally not a local interface.
    source.listeners[0].bind.address = "192.0.2.1".parse().unwrap();
    let recipe = compiler.compile(&source, &release).unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut material = inputs(true);
    identity(&mut material, &cert, &cert);
    let prepared = PreparedServerV2::prepare(&recipe, material).unwrap();
    let unavailable = std::net::TcpListener::bind(("192.0.2.1", 19001)).unwrap_err();
    assert_eq!(unavailable.kind(), std::io::ErrorKind::AddrNotAvailable);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        assert!(matches!(ManagedServerV2::start_prepared(prepared, Duration::from_secs(2)).await, Err(Failure::StartupFailed)));
        assert!(vp_core::task_scope::experimental_process_floor().is_some());
        assert!(vp_core::task_scope::check_destination(&vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), 443)).is_err());
        let legacy = self::recipe(&config(19002, false));
        let legacy_prepared = PreparedServerV2::prepare(&legacy, inputs(false)).unwrap();
        assert!(matches!(ManagedServerV2::start_prepared(legacy_prepared, Duration::from_secs(2)).await, Err(Failure::InvalidConfig)));
    });
}
