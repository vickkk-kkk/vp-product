// Test assertions intentionally panic on unexpected fixture/results.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use serde_json::{json, Value};
use vp_product_domain::*;

fn sample_node() -> NodeProfile {
    serde_json::from_str(include_str!(
        "../../../contracts/fixtures/node-vless-reality.json"
    ))
    .unwrap()
}
fn idle() -> RuntimeSnapshot {
    serde_json::from_str(include_str!(
        "../../../contracts/fixtures/runtime-idle.json"
    ))
    .unwrap()
}
#[test]
fn node_fixture_round_trips_without_inline_credential() {
    let node = sample_node();
    node.validate().unwrap();
    let encoded = serde_json::to_value(&node).unwrap();
    let expected: Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/node-vless-reality.json"
    ))
    .unwrap();
    assert_eq!(encoded, expected);
    assert!(encoded.get("password").is_none());
    assert_eq!(encoded["credentialRef"], "secret:fixture-node-credential");
}
#[test]
fn unknown_fields_and_inline_secrets_are_rejected() {
    assert!(serde_json::from_str::<NodeProfile>(include_str!(
        "../../../contracts/fixtures/node-inline-secret.rejected.json"
    ))
    .is_err());
    let mut node = serde_json::to_value(sample_node()).unwrap();
    node["security"]["skipVerify"] = json!(true);
    assert!(serde_json::from_value::<NodeProfile>(node).is_err());
}
#[test]
fn secret_boundaries_require_explicit_exposure() {
    let bytes = SecretBytes::new(b"test-only-not-a-real-credential".to_vec());
    assert_eq!(format!("{bytes:?}"), "SecretBytes([REDACTED])");
    assert_eq!(bytes.expose(), b"test-only-not-a-real-credential");
    let reference = SecretRef::new("fixture-id").unwrap();
    assert_eq!(format!("{reference:?}"), "SecretRef([REDACTED])");
    assert_eq!(reference.to_string(), "[REDACTED]");
    assert!(serde_json::from_str::<SecretRef>("\"/etc/private-key\"").is_err());
    assert!(serde_json::from_str::<SecretRef>("\"secret:../private-key\"").is_err());
    assert_eq!(
        redact_untrusted("https://user:password@example.invalid/private?token=test"),
        "[REDACTED]"
    );
}
#[test]
fn revisions_never_overflow_javascript_exact_integer_range() {
    assert_eq!(Revision::ZERO.next().unwrap().get(), 1);
    assert!(Revision::new(MAX_WIRE_COUNTER).unwrap().next().is_none());
    assert!(serde_json::from_str::<Revision>("9007199254740992").is_err());
    assert!(serde_json::from_str::<Revision>("-1").is_err());
}
#[test]
fn newer_documents_cannot_be_lossily_overwritten() {
    let writable = CompatibilityRange {
        minimum: 1,
        maximum: 1,
    };
    assert_eq!(
        document_access(1, 1, 1, writable),
        DocumentAccess::ReadWrite
    );
    assert_eq!(document_access(2, 1, 1, writable), DocumentAccess::ReadOnly);
    assert_eq!(
        document_access(2, 2, 1, writable),
        DocumentAccess::Incompatible
    );
    assert_eq!(
        document_access(1, 2, 2, writable),
        DocumentAccess::Incompatible
    );
    assert!(!VersionPair { major: 1, minor: 0 }.accepts(VersionPair { major: 2, minor: 0 }));
}
#[test]
fn preset_inventory_is_complete_and_never_claims_certification() {
    let catalog = preset_catalog().unwrap();
    assert_eq!(catalog.presets.len(), 22);
    assert_eq!(
        catalog
            .presets
            .iter()
            .filter(|p| p.scope == PresetScope::RequiredPublicBaseline)
            .count(),
        21
    );
    let keys: std::collections::BTreeSet<_> = catalog.presets.iter().map(|p| p.key).collect();
    assert_eq!(keys.len(), 22);
    assert!(catalog
        .presets
        .iter()
        .all(|p| p.status == CapabilityStatus::Blocked));
    let ss = catalog
        .presets
        .iter()
        .find(|p| p.key == CapabilityKey::Shadowsocks)
        .unwrap();
    assert_eq!(ss.ciphers, ShadowsocksCipher::ALL);
    let direct = catalog
        .presets
        .iter()
        .find(|p| p.key == CapabilityKey::DirectForward)
        .unwrap();
    assert_eq!(direct.scope, PresetScope::ExplicitDecisionRequired);
}
#[test]
fn idle_or_stale_events_are_not_connection_success() {
    let snapshot = idle();
    assert!(!snapshot.connection_verified_at(1));
    let mut event: RuntimeEvent = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/event-resync.json"
    ))
    .unwrap();
    assert_eq!(
        event_disposition(&snapshot, &event),
        EventDisposition::Resync
    );
    event.generation = Revision::ZERO;
    event.sequence = Revision::ZERO;
    assert_eq!(
        event_disposition(&snapshot, &event),
        EventDisposition::IgnoreStale
    );
}
#[test]
fn vision_cannot_be_silently_mapped_to_h2() {
    let mut node = sample_node();
    node.transport = Transport::H2 {
        path: "/".into(),
        host: "example.invalid".into(),
    };
    assert_eq!(node.validate().unwrap_err().code, ErrorCode::ConfigInvalid);
}
#[test]
fn error_and_result_cannot_coexist() {
    let value = json!({"schemaVersion":1,"requestId":"req-1","operationId":null,"result":null,"error":null});
    assert!(serde_json::from_value::<ResultEnvelope<Value>>(value).is_err());
}
#[test]
fn config_fixture_is_valid_but_not_applied() {
    let config: ProductConfig = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/config-empty.json"
    ))
    .unwrap();
    config.validate().unwrap();
    assert!(config.listeners.is_empty());
}
#[test]
fn mutation_requires_revision_and_idempotency() {
    let request = CommandEnvelope {
        schema_version: 1,
        request_id: RequestId::new("req-1").unwrap(),
        idempotency_key: None,
        expected_revision: None,
        method: CommandMethod::Connect,
        payload: json!({"nodeId":"node-1"}),
    };
    assert_eq!(
        request.validate_metadata().unwrap_err().code,
        ErrorCode::ConfigInvalid
    );
}
#[test]
fn all_serialized_node_fields_exist_in_baseline_schema() {
    let schema: Value =
        serde_json::from_str(include_str!("../../../contracts/schema/v1.schema.json")).unwrap();
    let model = serde_json::to_value(sample_node()).unwrap();
    let fields = model
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let declared = schema["$defs"]["NodeProfile"]["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(fields, declared);
}

fn vision_listener() -> ServerListener {
    ServerListener {
        schema_version: 1,
        id: ListenerId::new("listener-example").unwrap(),
        name: "Example".into(),
        enabled: true,
        bind: BindAddress {
            address: "127.0.0.1".parse().unwrap(),
            port: 8443,
        },
        protocol: ServerProtocol::Proxy {
            protocol: Protocol::Vless {
                flow: Some(VlessFlow::XtlsRprxVision),
            },
            users: vec![ListenerUser {
                id: UserId::new("user-example").unwrap(),
                credential_ref: SecretRef::new("user-example").unwrap(),
                enabled: true,
            }],
        },
        transport: Transport::Tcp {},
        security: ServerSecurity::Reality {
            private_key_ref: SecretRef::new("reality-fixture").unwrap(),
            server_names: vec!["example.invalid".into()],
            short_ids: vec!["aabb".into()],
            handshake_target: Endpoint {
                host: "example.invalid".into(),
                port: 443,
            },
        },
        requirements: vec![CapabilityKey::VlessRealityVision],
    }
}
#[test]
fn server_vision_reality_and_user_constraints_are_not_client_only() {
    let mut listener = vision_listener();
    listener.validate().unwrap();
    listener.transport = Transport::H2 {
        path: "/".into(),
        host: "example.invalid".into(),
    };
    assert!(listener.validate().is_err());
    listener = vision_listener();
    if let ServerProtocol::Proxy { users, .. } = &mut listener.protocol {
        users.push(users[0].clone());
    }
    assert!(listener.validate().is_err());
    listener = vision_listener();
    if let ServerProtocol::Proxy { protocol, .. } = &mut listener.protocol {
        *protocol = Protocol::Vmess {
            cipher: VmessCipher::Auto,
            alter_id: 0,
        };
    }
    assert!(listener.validate().is_err());
    listener = vision_listener();
    if let ServerSecurity::Reality {
        handshake_target, ..
    } = &mut listener.security
    {
        handshake_target.port = 0;
    }
    assert!(listener.validate().is_err());
    listener = vision_listener();
    if let ServerSecurity::Reality { server_names, .. } = &mut listener.security {
        server_names.clear();
    }
    assert!(listener.validate().is_err());
}
#[test]
fn endpoint_rejects_urls_and_malformed_hosts_not_only_whitespace() {
    for host in [
        "user@example.invalid",
        "example.invalid?token=test",
        "example.invalid/path",
        "[::1]",
        "a..invalid",
        "-bad.invalid",
        "host#fragment",
    ] {
        assert!(
            Endpoint {
                host: host.into(),
                port: 443
            }
            .validate()
            .is_err(),
            "{host}"
        );
    }
    assert!(Endpoint {
        host: "2001:db8::1".into(),
        port: 443
    }
    .validate()
    .is_ok());
}
#[test]
fn connection_requires_probe_evidence_revision_and_freshness() {
    let mut snapshot = idle();
    let node_id = NodeId::new("node-example").unwrap();
    snapshot.desired = ConnectionIntent::Connected {
        node_id: node_id.clone(),
    };
    snapshot.node_id = Some(node_id);
    snapshot.phase = RuntimePhase::Connected;
    snapshot.config_revision = Some(Revision::new(1).unwrap());
    snapshot.desired_revision = snapshot.config_revision;
    snapshot.observed_at = 100;
    snapshot.valid_until = 1000;
    let passed = HealthObservation {
        status: ObservationStatus::Passed,
        observed_at: Some(100),
        evidence_id: Some(EvidenceId::new("synthetic-unit-evidence").unwrap()),
        detail_key: None,
    };
    snapshot.health = RuntimeHealth {
        core: passed.clone(),
        takeover: passed.clone(),
        tunnel: passed.clone(),
        dns: passed.clone(),
        ipv4: passed.clone(),
        ipv6: passed.clone(),
        forwarding: passed,
        required_probes: vec![HealthProbe::Dns, HealthProbe::Ipv4, HealthProbe::Ipv6],
    };
    assert!(snapshot.connection_verified_at(200));
    assert!(!snapshot.connection_verified_at(1000));
    snapshot.health.dns.status = ObservationStatus::Failed;
    assert!(!snapshot.connection_verified_at(200));
    snapshot.health.dns.status = ObservationStatus::Passed;
    snapshot.health.takeover.evidence_id = None;
    assert!(!snapshot.connection_verified_at(200));
    snapshot.desired_revision = Some(Revision::new(2).unwrap());
    assert!(!snapshot.connection_verified_at(200));
}

#[test]
fn explicit_tls_fingerprint_survives_the_canonical_round_trip() {
    let mut node = sample_node();
    node.protocol = Protocol::Trojan {};
    node.requirements = vec![CapabilityKey::TrojanTls];
    node.security = ClientSecurity::Tls {
        server_name: "example.invalid".into(),
        alpn: vec!["http/1.1".into()],
        trust: TlsTrust::System {},
        client_hello_fingerprint: Some("chrome".into()),
    };
    node.validate().unwrap();
    let json = serde_json::to_value(&node).unwrap();
    assert_eq!(json["security"]["clientHelloFingerprint"], "chrome");
    assert_eq!(serde_json::from_value::<NodeProfile>(json).unwrap(), node);
    // A structurally preserved choice is not proof that the pinned runtime
    // implements that ClientHello. Compiler/capability gating remains required.
}

#[test]
fn ambiguous_generic_fingerprint_field_is_not_a_trust_pin() {
    let mut node = serde_json::to_value(sample_node()).unwrap();
    node["security"]["fingerprint"] =
        json!("0000000000000000000000000000000000000000000000000000000000000000");
    assert!(serde_json::from_value::<NodeProfile>(node).is_err());
}

#[test]
fn pre_vault_preview_cannot_serialize_or_accept_secret_references() {
    let node = sample_node();
    let mut preview = ImportNodePreview {
        name: node.name,
        endpoint: node.endpoint,
        protocol: Protocol::Hysteria2 {
            obfuscation_ref: None,
        },
        transport: Transport::Quic {},
        security: ClientSecurity::Tls {
            server_name: "example.invalid".into(),
            alpn: vec!["h3".into()],
            trust: TlsTrust::System {},
            client_hello_fingerprint: None,
        },
        has_obfuscation: true,
    };
    preview.validate().unwrap();
    let mut value = serde_json::to_value(&preview).unwrap();
    value["protocol"]["obfuscationRef"] = json!("secret:not-for-preview");
    assert!(serde_json::from_value::<ImportNodePreview>(value).is_err());
    preview.protocol = Protocol::Hysteria2 {
        obfuscation_ref: Some(SecretRef::new("not-for-preview").unwrap()),
    };
    assert!(preview.validate().is_err());
    assert!(serde_json::to_value(&preview).is_err());
}

#[test]
fn empty_tagged_variants_reject_security_fields_instead_of_discarding_them() {
    fn rejects<T: serde::de::DeserializeOwned>(plain: Value) {
        assert!(serde_json::from_value::<T>(plain.clone()).is_ok());
        let mut malicious = plain;
        malicious["securityOverride"] = json!("disable-tls");
        assert!(serde_json::from_value::<T>(malicious).is_err());
    }
    for kind in ["tcp", "quic"] {
        rejects::<Transport>(json!({"kind":kind}));
    }
    for kind in ["trojan", "anytls", "socks5"] {
        rejects::<Protocol>(json!({"kind":kind}));
    }
    rejects::<ClientSecurity>(json!({"kind":"none"}));
    rejects::<ServerSecurity>(json!({"kind":"none"}));
    rejects::<TlsTrust>(json!({"kind":"system"}));
    rejects::<ConnectionIntent>(json!({"kind":"disconnected"}));
    rejects::<SafeArg>(json!({"kind":"count", "value":1}));
}

#[test]
fn new_draft_and_listener_mutations_cannot_omit_revision_or_idempotency() {
    for method in [
        CommandMethod::DraftReplace,
        CommandMethod::DraftDelete,
        CommandMethod::ListenerCreate,
        CommandMethod::ListenerReplace,
        CommandMethod::ListenerDelete,
    ] {
        let mut request = CommandEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: RequestId::new("request-test").unwrap(),
            idempotency_key: None,
            expected_revision: None,
            method,
            payload: json!({}),
        };
        assert!(request.validate_metadata().is_err());
        request.expected_revision = Some(Revision::ZERO);
        assert!(request.validate_metadata().is_err());
        request.idempotency_key = Some(IdempotencyKey::new("idempotency-test").unwrap());
        assert!(request.validate_metadata().is_ok());
    }
}
