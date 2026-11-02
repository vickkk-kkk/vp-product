//! Negative contract tests; execution evidence is recorded under tools/core/evidence.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use vp_product_core_adapter::{capabilities, inspect_build, validate_listeners_json, CoreAdapter};
use vp_product_domain::{
    CapabilityStatus, Direction, ErrorCode, ObservationStatus, Platform, Revision, RuntimePhase,
};

#[test]
fn build_inspection_reports_linkage_not_certification() {
    let build = inspect_build().unwrap();
    assert_eq!(
        build.upstream_linked,
        cfg!(any(feature = "managed-runtime", feature = "mobile-ffi"))
    );
    assert_eq!(
        build.runtime_enabled,
        cfg!(any(feature = "managed-runtime", feature = "mobile-ffi"))
    );
    assert!(build.build.development);
    assert!(
        build.build.required_features.is_empty(),
        "v1 runtime prerequisites are not wire extensions"
    );
    let lock: serde_json::Value =
        serde_json::from_str(include_str!("../../../core-lock.json")).unwrap();
    assert_eq!(
        build.build.release.core_commit,
        lock["upstream"]["commit"].as_str().unwrap()
    );
    assert!(build.build.release.patchset_hash.is_some());
    assert!(build.build.release.evidence_manifest_hash.is_none());
}

#[test]
fn neither_direction_is_certified_by_presence_in_catalog() {
    for direction in [Direction::Inbound, Direction::Outbound] {
        let descriptors = capabilities(Platform::LinuxService, direction).unwrap();
        assert!(!descriptors.is_empty());
        for descriptor in descriptors {
            assert_eq!(descriptor.direction, direction);
            assert_eq!(descriptor.status, CapabilityStatus::Blocked);
            assert!(descriptor.evidence_ids.is_empty());
            descriptor.validate_claim().unwrap();
        }
    }
}

#[test]
fn start_and_reload_never_return_false_ready() {
    let mut adapter = CoreAdapter::new("test-instance".into(), 1).unwrap();
    let error = adapter.start(&[], Revision::ZERO, 2).unwrap_err();
    assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
    let snapshot = adapter.snapshot();
    assert_eq!(snapshot.phase, RuntimePhase::Failed);
    assert_eq!(snapshot.health.core.status, ObservationStatus::NotRun);
    assert_eq!(snapshot.health.forwarding.status, ObservationStatus::NotRun);
    assert!(!snapshot.connection_verified());
    assert!(adapter.apply_route_snapshot(Revision::ZERO).is_err());
    adapter.stop(Revision::ZERO, 3).unwrap();
    assert_eq!(adapter.snapshot().phase, RuntimePhase::Idle);
    assert_eq!(
        adapter.snapshot().health.core.status,
        ObservationStatus::NotRun
    );
}

#[test]
fn generation_conflict_does_not_mutate_observation() {
    let mut adapter = CoreAdapter::new("test-instance".into(), 1).unwrap();
    let before = adapter.snapshot();
    let error = adapter
        .start(&[], Revision::new(1).unwrap(), 2)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RevisionConflict);
    assert_eq!(before, adapter.snapshot());
}

#[test]
fn invalid_input_is_rejected_without_echoing_secret_data() {
    let input = br#"[{"private-password":"do-not-leak-this-value"}]"#;
    let error = validate_listeners_json(input).unwrap_err();
    assert_eq!(error.code, ErrorCode::ConfigInvalid);
    assert!(!format!("{error:?}").contains("do-not-leak"));
    assert_eq!(
        validate_listeners_json(&[0xff]).unwrap_err().code,
        ErrorCode::InvalidUtf8
    );
    let oversized = vec![b' '; (1 << 20) + 1];
    assert_eq!(
        validate_listeners_json(&oversized).unwrap_err().code,
        ErrorCode::InputTooLarge
    );
}

#[test]
fn empty_config_is_not_runtime_eligibility() {
    let report = validate_listeners_json(b"[]").unwrap();
    assert!(!report.runtime_eligible);
    assert!(report
        .issues
        .iter()
        .any(|e| e.code == ErrorCode::CapabilityUnavailable));
}

fn listener_fixture() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 1, "id": "listener-a", "name": "Local test", "enabled": true,
        "bind": {"address": "127.0.0.1", "port": 30001},
        "protocol": {"kind": "proxy", "protocol": {"kind": "vless", "flow": null},
            "users": [{"id": "user-a", "credentialRef": "secret:test-credential", "enabled": true}]},
        "transport": {"kind": "tcp"}, "security": {"kind": "none"}, "requirements": []
    })
}

#[test]
fn unknown_listener_field_is_not_silently_discarded() {
    let valid = listener_fixture();
    let valid_bytes = serde_json::to_vec(&vec![valid.clone()]).unwrap();
    assert!(validate_listeners_json(&valid_bytes).is_ok());
    let mut unknown = valid.clone();
    unknown["ignoredSecretFlag"] = serde_json::json!("must-not-leak");
    let error = validate_listeners_json(&serde_json::to_vec(&vec![unknown]).unwrap()).unwrap_err();
    assert_eq!(error.code, ErrorCode::ConfigInvalid);
    assert!(!format!("{error:?}").contains("must-not-leak"));
    let mut nested = valid;
    nested["transport"]["securityOverride"] = serde_json::json!("disable-tls");
    assert!(validate_listeners_json(&serde_json::to_vec(&vec![nested]).unwrap()).is_err());
}

#[test]
fn duplicate_ids_and_conflicting_wildcard_ports_are_rejected() {
    let first = listener_fixture();
    assert!(validate_listeners_json(
        &serde_json::to_vec(&vec![first.clone(), first.clone()]).unwrap()
    )
    .is_err());
    let mut second = first.clone();
    second["id"] = serde_json::json!("listener-b");
    second["name"] = serde_json::json!("Other test");
    second["bind"]["address"] = serde_json::json!("0.0.0.0");
    assert!(validate_listeners_json(&serde_json::to_vec(&vec![first, second]).unwrap()).is_err());
}

#[test]
fn unsupported_transport_and_security_have_specific_field_diagnostics() {
    let mut listener = listener_fixture();
    listener["transport"] =
        serde_json::json!({"kind":"ws", "path":"/proxy", "host":null,"earlyData":null});
    listener["security"] = serde_json::json!({"kind":"tls", "certificateRef":"cert-a", "privateKeyRef":"secret:key-a", "alpn":["http/1.1"]});
    let report = validate_listeners_json(&serde_json::to_vec(&vec![listener]).unwrap()).unwrap();
    assert!(!report.runtime_eligible);
    assert!(report.issues.iter().any(|e| e.field_path.as_deref()
        == Some("listeners[0].transport")
        && e.code == ErrorCode::ConfigUnsupported));
    assert!(report
        .issues
        .iter()
        .any(|e| e.field_path.as_deref() == Some("listeners[0].security")
            && e.code == ErrorCode::ConfigUnsupported));
}
