use std::net::SocketAddr;
use vp_product_domain::{NodeId, Revision};
use vp_product_import::{mobile::{encode_ephemeral, observe_snapshot, MobileObservation}, parse, ImportFormat};

fn candidate(uri: &str) -> vp_product_import::ImportCandidate {
    let mut batch = parse(uri.as_bytes(), ImportFormat::NodeUri).unwrap();
    batch.entries.remove(0).candidate.unwrap()
}
fn dns() -> Vec<SocketAddr> { vec!["1.1.1.1:53".parse().unwrap()] }

#[test]
fn payload_preserves_typed_security_and_redacts_debug() {
    let item = candidate("trojan://synthetic-secret@proxy.example:443?sni=proxy.example");
    let payload = encode_ephemeral(item, NodeId::new("node-1").unwrap(), Revision::ZERO, &dns(), &dns()).unwrap();
    assert!(!format!("{payload:?}").contains("synthetic-secret"));
    let value: serde_json::Value = serde_json::from_str(payload.expose()).unwrap();
    assert_eq!(value["schemaVersion"], 2);
    assert_eq!(value["credential"]["kind"], "password");
    assert_eq!(value["credential"]["value"], "synthetic-secret");
    assert_eq!(value["node"]["security"]["trust"]["kind"], "system");
    assert_eq!(value["dns"]["user"]["route"], "selected_proxy");
    assert_eq!(value["dns"]["bootstrapServers"][0], "1.1.1.1:53");
}

#[test]
fn no_dns_or_unusable_addresses_fail_closed() {
    for servers in [vec![], vec!["0.0.0.0:53".parse().unwrap()], vec!["1.1.1.1:0".parse().unwrap()]] {
        let item = candidate("trojan://synthetic-secret@proxy.example:443");
        assert!(encode_ephemeral(item, NodeId::new("node-1").unwrap(), Revision::ZERO, &servers, &dns()).is_err());
    }
}

#[test]
fn uuid_is_preserved_and_obfuscation_is_not_silently_discarded() {
    let item = candidate("vmess://00000000-0000-4000-8000-000000000001@proxy.example:443?security=tls");
    let payload = encode_ephemeral(item, NodeId::new("node-2").unwrap(), Revision::ZERO, &dns(), &dns()).unwrap();
    let value: serde_json::Value = serde_json::from_str(payload.expose()).unwrap();
    assert_eq!(value["credential"]["kind"], "uuid");
    assert_eq!(value["credential"]["value"], "00000000-0000-4000-8000-000000000001");
    let item = candidate("hy2://synthetic@proxy.example?obfs=salamander&obfs-password=synthetic-obfs");
    assert!(encode_ephemeral(item, NodeId::new("node-3").unwrap(), Revision::ZERO, &dns(), &dns()).is_err());
}

#[test]
fn snapshots_are_bounded_fresh_and_never_prove_connectivity() {
    let snapshot = r#"{"schemaVersion":1,"nativeSnapshot":{"schemaVersion":1,"phase":"connected","observedAt":100,"validUntil":200}}"#;
    assert_eq!(observe_snapshot(snapshot, 150), MobileObservation::ReportedActive);
    assert_eq!(observe_snapshot(snapshot, 200), MobileObservation::Stale);
    assert_eq!(observe_snapshot(snapshot, 99), MobileObservation::Stale);
    let excessive = r#"{"schemaVersion":1,"phase":"idle","observedAt":100,"validUntil":1000000}"#;
    assert_eq!(observe_snapshot(excessive, 150), MobileObservation::Stale);
    assert_eq!(observe_snapshot("{}", 150), MobileObservation::Unavailable);
    assert_eq!(observe_snapshot(&"x".repeat(1_048_577), 150), MobileObservation::Unavailable);
    let failed = r#"{"schemaVersion":1,"phase":"failed","observedAt":100,"validUntil":200}"#;
    assert_eq!(observe_snapshot(failed, 150), MobileObservation::Failed);
}
