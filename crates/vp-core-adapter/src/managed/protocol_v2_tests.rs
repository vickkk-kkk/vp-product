#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::managed::v2_test_support::{inputs, recipe};
use std::io::Cursor;
fn envelope(start: serde_json::Value) -> Vec<u8> {
    let mut value=serde_json::to_vec(&serde_json::json!({"version":2,"kind":"prepare_server_v2","instance":"fixture-instance","generation":1,"startServerV2":start,"drainMs":null})).unwrap();
    value.push(b'\n');
    value
}
fn start() -> serde_json::Value {
    serde_json::json!({"schemaVersion":2,"recipeJson":serde_json::to_string(&recipe(19231)).unwrap(),"startupMs":1000,"materials":[{"kind":"credential","reference":"secret:fixture-credential","value":b"12345678-1234-1234-1234-123456789abc".to_vec()}]})
}
#[test]
fn numeric_material_roundtrip_has_no_plaintext_string_and_preserves_exact_bytes() {
    let source = recipe(19231);
    let inputs = inputs();
    let instance = WorkerInstanceV2::new("fixture-instance").unwrap();
    let frame = encode_prepare(&instance, 7, &source, &inputs, 1000).unwrap();
    assert!(!frame
        .0
        .windows(36)
        .any(|bytes| bytes == b"12345678-1234-1234-1234-123456789abc"));
    let decoded = decode_request(&frame.0).unwrap();
    assert_eq!(decoded.generation, 7);
    let (decoded_recipe, decoded_inputs, _) = decoded
        .start_server_v2
        .unwrap()
        .into_materialized()
        .unwrap();
    assert_eq!(decoded_recipe, source);
    assert_eq!(
        decoded_inputs.credentials[&SecretRef::new("fixture-credential").unwrap()].expose(),
        inputs.credentials[&SecretRef::new("fixture-credential").unwrap()].expose()
    );
}
#[test]
fn v1_wrong_versions_duplicate_fields_and_unknown_material_never_echo_payload() {
    let marker = "NEVER-ECHO-UNTRUSTED-MATERIAL";
    for bytes in [b"{\"version\":1,\"kind\":\"start\",\"generation\":1}\n".to_vec(),
        b"{\"version\":2,\"version\":2,\"kind\":\"negotiate_server_v2\",\"instance\":\"fixture\",\"generation\":0}\n".to_vec(),
        b"{\"version\":2,\"kind\":\"negotiate_server_v2\",\"instance\":\"fixture\",\"generation\":0,\"startServerV2\":null,\"startServerV2\":null}\n".to_vec(),
        format!("{{\"version\":2,\"kind\":\"negotiate_server_v2\",\"instance\":\"fixture\",\"generation\":0,\"{marker}\":\"{marker}\"}}\n").into_bytes()] {
        let failure=match decode_request(&bytes){Ok(_)=>panic!("invalid request accepted"),Err(failure)=>failure};
        let response=encode_response(&ResponseV2::FailedServerV2 {failure}).unwrap();
        assert!(!String::from_utf8_lossy(&response.0).contains(marker));assert!(!format!("{failure:?}").contains(marker));
    }
    let wrong = b"{\"version\":3,\"kind\":\"negotiate_server_v2\",\"instance\":\"fixture\",\"generation\":0}\n";
    assert!(matches!(
        decode_request(wrong),
        Err(Failure::ProtocolViolation)
    ));
    let mut wrong_payload = start();
    wrong_payload["schemaVersion"] = serde_json::json!(3);
    assert!(decode_request(&envelope(wrong_payload))
        .unwrap()
        .start_server_v2
        .unwrap()
        .into_materialized()
        .is_err());
    let mut unsupported = start();
    unsupported["materials"][0]["value"] = serde_json::json!(marker);
    assert!(decode_request(&envelope(unsupported)).is_err());
    let mut unknown = start();
    unknown["materials"][0]["password"] = serde_json::json!(marker);
    assert!(decode_request(&envelope(unknown)).is_err());
}
#[test]
fn duplicate_references_kind_alias_and_partial_decode_fail_closed() {
    let mut duplicate = start();
    let item = duplicate["materials"][0].clone();
    duplicate["materials"].as_array_mut().unwrap().push(item);
    assert!(decode_request(&envelope(duplicate))
        .unwrap()
        .start_server_v2
        .unwrap()
        .into_materialized()
        .is_err());
    let mut alias = inputs();
    alias.private_keys.insert(
        SecretRef::new("fixture-credential").unwrap(),
        SecretBytes::new(vec![1]),
    );
    assert!(validate_material_budget(&alias).is_err());
    let duplicate_value = String::from_utf8(envelope(start()))
        .unwrap()
        .replace("\"value\":[", "\"value\":[1],\"value\":[");
    assert!(decode_request(duplicate_value.as_bytes()).is_err());
}
#[test]
fn budgets_reject_raw_aggregate_record_count_and_escaped_serialized_size() {
    assert!(bounded_json(&"\0", 7).is_err());
    assert_eq!(bounded_json(&"\0", 8).unwrap().len(), 8);
    let mut oversized = inputs();
    oversized.credentials.insert(
        SecretRef::new("too-large").unwrap(),
        SecretBytes::new(vec![1; 4097]),
    );
    assert!(validate_material_budget(&oversized).is_err());
    let mut records = ServerInputsV2::default();
    for index in 0..=MAX_MATERIAL_RECORDS_V2 {
        records.credentials.insert(
            SecretRef::new(&format!("entry-{index}")).unwrap(),
            SecretBytes::new(vec![1]),
        );
    }
    assert!(validate_material_budget(&records).is_err());
    let mut aggregate = ServerInputsV2::default();
    for index in 0..17 {
        aggregate.certificate_chains.insert(
            CertificateId::new(format!("certificate-{index}")).unwrap(),
            SecretBytes::new(vec![1; MAX_CERTIFICATE_BYTES_V2]),
        );
    }
    assert!(validate_material_budget(&aggregate).is_err());
    let mut huge = start();
    huge["recipeJson"] = serde_json::json!("x".repeat(MAX_RECIPE_JSON_V2 + 1));
    assert!(decode_request(&envelope(huge)).is_err());
}
#[test]
fn streaming_reader_is_bounded_preserves_frame_boundaries_and_scrubs_consumed_read_ahead() {
    let mut reader = FrameReaderV2::new(Cursor::new(b"first\nsecond\n"));
    assert_eq!(&*reader.read_frame(6).unwrap().unwrap(), b"first\n");
    assert!(reader.buffer[..reader.start].iter().all(|b| *b == 0));
    assert_eq!(&*reader.read_frame(7).unwrap().unwrap(), b"second\n");
    assert!(reader.read_frame(1).unwrap().is_none());
    assert!(FrameReaderV2::new(Cursor::new(b"truncated"))
        .read_frame(100)
        .is_err());
    assert!(FrameReaderV2::new(Cursor::new(b"longer-than-bound\n"))
        .read_frame(3)
        .is_err());
}
#[test]
fn command_shape_never_ignores_start_material_on_control_requests() {
    let mut bytes = envelope(start());
    let value = String::from_utf8(bytes)
        .unwrap()
        .replace("prepare_server_v2", "snapshot_server_v2");
    bytes = value.into_bytes();
    assert!(decode_request(&bytes).is_err());
    let bytes=b"{\"version\":2,\"kind\":\"stop_server_v2\",\"instance\":\"fixture\",\"generation\":1,\"drainMs\":5001}\n";
    assert!(decode_request(bytes).is_err());
    assert!(WorkerInstanceV2::new(&"x".repeat(65)).is_err());
    assert!(WorkerInstanceV2::new("unsafe instance").is_err());
}
