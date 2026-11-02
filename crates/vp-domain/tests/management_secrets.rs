// Assertions deliberately fail loudly on synthetic contract fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use serde_json::json;
use vp_product_domain::*;

fn publication() -> serde_json::Value {
    json!({"schemaVersion":1,"id":"publication-fixture","revision":1,
        "name":"Fixture","enabled":true,"format":"uri_list","sourceRevision":1,
        "sources":[{"listenerId":"listener-fixture","userId":"user-fixture",
            "endpoint":{"host":"127.0.0.1","port":18081},"clientSecurity":{"kind":"none"}}],
        "createdAt":1000,"updatedAt":1000,
        "token":{"state":"not_issued","version":0,"issuedAt":null,"expiresAt":null},
        "lastSuccessfulReadAt":null})
}
#[test]
fn explicit_confirmations_cannot_decode_false_or_missing() {
    for bad in [
        json!({"confirmGenerate":false,"kind":{"kind":"uuid"}}),
        json!({"kind":{"kind":"uuid"}}),
        json!({"confirmGenerate":"true","kind":{"kind":"uuid"}}),
    ] {
        assert!(serde_json::from_value::<CredentialCreatePayload>(bad).is_err());
    }
    assert!(ExplicitConfirmation::try_from(false).is_err());
    let confirmed: CredentialCreatePayload = serde_json::from_value(json!({
        "confirmGenerate":true,"kind":{"kind":"uuid"}}))
    .unwrap();
    assert!(confirmed.confirm_generate.is_confirmed());
    let schema = serde_json::to_value(schemars::schema_for!(ExplicitConfirmation)).unwrap();
    assert_eq!(schema["type"], "boolean");
    assert_eq!(schema["const"], true);
}
#[test]
fn every_new_mutation_requires_cas_and_idempotency() {
    for method in [
        CommandMethod::CredentialCreate,
        CommandMethod::CredentialRetire,
        CommandMethod::PublicationCreate,
        CommandMethod::PublicationReplace,
        CommandMethod::PublicationTokenIssue,
        CommandMethod::PublicationTokenRevoke,
    ] {
        let mut request = CommandEnvelope {
            schema_version: 1,
            request_id: RequestId::new("fixture-request").unwrap(),
            method,
            idempotency_key: None,
            expected_revision: None,
            payload: json!({}),
        };
        assert!(request.validate_metadata().is_err());
        request.idempotency_key = Some(IdempotencyKey::new("fixture-key").unwrap());
        assert!(request.validate_metadata().is_err());
        request.expected_revision = Some(Revision::ZERO);
        request.validate_metadata().unwrap();
        request.idempotency_key = None;
        assert!(request.validate_metadata().is_err());
    }
}
#[test]
fn publication_nullable_outputs_are_required_and_strict() {
    let original = publication();
    let good: PublicationSummary = serde_json::from_value(original.clone()).unwrap();
    good.validate().unwrap();
    for name in ["lastSuccessfulReadAt", "token"] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(name);
        assert!(serde_json::from_value::<PublicationSummary>(value).is_err());
    }
    for name in ["issuedAt", "expiresAt"] {
        let mut value = original.clone();
        value["token"].as_object_mut().unwrap().remove(name);
        assert!(serde_json::from_value::<PublicationSummary>(value).is_err());
    }
    let mut value = original.clone();
    value["token"]["rawToken"] = json!("fixture-not-a-secret");
    assert!(serde_json::from_value::<PublicationSummary>(value).is_err());
    let mut value = original;
    value["subscriptionUrl"] = json!("https://example.invalid/");
    assert!(serde_json::from_value::<PublicationSummary>(value).is_err());
}
#[test]
fn publication_validation_rejects_empty_duplicate_sources_and_invalid_token_state() {
    for change in 0..6 {
        let mut value = publication();
        match change {
            0 => value["sources"] = json!([]),
            1 => value["sources"]
                .as_array_mut()
                .unwrap()
                .push(publication()["sources"][0].clone()),
            2 => value["sourceRevision"] = json!(0),
            3 => value["token"]["state"] = json!("active"),
            4 => value["name"] = json!("\n"),
            _ => value["updatedAt"] = json!(9007199254740992_u64),
        }
        let decoded: PublicationSummary = serde_json::from_value(value).unwrap();
        assert!(decoded.validate().is_err());
    }
}
#[test]
fn credential_kind_is_not_an_inline_secret_channel() {
    for kind in ["uuid", "password", "username_password", "uuid_password"] {
        assert!(serde_json::from_value::<NodeCredentialKind>(json!({"kind":kind})).is_ok());
        assert!(serde_json::from_value::<NodeCredentialKind>(
            json!({"kind":kind,"password":"synthetic"})
        )
        .is_err());
    }
    let summary = CredentialSummary {
        schema_version: 1,
        id: CredentialId::new("fixture").unwrap(),
        revision: Revision::new(1).unwrap(),
        secret_ref: SecretRef::new("synthetic-reference").unwrap(),
        kind: NodeCredentialKind::Uuid {},
        created_at: 0,
        state: CredentialState::Available,
        display_key: CredentialDisplayKey::Managed,
    };
    summary.validate().unwrap();
    let mut retired = summary;
    retired.state = CredentialState::Retired;
    assert!(retired.validate().is_err());
    retired.display_key = CredentialDisplayKey::Retired;
    retired.validate().unwrap();
}
#[test]
fn sensitive_response_is_explicit_bounded_and_not_write_only() {
    assert!(SensitiveResponseText::new(String::new()).is_err());
    assert!(SensitiveResponseText::new("x".repeat(8193)).is_err());
    let text = SensitiveResponseText::new("synthetic-sensitive-fixture".into()).unwrap();
    assert_eq!(
        serde_json::to_value(text).unwrap(),
        "synthetic-sensitive-fixture"
    );
    let schema = serde_json::to_value(schemars::schema_for!(SensitiveResponseText)).unwrap();
    assert_eq!(schema["x-sensitive"], true);
    assert!(schema.get("writeOnly").is_none());
    assert_eq!(
        serde_json::to_value(ErrorCode::SecretResultUnavailable).unwrap(),
        "SECRET_RESULT_UNAVAILABLE"
    );
}
