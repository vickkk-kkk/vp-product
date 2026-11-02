#![allow(clippy::unwrap_used, clippy::expect_used)]
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use vp_product_api::*;
use vp_product_control::{ControlService, SystemClock, UnavailableRuntime, UnavailableSystem};
use vp_product_domain::SecretBytes;

const TOKEN: &str = "synthetic-test-only-not-a-deployed-credential-0123456789";
struct Fixture {
    router: Router,
    worker: Arc<OperationWorker>,
    handle: tokio::task::JoinHandle<()>,
    _root: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_executors(Arc::new(UnavailableRuntime), Arc::new(UnavailableSystem)).await
    }
    async fn with_executors(
        runtime: Arc<dyn vp_product_control::RuntimeExecutor>,
        system: Arc<dyn vp_product_control::SystemExecutor>,
    ) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = vp_product_storage::SqliteStore::open(root.path()).unwrap();
        let control = Arc::new(ControlService::new(
            Arc::new(store),
            runtime,
            system,
            Arc::new(SystemClock),
        ));
        control.recover().unwrap();
        let (worker, handle) = OperationWorker::start(control.clone());
        let state = ApiState::new(
            control,
            worker.clone(),
            BootstrapCredential::new("tester", SecretBytes::new(TOKEN.as_bytes().to_vec()))
                .unwrap(),
            SecurityPolicy::new("https://localhost:9443").unwrap(),
        )
        .unwrap();
        Self {
            router: router(state),
            worker,
            handle,
            _root: root,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Value,
        auth: Option<&(String, String)>,
        extra: &[(&str, &str)],
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost:9443")
            .header("origin", "https://localhost:9443")
            .header("content-type", "application/json");
        if let Some((cookie, csrf)) = auth {
            builder = builder.header("cookie", cookie).header("x-vp-csrf", csrf);
        }
        for (name, value) in extra {
            builder = builder.header(*name, *value);
        }
        let response = self
            .router
            .clone()
            .oneshot(
                builder
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap();
        (status, headers, value)
    }
    async fn login(&self) -> (String, String) {
        let (status, headers, body) = self
            .request(
                "POST",
                "/api/v1/auth/login",
                json!({"username":"tester","password":TOKEN,"secondFactor":null}),
                None,
                &[],
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let cookie = headers["set-cookie"].to_str().unwrap();
        for flag in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/api/v1"] {
            assert!(cookie.contains(flag));
        }
        (
            cookie.split(';').next().unwrap().to_owned(),
            body["result"]["csrfToken"].as_str().unwrap().to_owned(),
        )
    }
    async fn finish(self) {
        self.worker.stop();
        self.handle.await.unwrap();
    }
}
fn config() -> Value {
    json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"listeners":[],"subscriptions":[]})
}
fn command(method: &str, key: &str, rev: u64, payload: Value) -> Value {
    json!({"schemaVersion":1,"requestId":"test-request","idempotencyKey":key,"expectedRevision":rev,"method":method,"payload":payload})
}
#[tokio::test]
async fn auth_origin_host_csrf_rotation_explicit_unavailable() {
    let f = Fixture::new().await;
    assert_eq!(
        f.request("GET", "/api/v1/build", Value::Null, None, &[])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let auth = f.login().await;
    assert_eq!(
        f.request("GET", "/api/v1/build", Value::Null, Some(&auth), &[])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.request(
            "GET",
            "/api/v1/build",
            Value::Null,
            Some(&auth),
            &[("host", "attacker.invalid")]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request(
            "GET",
            "/api/v1/build?token=forbidden",
            Value::Null,
            Some(&auth),
            &[]
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/auth/logout",
            Value::Null,
            Some(&auth),
            &[("origin", "https://evil.invalid")]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let wrong = (auth.0.clone(), "wrong-token".into());
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/auth/logout",
            Value::Null,
            Some(&wrong),
            &[]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    for (header, value) in [("cookie", auth.0.as_str()), ("origin", "null")] {
        assert_eq!(
            f.request(
                "GET",
                "/api/v1/build",
                Value::Null,
                Some(&auth),
                &[(header, value)]
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let session = f
        .request("GET", "/api/v1/auth/session", Value::Null, Some(&auth), &[])
        .await;
    assert_eq!(session.2["result"]["csrfToken"], auth.1);
    let new = f.login().await;
    assert_ne!(new.0, auth.0);
    assert_eq!(
        f.request("GET", "/api/v1/build", Value::Null, Some(&auth), &[])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.request("GET", "/api/v1/events", Value::Null, Some(&new), &[])
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        f.request("POST", "/api/v1/auth/logout", Value::Null, Some(&new), &[])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.request("GET", "/api/v1/auth/session", Value::Null, Some(&new), &[])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    f.finish().await;
}
#[tokio::test]
async fn drafts_cas_strict_json_idempotency_no_false_runtime() {
    let f = Fixture::new().await;
    let auth = f.login().await;
    let create = command("draft_create", "create", 0, config());
    let (status, headers, first) = f
        .request("POST", "/api/v1/drafts", create.clone(), Some(&auth), &[])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["etag"], "\"1\"");
    assert_eq!(
        f.request("POST", "/api/v1/drafts", create, Some(&auth), &[])
            .await
            .2,
        first
    );
    let id = first["result"]["id"].as_str().unwrap();
    let path = format!("/api/v1/drafts/{id}");
    assert_eq!(
        f.request(
            "PUT",
            &path,
            command("draft_replace", "edit", 1, config()),
            Some(&auth),
            &[]
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    let updated = f
        .request(
            "PUT",
            &path,
            command("draft_replace", "edit", 1, config()),
            Some(&auth),
            &[("if-match", "\"1\"")],
        )
        .await;
    assert_eq!(updated.0, StatusCode::OK);
    assert_eq!(updated.2["result"]["revision"], 2);
    assert_eq!(
        f.request(
            "PUT",
            &path,
            command("draft_replace", "stale", 1, config()),
            Some(&auth),
            &[("if-match", "\"1\"")]
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        f.request(
            "PUT",
            &path,
            command("draft_replace", "edit", 2, config()),
            Some(&auth),
            &[("if-match", "\"2\"")]
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let mut invalid = config();
    invalid["password"] = json!("must-not-appear-in-errors");
    let rejected = f
        .request(
            "PUT",
            &path,
            command("draft_replace", "invalid", 2, invalid),
            Some(&auth),
            &[("if-match", "\"2\"")],
        )
        .await;
    assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
    assert!(!rejected.2.to_string().contains("must-not-appear"));
    let validate = f
        .request(
            "POST",
            &format!("{path}/validate"),
            command("validate", "validate", 2, json!({})),
            Some(&auth),
            &[],
        )
        .await;
    assert_eq!(validate.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(validate.2["error"]["code"], "CAPABILITY_UNAVAILABLE");
    let plan = f
        .request(
            "POST",
            "/api/v1/plans",
            command("plan_create", "plan", 0, json!({"draftId":id})),
            Some(&auth),
            &[],
        )
        .await;
    assert_eq!(plan.0, StatusCode::SERVICE_UNAVAILABLE);
    let snapshot = f
        .request("GET", "/api/v1/snapshot", Value::Null, Some(&auth), &[])
        .await;
    assert_eq!(snapshot.2["result"]["desiredRevision"], 0);
    assert!(snapshot.2["result"]["observedRevision"].is_null());
    assert_eq!(snapshot.2["result"]["operations"], json!([]));
    let delete = command("draft_delete", "delete", 2, json!({}));
    assert_eq!(
        f.request(
            "DELETE",
            &path,
            delete.clone(),
            Some(&auth),
            &[("if-match", "\"2\"")]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.request(
            "DELETE",
            &path,
            delete,
            Some(&auth),
            &[("if-match", "\"2\"")]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.request("GET", &path, Value::Null, Some(&auth), &[])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    f.finish().await;
}
#[tokio::test]
async fn login_rate_limit_and_no_default_credential() {
    assert!(BootstrapCredential::new("admin", SecretBytes::new(b"admin".to_vec())).is_err());
    assert!(SecurityPolicy::new("http://public.example").is_err());
    let f = Fixture::new().await;
    for _ in 0..10 {
        let response = f
            .request(
                "POST",
                "/api/v1/auth/login",
                json!({"username":"tester","password":"bad","secondFactor":null}),
                None,
                &[],
            )
            .await;
        assert_eq!(response.0, StatusCode::UNAUTHORIZED);
        assert!(!response.2.to_string().contains("bad"));
    }
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/auth/login",
            json!({"username":"tester","password":TOKEN,"secondFactor":null}),
            None,
            &[]
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    f.finish().await;
}

#[tokio::test]
async fn listener_crud_is_only_a_draft_no_bind_side_effect() {
    let f = Fixture::new().await;
    let auth = f.login().await;
    let created = f
        .request(
            "POST",
            "/api/v1/drafts",
            command("draft_create", "create", 0, config()),
            Some(&auth),
            &[],
        )
        .await;
    let id = created.2["result"]["id"].as_str().unwrap();
    let path = format!("/api/v1/drafts/{id}/listeners");
    let listener = json!({"schemaVersion":1,"id":"listener-one","name":"Draft-only SOCKS","enabled":true,"bind":{"address":"127.0.0.1","port":34567},"protocol":{"kind":"proxy","protocol":{"kind":"socks5"},"users":[{"id":"test-user","credentialRef":"secret:synthetic-reference","enabled":true}]},"transport":{"kind":"tcp"},"security":{"kind":"none"},"requirements":["preset.socks-auth"]});
    let added = f
        .request(
            "POST",
            &path,
            command("listener_create", "add", 1, listener.clone()),
            Some(&auth),
            &[("if-match", "\"1\"")],
        )
        .await;
    assert_eq!(added.0, StatusCode::OK);
    assert_eq!(
        added.2["result"]["config"]["listeners"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let mut updated = listener;
    updated["bind"]["port"] = json!(34568);
    let detail = format!("{path}/listener-one");
    assert_eq!(
        f.request(
            "PUT",
            &detail,
            command("listener_replace", "replace", 2, updated),
            Some(&auth),
            &[("if-match", "\"2\"")]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.request("GET", &path, Value::Null, Some(&auth), &[])
            .await
            .2["result"][0]["bind"]["port"],
        34568
    );
    assert_eq!(
        f.request(
            "DELETE",
            &detail,
            command("listener_delete", "delete", 3, json!({})),
            Some(&auth),
            &[("if-match", "\"3\"")]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.request("GET", &path, Value::Null, Some(&auth), &[])
            .await
            .2["result"],
        json!([])
    );
    assert!(f
        .request("GET", "/api/v1/config", Value::Null, Some(&auth), &[])
        .await
        .2["result"]["config"]
        .is_null());
    f.finish().await;
}

// Only an isolated test double. It can validate an empty test plan and fail at
// staging, never report runtime activation/authentication/forwarding success.
struct StagingFailure;
impl vp_product_control::RuntimeExecutor for StagingFailure {
    fn validate(
        &self,
        config: &vp_product_domain::ProductConfig,
        release: &vp_product_domain::ReleaseIdentity,
        _: Option<&vp_product_control::RevisionRecord>,
    ) -> Result<vp_product_control::ValidationReceipt, vp_product_control::ControlError> {
        use vp_product_control::*;
        Ok(ValidationReceipt {
            config_digest: ContentDigest::of("vp.product-config.v1", config)?,
            release_digest: ContentDigest::of("vp.release-identity.v1", release)?,
            artifact_digest: ContentDigest::bytes(b"isolated-test"),
            impact: RestartImpact::ControlledRestart,
            required_health: std::collections::BTreeSet::from([HealthCheck::Process]),
        })
    }
    fn stage(
        &self,
        _: &vp_product_domain::OperationId,
        _: &vp_product_control::ChangePlan,
        _: &vp_product_control::CancellationToken,
    ) -> Result<(), vp_product_control::ControlError> {
        Err(vp_product_control::ControlError::ExecutorFailed)
    }
    fn activate(
        &self,
        _: &vp_product_domain::OperationId,
        _: &vp_product_control::ChangePlan,
        _: Option<&vp_product_control::RevisionRecord>,
    ) -> Result<vp_product_control::RuntimeActivation, vp_product_control::ControlError> {
        Err(vp_product_control::ControlError::ExecutorUnavailable)
    }
    fn verify(
        &self,
        _: &vp_product_domain::OperationId,
        _: &vp_product_control::ChangePlan,
    ) -> Result<vp_product_control::RuntimeHealth, vp_product_control::ControlError> {
        Err(vp_product_control::ControlError::ExecutorUnavailable)
    }
    fn stop_candidate(
        &self,
        _: &vp_product_domain::OperationId,
        _: &vp_product_control::ChangePlan,
    ) -> Result<(), vp_product_control::ControlError> {
        Err(vp_product_control::ControlError::ExecutorUnavailable)
    }
    fn restore_previous(
        &self,
        _: &vp_product_domain::OperationId,
        _: Option<&vp_product_control::RevisionRecord>,
    ) -> Result<(), vp_product_control::ControlError> {
        Err(vp_product_control::ControlError::ExecutorUnavailable)
    }
    fn verify_previous(
        &self,
        _: &vp_product_domain::OperationId,
        _: Option<&vp_product_control::RevisionRecord>,
    ) -> Result<(), vp_product_control::ControlError> {
        Err(vp_product_control::ControlError::ExecutorUnavailable)
    }
    fn discard_stage(
        &self,
        _: &vp_product_domain::OperationId,
    ) -> Result<(), vp_product_control::ControlError> {
        Ok(())
    }
}
struct EmptyTestSystem;
impl vp_product_control::SystemExecutor for EmptyTestSystem {
    fn inspect(
        &self,
        r: &[vp_product_control::ResourceChange],
    ) -> Result<Vec<vp_product_control::ResourceObservation>, vp_product_control::ControlError>
    {
        assert!(r.is_empty());
        Ok(vec![])
    }
    fn capture(
        &self,
        _: &vp_product_domain::OperationId,
        _: &[vp_product_control::ResourceChange],
    ) -> Result<vp_product_control::ResourceSnapshot, vp_product_control::ControlError> {
        Err(vp_product_control::ControlError::ExecutorUnavailable)
    }
    fn apply(
        &self,
        _: &vp_product_domain::OperationId,
        _: &vp_product_control::ChangePlan,
        _: &vp_product_control::ResourceSnapshot,
    ) -> Result<(), vp_product_control::ControlError> {
        Err(vp_product_control::ControlError::ExecutorUnavailable)
    }
    fn restore(
        &self,
        _: &vp_product_domain::OperationId,
        _: &vp_product_control::ChangePlan,
        _: &vp_product_control::ResourceSnapshot,
    ) -> Result<(), vp_product_control::ControlError> {
        Err(vp_product_control::ControlError::ExecutorUnavailable)
    }
}
#[tokio::test]
async fn submit_retry_worker_failure_and_operation_reconciliation() {
    let f = Fixture::with_executors(Arc::new(StagingFailure), Arc::new(EmptyTestSystem)).await;
    let auth = f.login().await;
    let draft = f
        .request(
            "POST",
            "/api/v1/drafts",
            command("draft_create", "create", 0, config()),
            Some(&auth),
            &[],
        )
        .await
        .2;
    let plan = f
        .request(
            "POST",
            "/api/v1/plans",
            command(
                "plan_create",
                "plan",
                0,
                json!({"draftId":draft["result"]["id"]}),
            ),
            Some(&auth),
            &[],
        )
        .await;
    assert_eq!(plan.0, StatusCode::OK);
    let path = format!(
        "/api/v1/plans/{}/apply",
        plan.2["result"]["id"].as_str().unwrap()
    );
    let apply = command(
        "plan_apply",
        "apply",
        0,
        json!({"planHash":plan.2["result"]["planHash"],"confirmed":true}),
    );
    let accepted = f
        .request("POST", &path, apply.clone(), Some(&auth), &[])
        .await;
    assert_eq!(accepted.0, StatusCode::ACCEPTED);
    let id = accepted.2["operationId"].clone();
    assert_eq!(
        f.request("POST", &path, apply, Some(&auth), &[]).await.2["operationId"],
        id
    );
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let r = f
                .request(
                    "GET",
                    "/api/v1/operations/by-idempotency/apply",
                    Value::Null,
                    Some(&auth),
                    &[],
                )
                .await;
            assert_eq!(r.0, StatusCode::OK);
            if r.2["result"]["status"] == "failed" {
                break r.2;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(result["operationId"], id);
    assert_eq!(result["result"]["error"]["code"], "INTERNAL");
    let cancel_path = format!("/api/v1/operations/{}/cancel", id.as_str().unwrap());
    assert_eq!(
        f.request(
            "POST",
            &cancel_path,
            command("operation_cancel", "cancel", 0, json!({})),
            Some(&auth),
            &[]
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.request("GET", "/api/v1/config", Value::Null, Some(&auth), &[])
            .await
            .2["result"]["revision"],
        0
    );
    f.finish().await;
}

#[tokio::test]
async fn oversized_and_missing_nullable_fields_are_rejected() {
    let f = Fixture::new().await;
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/auth/login",
            json!({"username":"tester","password":TOKEN}),
            None,
            &[]
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let auth = f.login().await;
    let too_large = command(
        "draft_create",
        "large",
        0,
        json!({"payload": "x".repeat(600*1024)}),
    );
    assert_eq!(
        f.request("POST", "/api/v1/drafts", too_large, Some(&auth), &[])
            .await
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    f.finish().await;
}
