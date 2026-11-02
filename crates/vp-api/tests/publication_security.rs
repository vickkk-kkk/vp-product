//! Test-only router boundaries. No runtime acceptance or generated production secrets.
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
const MANAGEMENT: &str = "synthetic-management-fixture-only-01234567890123456789";
const PUBLIC_PATH:&str="/subscriptions/v1/fixture-publication/vps1_0000000000000000000000000000000000000000000000000000000000000000";
struct Fixture {
    app: Router,
    worker: Arc<OperationWorker>,
    join: tokio::task::JoinHandle<()>,
    _root: tempfile::TempDir,
}
impl Fixture {
    async fn new(enabled: bool) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let control = Arc::new(ControlService::new(
            Arc::new(vp_product_storage::SqliteStore::open(root.path()).unwrap()),
            Arc::new(UnavailableRuntime),
            Arc::new(UnavailableSystem),
            Arc::new(SystemClock),
        ));
        control.recover().unwrap();
        let (worker, join) = OperationWorker::start(control.clone());
        let base = enabled.then(|| {
            TrustedPublicationBase::new(
                "https://subscription.example.invalid",
                PublicationNetworkPolicy::Https,
                "https://localhost:9443",
            )
            .unwrap()
        });
        let state = ApiState::new_with_publication_base(
            control,
            worker.clone(),
            BootstrapCredential::new("fixture", SecretBytes::new(MANAGEMENT.as_bytes().to_vec()))
                .unwrap(),
            SecurityPolicy::new("https://localhost:9443").unwrap(),
            base,
        )
        .unwrap();
        Self {
            app: router(state),
            worker,
            join,
            _root: root,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Body,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        for (k, v) in headers {
            builder = builder.header(*k, *v)
        }
        let response = self
            .app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(!bytes
            .windows(MANAGEMENT.len())
            .any(|w| w == MANAGEMENT.as_bytes()));
        assert!(!bytes
            .windows(69)
            .any(|w| w == &PUBLIC_PATH.as_bytes()[PUBLIC_PATH.len() - 69..]));
        (status, headers, serde_json::from_slice(&bytes).unwrap())
    }
    async fn finish(self) {
        self.worker.stop();
        self.join.await.unwrap();
    }
}
#[test]
fn trusted_base_requires_explicit_https_or_exact_development_loopback() {
    let management = "http://127.0.0.1:8080";
    assert!(TrustedPublicationBase::new(
        "https://subscription.example.invalid",
        PublicationNetworkPolicy::Https,
        management
    )
    .is_ok());
    for base in [
        "http://example.invalid",
        "http://127.0.0.1:8080",
        "https://user@example.invalid",
        "https://example.invalid/path",
        "https://example.invalid?token=fixture",
        "https://example.invalid/",
    ] {
        assert!(
            TrustedPublicationBase::new(base, PublicationNetworkPolicy::Https, management).is_err()
        );
    }
    assert!(TrustedPublicationBase::new(
        management,
        PublicationNetworkPolicy::DevelopmentLoopback,
        management
    )
    .is_ok());
    assert!(TrustedPublicationBase::new(
        "http://localhost:8080",
        PublicationNetworkPolicy::DevelopmentLoopback,
        management
    )
    .is_err());
    assert!(TrustedPublicationBase::new(
        "https://example.invalid",
        PublicationNetworkPolicy::DevelopmentLoopback,
        management
    )
    .is_err());
}
#[tokio::test]
async fn subscription_authority_is_not_management_session_or_header() {
    let f = Fixture::new(true).await;
    let (status, _, body) = f
        .request(
            "POST",
            "/api/v1/auth/login",
            &[
                ("host", "localhost:9443"),
                ("origin", "https://localhost:9443"),
                ("content-type", "application/json"),
            ],
            Body::from(
                serde_json::to_vec(
                    &json!({"username":"fixture","password":MANAGEMENT,"secondFactor":null}),
                )
                .unwrap(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["result"]["csrfToken"].is_string());
    for headers in [
        vec![("host", "subscription.example.invalid")],
        vec![
            ("host", "subscription.example.invalid"),
            ("cookie", "vp_session=synthetic-session"),
        ],
    ] {
        let (status, headers, body) = f.request("GET", PUBLIC_PATH, &headers, Body::empty()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "AUTH_REQUIRED");
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert!(headers.get("access-control-allow-origin").is_none());
    }
    assert_eq!(
        f.request(
            "GET",
            PUBLIC_PATH,
            &[
                ("host", "subscription.example.invalid"),
                ("authorization", "Bearer fixture")
            ],
            Body::empty()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for path in ["/api/v1/credentials", "/api/v1/publications"] {
        assert_eq!(
            f.request("GET", path, &[("host", "localhost:9443")], Body::empty())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    f.finish().await;
}
#[tokio::test]
async fn public_path_rejects_host_origin_query_method_and_duplicate_headers() {
    let f = Fixture::new(true).await;
    for headers in [
        vec![("host", "attacker.invalid")],
        vec![("host", "subscription.example.invalid"), ("origin", "null")],
        vec![
            ("host", "subscription.example.invalid"),
            ("host", "subscription.example.invalid"),
        ],
        vec![
            ("host", "subscription.example.invalid"),
            ("origin", "https://subscription.example.invalid"),
            ("origin", "https://subscription.example.invalid"),
        ],
        vec![
            ("host", "subscription.example.invalid"),
            ("sec-fetch-site", "cross-site"),
        ],
    ] {
        assert_eq!(
            f.request("GET", PUBLIC_PATH, &headers, Body::empty())
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        f.request(
            "GET",
            &format!("{PUBLIC_PATH}?token=fixture"),
            &[("host", "subscription.example.invalid")],
            Body::empty()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (status, headers, body) = f
        .request(
            "POST",
            PUBLIC_PATH,
            &[("host", "subscription.example.invalid")],
            Body::empty(),
        )
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers["content-type"], "application/json");
    assert!(body.get("error").is_some());
    f.finish().await;
}
#[tokio::test]
async fn publication_public_attempt_rate_is_bounded_and_unconfigured_fails_closed() {
    let f = Fixture::new(true).await;
    for _ in 0..120 {
        assert_eq!(
            f.request(
                "GET",
                PUBLIC_PATH,
                &[("host", "subscription.example.invalid")],
                Body::empty()
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        f.request(
            "GET",
            PUBLIC_PATH,
            &[("host", "subscription.example.invalid")],
            Body::empty()
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    f.finish().await;
    let f = Fixture::new(false).await;
    assert_eq!(
        f.request(
            "GET",
            PUBLIC_PATH,
            &[("host", "localhost:9443")],
            Body::empty()
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    f.finish().await;
}
