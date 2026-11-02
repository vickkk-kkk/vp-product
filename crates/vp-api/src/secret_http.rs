//! Separate management and subscription authority. No raw request/path/body
//! logging is permitted here: the public path contains a bearer credential.
use crate::{
    auth::{one_header, Principal},
    error::ApiError,
    http::{blocking, command, etag, new_request_id, success, ApiState, Command},
    SecurityPolicy,
};
use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use vp_product_domain::*;
use zeroize::Zeroizing;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationNetworkPolicy {
    Https,
    DevelopmentLoopback,
}
#[derive(Clone)]
pub struct TrustedPublicationBase {
    policy: SecurityPolicy,
}
impl TrustedPublicationBase {
    /// Operator-supplied canonical origin only, never arbitrary HTTP Host/Origin.
    pub fn new(
        base: &str,
        network: PublicationNetworkPolicy,
        management_origin: &str,
    ) -> Result<Self, ApiError> {
        let policy = SecurityPolicy::new(base)?;
        match network {
            PublicationNetworkPolicy::Https if !base.starts_with("https://") => {
                return Err(ApiError::invalid())
            }
            PublicationNetworkPolicy::DevelopmentLoopback
                if !base.starts_with("http://") || base != management_origin =>
            {
                return Err(ApiError::invalid())
            }
            _ => (),
        }
        Ok(Self { policy })
    }
    fn sensitive_url(
        &self,
        id: &PublicationId,
        token: &SecretBytes,
    ) -> Result<SensitiveResponseText, ApiError> {
        let text = std::str::from_utf8(token.expose()).map_err(|_| ApiError::internal())?;
        if text.len() != 69
            || !text.starts_with("vps1_")
            || !text.as_bytes()[5..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(ApiError::internal());
        }
        let mut url = Zeroizing::new(format!(
            "{}/subscriptions/v1/{}/",
            self.policy.origin,
            id.as_str()
        ));
        url.push_str(text);
        SensitiveResponseText::new(std::mem::take(&mut *url)).map_err(|_| ApiError::internal())
    }
}
pub(crate) struct PublicationRate {
    inner: Mutex<(Instant, u32)>,
}
impl PublicationRate {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new((Instant::now(), 0)),
        }
    }
    fn acquire(&self) -> Result<(), ApiError> {
        let mut rate = self.inner.lock().map_err(|_| ApiError::internal())?;
        if rate.0.elapsed() >= Duration::from_secs(60) {
            *rate = (Instant::now(), 0);
        }
        if rate.1 >= 120 {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::QueueFull,
                ErrorStage::Authenticate,
            ));
        }
        rate.1 += 1;
        Ok(())
    }
}
pub(crate) fn admin_routes() -> Router<Arc<ApiState>> {
    Router::new()
        .route(
            "/api/v1/credentials",
            get(credentials).post(create_credential),
        )
        .route("/api/v1/credentials/{id}/retire", post(retire_credential))
        .route(
            "/api/v1/publications",
            get(publications).post(create_publication),
        )
        .route(
            "/api/v1/publications/{id}",
            get(publication).put(replace_publication),
        )
        .route(
            "/api/v1/publications/{id}/token",
            post(issue_token).delete(revoke_token),
        )
}
pub(crate) fn public_router(state: Arc<ApiState>) -> Router<Arc<ApiState>> {
    Router::new()
        .route("/subscriptions/v1/{id}/{token}", get(fetch))
        .layer(middleware::from_fn_with_state(state, public_security))
}
fn guarded_response(mut response: Response) -> Response {
    // Extractor/framework failures must not echo a tokenized path as text.
    if (response.status().is_client_error() || response.status().is_server_error())
        && response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
    {
        response = ApiError::new(
            response.status(),
            ErrorCode::ConfigInvalid,
            ErrorStage::Decode,
        )
        .into_response();
    }
    for (k, v) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("content-security-policy", "default-src 'none'; sandbox"),
    ] {
        response
            .headers_mut()
            .insert(k, HeaderValue::from_static(v));
    }
    response
}
async fn public_security(
    State(state): State<Arc<ApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let checked = (|| {
        if request.method() != Method::GET {
            return Err(ApiError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                ErrorCode::ConfigUnsupported,
                ErrorStage::Decode,
            ));
        }
        if request.uri().query().is_some()
            || request.uri().path().len() > 1024
            || request
                .headers()
                .iter()
                .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
                .sum::<usize>()
                > 16 * 1024
        {
            return Err(ApiError::invalid());
        }
        let policy = state
            .publication_base
            .as_ref()
            .map(|b| &b.policy)
            .unwrap_or(&state.policy);
        policy.check(request.headers(), false)?;
        if one_header(request.headers(), "authorization")?.is_some()
            || one_header(request.headers(), "transfer-encoding")?.is_some()
            || one_header(request.headers(), "content-length")?.is_some_and(|v| v != "0")
        {
            return Err(ApiError::invalid());
        }
        state.publication_rate.acquire()?;
        Ok(())
    })();
    guarded_response(match checked {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    })
}
fn metadata<T: serde::Serialize>(id: RequestId, result: T) -> Result<Response, ApiError> {
    // Collections have strict record limits, plus a hard serialized metadata cap.
    if serde_json::to_vec(&result)
        .map_err(|_| ApiError::internal())?
        .len()
        > 1024 * 1024
    {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::InputTooLarge,
            ErrorStage::Export,
        ));
    }
    Ok(success(id, None, result, StatusCode::OK))
}
async fn credentials(
    State(state): State<Arc<ApiState>>,
    Extension(p): Extension<Principal>,
) -> Result<Response, ApiError> {
    let service = state.control.clone();
    metadata(
        new_request_id()?,
        blocking(move || service.credential_inventory(&p.id)).await?,
    )
}
async fn publications(
    State(state): State<Arc<ApiState>>,
    Extension(p): Extension<Principal>,
) -> Result<Response, ApiError> {
    let service = state.control.clone();
    metadata(
        new_request_id()?,
        blocking(move || service.publications(&p.id)).await?,
    )
}
async fn publication(
    State(state): State<Arc<ApiState>>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = PublicationId::new(id).map_err(|_| ApiError::invalid())?;
    let service = state.control.clone();
    let result = blocking(move || service.publication(&p.id, &id)).await?;
    let revision = result.revision;
    etag(metadata(new_request_id()?, result)?, revision)
}
async fn create_credential(
    State(state): State<Arc<ApiState>>,
    Extension(p): Extension<Principal>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<CredentialCreatePayload> =
        command(request, CommandMethod::CredentialCreate, false).await?;
    let request_id = c.request_id.clone();
    let service = state.control.clone();
    let result = blocking(move || {
        service.create_credential(&p.id, c.expected_revision, c.idempotency_key, c.payload)
    })
    .await
    .map_err(|e| e.request(request_id.clone()))?;
    let revision = result.revision;
    etag(metadata(request_id, result)?, revision)
}
async fn retire_credential(
    State(state): State<Arc<ApiState>>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = CredentialId::new(id).map_err(|_| ApiError::invalid())?;
    let c: Command<CredentialRetirePayload> =
        command(request, CommandMethod::CredentialRetire, true).await?;
    let request_id = c.request_id.clone();
    let service = state.control.clone();
    let result = blocking(move || {
        service.retire_credential(
            &p.id,
            &id,
            c.expected_revision,
            c.idempotency_key,
            c.payload,
        )
    })
    .await
    .map_err(|e| e.request(request_id.clone()))?;
    let revision = result.revision;
    etag(metadata(request_id, result)?, revision)
}
async fn create_publication(
    State(state): State<Arc<ApiState>>,
    Extension(p): Extension<Principal>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<PublicationCreatePayload> =
        command(request, CommandMethod::PublicationCreate, false).await?;
    let request_id = c.request_id.clone();
    let service = state.control.clone();
    let result = blocking(move || {
        service.create_publication(&p.id, c.expected_revision, c.idempotency_key, c.payload)
    })
    .await
    .map_err(|e| e.request(request_id.clone()))?;
    let revision = result.revision;
    etag(metadata(request_id, result)?, revision)
}
async fn replace_publication(
    State(state): State<Arc<ApiState>>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = PublicationId::new(id).map_err(|_| ApiError::invalid())?;
    let c: Command<PublicationReplacePayload> =
        command(request, CommandMethod::PublicationReplace, true).await?;
    let request_id = c.request_id.clone();
    let service = state.control.clone();
    let result = blocking(move || {
        service.replace_publication(
            &p.id,
            &id,
            c.expected_revision,
            c.idempotency_key,
            c.payload,
        )
    })
    .await
    .map_err(|e| e.request(request_id.clone()))?;
    let revision = result.revision;
    etag(metadata(request_id, result)?, revision)
}
async fn issue_token(
    State(state): State<Arc<ApiState>>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    // No durable issuance without an explicitly configured, validated origin.
    let base = state
        .publication_base
        .clone()
        .ok_or_else(ApiError::unavailable)?;
    let id = PublicationId::new(id).map_err(|_| ApiError::invalid())?;
    let c: Command<PublicationIssuePayload> =
        command(request, CommandMethod::PublicationTokenIssue, true).await?;
    let request_id = c.request_id.clone();
    let service = state.control.clone();
    let requested = id.clone();
    let issued = blocking(move || {
        service.issue_publication_token(
            &p.id,
            &requested,
            c.expected_revision,
            c.idempotency_key,
            c.payload,
        )
    })
    .await
    .map_err(|e| e.request(request_id.clone()))?;
    let url = base.sensitive_url(&id, &issued.token)?;
    let revision = issued.publication.revision;
    let result = PublicationIssuedSecret {
        publication: issued.publication,
        subscription_url: url,
        display_once: ExplicitConfirmation::try_from(true).map_err(|_| ApiError::internal())?,
    };
    Ok(guarded_response(etag(
        success(request_id, None, result, StatusCode::OK),
        revision,
    )?))
}
async fn revoke_token(
    State(state): State<Arc<ApiState>>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let id = PublicationId::new(id).map_err(|_| ApiError::invalid())?;
    let c: Command<PublicationRevokePayload> =
        command(request, CommandMethod::PublicationTokenRevoke, true).await?;
    let request_id = c.request_id.clone();
    let service = state.control.clone();
    let result = blocking(move || {
        service.revoke_publication_token(
            &p.id,
            &id,
            c.expected_revision,
            c.idempotency_key,
            c.payload,
        )
    })
    .await
    .map_err(|e| e.request(request_id.clone()))?;
    let revision = result.revision;
    etag(metadata(request_id, result)?, revision)
}
async fn fetch(
    State(state): State<Arc<ApiState>>,
    Path((id, token)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let token = SecretBytes::new(token.into_bytes());
    let id = PublicationId::new(id).map_err(|_| ApiError::unauthorized())?;
    if state.publication_base.is_none() {
        return Err(ApiError::unavailable());
    }
    let permit = state
        .subscription_work
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::QueueFull,
                ErrorStage::Authenticate,
            )
        })?;
    let service = state.control.clone();
    let content = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        service.fetch_publication(&id, token)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|error| {
        if error == vp_product_control::ControlError::PermissionDenied {
            ApiError::unauthorized()
        } else {
            ApiError::from(error)
        }
    })?;
    let mut response = content.bytes.expose().to_vec().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=vp-subscription.txt"),
    );
    response.headers_mut().insert(
        "x-vp-config-revision",
        HeaderValue::from_str(&content.source_revision.to_string())
            .map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}
