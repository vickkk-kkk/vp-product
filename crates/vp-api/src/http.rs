use crate::{
    auth::{one_header, Auth, Principal},
    error::ApiError,
    BootstrapCredential, OperationWorker, SecurityPolicy,
};
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;
use vp_product_control::{self as control, ControlService, DraftMutation, DraftRequest};
use vp_product_domain::*;
use zeroize::Zeroize;

pub struct ApiState {
    pub control: Arc<ControlService>,
    pub worker: Arc<OperationWorker>,
    auth: Auth,
    pub(crate) policy: SecurityPolicy,
    release: ReleaseIdentity,
    pub(crate) publication_base: Option<crate::TrustedPublicationBase>,
    pub(crate) subscription_work: Arc<tokio::sync::Semaphore>,
    pub(crate) publication_rate: crate::secret_http::PublicationRate,
    requests: tokio::sync::Semaphore,
    observations: Arc<tokio::sync::Semaphore>,
}
impl ApiState {
    pub fn new(
        control: Arc<ControlService>,
        worker: Arc<OperationWorker>,
        credential: BootstrapCredential,
        policy: SecurityPolicy,
    ) -> Result<Arc<Self>, ApiError> {
        Self::new_with_publication_base(control, worker, credential, policy, None)
    }
    pub fn new_with_publication_base(
        control: Arc<ControlService>,
        worker: Arc<OperationWorker>,
        credential: BootstrapCredential,
        policy: SecurityPolicy,
        publication_base: Option<crate::TrustedPublicationBase>,
    ) -> Result<Arc<Self>, ApiError> {
        let release = vp_product_core_adapter::inspect_build()
            .map_err(|_| ApiError::unavailable())?
            .build
            .release;
        Ok(Arc::new(Self {
            control,
            worker,
            publication_base,
            subscription_work: Arc::new(tokio::sync::Semaphore::new(1)),
            publication_rate: crate::secret_http::PublicationRate::new(),
            auth: Auth::new(credential),
            policy,
            release,
            requests: tokio::sync::Semaphore::new(32),
            observations: Arc::new(tokio::sync::Semaphore::new(1)),
        }))
    }
}
/// Every route, including not-found/method-not-allowed, passes this boundary.
pub fn router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/session", get(session))
        .route("/api/v1/build", get(build))
        .route("/api/v1/capabilities", get(capabilities))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/config", get(config))
        .route("/api/v1/drafts", get(drafts).post(create_draft))
        .route(
            "/api/v1/drafts/{id}",
            get(draft).put(replace_draft).delete(delete_draft),
        )
        .route(
            "/api/v1/drafts/{id}/listeners",
            get(listeners).post(create_listener),
        )
        .route(
            "/api/v1/drafts/{id}/listeners/{listener_id}",
            axum::routing::put(replace_listener).delete(delete_listener),
        )
        .route("/api/v1/drafts/{id}/validate", post(validate_draft))
        .route("/api/v1/plans", post(plan))
        .route("/api/v1/plans/{id}/apply", post(apply))
        .route("/api/v1/operations/{id}", get(operation))
        .route(
            "/api/v1/operations/by-idempotency/{key}",
            get(operation_by_key),
        )
        .route("/api/v1/operations/{id}/cancel", post(cancel))
        .route("/api/v1/events", get(unavailable))
        .route("/api/v1/imports/preview", post(unavailable))
        .route("/api/v1/exports", post(unavailable))
        .route("/api/v1/diagnostics/preview", post(unavailable))
        .route("/api/v1/updates/plan", post(unavailable))
        .merge(crate::secret_http::admin_routes())
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(state.clone(), security))
        .merge(crate::secret_http::public_router(state.clone()))
        .with_state(state)
}
async fn security(
    State(state): State<Arc<ApiState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let check = (|| {
        if request.uri().query().is_some() {
            return Err(ApiError::invalid());
        }
        if request
            .headers()
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
            .sum::<usize>()
            > 16 * 1024
        {
            return Err(ApiError::invalid());
        }
        let mutation = request.method() != Method::GET && request.method() != Method::HEAD;
        state.policy.check(request.headers(), mutation)?;
        if request.uri().path() != "/api/v1/auth/login" || request.method() != Method::POST {
            let principal = state.auth.authenticate(request.headers(), mutation)?;
            request.extensions_mut().insert(principal);
        }
        Ok(())
    })();
    let mut response = match check {
        Err(error) => error.into_response(),
        Ok(()) => match state.requests.try_acquire() {
            Err(_) => ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::QueueFull,
                ErrorStage::Decode,
            )
            .into_response(),
            Ok(_permit) => next.run(request).await,
        },
    };
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
    for (key, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
        ("referrer-policy", "no-referrer"),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(key),
            HeaderValue::from_static(value),
        );
    }
    response
}
pub(crate) fn new_request_id() -> Result<RequestId, ApiError> {
    RequestId::new(format!("request-{}", crate::auth::random_token()?))
        .map_err(|_| ApiError::internal())
}
pub(crate) fn success<T: Serialize>(
    id: RequestId,
    op: Option<OperationId>,
    result: T,
    status: StatusCode,
) -> Response {
    (
        status,
        Json(SuccessEnvelope {
            schema_version: 1,
            request_id: id,
            operation_id: op,
            result,
        }),
    )
        .into_response()
}
pub(crate) fn etag(mut response: Response, revision: Revision) -> Result<Response, ApiError> {
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{revision}\"")).map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}
async fn json<T: DeserializeOwned>(request: Request, limit: usize) -> Result<T, ApiError> {
    let content_type =
        one_header(request.headers(), "content-type")?.ok_or_else(ApiError::invalid)?;
    if content_type != "application/json" && content_type != "application/json; charset=utf-8" {
        return Err(ApiError::invalid());
    }
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        to_bytes(request.into_body(), limit),
    )
    .await
    .map_err(|_| {
        ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            ErrorCode::Timeout,
            ErrorStage::Decode,
        )
    })?
    .map_err(|_| {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::InputTooLarge,
            ErrorStage::Decode,
        )
    })?;
    let result = serde_json::from_slice(&bytes).map_err(|_| ApiError::invalid());
    if let Ok(mut unique) = bytes.try_into_mut() {
        unique.as_mut().zeroize();
    }
    result
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
    #[serde(deserialize_with = "required_option")]
    second_factor: Option<String>,
}
fn required_option<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
impl Drop for Login {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(v) = &mut self.second_factor {
            v.zeroize();
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginResult {
    csrf_token: String,
}
async fn login(State(state): State<Arc<ApiState>>, request: Request) -> Result<Response, ApiError> {
    let login: Login = json(request, 4096).await?;
    let (session, csrf) = state.auth.login(
        &login.username,
        login.password.as_bytes(),
        login.second_factor.as_deref(),
    )?;
    let mut response = success(
        new_request_id()?,
        None,
        LoginResult { csrf_token: csrf },
        StatusCode::OK,
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "vp_session={session}; Path=/api/v1; HttpOnly; Secure; SameSite=Strict; Max-Age=1800"
        ))
        .map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}
async fn session(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
) -> Result<Response, ApiError> {
    Ok(success(
        new_request_id()?,
        None,
        LoginResult {
            csrf_token: state.auth.csrf_token(&principal)?,
        },
        StatusCode::OK,
    ))
}
async fn logout(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
) -> Result<Response, ApiError> {
    state.auth.logout(&principal)?;
    let mut response = success(new_request_id()?, None, (), StatusCode::OK);
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "vp_session=; Path=/api/v1; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
        ),
    );
    Ok(response)
}
async fn build() -> Result<Response, ApiError> {
    let build = vp_product_core_adapter::inspect_build()
        .map_err(|_| ApiError::unavailable())?
        .build;
    Ok(success(new_request_id()?, None, build, StatusCode::OK))
}
async fn capabilities() -> Result<Response, ApiError> {
    let result = vp_product_core_adapter::capabilities(Platform::LinuxService, Direction::Inbound)
        .map_err(|_| ApiError::unavailable())?;
    Ok(success(new_request_id()?, None, result, StatusCode::OK))
}
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, control::ControlError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(Into::into)
}
async fn snapshot(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
) -> Result<Response, ApiError> {
    // Do not queue arbitrary amounts of active probe work behind a transaction.
    let observation = state
        .observations
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::QueueFull,
                ErrorStage::Decode,
            )
        })?;
    let service = state.control.clone();
    let result = blocking(move || {
        // Owned permit remains held if the caller drops its HTTP future while
        // the bounded blocking probe is still finishing.
        let _observation = observation;
        let snapshot = service.management_view(&principal.id)?;
        let operations = snapshot
            .operations
            .into_iter()
            .map(|(op, base, target)| operation_summary(op, base, target))
            .collect();
        let observed_revision = snapshot.observed.as_ref().map(|health| health.revision);
        let generation = snapshot
            .observed
            .as_ref()
            .map(|health| {
                Revision::new(health.generation).map_err(|_| control::ControlError::CorruptState)
            })
            .transpose()?
            .unwrap_or(Revision::ZERO);
        let evidence = snapshot
            .observed
            .as_ref()
            .map(|health| {
                let digest = control::ContentDigest::of("vp.runtime-observation.v1", health)?;
                EvidenceId::new(format!("observation-{}", digest.as_str()))
                    .map_err(|_| control::ControlError::CorruptState)
            })
            .transpose()?;
        let observed_at = snapshot
            .observed
            .as_ref()
            .map(|health| health.checked_at_ms);
        let available = snapshot.observed.is_some();
        let observation_error = snapshot
            .observation_error
            .map(|error| *ApiError::from(error).error);
        let listeners = snapshot
            .listeners
            .into_iter()
            .map(|listener| {
                let ready = available && listener.enabled;
                ListenerObservation {
                    listener_id: listener.id,
                    generation,
                    status: if !listener.enabled {
                        ListenerObservedStatus::Disabled
                    } else if ready {
                        ListenerObservedStatus::Ready
                    } else {
                        ListenerObservedStatus::Degraded
                    },
                    bound: ready,
                    authentication_loaded: ready,
                    forwarding: HealthObservation {
                        status: if ready {
                            ObservationStatus::Passed
                        } else {
                            ObservationStatus::NotRun
                        },
                        observed_at: if ready { observed_at } else { None },
                        evidence_id: if ready { evidence.clone() } else { None },
                        detail_key: None,
                    },
                    error: if listener.enabled && !ready {
                        observation_error.clone()
                    } else {
                        None
                    },
                }
            })
            .collect();
        Ok(ManagementSnapshot {
            schema_version: 1,
            desired_revision: snapshot.desired_revision,
            observed_revision,
            listeners,
            operations,
        })
    })
    .await?;
    Ok(success(new_request_id()?, None, result, StatusCode::OK))
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigResult {
    revision: Revision,
    config: Option<ProductConfig>,
}
async fn config(State(state): State<Arc<ApiState>>) -> Result<Response, ApiError> {
    let service = state.control.clone();
    let (revision, config) = blocking(move || service.active_config()).await?;
    etag(
        success(
            new_request_id()?,
            None,
            ConfigResult { revision, config },
            StatusCode::OK,
        ),
        revision,
    )
}
async fn drafts(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
) -> Result<Response, ApiError> {
    let service = state.control.clone();
    let result = blocking(move || service.drafts(&principal.id)).await?;
    Ok(success(new_request_id()?, None, result, StatusCode::OK))
}
async fn draft(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = DraftId::new(id).map_err(|_| ApiError::invalid())?;
    let service = state.control.clone();
    let result = blocking(move || service.draft(&id, &principal.id)).await?;
    let revision = result.revision;
    etag(
        success(new_request_id()?, None, result, StatusCode::OK),
        revision,
    )
}
async fn listeners(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = DraftId::new(id).map_err(|_| ApiError::invalid())?;
    let service = state.control.clone();
    let result = blocking(move || service.draft(&id, &principal.id)).await?;
    etag(
        success(
            new_request_id()?,
            None,
            result.config.listeners,
            StatusCode::OK,
        ),
        result.revision,
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Command<T> {
    pub(crate) schema_version: u16,
    pub(crate) request_id: RequestId,
    pub(crate) idempotency_key: IdempotencyKey,
    pub(crate) expected_revision: Revision,
    pub(crate) method: CommandMethod,
    pub(crate) payload: T,
}
pub(crate) async fn command<T: DeserializeOwned>(
    request: Request,
    method: CommandMethod,
    if_match: bool,
) -> Result<Command<T>, ApiError> {
    let expected_etag = one_header(request.headers(), "if-match")?.map(str::to_owned);
    let command: Command<T> = json(request, 512 * 1024).await?;
    if command.schema_version != 1 || command.method != method {
        return Err(ApiError::invalid().request(command.request_id));
    }
    if if_match && expected_etag.as_deref() != Some(&format!("\"{}\"", command.expected_revision)) {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            ErrorCode::RevisionConflict,
            ErrorStage::Validate,
        )
        .request(command.request_id));
    }
    Ok(command)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
async fn edit(
    state: Arc<ApiState>,
    principal: Principal,
    id: Option<DraftId>,
    request_id: RequestId,
    key: IdempotencyKey,
    revision: Revision,
    mutation: DraftMutation,
) -> Result<Response, ApiError> {
    let service = state.control.clone();
    let result = blocking(move || {
        service.edit_draft(DraftRequest {
            principal: principal.id,
            draft_id: id,
            expected_revision: revision,
            idempotency_key: key,
            mutation,
        })
    })
    .await
    .map_err(|e| e.request(request_id.clone()))?;
    let revision = result.as_ref().map(|d| d.revision);
    let response = success(request_id, None, result, StatusCode::OK);
    if let Some(revision) = revision {
        etag(response, revision)
    } else {
        Ok(response)
    }
}
async fn create_draft(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<ProductConfig> = command(request, CommandMethod::DraftCreate, false).await?;
    edit(
        state,
        principal,
        None,
        c.request_id,
        c.idempotency_key,
        c.expected_revision,
        DraftMutation::Create(c.payload),
    )
    .await
}
async fn replace_draft(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<ProductConfig> = command(request, CommandMethod::DraftReplace, true).await?;
    edit(
        state,
        principal,
        Some(DraftId::new(id).map_err(|_| ApiError::invalid())?),
        c.request_id,
        c.idempotency_key,
        c.expected_revision,
        DraftMutation::Replace(c.payload),
    )
    .await
}
async fn delete_draft(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<Empty> = command(request, CommandMethod::DraftDelete, true).await?;
    edit(
        state,
        principal,
        Some(DraftId::new(id).map_err(|_| ApiError::invalid())?),
        c.request_id,
        c.idempotency_key,
        c.expected_revision,
        DraftMutation::Delete {},
    )
    .await
}
async fn create_listener(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<ServerListener> = command(request, CommandMethod::ListenerCreate, true).await?;
    edit(
        state,
        principal,
        Some(DraftId::new(id).map_err(|_| ApiError::invalid())?),
        c.request_id,
        c.idempotency_key,
        c.expected_revision,
        DraftMutation::ListenerCreate(c.payload),
    )
    .await
}
async fn replace_listener(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path((id, listener_id)): Path<(String, String)>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<ServerListener> = command(request, CommandMethod::ListenerReplace, true).await?;
    if c.payload.id.as_str() != listener_id {
        return Err(ApiError::invalid().request(c.request_id));
    }
    edit(
        state,
        principal,
        Some(DraftId::new(id).map_err(|_| ApiError::invalid())?),
        c.request_id,
        c.idempotency_key,
        c.expected_revision,
        DraftMutation::ListenerReplace(c.payload),
    )
    .await
}
async fn delete_listener(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path((id, listener_id)): Path<(String, String)>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<Empty> = command(request, CommandMethod::ListenerDelete, true).await?;
    edit(
        state,
        principal,
        Some(DraftId::new(id).map_err(|_| ApiError::invalid())?),
        c.request_id,
        c.idempotency_key,
        c.expected_revision,
        DraftMutation::ListenerDelete(
            ListenerId::new(listener_id).map_err(|_| ApiError::invalid())?,
        ),
    )
    .await
}
#[derive(Serialize)]
struct ValidationResult {
    valid: bool,
    errors: Vec<ProductError>,
}
async fn validate_draft(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<Empty> = command(request, CommandMethod::Validate, false).await?;
    let id = DraftId::new(id).map_err(|_| ApiError::invalid())?;
    let service = state.control.clone();
    let release = state.release.clone();
    blocking(move || service.validate_draft(&id, &principal.id, c.expected_revision, &release))
        .await
        .map_err(|e| e.request(c.request_id.clone()))?;
    Ok(success(
        c.request_id,
        None,
        ValidationResult {
            valid: true,
            errors: vec![],
        },
        StatusCode::OK,
    ))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanPayload {
    draft_id: DraftId,
}
async fn plan(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<PlanPayload> = command(request, CommandMethod::PlanCreate, false).await?;
    let service = state.control.clone();
    let release = state.release.clone();
    let plan = blocking(move || {
        service.plan_draft(
            &c.payload.draft_id,
            &principal.id,
            c.expected_revision,
            c.idempotency_key,
            release,
        )
    })
    .await
    .map_err(|e| e.request(c.request_id.clone()))?;
    let summary = plan_summary(plan)?;
    Ok(success(c.request_id, None, summary, StatusCode::OK))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplyPayload {
    plan_hash: control::ContentDigest,
    confirmed: bool,
}
async fn apply(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<ApplyPayload> = command(request, CommandMethod::PlanApply, false).await?;
    if !c.payload.confirmed {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::ConfirmationRequired,
            ErrorStage::Apply,
        )
        .request(c.request_id));
    }
    if !state.worker.accepting() {
        return Err(ApiError::unavailable().request(c.request_id));
    }
    let id = PlanId::new(id).map_err(|_| ApiError::invalid())?;
    let service = state.control.clone();
    let user = principal.id.clone();
    let op = blocking(move || {
        service.submit(control::ApplyRequest {
            principal: user,
            plan_id: id,
            confirmed_hash: c.payload.plan_hash,
            expected_revision: c.expected_revision,
            idempotency_key: c.idempotency_key,
        })
    })
    .await
    .map_err(|e| e.request(c.request_id.clone()))?;
    state.worker.notify();
    let op_id = op.id.clone();
    let service = state.control.clone();
    let (_, base, target) =
        blocking(move || service.operation_details(&op_id, &principal.id)).await?;
    Ok(success(
        c.request_id,
        Some(op.id.clone()),
        operation_summary(op, base, target),
        StatusCode::ACCEPTED,
    ))
}
async fn operation(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = OperationId::new(id).map_err(|_| ApiError::invalid())?;
    let service = state.control.clone();
    let (op, base, target) =
        blocking(move || service.operation_details(&id, &principal.id)).await?;
    Ok(success(
        new_request_id()?,
        Some(op.id.clone()),
        operation_summary(op, base, target),
        StatusCode::OK,
    ))
}
async fn operation_by_key(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    let key = IdempotencyKey::new(key).map_err(|_| ApiError::invalid())?;
    let service = state.control.clone();
    let (op, base, target) =
        blocking(move || service.operation_by_idempotency(&key, &principal.id)).await?;
    Ok(success(
        new_request_id()?,
        Some(op.id.clone()),
        operation_summary(op, base, target),
        StatusCode::OK,
    ))
}
async fn cancel(
    State(state): State<Arc<ApiState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let c: Command<Empty> = command(request, CommandMethod::OperationCancel, false).await?;
    let id = OperationId::new(id).map_err(|_| ApiError::invalid())?;
    let (op, base, target) = state
        .worker
        .cancel(control::CancelRequest {
            principal: principal.id,
            operation_id: id,
            expected_revision: c.expected_revision,
            idempotency_key: c.idempotency_key,
        })
        .await
        .map_err(|e| e.request(c.request_id.clone()))?;
    Ok(success(
        c.request_id,
        Some(op.id.clone()),
        operation_summary(op, base, target),
        StatusCode::ACCEPTED,
    ))
}
fn operation_summary(op: control::Operation, base: Revision, target: Revision) -> OperationSummary {
    use control::OperationState as S;
    let (status, stage, steps) = match op.state {
        S::Queued => (OperationStatus::Queued, OperationStage::Validate, 0),
        S::Staging | S::Snapshotting => (OperationStatus::Running, OperationStage::Stage, 1),
        S::ApplyingResources | S::Activating => {
            (OperationStatus::Running, OperationStage::StartNew, 2)
        }
        S::Verifying => (OperationStatus::Running, OperationStage::Verify, 3),
        S::Committing => (OperationStatus::Running, OperationStage::Commit, 4),
        S::Committed => (OperationStatus::Succeeded, OperationStage::Commit, 5),
        S::Canceling => (OperationStatus::Running, OperationStage::Stage, 1),
        S::Canceled => (OperationStatus::Canceled, OperationStage::Stage, 1),
        S::RollingBack => (OperationStatus::RollingBack, OperationStage::Rollback, 2),
        S::RolledBack => (OperationStatus::RolledBack, OperationStage::Rollback, 5),
        S::Failed => (OperationStatus::Failed, OperationStage::Stage, 1),
        S::RecoveryRequired => (
            OperationStatus::RecoveryRequired,
            OperationStage::Recover,
            1,
        ),
    };
    OperationSummary {
        id: op.id,
        plan_id: Some(op.plan_id),
        status,
        stage,
        cancellable: op.state == control::OperationState::Queued,
        completed_steps: steps,
        total_steps: 5,
        base_revision: base,
        target_revision: Some(target),
        error: op.failure.map(|e| *ApiError::from(e).error),
    }
}
fn plan_summary(plan: control::ChangePlan) -> Result<ChangePlanSummary, ApiError> {
    let body = plan.body();
    Ok(ChangePlanSummary {
        id: body.id.clone(),
        plan_hash: plan.hash().as_str().into(),
        base_revision: body.base_revision,
        expires_at: body.expires_at_ms,
        changes: vec![ChangeSummary {
            resource_id: "product-config".into(),
            action: ChangeAction::Update,
            message_key: SafeCode::try_from("change.configuration".to_owned())
                .map_err(|_| ApiError::internal())?,
        }],
        impact: match body.validation.impact {
            control::RestartImpact::ControlledRestart => ChangeImpact::ControlledRestart,
            control::RestartImpact::RouteOnly => ChangeImpact::RouteHotSwap,
        },
        required_permissions: vec![],
        recovery_available: false,
        recovery_description_key: SafeCode::try_from("recovery.executor_required".to_owned())
            .map_err(|_| ApiError::internal())?,
    })
}
async fn unavailable() -> Result<Response, ApiError> {
    Err(ApiError::unavailable())
}
async fn not_found() -> Result<Response, ApiError> {
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::ConfigUnsupported,
        ErrorStage::Decode,
    ))
}
async fn method_not_allowed() -> Result<Response, ApiError> {
    Err(ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        ErrorCode::ConfigUnsupported,
        ErrorStage::Decode,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod projection_tests {
    use super::*;
    #[test]
    fn canceling_is_not_a_completed_cancellation() {
        let operation = control::Operation {
            id: OperationId::new("op").unwrap(),
            plan_id: PlanId::new("plan").unwrap(),
            principal: UserId::new("principal").unwrap(),
            state: control::OperationState::Canceling,
            created_at_ms: 0,
            updated_at_ms: 0,
            snapshot: None,
            failure: None,
            health: None,
            activation: None,
            cancel_requested: true,
            mutation_started: false,
        };
        let result = operation_summary(operation, Revision::ZERO, Revision::new(1).unwrap());
        assert_eq!(result.status, OperationStatus::Running);
        assert!(!result.status.is_terminal());
        assert!(!result.cancellable);
    }
}
