use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use vp_product_control::ControlError;
use vp_product_domain::{ErrorCode, ErrorStage, FailureEnvelope, ProductError, RequestId, SafeArg};

/// Contains only typed public errors. Never attach serde/IO error strings.
#[derive(Debug)]
pub struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) error: Box<ProductError>,
    request_id: Option<RequestId>,
}
impl ApiError {
    pub(crate) fn new(status: StatusCode, code: ErrorCode, stage: ErrorStage) -> Self {
        Self {
            status,
            error: Box::new(ProductError::new(code, stage)),
            request_id: None,
        }
    }
    pub(crate) fn invalid() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            ErrorCode::ConfigInvalid,
            ErrorStage::Decode,
        )
    }
    pub(crate) fn internal() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Internal,
            ErrorStage::Recover,
        )
    }
    pub(crate) fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            ErrorCode::PermissionDenied,
            ErrorStage::Authenticate,
        )
    }
    pub(crate) fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::AuthRequired,
            ErrorStage::Authenticate,
        )
    }
    pub(crate) fn unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::CapabilityUnavailable,
            ErrorStage::Validate,
        )
    }
    pub(crate) fn request(mut self, id: RequestId) -> Self {
        self.request_id = Some(id);
        self
    }
}
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}
impl std::error::Error for ApiError {}
impl From<ControlError> for ApiError {
    fn from(error: ControlError) -> Self {
        use ControlError::*;
        let (status, code) = match error {
            RevisionConflict { .. } => {
                (StatusCode::PRECONDITION_FAILED, ErrorCode::RevisionConflict)
            }
            SecretResultUnavailable => (StatusCode::CONFLICT, ErrorCode::SecretResultUnavailable),
            ExportLossy => (StatusCode::BAD_REQUEST, ErrorCode::ExportLossy),
            IdempotencyConflict => (StatusCode::CONFLICT, ErrorCode::IdempotencyConflict),
            PlanExpired => (StatusCode::CONFLICT, ErrorCode::PlanExpired),
            ConfirmationMismatch => (StatusCode::CONFLICT, ErrorCode::ConfirmationRequired),
            PermissionDenied => (StatusCode::FORBIDDEN, ErrorCode::PermissionDenied),
            NotFound => (StatusCode::NOT_FOUND, ErrorCode::ConfigInvalid),
            InvalidConfiguration | InvalidRequest => {
                (StatusCode::BAD_REQUEST, ErrorCode::ConfigInvalid)
            }
            ExecutorUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::CapabilityUnavailable,
            ),
            CannotCancel => (StatusCode::CONFLICT, ErrorCode::OperationNotCancelable),
            Canceled => (StatusCode::CONFLICT, ErrorCode::OperationCanceled),
            RecoveryRequired | StorageUnavailable | CorruptState => {
                (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::RecoveryRequired)
            }
            ResourceConflict => (StatusCode::CONFLICT, ErrorCode::RevisionConflict),
            HealthFailed | ExecutorFailed | CounterExhausted => {
                (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Internal)
            }
        };
        let stage = if matches!(error, SecretResultUnavailable | ExportLossy) {
            ErrorStage::Export
        } else {
            ErrorStage::Apply
        };
        let mut out = Self::new(status, code, stage);
        if let RevisionConflict { expected, actual } = error {
            // Revision is a safe integer but SafeArg counts are u32; only add when representable.
            if let Ok(actual) = u32::try_from(actual.get()) {
                out.error
                    .safe_args
                    .insert("actualRevision".into(), SafeArg::Count(actual));
            }
            if let Ok(expected) = u32::try_from(expected.get()) {
                out.error
                    .safe_args
                    .insert("expectedRevision".into(), SafeArg::Count(expected));
            }
        }
        out
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = self.request_id.unwrap_or_else(|| {
            RequestId::new("request-rejected").unwrap_or_else(|_| unreachable!())
        });
        (
            self.status,
            Json(FailureEnvelope {
                schema_version: 1,
                request_id,
                operation_id: None,
                error: *self.error,
            }),
        )
            .into_response()
    }
}
