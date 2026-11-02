//! Authenticated HTTP boundary only. Configuration and operations are exclusively
//! delegated to ControlService; this crate never writes configurations or invokes shell commands.
#![forbid(unsafe_code)]
mod auth;
mod error;
mod http;
mod worker;
pub use auth::{BootstrapCredential, SecurityPolicy};
pub use error::ApiError;
pub use http::{router, ApiState};
pub use worker::OperationWorker;

mod secret_http;
pub use secret_http::{PublicationNetworkPolicy, TrustedPublicationBase};
