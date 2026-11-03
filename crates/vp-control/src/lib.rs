//! The single product mutation state machine. This library performs no shell,
//! network, secret generation or service actions itself. Executors are mandatory;
//! absent production adapters fail closed. Tests are not runtime certification.
#![forbid(unsafe_code)]

mod drafts;
pub use drafts::*;
mod model;
mod ports;
mod runtime_context;
pub use runtime_context::*;
mod service;
pub use model::*;
pub use ports::*;
pub use service::*;

#[cfg(test)]
mod tests;

mod managed_secrets;
pub use managed_secrets::*;

mod credentials;

mod publications;

mod genesis;
pub use genesis::{
    FreshControlEnvelope, GenesisPhase, InstanceBinding, FRESH_ADMIN_PROFILE,
    FRESH_RUNTIME_PROFILE, FRESH_TLS_RUNTIME_PROFILE,
};

mod tls_registry;
#[cfg(feature = "private-tls")]
pub use tls_registry::{
    TlsActionRequest, TlsAssetWriterLease, TlsBackendPolicy, TlsImportRequest, TlsImportService,
    TlsMaterialAdmission, TlsMaterialVault, TlsRawRecord, TlsRetireRequest, TlsTombstone,
    TlsVaultIo,
};
pub use tls_registry::{
    TlsAssetEvent, TlsAssetMutation, TlsControlEnvelope, VerifiedTlsImport, VerifiedTlsReadback,
    VerifiedTlsRetirement,
};
#[cfg(all(test, feature = "private-tls"))]
mod tls_test_pem;
