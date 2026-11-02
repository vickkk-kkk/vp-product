//! Durable Linux server secrets, separate from control/revision storage.
//!
//! This is an offline-ciphertext protection boundary, not protection against
//! root, the service UID, memory compromise, disk rollback or lost master keys.
//! See README.md for provisioning, retention, deadline and migration contracts.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod crypto;
#[cfg(target_os = "linux")]
mod filesystem;
#[cfg(target_os = "linux")]
mod inspection;
#[cfg(target_os = "linux")]
mod server;
mod types;

#[cfg(target_os = "linux")]
pub use inspection::{
    inspect_vault_read_only, inspect_vault_read_only_at_identity, VaultInspection,
    VaultInspectionReceipt,
};
#[cfg(target_os = "linux")]
pub use server::{DurableSecretStore, VaultDirectoryIdentity};
pub use types::{Limits, MasterKey, Namespace, SecretKind, SecretRecord, VaultError};

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

#[cfg(all(target_os = "linux", feature = "private-tls"))]
pub use server::TlsSecretStore;
