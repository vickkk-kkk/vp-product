//! Durable control-plane persistence. SQLite transactions commit each journal
//! boundary; a separate OS advisory lock serializes external side effects.
//! Opening these stores performs filesystem I/O and is never implicit in plan UI.
#![forbid(unsafe_code)]

mod artifacts;
mod migration;
pub use migration::PayloadMigrationReceipt;
#[cfg(target_os = "linux")]
mod bound;
mod sqlite;
#[cfg(target_os = "linux")]
pub use bound::{
    AnchoredControlRoot, BoundDirectory, BoundOpenMode, DirectoryIdentity, ReadOnlyBoundFile,
};
#[cfg(target_os = "linux")]
mod fresh;
pub use artifacts::*;
#[cfg(target_os = "linux")]
pub use fresh::FreshSqliteStore;
pub use sqlite::*;
#[cfg(target_os = "linux")]
mod inspection;
#[cfg(target_os = "linux")]
pub use inspection::{
    inspect_control_read_only, inspect_control_read_only_in_scratch, ControlInspection,
    ControlInspectionReceipt, InspectionError,
};

// The production store deliberately requires installer-provisioned 0700 roots.
// tempfile::tempdir follows the process umask; do not weaken that permission
// boundary merely to make tests work on a permissive-umask runner.
#[cfg(test)]
#[allow(clippy::expect_used)]
fn private_test_directory() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder
        .tempdir()
        .expect("create private test fixture directory")
}

#[cfg(target_os = "linux")]
mod tls;
#[cfg(target_os = "linux")]
pub use tls::{
    inspect_tls_control_read_only, TlsControlInspection, TlsControlSnapshot, TlsSqliteStore,
    TlsWriter,
};
