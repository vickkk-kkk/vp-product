use serde::{Deserialize, Serialize};
use vp_product_domain::{
    BuildInfo, CompatibilityRange, ErrorCode, ErrorStage, ProductError, ReleaseId, ReleaseIdentity,
    VersionPair, ABI_MAJOR, ABI_MINOR, API_MAJOR, SCHEMA_VERSION,
};

/// Pinned source identities plus feature linkage. A linked execution entry point
/// does not imply a loaded runtime, verified connection or release certification.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildInspection {
    pub build: BuildInfo,
    pub upstream_tree: String,
    pub patched_tree: String,
    pub integration_commit: String,
    pub upstream_linked: bool,
    pub runtime_enabled: bool,
}
#[derive(Deserialize)]
struct SourceLock {
    schema_version: u16,
    upstream: Upstream,
    patchset: Patchset,
    integration: Integration,
}
#[derive(Deserialize)]
struct Upstream {
    commit: String,
    tree: String,
}
#[derive(Deserialize)]
struct Patchset {
    sha256: String,
}
#[derive(Deserialize)]
struct Integration {
    patched_tree: String,
    commit: String,
}

pub fn inspect_build() -> Result<BuildInspection, ProductError> {
    let lock: SourceLock = serde_json::from_str(include_str!("../../../core-lock.json"))
        .map_err(|_| ProductError::new(ErrorCode::UpgradeIncompatible, ErrorStage::Validate))?;
    if lock.schema_version != 1 {
        return Err(ProductError::new(
            ErrorCode::UpgradeIncompatible,
            ErrorStage::Validate,
        ));
    }
    let release = ReleaseIdentity {
        release_id: ReleaseId::new("development-source-only")
            .map_err(|_| ProductError::new(ErrorCode::Internal, ErrorStage::Validate))?,
        product_version: env!("CARGO_PKG_VERSION").to_owned(),
        adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
        core_commit: lock.upstream.commit,
        patchset_hash: Some(lock.patchset.sha256),
        build_target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        // A declared rust-toolchain file is not proof of the compiler used.
        toolchain: option_env!("VP_VERIFIED_TOOLCHAIN")
            .unwrap_or("unrecorded")
            .to_owned(),
        schema_read: CompatibilityRange {
            minimum: SCHEMA_VERSION,
            maximum: SCHEMA_VERSION,
        },
        schema_write: CompatibilityRange {
            minimum: SCHEMA_VERSION,
            maximum: SCHEMA_VERSION,
        },
        abi: VersionPair {
            major: ABI_MAJOR,
            minor: ABI_MINOR,
        },
        api: VersionPair {
            major: API_MAJOR,
            minor: 0,
        },
        evidence_manifest_hash: None,
    };
    release.validate()?;
    Ok(BuildInspection {
        build: BuildInfo {
            schema_version: SCHEMA_VERSION,
            release,
            development: true,
            // Wire extensions clients must understand, not runtime prerequisites.
            // Baseline v1 adds none; blocked runtime requirements live in capabilities.
            required_features: Vec::new(),
        },
        upstream_tree: lock.upstream.tree,
        patched_tree: lock.integration.patched_tree,
        integration_commit: lock.integration.commit,
        upstream_linked: cfg!(any(feature = "managed-runtime", feature = "mobile-ffi")),
        runtime_enabled: cfg!(any(feature = "managed-runtime", feature = "mobile-ffi")),
    })
}
