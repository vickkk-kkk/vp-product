use vp_product_domain::{
    preset_catalog, CapabilityDescriptor, CapabilityStatus, Direction, ErrorCode, ErrorStage,
    IpFamily, Platform, ProductError, SafeCode, Traffic,
};

/// Full preset inventory, explicitly blocked in both directions. A compiler/UI
/// must never infer certification from the presence of a descriptor or enum.
pub fn capabilities(
    platform: Platform,
    direction: Direction,
) -> Result<Vec<CapabilityDescriptor>, ProductError> {
    let release = crate::inspect_build()?.build.release;
    let catalog = preset_catalog()
        .map_err(|_| ProductError::new(ErrorCode::Internal, ErrorStage::Validate))?;
    let reason = SafeCode::try_from(
        if cfg!(any(feature = "managed-runtime", feature = "mobile-ffi")) {
            "capability.not_release_certified"
        } else {
            "capability.runtime_not_linked"
        }
        .to_owned(),
    )
    .map_err(|_| ProductError::new(ErrorCode::Internal, ErrorStage::Validate))?;
    let mut descriptors = Vec::new();
    for preset in catalog.presets {
        let ciphers = if preset.ciphers.is_empty() {
            vec![None]
        } else {
            preset.ciphers.into_iter().map(Some).collect()
        };
        for cipher in ciphers {
            for traffic in [Traffic::Tcp, Traffic::Udp] {
                for ip_family in [IpFamily::Ipv4, IpFamily::Ipv6] {
                    descriptors.push(CapabilityDescriptor {
                        key: preset.key,
                        direction,
                        protocol: preset.protocol,
                        transport: preset.transport,
                        security: preset.security,
                        cipher,
                        traffic,
                        ip_family,
                        platform,
                        status: CapabilityStatus::Blocked,
                        reason: reason.clone(),
                        evidence_ids: Vec::new(),
                        release_identity: release.clone(),
                    });
                }
            }
        }
    }
    Ok(descriptors)
}
