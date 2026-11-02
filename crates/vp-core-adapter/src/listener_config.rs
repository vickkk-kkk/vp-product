use std::collections::BTreeSet;
use vp_product_domain::{
    ErrorCode, ErrorStage, ProductError, ServerListener, ServerProtocol, ServerSecurity, Transport,
};

pub const MAX_LISTENER_DOCUMENT_BYTES: usize = 1 << 20;
pub const MAX_LISTENERS: usize = 128;

/// Structural validity and runtime eligibility are intentionally different.
/// No secrets are resolved or copied to a core config during this preflight.
#[derive(Clone, Debug)]
pub struct ListenerValidation {
    pub listener_count: usize,
    pub enabled_count: usize,
    pub runtime_eligible: bool,
    pub issues: Vec<ProductError>,
}

/// The accepted format is a JSON array of domain ServerListener DTOs, not raw
/// upstream YAML. Domain serde denies unknown fields, including nested unions.
/// Serde's raw error is not returned: it may echo an untrusted/secret field value.
pub fn validate_listeners_json(bytes: &[u8]) -> Result<ListenerValidation, ProductError> {
    if bytes.len() > MAX_LISTENER_DOCUMENT_BYTES {
        return Err(ProductError::new(
            ErrorCode::InputTooLarge,
            ErrorStage::Decode,
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ProductError::new(ErrorCode::InvalidUtf8, ErrorStage::Decode))?;
    let listeners: Vec<ServerListener> = serde_json::from_str(text)
        .map_err(|_| ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Decode))?;
    validate_listeners(&listeners)
}

pub fn validate_listeners(
    listeners: &[ServerListener],
) -> Result<ListenerValidation, ProductError> {
    if listeners.len() > MAX_LISTENERS {
        return Err(ProductError::new(
            ErrorCode::InputTooLarge,
            ErrorStage::Validate,
        ));
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut enabled_binds = Vec::new();
    let mut issues = Vec::new();
    let mut enabled_count = 0;
    for (index, listener) in listeners.iter().enumerate() {
        listener.validate()?;
        if !ids.insert(listener.id.as_str()) || !names.insert(listener.name.as_str()) {
            return Err(
                ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Validate)
                    .at(format!("listeners[{index}].id_or_name")),
            );
        }
        if !listener.enabled {
            continue;
        }
        enabled_count += 1;
        // Conservatively reject wildcard collisions without guessing IPv6-only
        // socket behavior. Different explicit addresses can use the same port.
        if enabled_binds.iter().any(|other: &&ServerListener| {
            other.bind.port == listener.bind.port
                && (other.bind.address == listener.bind.address
                    || other.bind.address.is_unspecified()
                    || listener.bind.address.is_unspecified())
        }) {
            return Err(
                ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Validate)
                    .at(format!("listeners[{index}].bind")),
            );
        }
        enabled_binds.push(listener);
        if !matches!(&listener.transport, Transport::Tcp {}) {
            issues.push(
                ProductError::new(ErrorCode::ConfigUnsupported, ErrorStage::Validate)
                    .at(format!("listeners[{index}].transport")),
            );
        }
        if !matches!(&listener.security, ServerSecurity::None {}) {
            issues.push(
                ProductError::new(ErrorCode::ConfigUnsupported, ErrorStage::Validate)
                    .at(format!("listeners[{index}].security")),
            );
        }
        if matches!(&listener.protocol, ServerProtocol::Direct { .. }) {
            issues.push(
                ProductError::new(ErrorCode::ConfigUnsupported, ErrorStage::Validate)
                    .at(format!("listeners[{index}].protocol")),
            );
        }
        // Even source-reachable TCP paths are not certified or enabled here.
        issues.push(
            ProductError::new(ErrorCode::CapabilityUncertified, ErrorStage::Validate)
                .at(format!("listeners[{index}]")),
        );
    }
    issues.push(
        ProductError::new(ErrorCode::CapabilityUnavailable, ErrorStage::Validate)
            .at("runtime.managedListenerLifecycle"),
    );
    Ok(ListenerValidation {
        listener_count: listeners.len(),
        enabled_count,
        runtime_eligible: false,
        issues,
    })
}
