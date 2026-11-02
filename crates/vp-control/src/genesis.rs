//! Private fresh-profile pairing metadata. Never an HTTP DTO or anti-rollback
//! authority. The enclosing payload format is 3; its ordinary state remains 2.
use crate::{ContentDigest, ControlError, StoredState};
use serde::{Deserialize, Serialize};

pub const FRESH_ADMIN_PROFILE: &str = "fresh-admin-v1";
pub const FRESH_RUNTIME_PROFILE: &str = "fresh-runtime-v1";
/// Private fresh-only profile; recognizing it does not authorize migration.
pub const FRESH_TLS_RUNTIME_PROFILE: &str = "fresh-tls-runtime-v1";

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstanceBinding {
    pub binding_version: u16,
    pub genesis_id: String,
    pub vault_id: String,
    pub namespace_digest: ContentDigest,
    pub administrator_commitment: ContentDigest,
    pub preparation_digest: ContentDigest,
    pub activation_intent_digest: ContentDigest,
    pub artifact_set_digest: ContentDigest,
    pub profile: String,
}
impl InstanceBinding {
    pub fn validate(&self) -> Result<(), ControlError> {
        let id = |v: &str| {
            v.len() == 32
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.binding_version != 1
            || !id(&self.genesis_id)
            || !id(&self.vault_id)
            || ![
                FRESH_ADMIN_PROFILE,
                FRESH_RUNTIME_PROFILE,
                FRESH_TLS_RUNTIME_PROFILE,
            ]
            .contains(&self.profile.as_str())
        {
            return Err(ControlError::CorruptState);
        }
        Ok(())
    }
    /// Envelope-3/ordinary fresh reader boundary, not generic recognition.
    pub fn validate_fresh_profile(&self) -> Result<(), ControlError> {
        self.validate()?;
        if ![FRESH_ADMIN_PROFILE, FRESH_RUNTIME_PROFILE].contains(&self.profile.as_str()) {
            return Err(ControlError::CorruptState);
        }
        Ok(())
    }
    /// Envelope-4/private TLS reader boundary, not instance admission.
    pub fn validate_tls_profile(&self) -> Result<(), ControlError> {
        self.validate()?;
        if self.profile != FRESH_TLS_RUNTIME_PROFILE {
            return Err(ControlError::CorruptState);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<ContentDigest, ControlError> {
        self.validate()?;
        ContentDigest::of("vp.instance-binding.v1", self)
    }
}
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisPhase {
    Preparing,
    Initialized,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FreshControlEnvelope {
    pub schema_version: u16,
    pub binding: InstanceBinding,
    pub phase: GenesisPhase,
    pub state: StoredState,
}
impl FreshControlEnvelope {
    pub fn preparing(binding: InstanceBinding) -> Result<Self, ControlError> {
        binding.validate_fresh_profile()?;
        Ok(Self {
            schema_version: 3,
            binding,
            phase: GenesisPhase::Preparing,
            state: StoredState::default(),
        })
    }
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != 3 {
            return Err(ControlError::CorruptState);
        }
        self.binding.validate_fresh_profile()?;
        self.state.verify_integrity()?;
        if self.phase == GenesisPhase::Preparing
            && serde_json::to_vec(&self.state).map_err(|_| ControlError::CorruptState)?
                != serde_json::to_vec(&StoredState::default())
                    .map_err(|_| ControlError::CorruptState)?
        {
            return Err(ControlError::CorruptState);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn binding() -> InstanceBinding {
        InstanceBinding {
            binding_version: 1,
            genesis_id: "1".repeat(32),
            vault_id: "2".repeat(32),
            namespace_digest: ContentDigest::bytes(b"namespace"),
            administrator_commitment: ContentDigest::bytes(b"administrator"),
            preparation_digest: ContentDigest::bytes(b"prepare"),
            activation_intent_digest: ContentDigest::bytes(b"intent"),
            artifact_set_digest: ContentDigest::bytes(b"artifact"),
            profile: FRESH_ADMIN_PROFILE.into(),
        }
    }
    #[test]
    fn preparing_is_not_mutable_operational_state() {
        let mut envelope = FreshControlEnvelope::preparing(binding()).unwrap();
        envelope.validate().unwrap();
        envelope.state.version = 1;
        assert!(envelope.validate().is_err());
        envelope.phase = GenesisPhase::Initialized;
        envelope.validate().unwrap();
    }
    #[test]
    fn legacy_state_decoder_refuses_envelope_and_binding_is_strict() {
        let envelope = FreshControlEnvelope::preparing(binding()).unwrap();
        assert!(
            serde_json::from_slice::<StoredState>(&serde_json::to_vec(&envelope).unwrap()).is_err()
        );
        let mut bad = binding();
        bad.profile = "automatic".into();
        assert!(bad.validate().is_err());
        let mut value = serde_json::to_value(envelope).unwrap();
        value["ignoreMe"] = true.into();
        assert!(serde_json::from_value::<FreshControlEnvelope>(value).is_err());
    }
    #[test]
    fn envelope_profiles_are_closed_at_construction_and_validation() {
        for profile in [
            FRESH_ADMIN_PROFILE,
            FRESH_RUNTIME_PROFILE,
            FRESH_TLS_RUNTIME_PROFILE,
            "unknown",
        ] {
            let mut b = binding();
            b.profile = profile.into();
            let legacy = profile == FRESH_ADMIN_PROFILE || profile == FRESH_RUNTIME_PROFILE;
            let tls = profile == FRESH_TLS_RUNTIME_PROFILE;
            assert_eq!(FreshControlEnvelope::preparing(b.clone()).is_ok(), legacy);
            assert_eq!(crate::TlsControlEnvelope::preparing(b.clone()).is_ok(), tls);
            let e = FreshControlEnvelope {
                schema_version: 3,
                binding: b.clone(),
                phase: GenesisPhase::Initialized,
                state: StoredState::default(),
            };
            assert_eq!(e.validate().is_ok(), legacy);
            let mut tls_binding = binding();
            tls_binding.profile = FRESH_TLS_RUNTIME_PROFILE.into();
            let e = crate::TlsControlEnvelope::preparing(tls_binding).unwrap();
            let mut value = serde_json::to_value(e).unwrap();
            value["binding"]["profile"] = profile.into();
            let e: crate::TlsControlEnvelope = serde_json::from_value(value).unwrap();
            assert_eq!(e.validate().is_ok(), tls);
        }
    }
}
