use std::{fmt, time::Instant};
use vp_product_domain::SecretBytes;

/// Stable, deliberately content-free errors; never include paths, refs or bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultError {
    InvalidInput,
    PermissionDenied,
    Busy,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    Retired,
    MetadataMismatch,
    Integrity,
    UnsupportedVersion,
    LimitExceeded,
    StorageUnavailable,
    RecoveryRequired,
}
impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidInput => "invalid vault input",
            Self::PermissionDenied => "vault ownership or permissions refused",
            Self::Busy => "vault is busy",
            Self::DeadlineExceeded => "vault deadline exceeded",
            Self::NotFound => "secret reference not found",
            Self::AlreadyExists => "secret reference already reserved",
            Self::Retired => "secret reference is retired",
            Self::MetadataMismatch => "secret metadata does not match",
            Self::Integrity => "vault authentication or integrity failed",
            Self::UnsupportedVersion => "vault format version is unsupported",
            Self::LimitExceeded => "vault capacity exceeded",
            Self::StorageUnavailable => "vault storage unavailable",
            Self::RecoveryRequired => "vault requires authenticated reopen",
        };
        f.write_str(text)
    }
}
impl std::error::Error for VaultError {}

/// A vault is bound to exactly one explicit namespace; not a filesystem path.
#[derive(Clone, Eq, PartialEq)]
pub struct Namespace(pub(crate) String);
impl Namespace {
    pub fn new(value: &str) -> Result<Self, VaultError> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
        {
            return Err(VaultError::InvalidInput);
        }
        Ok(Self(value.into()))
    }
}
impl fmt::Debug for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Namespace([REDACTED])")
    }
}

/// Externally provisioned 256-bit key, consumed in memory. No key generation,
/// environment lookup, filesystem key loading or persistent-key fallback exists.
/// Provision a dedicated independent key per vault. Do not reuse across vaults.
pub struct MasterKey(pub(crate) SecretBytes);
impl MasterKey {
    pub fn new(bytes: SecretBytes) -> Result<Self, VaultError> {
        if bytes.expose().len() != 32 {
            return Err(VaultError::InvalidInput);
        }
        Ok(Self(bytes))
    }
}
impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SecretKind {
    Credential = 1,
    PrivateKey = 2,
    SubscriptionUrl = 3,
    ManagementToken = 4,
    InstanceBinding = 5,
    /// Accepted only by the explicit private TLS profile.
    CertificateChain = 6,
}
impl SecretKind {
    pub(crate) fn parse(byte: u8) -> Result<Self, VaultError> {
        match byte {
            1 => Ok(Self::Credential),
            2 => Ok(Self::PrivateKey),
            3 => Ok(Self::SubscriptionUrl),
            4 => Ok(Self::ManagementToken),
            5 => Ok(Self::InstanceBinding),
            _ => Err(VaultError::UnsupportedVersion),
        }
    }
}

/// Credential versions are immutable metadata, not mutable aliases. Rotation
/// must allocate a NEW SecretRef; even a higher version cannot reuse an old ref.
#[derive(Debug)]
pub struct SecretRecord {
    pub kind: SecretKind,
    pub version: u64,
    pub bytes: SecretBytes,
}

/// Persisted at initialization; reopening cannot silently relax the policy.
/// Tombstones and retired ciphertext count forever. No automatic GC exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_secret_bytes: u32,
    pub max_records: u32,
    pub max_total_bytes: u64,
    pub min_free_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_secret_bytes: 64 * 1024,
            max_records: 65_536,
            max_total_bytes: 128 * 1024 * 1024,
            min_free_bytes: 16 * 1024 * 1024,
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<Self, VaultError> {
        if self.max_secret_bytes == 0
            || self.max_secret_bytes > 64 * 1024
            || self.max_records == 0
            || self.max_records > 1_000_000
            || self.max_total_bytes < 4096
            || self.max_total_bytes > 1024 * 1024 * 1024
            || self.min_free_bytes > 1024 * 1024 * 1024 * 1024
        {
            return Err(VaultError::InvalidInput);
        }
        Ok(self)
    }
    pub(crate) fn encode(self) -> Vec<u8> {
        [
            self.max_secret_bytes.to_be_bytes().as_slice(),
            self.max_records.to_be_bytes().as_slice(),
            self.max_total_bytes.to_be_bytes().as_slice(),
            self.min_free_bytes.to_be_bytes().as_slice(),
        ]
        .concat()
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() != 24 {
            return Err(VaultError::Integrity);
        }
        let u32_at = |n| -> Result<u32, VaultError> {
            Ok(u32::from_be_bytes(
                bytes[n..n + 4]
                    .try_into()
                    .map_err(|_| VaultError::Integrity)?,
            ))
        };
        let u64_at = |n| -> Result<u64, VaultError> {
            Ok(u64::from_be_bytes(
                bytes[n..n + 8]
                    .try_into()
                    .map_err(|_| VaultError::Integrity)?,
            ))
        };
        // Explicit arrays avoid infallible-looking unchecked casts of disk data.
        Self {
            max_secret_bytes: u32_at(0)?,
            max_records: u32_at(4)?,
            max_total_bytes: u64_at(8)?,
            min_free_bytes: u64_at(16)?,
        }
        .validate()
        .map_err(|_| VaultError::Integrity)
    }
}
pub(crate) fn within(deadline: Instant) -> Result<(), VaultError> {
    if Instant::now() >= deadline {
        Err(VaultError::DeadlineExceeded)
    } else {
        Ok(())
    }
}
