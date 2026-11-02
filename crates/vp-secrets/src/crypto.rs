use crate::{MasterKey, Namespace, SecretKind, VaultError};
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use vp_product_domain::{SecretBytes, SecretRef};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"VPVAULT\0";
const SCHEMA: u16 = 1;
const FIXED_HEADER: usize = 50;
pub(crate) const MAX_FILE_BYTES: u64 = 64 * 1024 + FIXED_HEADER as u64 + 135 + 16;
pub(crate) const MANIFEST: u8 = 0;
pub(crate) const RECORD: u8 = 1;
pub(crate) const TOMBSTONE: u8 = 2;

pub(crate) struct Crypto {
    key: MasterKey,
    namespace: Namespace,
    pub id: [u8; 16],
    tls_profile: bool,
}
pub(crate) struct Decoded {
    pub class: u8,
    pub kind: Option<SecretKind>,
    pub version: u64,
    pub reference: Option<SecretRef>,
    pub bytes: SecretBytes,
}
impl Crypto {
    pub(crate) fn namespace(&self) -> &Namespace {
        &self.namespace
    }
    pub fn new(key: MasterKey, namespace: Namespace, id: [u8; 16]) -> Self {
        Self {
            key,
            namespace,
            id,
            tls_profile: false,
        }
    }
    #[cfg(feature = "private-tls")]
    pub(super) fn enable_tls_profile(&mut self) {
        self.tls_profile = true;
    }
    pub(crate) fn validate_instance_profile(
        &self,
        binding: &vp_product_control::InstanceBinding,
    ) -> Result<(), VaultError> {
        let result = if self.tls_profile {
            binding.validate_tls_profile()
        } else {
            binding.validate_fresh_profile()
        };
        result.map_err(|_| VaultError::MetadataMismatch)
    }
    /// Validate the authenticated reserved record before returning a writable
    /// reader or doing any cleanup. Absence of kind 6 is not profile admission.
    pub(crate) fn validate_instance_binding_record(
        &self,
        decoded: &Decoded,
    ) -> Result<(), VaultError> {
        if decoded.class != RECORD
            || decoded.kind != Some(SecretKind::InstanceBinding)
            || decoded.version != 1
            || decoded.reference.as_ref().map(SecretRef::as_str)
                != Some("secret:vp-instance-binding-v1")
            || decoded.bytes.expose().len() > 4096
        {
            return Err(VaultError::MetadataMismatch);
        }
        let binding: vp_product_control::InstanceBinding =
            serde_json::from_slice(decoded.bytes.expose()).map_err(|_| VaultError::Integrity)?;
        self.validate_instance_profile(&binding)?;
        let vault_id: String = self.id.iter().map(|b| format!("{b:02x}")).collect();
        let mut namespace = Sha256::new();
        namespace.update(b"vp.vault.namespace.v1\0");
        namespace.update(self.namespace.0.as_bytes());
        if binding.vault_id != vault_id
            || binding.namespace_digest.as_str() != format!("{:x}", namespace.finalize())
        {
            return Err(VaultError::MetadataMismatch);
        }
        Ok(())
    }
    pub fn id_from_manifest(bytes: &[u8]) -> Result<[u8; 16], VaultError> {
        if bytes.len() < FIXED_HEADER + 16 {
            return Err(VaultError::Integrity);
        }
        bytes[20..36].try_into().map_err(|_| VaultError::Integrity)
    }
    fn cipher(&self) -> Result<Aes256Gcm, VaultError> {
        Aes256Gcm::new_from_slice(self.key.0.expose()).map_err(|_| VaultError::InvalidInput)
    }
    fn aad(&self, header: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(32 + self.namespace.0.len() + header.len());
        aad.extend_from_slice(b"vp.server.immutable-vault.v1\0");
        aad.push(self.namespace.0.len() as u8);
        aad.extend_from_slice(self.namespace.0.as_bytes());
        aad.extend_from_slice(header);
        aad
    }
    pub fn seal(
        &self,
        class: u8,
        kind: Option<SecretKind>,
        version: u64,
        reference: Option<&SecretRef>,
        bytes: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        if kind == Some(SecretKind::CertificateChain) && !self.tls_profile {
            return Err(VaultError::UnsupportedVersion);
        }
        let reference = reference.map_or("", SecretRef::as_str);
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| VaultError::StorageUnavailable)?;
        let mut header = Vec::with_capacity(FIXED_HEADER + reference.len());
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&SCHEMA.to_be_bytes());
        header.push(class);
        header.push(kind.map_or(0, |k| k as u8));
        header.extend_from_slice(&version.to_be_bytes());
        header.extend_from_slice(&self.id);
        header.extend_from_slice(&(reference.len() as u16).to_be_bytes());
        header.extend_from_slice(&nonce);
        header.extend_from_slice(reference.as_bytes());
        // Only the zeroizing buffer ever contains an owned plaintext copy.
        // Preallocate tag capacity before copying plaintext (no realloc copy).
        let mut ciphertext = Zeroizing::new(Vec::with_capacity(bytes.len() + 16));
        ciphertext.extend_from_slice(bytes);
        self.cipher()?
            .encrypt_in_place(
                Nonce::from_slice(&nonce),
                &self.aad(&header),
                &mut *ciphertext,
            )
            .map_err(|_| VaultError::Integrity)?;
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }
    pub fn open(&self, encoded: &[u8]) -> Result<Decoded, VaultError> {
        if encoded.len() < FIXED_HEADER + 16
            || encoded.len() as u64 > MAX_FILE_BYTES
            || &encoded[..8] != MAGIC
        {
            return Err(VaultError::Integrity);
        }
        if encoded[8..10] != SCHEMA.to_be_bytes() {
            return Err(VaultError::UnsupportedVersion);
        }
        if encoded[20..36] != self.id {
            return Err(VaultError::Integrity);
        }
        let length = u16::from_be_bytes([encoded[36], encoded[37]]) as usize;
        let header_len = FIXED_HEADER + length;
        if length > 135 || encoded.len() < header_len + 16 {
            return Err(VaultError::Integrity);
        }
        let version = u64::from_be_bytes(
            encoded[12..20]
                .try_into()
                .map_err(|_| VaultError::Integrity)?,
        );
        let (kind, reference) = if encoded[10] == MANIFEST {
            if length != 0 || encoded[11] != 0 || version != 0 {
                return Err(VaultError::Integrity);
            }
            (None, None)
        } else if encoded[10] == RECORD || encoded[10] == TOMBSTONE {
            if version == 0 {
                return Err(VaultError::Integrity);
            }
            let text = std::str::from_utf8(&encoded[FIXED_HEADER..header_len])
                .map_err(|_| VaultError::Integrity)?;
            (
                Some(if encoded[11] == 6 && self.tls_profile {
                    SecretKind::CertificateChain
                } else {
                    SecretKind::parse(encoded[11])?
                }),
                Some(SecretRef::try_from(text.to_owned()).map_err(|_| VaultError::Integrity)?),
            )
        } else {
            return Err(VaultError::UnsupportedVersion);
        };
        let mut plaintext = Zeroizing::new(encoded[header_len..].to_vec());
        self.cipher()?
            .decrypt_in_place(
                Nonce::from_slice(&encoded[38..50]),
                &self.aad(&encoded[..header_len]),
                &mut *plaintext,
            )
            .map_err(|_| VaultError::Integrity)?;
        let bytes = SecretBytes::new(std::mem::take(&mut *plaintext));
        Ok(Decoded {
            class: encoded[10],
            kind,
            version,
            reference,
            bytes,
        })
    }
}
