//! Shared safe registries and vault/publication ports. No raw connection secret,
//! access token or URL is serializable into control state or idempotency/audit.
use crate::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Instant};
use vp_product_domain::*;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretState {
    pub credentials: BTreeMap<CredentialId, CredentialRecord>,
    pub publications: BTreeMap<PublicationId, PublicationRecord>,
    pub actions: Vec<SecretActionRecord>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRecord {
    pub summary: CredentialSummary,
    pub principal: UserId,
    pub vault_version: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationRecord {
    pub summary: PublicationSummary,
    pub principal: UserId,
    pub verifier: Option<ContentDigest>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretActionKind {
    CredentialCreate,
    CredentialRetire,
    PublicationCreate,
    PublicationReplace,
    PublicationTokenIssue,
    PublicationTokenRevoke,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretActionRecord {
    pub principal: UserId,
    pub method: SecretActionKind,
    pub key: IdempotencyKey,
    pub request_digest: ContentDigest,
    pub outcome: SecretActionOutcome,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SecretActionOutcome {
    PendingCreate(CredentialRecord),
    PendingRetire(CredentialId),
    Credential(CredentialSummary),
    Publication(PublicationSummary),
    TokenIssued {
        publication_id: PublicationId,
        revision: Revision,
    },
    Failed(ControlError),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecurityAuditActor {
    Administrator {
        id: UserId,
    },
    PublicationToken {
        id: PublicationId,
        version: Revision,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityAuditEvent {
    pub actor: SecurityAuditActor,
    pub action: SecurityAuditAction,
    pub subject: String,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAuditAction {
    CredentialPrepared,
    CredentialCreated,
    CredentialRetirePrepared,
    CredentialRetired,
    CredentialActionFailed,
    PublicationCreated,
    PublicationReplaced,
    PublicationTokenIssuePrepared,
    PublicationTokenIssued,
    PublicationTokenRevoked,
    PublicationFetched,
}

pub struct GeneratedCredential {
    pub reference: SecretRef,
    pub bytes: SecretBytes,
}
/// Actual immutable vault plus OS entropy. Confirmation, permissions, intent,
/// CAS/idempotency, reference retention and audit are owned by ControlService.
pub trait SecretManager: Send + Sync {
    fn supported_kinds(&self) -> Vec<NodeCredentialKind>;
    fn generate_credential(
        &self,
        kind: &NodeCredentialKind,
        deadline: Instant,
    ) -> Result<GeneratedCredential, ControlError>;
    fn put_credential(
        &self,
        reference: &SecretRef,
        kind: &NodeCredentialKind,
        version: u64,
        bytes: SecretBytes,
        deadline: Instant,
    ) -> Result<(), ControlError>;
    fn load_credential(
        &self,
        reference: &SecretRef,
        kind: &NodeCredentialKind,
        version: Option<u64>,
        deadline: Instant,
    ) -> Result<Option<SecretBytes>, ControlError>;
    fn retire_credential(
        &self,
        reference: &SecretRef,
        version: u64,
        deadline: Instant,
    ) -> Result<(), ControlError>;
    fn generate_publication_token(&self, deadline: Instant) -> Result<SecretBytes, ControlError>;
    fn publication_verifier(&self, token: &[u8]) -> Result<ContentDigest, ControlError>;
    fn verify_publication_token(&self, verifier: &ContentDigest, token: &[u8]) -> bool;
}
pub struct UnavailableSecretManager;
impl SecretManager for UnavailableSecretManager {
    fn supported_kinds(&self) -> Vec<NodeCredentialKind> {
        vec![]
    }
    fn generate_credential(
        &self,
        _: &NodeCredentialKind,
        _: Instant,
    ) -> Result<GeneratedCredential, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn put_credential(
        &self,
        _: &SecretRef,
        _: &NodeCredentialKind,
        _: u64,
        _: SecretBytes,
        _: Instant,
    ) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn load_credential(
        &self,
        _: &SecretRef,
        _: &NodeCredentialKind,
        _: Option<u64>,
        _: Instant,
    ) -> Result<Option<SecretBytes>, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn retire_credential(&self, _: &SecretRef, _: u64, _: Instant) -> Result<(), ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn generate_publication_token(&self, _: Instant) -> Result<SecretBytes, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn publication_verifier(&self, _: &[u8]) -> Result<ContentDigest, ControlError> {
        Err(ControlError::ExecutorUnavailable)
    }
    fn verify_publication_token(&self, _: &ContentDigest, _: &[u8]) -> bool {
        false
    }
}
/// Sensitive one-time result; deliberately no Serialize, Debug or Clone.
pub struct IssuedPublicationToken {
    pub publication: PublicationSummary,
    pub token: SecretBytes,
}
/// Fully authorized/constructed content; transport must not log or partially emit
/// before this result is returned. No general serialization/diagnostic interface.
pub struct SubscriptionContent {
    pub bytes: SecretBytes,
    pub source_revision: Revision,
}
impl SecretState {
    pub fn needs_recovery(&self) -> bool {
        self.actions.iter().any(|a| {
            matches!(
                a.outcome,
                SecretActionOutcome::PendingCreate(_) | SecretActionOutcome::PendingRetire(_)
            )
        })
    }
    pub fn verify_integrity(&self) -> Result<(), ControlError> {
        if self.credentials.len() > 128 || self.publications.len() > 16 || self.actions.len() > 256
        {
            return Err(ControlError::CorruptState);
        }
        let mut refs = std::collections::BTreeSet::new();
        for (id, record) in &self.credentials {
            record
                .summary
                .validate()
                .map_err(|_| ControlError::CorruptState)?;
            if id != &record.summary.id
                || record.vault_version == 0
                || !refs.insert(&record.summary.secret_ref)
            {
                return Err(ControlError::CorruptState);
            }
        }
        for (id, record) in &self.publications {
            record
                .summary
                .validate()
                .map_err(|_| ControlError::CorruptState)?;
            if id != &record.summary.id
                || (record.summary.token.state == PublicationTokenState::Active)
                    != record.verifier.is_some()
            {
                return Err(ControlError::CorruptState);
            }
        }
        let mut keys = std::collections::BTreeSet::new();
        for action in &self.actions {
            let key = (
                &action.principal,
                format!("{:?}", action.method),
                &action.key,
            );
            if !keys.insert(key) {
                return Err(ControlError::CorruptState);
            }
            match &action.outcome {
                SecretActionOutcome::PendingCreate(record) => {
                    record
                        .summary
                        .validate()
                        .map_err(|_| ControlError::CorruptState)?;
                    if action.method != SecretActionKind::CredentialCreate
                        || action.principal != record.principal
                        || record.vault_version == 0
                        || record.summary.state != CredentialState::Available
                        || self.credentials.contains_key(&record.summary.id)
                        || !refs.insert(&record.summary.secret_ref)
                    {
                        return Err(ControlError::CorruptState);
                    }
                }
                SecretActionOutcome::PendingRetire(id) => {
                    if action.method != SecretActionKind::CredentialRetire
                        || !self.credentials.get(id).is_some_and(|record| {
                            record.principal == action.principal
                                && record.summary.state == CredentialState::Available
                        })
                    {
                        return Err(ControlError::CorruptState);
                    }
                }
                SecretActionOutcome::Credential(summary) => {
                    summary.validate().map_err(|_| ControlError::CorruptState)?;
                    if !matches!(
                        action.method,
                        SecretActionKind::CredentialCreate | SecretActionKind::CredentialRetire
                    ) || !self.credentials.get(&summary.id).is_some_and(|record| {
                        record.principal == action.principal
                            && record.summary.secret_ref == summary.secret_ref
                            && record.summary.kind == summary.kind
                            && record.summary.revision >= summary.revision
                    }) {
                        return Err(ControlError::CorruptState);
                    }
                }
                SecretActionOutcome::Publication(summary) => {
                    summary.validate().map_err(|_| ControlError::CorruptState)?;
                    if !matches!(
                        action.method,
                        SecretActionKind::PublicationCreate
                            | SecretActionKind::PublicationReplace
                            | SecretActionKind::PublicationTokenRevoke
                    ) || !self.publications.get(&summary.id).is_some_and(|record| {
                        record.principal == action.principal
                            && record.summary.revision >= summary.revision
                    }) {
                        return Err(ControlError::CorruptState);
                    }
                }
                SecretActionOutcome::TokenIssued {
                    publication_id,
                    revision,
                } => {
                    if action.method != SecretActionKind::PublicationTokenIssue
                        || *revision == Revision::ZERO
                        || !self.publications.get(publication_id).is_some_and(|record| {
                            record.principal == action.principal
                                && record.summary.revision >= *revision
                        })
                    {
                        return Err(ControlError::CorruptState);
                    }
                }
                SecretActionOutcome::Failed(_) => (),
            }
        }
        Ok(())
    }
}
