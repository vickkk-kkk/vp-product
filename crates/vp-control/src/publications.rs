//! Authorized publication over exact verified active configuration. URL/HTTP
//! policy belongs to the transport boundary; all durable changes use one writer.
use crate::credentials::*;
use crate::service::{check_revision, take_id};
use crate::*;
use std::time::Instant;
use vp_product_domain::*;
use vp_product_import::{Credential, SecretBundle};
use zeroize::Zeroizing;
fn public_summary(record: &PublicationRecord, now: u64) -> PublicationSummary {
    let mut summary = record.summary.clone();
    if summary.token.state == PublicationTokenState::Active
        && summary.token.expires_at.is_some_and(|at| now >= at)
    {
        summary.token.state = PublicationTokenState::Expired;
    }
    summary
}
fn publication_result(outcome: SecretActionOutcome) -> Result<PublicationSummary, ControlError> {
    if let SecretActionOutcome::Publication(s) = outcome {
        Ok(s)
    } else {
        Err(action_failure(outcome))
    }
}
impl ControlService {
    pub fn publications(
        &self,
        principal: &UserId,
    ) -> Result<Vec<PublicationSummary>, ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        let now = self.clock.now_ms()?;
        Ok(state
            .secrets
            .publications
            .values()
            .filter(|p| &p.principal == principal)
            .map(|p| public_summary(p, now))
            .collect())
    }
    pub fn publication(
        &self,
        principal: &UserId,
        id: &PublicationId,
    ) -> Result<PublicationSummary, ControlError> {
        let state = self.store.read()?;
        state.verify_integrity()?;
        let record = state
            .secrets
            .publications
            .get(id)
            .filter(|p| &p.principal == principal)
            .ok_or(ControlError::NotFound)?;
        Ok(public_summary(record, self.clock.now_ms()?))
    }
    fn verified_publication_active<'a>(
        &self,
        state: &'a StoredState,
        revision: Revision,
    ) -> Result<&'a RevisionRecord, ControlError> {
        if state.needs_recovery() {
            return Err(ControlError::RecoveryRequired);
        }
        check_revision(revision, state.active_revision)?;
        let active = state.active().ok_or(ControlError::ExecutorUnavailable)?;
        let health = self.runtime.observe_committed(active)?;
        crate::drafts::validate_observation(active, &health, self.clock.now_ms()?)?;
        Ok(active)
    }
    pub fn create_publication(
        &self,
        principal: &UserId,
        expected: Revision,
        key: IdempotencyKey,
        payload: PublicationCreatePayload,
    ) -> Result<PublicationSummary, ControlError> {
        if !payload.confirm_publish_connection_secrets.is_confirmed() {
            return Err(ControlError::ConfirmationMismatch);
        }
        validate_publication_sources(&payload.name, &payload.sources)
            .map_err(|_| ControlError::InvalidConfiguration)?;
        let digest =
            ContentDigest::of("vp.publication-create.v1", &(principal, expected, &payload))?;
        let mut lease = self.store.writer()?;
        if let Some(result) = prior_secret_action(
            lease.state(),
            principal,
            SecretActionKind::PublicationCreate,
            &key,
            &digest,
        )? {
            return publication_result(result);
        }
        ensure_secret_write(lease.state())?;
        if lease.state().secrets.publications.len() >= 16 {
            return Err(ControlError::InvalidRequest);
        }
        let active = self
            .verified_publication_active(lease.state(), expected)?
            .clone();
        let mut next = lease.state().clone();
        let now = self.clock.now_ms()?;
        let id = PublicationId::new(format!("publication-{}", take_id(&mut next)?))
            .map_err(|_| ControlError::CounterExhausted)?;
        let summary = PublicationSummary {
            schema_version: 1,
            id: id.clone(),
            revision: Revision::new(1).map_err(|_| ControlError::CounterExhausted)?,
            name: payload.name,
            enabled: payload.enabled,
            format: payload.format,
            source_revision: expected,
            sources: payload.sources,
            created_at: now,
            updated_at: now,
            token: PublicationTokenStatus {
                state: PublicationTokenState::NotIssued,
                version: Revision::ZERO,
                issued_at: None,
                expires_at: None,
            },
            last_successful_read_at: None,
        };
        drop(self.prepare_publication_content(&active, &summary)?);
        next.secrets.publications.insert(
            id.clone(),
            PublicationRecord {
                summary: summary.clone(),
                principal: principal.clone(),
                verifier: None,
            },
        );
        next.secrets.actions.push(SecretActionRecord {
            principal: principal.clone(),
            method: SecretActionKind::PublicationCreate,
            key,
            request_digest: digest,
            outcome: SecretActionOutcome::Publication(summary.clone()),
        });
        secret_checkpoint(
            &mut *lease,
            next,
            now,
            audit_admin(
                principal,
                SecurityAuditAction::PublicationCreated,
                id.as_str(),
            ),
        )?;
        Ok(summary)
    }
    pub fn replace_publication(
        &self,
        principal: &UserId,
        id: &PublicationId,
        expected: Revision,
        key: IdempotencyKey,
        payload: PublicationReplacePayload,
    ) -> Result<PublicationSummary, ControlError> {
        if !payload.confirm_publish_connection_secrets.is_confirmed() {
            return Err(ControlError::ConfirmationMismatch);
        }
        validate_publication_sources(&payload.name, &payload.sources)
            .map_err(|_| ControlError::InvalidConfiguration)?;
        let digest = ContentDigest::of(
            "vp.publication-replace.v1",
            &(principal, id, expected, &payload),
        )?;
        let mut lease = self.store.writer()?;
        if let Some(result) = prior_secret_action(
            lease.state(),
            principal,
            SecretActionKind::PublicationReplace,
            &key,
            &digest,
        )? {
            return publication_result(result);
        }
        ensure_secret_write(lease.state())?;
        let mut record = lease
            .state()
            .secrets
            .publications
            .get(id)
            .filter(|r| &r.principal == principal)
            .cloned()
            .ok_or(ControlError::NotFound)?;
        check_revision(expected, record.summary.revision)?;
        let active = self
            .verified_publication_active(lease.state(), payload.source_revision)?
            .clone();
        record.summary.name = payload.name;
        record.summary.enabled = payload.enabled;
        record.summary.sources = payload.sources;
        record.summary.source_revision = payload.source_revision;
        record.summary.format = payload.format;
        record.summary.revision = next_revision(record.summary.revision)?;
        record.summary.updated_at = self.clock.now_ms()?;
        if !record.summary.enabled {
            revoke(&mut record);
        }
        drop(self.prepare_publication_content(&active, &record.summary)?);
        self.save_publication_action(
            &mut *lease,
            key,
            digest,
            SecretActionKind::PublicationReplace,
            record,
            SecurityAuditAction::PublicationReplaced,
        )
    }
    fn save_publication_action(
        &self,
        lease: &mut dyn WriterLease,
        key: IdempotencyKey,
        digest: ContentDigest,
        method: SecretActionKind,
        record: PublicationRecord,
        audit: SecurityAuditAction,
    ) -> Result<PublicationSummary, ControlError> {
        let principal = record.principal.clone();
        let id = record.summary.id.clone();
        let summary = public_summary(&record, self.clock.now_ms()?);
        let mut next = lease.state().clone();
        next.secrets.publications.insert(id.clone(), record);
        next.secrets.actions.push(SecretActionRecord {
            principal: principal.clone(),
            method,
            key,
            request_digest: digest,
            outcome: SecretActionOutcome::Publication(summary.clone()),
        });
        secret_checkpoint(
            lease,
            next,
            self.clock.now_ms()?,
            audit_admin(&principal, audit, id.as_str()),
        )?;
        Ok(summary)
    }
    /// Transport must validate its explicitly trusted public base BEFORE this
    /// call. An uncertain response is never replayed or regenerated by key.
    pub fn issue_publication_token(
        &self,
        principal: &UserId,
        id: &PublicationId,
        expected: Revision,
        key: IdempotencyKey,
        payload: PublicationIssuePayload,
    ) -> Result<IssuedPublicationToken, ControlError> {
        if !payload.confirm_issue_secret_url.is_confirmed() {
            return Err(ControlError::ConfirmationMismatch);
        }
        if !(300..=2592000).contains(&payload.expires_in_seconds) {
            return Err(ControlError::InvalidRequest);
        }
        let digest = ContentDigest::of(
            "vp.publication-token-issue.v1",
            &(principal, id, expected, &payload),
        )?;
        let mut lease = self.store.writer()?;
        if let Some(result) = prior_secret_action(
            lease.state(),
            principal,
            SecretActionKind::PublicationTokenIssue,
            &key,
            &digest,
        )? {
            return Err(action_failure(result));
        }
        ensure_secret_write(lease.state())?;
        let mut record = lease
            .state()
            .secrets
            .publications
            .get(id)
            .filter(|r| &r.principal == principal)
            .cloned()
            .ok_or(ControlError::NotFound)?;
        check_revision(expected, record.summary.revision)?;
        if !record.summary.enabled {
            return Err(ControlError::PermissionDenied);
        }
        let active = self
            .verified_publication_active(lease.state(), record.summary.source_revision)?
            .clone();
        drop(self.prepare_publication_content(&active, &record.summary)?);
        let now = self.clock.now_ms()?;
        let expires = now
            .checked_add(u64::from(payload.expires_in_seconds) * 1000)
            .filter(|t| *t <= MAX_WIRE_COUNTER)
            .ok_or(ControlError::CounterExhausted)?;
        // Consume the action key durably BEFORE entropy. This safe terminal
        // reservation intentionally has no token/verifier. If anything fails or
        // the process exits afterward, the same key cannot generate a different
        // secret. Existing access remains unchanged until the final atomic commit.
        let mut reserved = lease.state().clone();
        let index = reserved.secrets.actions.len();
        reserved.secrets.actions.push(SecretActionRecord {
            principal: principal.clone(),
            method: SecretActionKind::PublicationTokenIssue,
            key,
            request_digest: digest,
            outcome: SecretActionOutcome::Failed(ControlError::SecretResultUnavailable),
        });
        secret_checkpoint(
            &mut *lease,
            reserved,
            now,
            audit_admin(
                principal,
                SecurityAuditAction::PublicationTokenIssuePrepared,
                id.as_str(),
            ),
        )?;
        let token = self
            .secret_manager
            .generate_publication_token(secret_deadline())?;
        record.verifier = Some(self.secret_manager.publication_verifier(token.expose())?);
        record.summary.token = PublicationTokenStatus {
            state: PublicationTokenState::Active,
            version: next_revision(record.summary.token.version)?,
            issued_at: Some(now),
            expires_at: Some(expires),
        };
        record.summary.revision = next_revision(record.summary.revision)?;
        record.summary.updated_at = now;
        let summary = record.summary.clone();
        let mut next = lease.state().clone();
        next.secrets.publications.insert(id.clone(), record);
        next.secrets
            .actions
            .get_mut(index)
            .ok_or(ControlError::CorruptState)?
            .outcome = SecretActionOutcome::TokenIssued {
            publication_id: id.clone(),
            revision: summary.revision,
        };
        secret_checkpoint(
            &mut *lease,
            next,
            now,
            audit_admin(
                principal,
                SecurityAuditAction::PublicationTokenIssued,
                id.as_str(),
            ),
        )?;
        Ok(IssuedPublicationToken {
            publication: summary,
            token,
        })
    }
    pub fn revoke_publication_token(
        &self,
        principal: &UserId,
        id: &PublicationId,
        expected: Revision,
        key: IdempotencyKey,
        payload: PublicationRevokePayload,
    ) -> Result<PublicationSummary, ControlError> {
        if !payload.confirm_revoke_access.is_confirmed() {
            return Err(ControlError::ConfirmationMismatch);
        }
        let digest = ContentDigest::of(
            "vp.publication-token-revoke.v1",
            &(principal, id, expected, &payload),
        )?;
        let mut lease = self.store.writer()?;
        if let Some(result) = prior_secret_action(
            lease.state(),
            principal,
            SecretActionKind::PublicationTokenRevoke,
            &key,
            &digest,
        )? {
            return publication_result(result);
        }
        ensure_secret_write(lease.state())?;
        let mut record = lease
            .state()
            .secrets
            .publications
            .get(id)
            .filter(|r| &r.principal == principal)
            .cloned()
            .ok_or(ControlError::NotFound)?;
        check_revision(expected, record.summary.revision)?;
        revoke(&mut record);
        record.summary.revision = next_revision(record.summary.revision)?;
        record.summary.updated_at = self.clock.now_ms()?;
        // Revoking fetch permission NEVER changes nodes/users or retires vault credentials.
        self.save_publication_action(
            &mut *lease,
            key,
            digest,
            SecretActionKind::PublicationTokenRevoke,
            record,
            SecurityAuditAction::PublicationTokenRevoked,
        )
    }
    pub fn fetch_publication(
        &self,
        id: &PublicationId,
        token: SecretBytes,
    ) -> Result<SubscriptionContent, ControlError> {
        // Authenticate from an ordinary bounded read before expensive probes or
        // acquiring the global writer; recheck under lease to close rotate races.
        let preliminary = self.store.read()?;
        preliminary.verify_integrity()?;
        self.authenticate_publication(&preliminary, id, token.expose(), self.clock.now_ms()?)?;
        let mut lease = self.store.writer()?;
        lease.state().verify_integrity()?;
        let now = self.clock.now_ms()?;
        let record = self
            .authenticate_publication(lease.state(), id, token.expose(), now)?
            .clone();
        drop(token);
        let active = self
            .verified_publication_active(lease.state(), record.summary.source_revision)?
            .clone();
        let bytes = self.prepare_publication_content(&active, &record.summary)?;
        let now = self.clock.now_ms()?;
        if record
            .summary
            .token
            .expires_at
            .is_none_or(|expires| now >= expires)
        {
            return Err(ControlError::PermissionDenied);
        }
        let mut next = lease.state().clone();
        next.secrets
            .publications
            .get_mut(id)
            .ok_or(ControlError::CorruptState)?
            .summary
            .last_successful_read_at = Some(now);
        // Fully assembled output remains private until this bounded audit commit
        // succeeds. No half-response is emitted if persistence fails.
        secret_checkpoint(
            &mut *lease,
            next,
            now,
            SecurityAuditEvent {
                actor: SecurityAuditActor::PublicationToken {
                    id: id.clone(),
                    version: record.summary.token.version,
                },
                action: SecurityAuditAction::PublicationFetched,
                subject: id.as_str().into(),
            },
        )?;
        Ok(SubscriptionContent {
            bytes,
            source_revision: active.revision,
        })
    }
    fn authenticate_publication<'a>(
        &self,
        state: &'a StoredState,
        id: &PublicationId,
        token: &[u8],
        now: u64,
    ) -> Result<&'a PublicationRecord, ControlError> {
        let record = state
            .secrets
            .publications
            .get(id)
            .ok_or(ControlError::PermissionDenied)?;
        let status = &record.summary.token;
        if !record.summary.enabled
            || status.state != PublicationTokenState::Active
            || !status
                .issued_at
                .zip(status.expires_at)
                .is_some_and(|(issued, expires)| now >= issued && now < expires)
            || !record
                .verifier
                .as_ref()
                .is_some_and(|v| self.secret_manager.verify_publication_token(v, token))
        {
            return Err(ControlError::PermissionDenied);
        }
        Ok(record)
    }
    fn prepare_publication_content(
        &self,
        active: &RevisionRecord,
        publication: &PublicationSummary,
    ) -> Result<SecretBytes, ControlError> {
        let deadline = secret_deadline();
        let mut output = Zeroizing::new(Vec::new());
        for source in &publication.sources {
            let listener = active
                .config
                .listeners
                .iter()
                .find(|l| l.id == source.listener_id && l.enabled)
                .ok_or(ControlError::InvalidConfiguration)?;
            let ServerProtocol::Proxy { protocol, users } = &listener.protocol else {
                return Err(ControlError::ExecutorUnavailable);
            };
            let user = users
                .iter()
                .find(|u| u.id == source.user_id && u.enabled)
                .ok_or(ControlError::InvalidConfiguration)?;
            // No TLS/REALITY public-identity guess. A later compiler-v2 asset
            // resolver must prove that mapping before these kinds are enabled.
            if listener.transport != (Transport::Tcp {})
                || listener.security != (ServerSecurity::None {})
                || source.client_security != (ClientSecurity::None {})
            {
                return Err(ControlError::ExecutorUnavailable);
            }
            let kind = match protocol {
                Protocol::Vless { flow: None } | Protocol::Vmess { .. } => {
                    NodeCredentialKind::Uuid {}
                }
                Protocol::Shadowsocks { method } => {
                    NodeCredentialKind::Shadowsocks { method: *method }
                }
                _ => return Err(ControlError::ExecutorUnavailable),
            };
            let bytes = self
                .secret_manager
                .load_credential(&user.credential_ref, &kind, None, deadline)?
                .ok_or(ControlError::NotFound)?;
            let credential = match kind {
                NodeCredentialKind::Uuid {} => Credential::uuid(bytes.expose().to_vec()),
                NodeCredentialKind::Shadowsocks { .. } => {
                    Credential::password(bytes.expose().to_vec())
                }
                _ => return Err(ControlError::ExecutorUnavailable),
            };
            drop(bytes);
            let node_id = ContentDigest::of(
                "vp.publication-node-id.v1",
                &(&publication.id, &source.listener_id, &source.user_id),
            )?;
            let node = NodeProfile {
                schema_version: 1,
                id: NodeId::new(format!("published-{}", node_id.as_str()))
                    .map_err(|_| ControlError::InvalidConfiguration)?,
                name: listener.name.clone(),
                endpoint: source.endpoint.clone(),
                protocol: protocol.clone(),
                transport: listener.transport.clone(),
                security: source.client_security.clone(),
                credential_ref: user.credential_ref.clone(),
                requirements: listener.requirements.clone(),
                source_ref: None,
            };
            let text = vp_product_import::export_uri(
                &node,
                &SecretBundle {
                    credential,
                    obfuscation: None,
                },
            )
            .map_err(|issue| match issue.kind {
                vp_product_import::IssueKind::LossyExport => ControlError::ExportLossy,
                _ => ControlError::InvalidConfiguration,
            })?;
            if output
                .len()
                .checked_add(text.expose().len() + 1)
                .is_none_or(|n| n > 256 * 1024)
            {
                return Err(ControlError::InvalidRequest);
            }
            output.extend_from_slice(text.expose().as_bytes());
            output.push(b'\n');
            if Instant::now() >= deadline {
                return Err(ControlError::ExecutorFailed);
            }
        }
        if output.is_empty() {
            return Err(ControlError::InvalidConfiguration);
        }
        Ok(SecretBytes::new(std::mem::take(&mut *output)))
    }
}
fn revoke(record: &mut PublicationRecord) {
    record.verifier = None;
    if record.summary.token.state != PublicationTokenState::NotIssued {
        record.summary.token.state = PublicationTokenState::Revoked;
    }
}
