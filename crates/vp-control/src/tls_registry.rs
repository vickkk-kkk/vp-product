//! Private envelope-4 persistence foundation. No production importer/factory is
//! enabled. Persisted facts are not an authorization token; only a writer-held
//! aggregate and an internally verified bundle can produce an import mutation.
use crate::{ContentDigest, ControlError, GenesisPhase, InstanceBinding, StoredState};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicFacts {
    chain_digest: ContentDigest,
    chain_size: u32,
    leaf_digest: ContentDigest,
    spki_digest: ContentDigest,
    // X.509 facts: signed seconds, inclusive endpoints (including equality).
    not_before: i64,
    not_after: i64,
    policy: String,
    display_dns_names: Vec<String>,
}
impl PublicFacts {
    fn validate(&self) -> Result<(), ControlError> {
        if self.chain_size == 0
            || self.chain_size > 65536
            || self.not_before > self.not_after
            || !token(&self.policy)
            || self.display_dns_names.len() > 128
            || self
                .display_dns_names
                .iter()
                .any(|n| n.is_empty() || n.len() > 253 || !n.is_ascii())
        {
            return Err(ControlError::CorruptState);
        }
        Ok(())
    }
}
/// Deliberately has NO public constructor and NO Deserialize implementation.
/// The private-tls backend validates DER, SPKI, trusted backend anchors/name/time
/// and these facts. Disk metadata is not this proof. Only the private descendant
/// service and cfg(test) synthetic code construct it; no production factory is wired.
pub struct VerifiedTlsImport {
    facts: PublicFacts,
}
/// Separate unforgeable readback evidence. Upload proof is not accepted here.
pub struct VerifiedTlsReadback {
    facts: PublicFacts,
    asset_id: String,
    chain_ref: String,
    chain_version: u64,
    key_ref: String,
    key_version: u64,
}
/// Future exact authenticated tombstone observation, not a caller boolean.
pub struct VerifiedTlsRetirement {
    asset_id: String,
    chain_ref: String,
    chain_version: u64,
    key_ref: String,
    key_version: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AssetPhase {
    PendingImport,
    Available,
    PendingRetire,
    Retired,
    Aborted,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Asset {
    id: String,
    revision: u64,
    import_action: String,
    chain_ref: String,
    chain_kind: u8,
    chain_version: u64,
    key_ref: String,
    key_kind: u8,
    key_version: u64,
    key_role: String,
    encoding: String,
    phase: AssetPhase,
    facts: PublicFacts,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ActionPhase {
    ImportReserved,
    ImportCompleted,
    Aborted,
    RetireReserved,
    RetireCompleted,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Action {
    id: String,
    asset_id: String,
    actor: String,
    idempotency: String,
    created_at_ms: u64,
    phase: ActionPhase,
    historical_loss: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsControlEnvelope {
    schema_version: u16,
    binding: InstanceBinding,
    phase: GenesisPhase,
    state: StoredState,
    #[serde(deserialize_with = "unique_map")]
    certificate_assets: BTreeMap<String, Asset>,
    #[serde(deserialize_with = "unique_map")]
    certificate_actions: BTreeMap<String, Action>,
}
fn unique_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct Unique<V>(std::marker::PhantomData<V>);
    impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for Unique<V> {
        type Value = BTreeMap<String, V>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded map with unique keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, V>()? {
                if result.len() >= 32768 || result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive registry entries",
                    ));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}
/// Explicit envelope-4 journal. Never masquerades as an ordinary operation event.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsAssetEvent {
    pub sequence: u64,
    pub at_ms: u64,
    action: String,
    asset: String,
    transition: ActionPhase,
}
/// Single-use transition bound to the exact source aggregate, not just revision.
pub struct TlsAssetMutation {
    previous: ContentDigest,
    next: TlsControlEnvelope,
    event: TlsAssetEvent,
}
impl TlsAssetMutation {
    pub fn into_parts(self) -> (ContentDigest, TlsControlEnvelope, TlsAssetEvent) {
        (self.previous, self.next, self.event)
    }
}
fn token(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn identifier(v: &str) -> bool {
    vp_product_domain::CertificateId::new(v).is_ok()
}
fn secret_ref(v: &str) -> bool {
    vp_product_domain::SecretRef::try_from(v.to_owned()).is_ok()
        && v != "secret:vp-instance-binding-v1"
}

impl TlsControlEnvelope {
    pub fn preparing(binding: InstanceBinding) -> Result<Self, ControlError> {
        binding.validate_tls_profile()?;
        Ok(Self {
            schema_version: 4,
            binding,
            phase: GenesisPhase::Preparing,
            state: StoredState::default(),
            certificate_assets: BTreeMap::new(),
            certificate_actions: BTreeMap::new(),
        })
    }
    pub fn state(&self) -> &StoredState {
        &self.state
    }
    pub fn binding(&self) -> &InstanceBinding {
        &self.binding
    }
    pub fn phase(&self) -> GenesisPhase {
        self.phase
    }
    pub fn digest(&self) -> Result<ContentDigest, ControlError> {
        self.validate()?;
        ContentDigest::of("vp.tls-control-envelope.v4", self)
    }
    pub fn mark_initialized(&mut self) -> Result<(), ControlError> {
        self.validate()?;
        if self.phase != GenesisPhase::Preparing {
            return Err(ControlError::RecoveryRequired);
        }
        self.phase = GenesisPhase::Initialized;
        Ok(())
    }
    pub fn needs_recovery(&self) -> bool {
        self.state.needs_recovery()
            || self.certificate_actions.values().any(|a| {
                matches!(
                    a.phase,
                    ActionPhase::ImportReserved | ActionPhase::RetireReserved
                )
            })
    }
    /// Ordinary lifecycle/recovery must be able to finish its own checkpoints.
    /// Only a pending TLS action excludes the ordinary pipeline here; ordinary
    /// in-flight/recovery policy belongs to the existing ControlService methods.
    pub fn require_ordinary_access(&self) -> Result<(), ControlError> {
        self.validate()?;
        if self.phase != GenesisPhase::Initialized
            || self.certificate_actions.values().any(|a| {
                matches!(
                    a.phase,
                    ActionPhase::ImportReserved | ActionPhase::RetireReserved
                )
            })
        {
            return Err(ControlError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn require_admission(&self, expected_version: u64) -> Result<(), ControlError> {
        self.require_ordinary_access()?;
        if self.state.needs_recovery() {
            return Err(ControlError::RecoveryRequired);
        }
        if self.state.version != expected_version {
            return Err(ControlError::ResourceConflict);
        }
        Ok(())
    }
    /// Ordinary writes retain all registry/action bytes and cannot run while an
    /// asset action is pending. This does not authorize any TLS material.
    pub fn with_ordinary_state(&self, next: StoredState) -> Result<Self, ControlError> {
        self.require_ordinary_access()?;
        if self.state.version.checked_add(1) != Some(next.version) {
            return Err(ControlError::CorruptState);
        }
        let mut result = self.clone();
        result.state = next;
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != 4
            || self.certificate_assets.len() > 16384
            || self.certificate_actions.len() > 32768
        {
            return Err(ControlError::CorruptState);
        }
        self.binding.validate_tls_profile()?;
        self.state.verify_integrity()?;
        if self
            .certificate_actions
            .values()
            .filter(|a| {
                matches!(
                    a.phase,
                    ActionPhase::ImportReserved | ActionPhase::RetireReserved
                )
            })
            .count()
            > 1
        {
            return Err(ControlError::CorruptState);
        }
        if self.phase == GenesisPhase::Preparing
            && (!self.certificate_assets.is_empty()
                || !self.certificate_actions.is_empty()
                || serde_json::to_vec(&self.state).ok()
                    != serde_json::to_vec(&StoredState::default()).ok())
        {
            return Err(ControlError::CorruptState);
        }
        let mut credential_refs = BTreeSet::new();
        for c in self.state.secrets.credentials.values() {
            credential_refs.insert(c.summary.secret_ref.as_str());
        }
        for a in &self.state.secrets.actions {
            match &a.outcome {
                crate::SecretActionOutcome::PendingCreate(c) => {
                    credential_refs.insert(c.summary.secret_ref.as_str());
                }
                crate::SecretActionOutcome::Credential(c) => {
                    credential_refs.insert(c.secret_ref.as_str());
                }
                _ => {}
            }
        }
        let mut refs = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for (id, a) in &self.certificate_assets {
            a.facts.validate()?;
            if id != &a.id
                || !identifier(id)
                || a.revision
                    != (if matches!(a.phase, AssetPhase::PendingRetire | AssetPhase::Retired) {
                        2
                    } else {
                        1
                    })
                || a.chain_kind != 6
                || a.key_kind != 2
                || a.chain_version == 0
                || a.key_version == 0
                || a.key_role != "tls-server-key"
                || a.encoding != "pem-v1"
                || !secret_ref(&a.chain_ref)
                || !secret_ref(&a.key_ref)
                || credential_refs.contains(a.chain_ref.as_str())
                || credential_refs.contains(a.key_ref.as_str())
                || !refs.insert(&a.chain_ref)
                || !refs.insert(&a.key_ref)
                || !self
                    .certificate_actions
                    .get(&a.import_action)
                    .is_some_and(|i| {
                        i.asset_id == *id
                            && matches!(
                                i.phase,
                                ActionPhase::ImportReserved
                                    | ActionPhase::ImportCompleted
                                    | ActionPhase::Aborted
                            )
                    })
            {
                return Err(ControlError::CorruptState);
            }
            let import = &self.certificate_actions[&a.import_action];
            if !matches!(
                (a.phase, import.phase),
                (AssetPhase::PendingImport, ActionPhase::ImportReserved)
                    | (AssetPhase::Aborted, ActionPhase::Aborted)
                    | (AssetPhase::Available, ActionPhase::ImportCompleted)
                    | (AssetPhase::PendingRetire, ActionPhase::ImportCompleted)
                    | (AssetPhase::Retired, ActionPhase::ImportCompleted)
            ) {
                return Err(ControlError::CorruptState);
            }
            let retires: Vec<_> = self
                .certificate_actions
                .values()
                .filter(|i| {
                    i.asset_id == *id
                        && matches!(
                            i.phase,
                            ActionPhase::RetireReserved | ActionPhase::RetireCompleted
                        )
                })
                .collect();
            if match a.phase {
                AssetPhase::PendingRetire => {
                    retires.len() != 1 || retires[0].phase != ActionPhase::RetireReserved
                }
                AssetPhase::Retired => {
                    retires.len() != 1 || retires[0].phase != ActionPhase::RetireCompleted
                }
                _ => !retires.is_empty(),
            } {
                return Err(ControlError::CorruptState);
            }
        }
        for (id, a) in &self.certificate_actions {
            if id != &a.id
                || !identifier(id)
                || !identifier(&a.actor)
                || !identifier(&a.idempotency)
                || !keys.insert((&a.actor, &a.idempotency))
                || !self.certificate_assets.contains_key(&a.asset_id)
            {
                return Err(ControlError::CorruptState);
            }
            if matches!(
                a.phase,
                ActionPhase::ImportReserved | ActionPhase::ImportCompleted | ActionPhase::Aborted
            ) && self.certificate_assets[&a.asset_id].import_action != *id
            {
                return Err(ControlError::CorruptState);
            }
        }
        Ok(())
    }
    fn mutation(
        &self,
        mut next: Self,
        action: &str,
        now: u64,
    ) -> Result<TlsAssetMutation, ControlError> {
        next.state.version = self
            .state
            .version
            .checked_add(1)
            .ok_or(ControlError::CounterExhausted)?;
        next.validate()?;
        let a = next
            .certificate_actions
            .get(action)
            .ok_or(ControlError::CorruptState)?;
        let event = TlsAssetEvent {
            sequence: next.state.version,
            at_ms: now,
            action: action.into(),
            asset: a.asset_id.clone(),
            transition: a.phase,
        };
        Ok(TlsAssetMutation {
            previous: self.digest()?,
            next,
            event,
        })
    }
    /// External callers cannot manufacture `verified`. The private-tls descendant
    /// service constructs it after validation; no production composition selects it.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_import(
        &self,
        expected: u64,
        actor: &str,
        action: &str,
        idempotency: &str,
        asset: &str,
        chain_ref: &str,
        key_ref: &str,
        now: u64,
        verified: VerifiedTlsImport,
    ) -> Result<TlsAssetMutation, ControlError> {
        self.require_admission(expected)?;
        if self.certificate_assets.contains_key(asset)
            || self.certificate_actions.contains_key(action)
        {
            return Err(ControlError::InvalidRequest);
        }
        let mut next = self.clone();
        next.certificate_assets.insert(
            asset.into(),
            Asset {
                id: asset.into(),
                revision: 1,
                import_action: action.into(),
                chain_ref: chain_ref.into(),
                chain_kind: 6,
                chain_version: 1,
                key_ref: key_ref.into(),
                key_kind: 2,
                key_version: 1,
                key_role: "tls-server-key".into(),
                encoding: "pem-v1".into(),
                phase: AssetPhase::PendingImport,
                facts: verified.facts,
            },
        );
        next.certificate_actions.insert(
            action.into(),
            Action {
                id: action.into(),
                asset_id: asset.into(),
                actor: actor.into(),
                idempotency: idempotency.into(),
                created_at_ms: now,
                phase: ActionPhase::ImportReserved,
                historical_loss: false,
            },
        );
        self.mutation(next, action, now)
    }
    /// The private-tls service creates this proof from authenticated exact vault
    /// readback, never upload validation alone. Production wiring remains disabled.
    pub fn complete_import(
        &self,
        expected: u64,
        action: &str,
        now: u64,
        readback: VerifiedTlsReadback,
    ) -> Result<TlsAssetMutation, ControlError> {
        self.validate()?;
        if self.state.version != expected {
            return Err(ControlError::ResourceConflict);
        }
        let a = self
            .certificate_actions
            .get(action)
            .ok_or(ControlError::InvalidRequest)?;
        if a.phase != ActionPhase::ImportReserved || now < a.created_at_ms {
            return Err(ControlError::RecoveryRequired);
        }
        let mut next = self.clone();
        let asset = next
            .certificate_assets
            .get_mut(&a.asset_id)
            .ok_or(ControlError::CorruptState)?;
        if asset.facts != readback.facts
            || asset.id != readback.asset_id
            || asset.chain_ref != readback.chain_ref
            || asset.chain_version != readback.chain_version
            || asset.key_ref != readback.key_ref
            || asset.key_version != readback.key_version
        {
            return Err(ControlError::InvalidRequest);
        }
        asset.phase = AssetPhase::Available;
        next.certificate_actions
            .get_mut(action)
            .ok_or(ControlError::CorruptState)?
            .phase = ActionPhase::ImportCompleted;
        self.mutation(next, action, now)
    }
    pub fn abort_import(
        &self,
        expected: u64,
        action: &str,
        now: u64,
    ) -> Result<TlsAssetMutation, ControlError> {
        self.validate()?;
        if self.state.version != expected {
            return Err(ControlError::ResourceConflict);
        }
        let a = self
            .certificate_actions
            .get(action)
            .ok_or(ControlError::InvalidRequest)?;
        if a.phase != ActionPhase::ImportReserved || now < a.created_at_ms {
            return Err(ControlError::RecoveryRequired);
        }
        let mut next = self.clone();
        next.certificate_assets
            .get_mut(&a.asset_id)
            .ok_or(ControlError::CorruptState)?
            .phase = AssetPhase::Aborted;
        next.certificate_actions
            .get_mut(action)
            .ok_or(ControlError::CorruptState)?
            .phase = ActionPhase::Aborted;
        self.mutation(next, action, now)
    }
}

impl TlsControlEnvelope {
    /// Inspect all serialized references conservatively; false positives refuse.
    /// Inactive revision history is separated, never silently removed.
    fn reference_usage(&self, a: &Asset) -> Result<(bool, bool), ControlError> {
        fn contains(v: &serde_json::Value, refs: &[&str]) -> bool {
            match v {
                serde_json::Value::String(s) => refs.contains(&s.as_str()),
                serde_json::Value::Array(xs) => xs.iter().any(|v| contains(v, refs)),
                serde_json::Value::Object(xs) => xs
                    .iter()
                    .any(|(k, v)| refs.contains(&k.as_str()) || contains(v, refs)),
                _ => false,
            }
        }
        let refs = [a.id.as_str(), a.chain_ref.as_str(), a.key_ref.as_str()];
        let mut live = self.state.clone();
        let live_publication_revisions: BTreeSet<_> = self
            .state
            .secrets
            .publications
            .values()
            .filter(|p| p.summary.enabled)
            .map(|p| p.summary.source_revision)
            .collect();
        live.revisions.retain(|r| {
            r.revision == self.state.active_revision
                || live_publication_revisions.contains(&r.revision)
        });
        let mut historical = self
            .state
            .revisions
            .iter()
            .filter(|r| {
                r.revision != self.state.active_revision
                    && !live_publication_revisions.contains(&r.revision)
            })
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ControlError::CorruptState)?;
        historical.push(
            serde_json::to_value(&live.draft_idempotency)
                .map_err(|_| ControlError::CorruptState)?,
        );
        live.draft_idempotency.clear();
        // A retained plan is inert history only when it has terminal operations,
        // none belongs to the active revision, and none can require recovery.
        // Unused plans and every queued/in-flight plan remain live dependencies.
        let active_operation = self.state.active().map(|r| &r.operation_id);
        for (id, plan) in &self.state.plans {
            let ops: Vec<_> = self
                .state
                .operations
                .values()
                .filter(|o| &o.plan_id == id)
                .collect();
            if !ops.is_empty()
                && ops
                    .iter()
                    .all(|o| o.state.is_terminal() && Some(&o.id) != active_operation)
            {
                historical
                    .push(serde_json::to_value(plan).map_err(|_| ControlError::CorruptState)?);
                live.plans.remove(id);
                for op in ops {
                    historical
                        .push(serde_json::to_value(op).map_err(|_| ControlError::CorruptState)?);
                    live.operations.remove(&op.id);
                }
            }
        }
        let live = serde_json::to_value(live).map_err(|_| ControlError::CorruptState)?;
        Ok((
            contains(&live, &refs),
            historical.iter().any(|v| contains(v, &refs)),
        ))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_retirement(
        &self,
        expected: u64,
        asset_id: &str,
        asset_revision: u64,
        actor: &str,
        action: &str,
        idempotency: &str,
        confirm_history_loss: bool,
        now: u64,
    ) -> Result<TlsAssetMutation, ControlError> {
        self.require_admission(expected)?;
        let asset = self
            .certificate_assets
            .get(asset_id)
            .ok_or(ControlError::NotFound)?;
        if asset.phase != AssetPhase::Available
            || asset.revision != asset_revision
            || self.certificate_actions.contains_key(action)
        {
            return Err(ControlError::ResourceConflict);
        }
        let (live, history) = self.reference_usage(asset)?;
        if live {
            return Err(ControlError::ResourceConflict);
        }
        if history && !confirm_history_loss {
            return Err(ControlError::ConfirmationMismatch);
        }
        let mut next = self.clone();
        let a = next
            .certificate_assets
            .get_mut(asset_id)
            .ok_or(ControlError::CorruptState)?;
        a.phase = AssetPhase::PendingRetire;
        a.revision = a
            .revision
            .checked_add(1)
            .ok_or(ControlError::CounterExhausted)?;
        next.certificate_actions.insert(
            action.into(),
            Action {
                id: action.into(),
                asset_id: asset_id.into(),
                actor: actor.into(),
                idempotency: idempotency.into(),
                created_at_ms: now,
                phase: ActionPhase::RetireReserved,
                historical_loss: history,
            },
        );
        self.mutation(next, action, now)
    }
    pub fn complete_retirement(
        &self,
        expected: u64,
        action: &str,
        now: u64,
        verified: VerifiedTlsRetirement,
    ) -> Result<TlsAssetMutation, ControlError> {
        self.validate()?;
        if self.state.version != expected {
            return Err(ControlError::ResourceConflict);
        }
        let action_record = self
            .certificate_actions
            .get(action)
            .ok_or(ControlError::NotFound)?;
        let a = self
            .certificate_assets
            .get(&action_record.asset_id)
            .ok_or(ControlError::CorruptState)?;
        if action_record.phase != ActionPhase::RetireReserved
            || now < action_record.created_at_ms
            || verified.asset_id != a.id
            || verified.chain_ref != a.chain_ref
            || verified.key_ref != a.key_ref
            || verified.chain_version != a.chain_version
            || verified.key_version != a.key_version
        {
            return Err(ControlError::RecoveryRequired);
        }
        let mut next = self.clone();
        next.certificate_assets
            .get_mut(&a.id)
            .ok_or(ControlError::CorruptState)?
            .phase = AssetPhase::Retired;
        next.certificate_actions
            .get_mut(action)
            .ok_or(ControlError::CorruptState)?
            .phase = ActionPhase::RetireCompleted;
        self.mutation(next, action, now)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn empty() -> TlsControlEnvelope {
        let d = ContentDigest::bytes(b"synthetic");
        let mut e = TlsControlEnvelope::preparing(InstanceBinding {
            binding_version: 1,
            genesis_id: "1".repeat(32),
            vault_id: "2".repeat(32),
            namespace_digest: d.clone(),
            administrator_commitment: d.clone(),
            preparation_digest: d.clone(),
            activation_intent_digest: d.clone(),
            artifact_set_digest: d,
            profile: crate::FRESH_TLS_RUNTIME_PROFILE.into(),
        })
        .unwrap();
        e.mark_initialized().unwrap();
        e
    }
    fn facts() -> PublicFacts {
        PublicFacts {
            chain_digest: ContentDigest::bytes(b"test chain"),
            chain_size: 10,
            leaf_digest: ContentDigest::bytes(b"test leaf"),
            spki_digest: ContentDigest::bytes(b"test public key"),
            not_before: -1,
            not_after: -1,
            policy: "synthetic-test-only".into(),
            display_dns_names: vec!["test.invalid".into()],
        }
    }
    fn readback(facts: PublicFacts) -> VerifiedTlsReadback {
        VerifiedTlsReadback {
            facts,
            asset_id: "cert".into(),
            chain_ref: "secret:chain".into(),
            chain_version: 1,
            key_ref: "secret:key".into(),
            key_version: 1,
        }
    }
    fn pending() -> TlsControlEnvelope {
        empty()
            .reserve_import(
                0,
                "actor",
                "action",
                "request",
                "cert",
                "secret:chain",
                "secret:key",
                1,
                VerifiedTlsImport { facts: facts() },
            )
            .unwrap()
            .into_parts()
            .1
    }
    fn available() -> TlsControlEnvelope {
        pending()
            .complete_import(1, "action", 2, readback(facts()))
            .unwrap()
            .into_parts()
            .1
    }
    #[test]
    fn new_envelope_is_strict_and_legacy_refuses_even_empty() {
        let value = serde_json::to_value(empty()).unwrap();
        assert!(serde_json::from_value::<crate::FreshControlEnvelope>(value.clone()).is_err());
        for field in ["certificateAssets", "certificateActions"] {
            let mut v = value.clone();
            v.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<TlsControlEnvelope>(v).is_err());
        }
        let mut v = value;
        v["unexpected"] = true.into();
        assert!(serde_json::from_value::<TlsControlEnvelope>(v).is_err());
    }
    #[test]
    fn pending_blocks_admission_and_ordinary_writes() {
        let e = pending();
        assert!(e.needs_recovery());
        assert!(e.require_admission(1).is_err());
        let mut state = e.state.clone();
        state.version += 1;
        assert!(e.with_ordinary_state(state).is_err());
    }
    #[test]
    fn import_advances_global_cas_not_active_revision() {
        let e = available();
        assert_eq!(e.state.version, 2);
        assert_eq!(e.state.active_revision, empty().state.active_revision);
        assert!(e.require_admission(0).is_err());
        assert!(e.require_admission(2).is_ok());
    }
    #[test]
    fn exact_public_identity_required_on_readback() {
        let mut f = facts();
        f.spki_digest = ContentDigest::bytes(b"wrong public key");
        assert!(pending()
            .complete_import(1, "action", 2, readback(f))
            .is_err());
    }
    #[test]
    fn aborted_refs_and_scoped_idempotency_never_reused() {
        let e = pending()
            .abort_import(1, "action", 2)
            .unwrap()
            .into_parts()
            .1;
        assert!(!e.needs_recovery());
        for (request, chain, key) in [
            ("new", "secret:chain", "secret:other"),
            ("request", "secret:other", "secret:other2"),
        ] {
            assert!(e
                .reserve_import(
                    2,
                    "actor",
                    "other-action",
                    request,
                    "other-cert",
                    chain,
                    key,
                    3,
                    VerifiedTlsImport { facts: facts() }
                )
                .is_err());
        }
        assert!(e
            .complete_import(2, "action", 3, readback(facts()))
            .is_err());
    }
    #[test]
    fn alias_reserved_ref_and_role_corruption_refused() {
        for (chain, key) in [
            ("secret:same", "secret:same"),
            ("secret:vp-instance-binding-v1", "secret:key"),
        ] {
            assert!(empty()
                .reserve_import(
                    0,
                    "actor",
                    "action",
                    "request",
                    "cert",
                    chain,
                    key,
                    1,
                    VerifiedTlsImport { facts: facts() }
                )
                .is_err());
        }
        let mut e = available();
        e.certificate_assets.get_mut("cert").unwrap().key_kind = 6;
        assert!(e.validate().is_err());
    }
    #[test]
    fn signed_equal_inclusive_validity_facts_preserved() {
        let e = available();
        assert_eq!(e.certificate_assets["cert"].facts.not_before, -1);
        assert_eq!(e.certificate_assets["cert"].facts.not_after, -1);
        let mut bad = e;
        bad.certificate_assets
            .get_mut("cert")
            .unwrap()
            .facts
            .not_before = 0;
        assert!(bad.validate().is_err());
    }
    #[test]
    fn ordinary_write_preserves_registry_and_actions() {
        let e = available();
        let mut state = e.state.clone();
        state.version += 1;
        let next = e.with_ordinary_state(state).unwrap();
        assert_eq!(
            serde_json::to_value(&e.certificate_assets).unwrap(),
            serde_json::to_value(&next.certificate_assets).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&e.certificate_actions).unwrap(),
            serde_json::to_value(&next.certificate_actions).unwrap()
        );
    }
    #[test]
    fn repeated_completion_and_clock_regression_refused() {
        assert!(pending()
            .complete_import(1, "action", 0, readback(facts()))
            .is_err());
        assert!(available()
            .complete_import(2, "action", 3, readback(facts()))
            .is_err());
    }
    #[test]
    fn mutation_is_bound_to_full_aggregate() {
        let e = pending();
        let mut changed = e.clone();
        changed.certificate_actions.get_mut("action").unwrap().actor = "other".into();
        assert!(e.digest().unwrap() != changed.digest().unwrap());
        let (previous, next, event) = e.abort_import(1, "action", 2).unwrap().into_parts();
        assert_eq!(previous, e.digest().unwrap());
        assert_eq!(event.sequence, next.state.version);
    }
    #[test]
    fn retirement_is_pending_until_exact_proof_then_irreversible() {
        let e = available()
            .reserve_retirement(2, "cert", 1, "actor", "retire", "retire-request", false, 3)
            .unwrap()
            .into_parts()
            .1;
        assert!(e.needs_recovery());
        let proof = VerifiedTlsRetirement {
            asset_id: "cert".into(),
            chain_ref: "secret:chain".into(),
            chain_version: 1,
            key_ref: "secret:key".into(),
            key_version: 1,
        };
        let e = e
            .complete_retirement(3, "retire", 4, proof)
            .unwrap()
            .into_parts()
            .1;
        assert!(!e.needs_recovery());
        assert!(e
            .reserve_retirement(
                4,
                "cert",
                2,
                "actor",
                "retire-again",
                "request-again",
                false,
                5
            )
            .is_err());
        assert_eq!(e.state.active_revision, empty().state.active_revision);
    }
    #[test]
    fn missing_or_duplicate_actions_and_bad_versions_refused() {
        let mut e = pending();
        e.certificate_actions.clear();
        assert!(e.validate().is_err());
        let mut e = pending();
        e.certificate_assets.get_mut("cert").unwrap().chain_version = 0;
        assert!(e.validate().is_err());
        let mut e = available();
        e.certificate_assets.get_mut("cert").unwrap().phase = AssetPhase::Retired;
        assert!(e.validate().is_err());
    }
    #[test]
    fn serialized_records_have_no_private_key_digest_or_bytes() {
        let encoded = serde_json::to_string(&pending()).unwrap();
        for prohibited in [
            "privateKeyDigest",
            "privateKeyBytes",
            "BEGIN PRIVATE",
            "keyDigest",
        ] {
            assert!(!encoded.contains(prohibited));
        }
    }
    // A synthetically named release field exercises the conservative all-string
    // reference scanner without pretending to create a real TLS listener.
    fn with_history(mut e: TlsControlEnvelope, active: bool, terminal: bool) -> TlsControlEnvelope {
        use vp_product_domain::*;
        let config = ProductConfig {
            schema_version: 1,
            minimum_reader_version: 1,
            nodes: vec![],
            listeners: vec![],
            subscriptions: vec![],
        };
        let release = ReleaseIdentity {
            release_id: ReleaseId::new("release").unwrap(),
            product_version: "cert".into(),
            adapter_version: "synthetic".into(),
            core_commit: "a".repeat(40),
            patchset_hash: None,
            build_target: "test".into(),
            toolchain: "test".into(),
            schema_read: CompatibilityRange {
                minimum: 1,
                maximum: 1,
            },
            schema_write: CompatibilityRange {
                minimum: 1,
                maximum: 1,
            },
            abi: VersionPair { major: 1, minor: 0 },
            api: VersionPair { major: 1, minor: 0 },
            evidence_manifest_hash: None,
        };
        let config_digest = ContentDigest::of("vp.product-config.v1", &config).unwrap();
        let release_digest = ContentDigest::of("vp.release-identity.v1", &release).unwrap();
        let artifact_digest = ContentDigest::bytes(b"synthetic artifact");
        let id = PlanId::new("plan").unwrap();
        let operation = OperationId::new("operation").unwrap();
        let revision = Revision::ZERO.next().unwrap();
        let plan = crate::ChangePlan::seal(crate::PlanBody {
            schema_version: 1,
            id: id.clone(),
            principal: UserId::new("actor").unwrap(),
            base_revision: Revision::ZERO,
            target_revision: revision,
            created_at_ms: 1,
            expires_at_ms: 100,
            config: config.clone(),
            release: release.clone(),
            validation: crate::ValidationReceipt {
                config_digest: config_digest.clone(),
                release_digest: release_digest.clone(),
                artifact_digest: artifact_digest.clone(),
                impact: crate::RestartImpact::ControlledRestart,
                required_health: BTreeSet::new(),
            },
            resources: vec![],
        })
        .unwrap();
        e.state.plans.insert(id.clone(), plan);
        e.state.operations.insert(
            operation.clone(),
            crate::Operation {
                id: operation.clone(),
                plan_id: id,
                principal: UserId::new("actor").unwrap(),
                state: if terminal {
                    crate::OperationState::Committed
                } else {
                    crate::OperationState::Queued
                },
                created_at_ms: 1,
                updated_at_ms: 1,
                snapshot: None,
                failure: None,
                health: None,
                activation: None,
                cancel_requested: false,
                mutation_started: false,
            },
        );
        if terminal {
            let op = e.state.operations.get_mut(&operation).unwrap();
            op.health = Some(crate::RuntimeHealth {
                revision,
                operation_id: operation.clone(),
                config_digest: config_digest.clone(),
                release_digest: release_digest.clone(),
                generation: 1,
                checked_at_ms: 1,
                checks: vec![],
                external_connectivity: crate::CheckOutcome::NotChecked,
            });
            op.activation = Some(crate::RuntimeActivation {
                revision,
                operation_id: operation.clone(),
                config_digest: config_digest.clone(),
                release_digest: release_digest.clone(),
                generation: 1,
            });
            e.state.revisions.push(crate::RevisionRecord {
                revision,
                config,
                release,
                config_digest,
                release_digest,
                artifact_digest,
                operation_id: operation,
            });
            if active {
                e.state.active_revision = revision;
            }
        }
        e.validate().unwrap();
        e
    }
    #[test]
    fn active_and_queued_references_veto_retirement() {
        for (active, terminal) in [(true, true), (false, false)] {
            let e = with_history(available(), active, terminal);
            assert!(e
                .reserve_retirement(2, "cert", 1, "actor", "retire", "retire-request", true, 3)
                .is_err());
        }
    }
    #[test]
    fn inert_revision_and_terminal_plan_require_confirmed_history_loss_not_permanent_veto() {
        let e = with_history(available(), false, true);
        assert!(e
            .reserve_retirement(2, "cert", 1, "actor", "retire", "retire-request", false, 3)
            .is_err());
        assert!(e
            .reserve_retirement(1, "cert", 1, "actor", "retire", "retire-request", true, 3)
            .is_err());
        let next = e
            .reserve_retirement(2, "cert", 1, "actor", "retire", "retire-request", true, 3)
            .unwrap()
            .into_parts()
            .1;
        assert!(next.certificate_actions["retire"].historical_loss);
        assert_eq!(next.state.revisions.len(), 1);
        assert_eq!(next.state.plans.len(), 1);
    }
    #[test]
    fn readback_cannot_substitute_other_pair_or_version() {
        let mut wrong = readback(facts());
        wrong.key_ref = "secret:other".into();
        assert!(pending().complete_import(1, "action", 2, wrong).is_err());
        let mut wrong = readback(facts());
        wrong.chain_version = 2;
        assert!(pending().complete_import(1, "action", 2, wrong).is_err());
    }
    #[test]
    fn duplicate_registry_keys_rejected_before_overwrite() {
        let e = serde_json::to_string(&available()).unwrap();
        let action = serde_json::to_string(&available().certificate_actions["action"]).unwrap();
        let needle = format!("\"certificateActions\":{{\"action\":{action}");
        let duplicate = format!("\"certificateActions\":{{\"action\":{action},\"action\":{action}");
        assert!(e.contains(&needle));
        assert!(
            serde_json::from_str::<TlsControlEnvelope>(&e.replace(&needle, &duplicate)).is_err()
        );
    }
    #[test]
    fn ordinary_inflight_checkpoint_allowed_but_new_tls_admission_stays_blocked() {
        let mut e = with_history(available(), false, false);
        e.state.operations.values_mut().next().unwrap().state = crate::OperationState::Staging;
        assert!(e.needs_recovery());
        assert!(e.require_ordinary_access().is_ok());
        assert!(e.require_admission(e.state.version).is_err());
        assert!(e
            .reserve_import(
                e.state.version,
                "actor",
                "other-action",
                "other-request",
                "other-cert",
                "secret:other-chain",
                "secret:other-key",
                3,
                VerifiedTlsImport { facts: facts() }
            )
            .is_err());
        let mut state = e.state.clone();
        state.version += 1;
        state.operations.values_mut().next().unwrap().state = crate::OperationState::Snapshotting;
        assert!(e.with_ordinary_state(state).is_ok());
        assert!(pending().require_ordinary_access().is_err());
    }
}

#[cfg(feature = "private-tls")]
mod service;
#[cfg(feature = "private-tls")]
mod validation;
#[cfg(feature = "private-tls")]
pub use service::*;

#[cfg(feature = "private-tls")]
mod materials;
#[cfg(feature = "private-tls")]
pub use materials::{TlsMaterialAdmission, TlsMaterialVault};
