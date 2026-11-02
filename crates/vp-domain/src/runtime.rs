use crate::{EvidenceId, ListenerId, NodeId, OperationId, ProductError, Revision, SafeCode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ConnectionIntent {
    Disconnected {},
    Connected {
        #[serde(rename = "nodeId")]
        node_id: NodeId,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePhase {
    Idle,
    Preparing,
    AwaitingPermission,
    Starting,
    Verifying,
    Connected,
    Degraded,
    Reconnecting,
    Stopping,
    Failed,
    Recovering,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    NotRun,
    Passed,
    Failed,
    NotApplicable,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthObservation {
    pub status: ObservationStatus,
    pub observed_at: Option<u64>,
    pub evidence_id: Option<EvidenceId>,
    pub detail_key: Option<SafeCode>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeHealth {
    pub core: HealthObservation,
    pub takeover: HealthObservation,
    pub tunnel: HealthObservation,
    pub dns: HealthObservation,
    pub ipv4: HealthObservation,
    pub ipv6: HealthObservation,
    pub forwarding: HealthObservation,
    pub required_probes: Vec<HealthProbe>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthProbe {
    Core,
    Takeover,
    Tunnel,
    Dns,
    Ipv4,
    Ipv6,
    Forwarding,
}
impl RuntimeHealth {
    pub fn observation(&self, probe: HealthProbe) -> &HealthObservation {
        match probe {
            HealthProbe::Core => &self.core,
            HealthProbe::Takeover => &self.takeover,
            HealthProbe::Tunnel => &self.tunnel,
            HealthProbe::Dns => &self.dns,
            HealthProbe::Ipv4 => &self.ipv4,
            HealthProbe::Ipv6 => &self.ipv6,
            HealthProbe::Forwarding => &self.forwarding,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSnapshot {
    pub schema_version: u16,
    /// Opaque identifier changes when the hosting runtime process is replaced.
    pub instance_id: String,
    pub generation: Revision,
    pub sequence: Revision,
    /// Milliseconds since Unix epoch. UI must mark expired observations stale.
    pub observed_at: u64,
    pub valid_until: u64,
    pub desired: ConnectionIntent,
    pub phase: RuntimePhase,
    pub config_revision: Option<Revision>,
    pub desired_revision: Option<Revision>,
    pub node_id: Option<NodeId>,
    pub operation_id: Option<OperationId>,
    pub health: RuntimeHealth,
    pub error: Option<ProductError>,
}
impl RuntimeSnapshot {
    pub fn is_fresh(&self, now_ms: u64) -> bool {
        self.observed_at <= now_ms && now_ms < self.valid_until
    }
    pub fn connection_verified_at(&self, now_ms: u64) -> bool {
        self.is_fresh(now_ms) && self.connection_verified()
    }
    /// A process existing or start() returning is not connection evidence.
    /// For live UI decisions call connection_verified_at(now_ms), not this evidence-only check.
    pub fn connection_verified(&self) -> bool {
        let required = [
            HealthProbe::Core,
            HealthProbe::Takeover,
            HealthProbe::Tunnel,
            HealthProbe::Forwarding,
        ];
        self.phase == RuntimePhase::Connected
            && self.desired_revision.is_some()
            && self.config_revision == self.desired_revision
            && required
                .iter()
                .chain(self.health.required_probes.iter())
                .all(|probe| {
                    let observation = self.health.observation(*probe);
                    observation.status == ObservationStatus::Passed
                        && observation.evidence_id.is_some()
                        && observation.observed_at.is_some_and(|at| {
                            at <= self.observed_at
                                && self.valid_until > self.observed_at
                                && self.observed_at - at <= self.valid_until - self.observed_at
                        })
                })
            && matches!(&self.desired, ConnectionIntent::Connected { node_id } if Some(node_id) == self.node_id.as_ref())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ListenerObservedStatus {
    Configured,
    Disabled,
    Starting,
    Ready,
    Degraded,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerObservation {
    pub listener_id: ListenerId,
    pub generation: Revision,
    pub status: ListenerObservedStatus,
    pub bound: bool,
    pub authentication_loaded: bool,
    pub forwarding: HealthObservation,
    pub error: Option<ProductError>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RuntimeEventPayload {
    Snapshot {
        snapshot: Box<RuntimeSnapshot>,
    },
    PhaseChanged {
        phase: RuntimePhase,
        error: Option<ProductError>,
    },
    ListenerChanged {
        listener: ListenerObservation,
    },
    ResyncRequired {
        #[serde(rename = "lastRetainedSequence")]
        last_retained_sequence: Revision,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvent {
    pub schema_version: u16,
    pub instance_id: String,
    pub generation: Revision,
    pub sequence: Revision,
    pub operation_id: Option<OperationId>,
    pub revision: Option<Revision>,
    pub payload: RuntimeEventPayload,
}
/// Discard stale process/generation events and demand a snapshot after any gap.
pub fn event_disposition(snapshot: &RuntimeSnapshot, event: &RuntimeEvent) -> EventDisposition {
    if event.schema_version != crate::SCHEMA_VERSION
        || snapshot.schema_version != crate::SCHEMA_VERSION
        || event.instance_id != snapshot.instance_id
    {
        return EventDisposition::Resync;
    }
    if event.generation < snapshot.generation || event.sequence <= snapshot.sequence {
        return EventDisposition::IgnoreStale;
    }
    if event.generation > snapshot.generation
        || snapshot.sequence.next() != Some(event.sequence)
        || matches!(&event.payload, RuntimeEventPayload::ResyncRequired { .. })
    {
        EventDisposition::Resync
    } else {
        EventDisposition::Apply
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventDisposition {
    Apply,
    IgnoreStale,
    Resync,
}
