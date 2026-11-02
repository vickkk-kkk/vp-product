use vp_product_domain::{
    ConnectionIntent, ErrorCode, ErrorStage, HealthObservation, HealthProbe, ObservationStatus,
    ProductError, Revision, RuntimeHealth, RuntimePhase, RuntimeSnapshot, ServerListener,
    SCHEMA_VERSION,
};

/// No engine is held in this source-only gate. This is NOT an in-memory proxy,
/// fake successful runtime, or substitute for the specified vp_core.
pub struct CoreAdapter {
    snapshot: RuntimeSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopOutcome {
    NoRuntimeWasLoaded,
}

impl CoreAdapter {
    pub fn new(instance_id: String, now_ms: u64) -> Result<Self, ProductError> {
        if instance_id.is_empty()
            || instance_id.len() > 128
            || !instance_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(
                ProductError::new(ErrorCode::ConfigInvalid, ErrorStage::Validate).at("instanceId"),
            );
        }
        let not_run = || HealthObservation {
            status: ObservationStatus::NotRun,
            observed_at: None,
            evidence_id: None,
            detail_key: None,
        };
        Ok(Self {
            snapshot: RuntimeSnapshot {
                schema_version: SCHEMA_VERSION,
                instance_id,
                generation: Revision::ZERO,
                sequence: Revision::ZERO,
                observed_at: now_ms,
                valid_until: now_ms.saturating_add(30_000),
                desired: ConnectionIntent::Disconnected {},
                phase: RuntimePhase::Idle,
                config_revision: None,
                desired_revision: None,
                node_id: None,
                operation_id: None,
                health: RuntimeHealth {
                    core: not_run(),
                    takeover: not_run(),
                    tunnel: not_run(),
                    dns: not_run(),
                    ipv4: not_run(),
                    ipv6: not_run(),
                    forwarding: not_run(),
                    required_probes: vec![
                        HealthProbe::Core,
                        HealthProbe::Takeover,
                        HealthProbe::Tunnel,
                        HealthProbe::Dns,
                        HealthProbe::Ipv4,
                        HealthProbe::Ipv6,
                        HealthProbe::Forwarding,
                    ],
                },
                error: None,
            },
        })
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        self.snapshot.clone()
    }

    /// Validation can reject bad data, but never grants runtime availability.
    /// No upstream API, file, bind, resolver, TUN or credential vault is touched.
    pub fn start(
        &mut self,
        listeners: &[ServerListener],
        expected_generation: Revision,
        now_ms: u64,
    ) -> Result<(), ProductError> {
        self.check_generation(expected_generation, ErrorStage::Start)?;
        crate::validate_listeners(listeners)?;
        let error = ProductError::new(ErrorCode::CapabilityUnavailable, ErrorStage::Start)
            .at("runtime.managedListenerLifecycle");
        self.record(RuntimePhase::Failed, Some(error.clone()), now_ms)?;
        Err(error)
    }

    /// Clearing a source-gate failure is not represented as actual engine drain.
    pub fn stop(
        &mut self,
        expected_generation: Revision,
        now_ms: u64,
    ) -> Result<StopOutcome, ProductError> {
        self.check_generation(expected_generation, ErrorStage::Stop)?;
        self.record(RuntimePhase::Idle, None, now_ms)?;
        Ok(StopOutcome::NoRuntimeWasLoaded)
    }

    /// No listener/user/certificate change is mislabeled a route-only reload.
    pub fn apply_route_snapshot(&self, expected_generation: Revision) -> Result<(), ProductError> {
        self.check_generation(expected_generation, ErrorStage::Apply)?;
        Err(
            ProductError::new(ErrorCode::CapabilityUnavailable, ErrorStage::Apply)
                .at("runtime.routeSnapshot"),
        )
    }

    fn check_generation(&self, expected: Revision, stage: ErrorStage) -> Result<(), ProductError> {
        if expected != self.snapshot.generation {
            Err(ProductError::new(ErrorCode::RevisionConflict, stage))
        } else {
            Ok(())
        }
    }

    fn record(
        &mut self,
        phase: RuntimePhase,
        error: Option<ProductError>,
        now_ms: u64,
    ) -> Result<(), ProductError> {
        let sequence =
            self.snapshot.sequence.next().ok_or_else(|| {
                ProductError::new(ErrorCode::RecoveryRequired, ErrorStage::Recover)
            })?;
        self.snapshot.phase = phase;
        self.snapshot.error = error;
        self.snapshot.sequence = sequence;
        self.snapshot.observed_at = now_ms;
        self.snapshot.valid_until = now_ms.saturating_add(30_000);
        Ok(())
    }
}
