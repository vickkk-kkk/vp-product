#![allow(clippy::unwrap_used)]
use super::*;
use crate::tls_test_pem::TestPem;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    time::Duration,
};
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
// Clock requires Sync. Use atomic for the actual fault fixture, not unsound Cell.
struct Wall(std::sync::atomic::AtomicU64);
impl Clock for Wall {
    fn now_ms(&self) -> Result<u64, ControlError> {
        Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}
fn clock() -> Wall {
    Wall(std::sync::atomic::AtomicU64::new(1_735_689_600_000))
}
fn binding() -> InstanceBinding {
    let d = ContentDigest::bytes(b"synthetic");
    InstanceBinding {
        binding_version: 1,
        genesis_id: "1".repeat(32),
        vault_id: "2".repeat(32),
        namespace_digest: d.clone(),
        administrator_commitment: d.clone(),
        preparation_digest: d.clone(),
        activation_intent_digest: d.clone(),
        artifact_set_digest: d,
        profile: crate::FRESH_TLS_RUNTIME_PROFILE.into(),
    }
}
struct Lease {
    e: TlsControlEnvelope,
    fail: Option<u64>,
}
impl Lease {
    fn new() -> Self {
        let mut e = TlsControlEnvelope::preparing(binding()).unwrap();
        e.mark_initialized().unwrap();
        Self { e, fail: None }
    }
}
impl TlsAssetWriterLease for Lease {
    fn aggregate(&self) -> &TlsControlEnvelope {
        &self.e
    }
    fn persist_asset(&mut self, m: TlsAssetMutation) -> Result<(), ControlError> {
        let (p, n, _) = m.into_parts();
        if p != self.e.digest()? {
            return Err(ControlError::ResourceConflict);
        }
        if self.fail == Some(n.state.version) {
            return Err(ControlError::StorageUnavailable);
        }
        self.e = n;
        Ok(())
    }
}
type StoredVaultRecord = (u8, u64, Vec<u8>);
type VaultRecords = BTreeMap<String, StoredVaultRecord>;

struct Vault {
    data: RefCell<VaultRecords>,
    put_count: Cell<usize>,
    fail: Cell<usize>,
    wrong_version: Cell<bool>,
    whitespace: Cell<bool>,
    wrong_binding: Cell<bool>,
    dead: RefCell<BTreeSet<String>>,
}
impl Vault {
    fn new() -> Self {
        Self {
            data: RefCell::new(BTreeMap::new()),
            put_count: Cell::new(0),
            fail: Cell::new(0),
            wrong_version: Cell::new(false),
            whitespace: Cell::new(false),
            wrong_binding: Cell::new(false),
            dead: RefCell::new(BTreeSet::new()),
        }
    }
}
impl TlsVaultIo for Vault {
    fn binding(&self, _: Instant) -> Result<InstanceBinding, ControlError> {
        let mut b = binding();
        if self.wrong_binding.get() {
            b.genesis_id = "3".repeat(32)
        }
        Ok(b)
    }
    fn read(&self, r: &SecretRef, _: Instant) -> Result<Option<TlsRawRecord>, ControlError> {
        if self.dead.borrow().contains(r.as_str()) {
            return Err(ControlError::NotFound);
        }
        Ok(self
            .data
            .borrow()
            .get(r.as_str())
            .map(|(k, v, b)| TlsRawRecord {
                reference: r.clone(),
                kind: *k,
                version: if self.wrong_version.get() { v + 1 } else { *v },
                bytes: SecretBytes::new(if self.whitespace.get() && *k == 2 {
                    [b.as_slice(), b"\n"].concat()
                } else {
                    b.clone()
                }),
            }))
    }
    fn put(&self, r: TlsRawRecord, _: Instant) -> Result<(), ControlError> {
        let n = self.put_count.get() + 1;
        self.put_count.set(n);
        if self.fail.get() == n {
            return Err(ControlError::StorageUnavailable);
        }
        let mut data = self.data.borrow_mut();
        if data.contains_key(r.reference.as_str()) {
            return Err(ControlError::ResourceConflict);
        }
        data.insert(
            r.reference.as_str().into(),
            (r.kind, r.version, r.bytes.expose().to_vec()),
        );
        Ok(())
    }
    fn retire(&self, r: &SecretRef, k: u8, v: u64, _: Instant) -> Result<(), ControlError> {
        let data = self.data.borrow();
        let (k2, v2, _) = data.get(r.as_str()).ok_or(ControlError::NotFound)?;
        if *k2 != k || *v2 != v {
            return Err(ControlError::ResourceConflict);
        }
        self.dead.borrow_mut().insert(r.as_str().into());
        Ok(())
    }
    fn tombstone(&self, r: &SecretRef, _: Instant) -> Result<TlsTombstone, ControlError> {
        if !self.dead.borrow().contains(r.as_str()) {
            return Err(ControlError::NotFound);
        }
        let data = self.data.borrow();
        let (k, v, _) = data.get(r.as_str()).ok_or(ControlError::NotFound)?;
        Ok(TlsTombstone {
            reference: r.clone(),
            kind: *k,
            version: *v,
        })
    }
}
struct Material {
    chain: Vec<u8>,
    key: Vec<u8>,
    policy: TlsBackendPolicy,
}
fn material(eku: bool, before: i32, after: i32) -> Material {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(vec!["synthetic-ca.invalid".into()]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf.not_before = rcgen::date_time_ymd(before, 1, 1);
    leaf.not_after = rcgen::date_time_ymd(after, 1, 1);
    if eku {
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth]
    };
    let leaf = leaf.signed_by(&key, &ca, &ca_key).unwrap();
    Material {
        chain: leaf.pem().into_bytes(),
        key: key.serialize_pem().into_bytes(),
        policy: TlsBackendPolicy::new(
            "administrator".into(),
            vec![ca.der().to_vec()],
            "localhost".into(),
        )
        .unwrap(),
    }
}
fn request(m: &Material) -> TlsImportRequest {
    TlsImportRequest {
        actor: "administrator".into(),
        expected_version: 0,
        action: "import-1".into(),
        idempotency: "request-1".into(),
        asset: "certificate-1".into(),
        confirmed: true,
        chain: SecretBytes::new(m.chain.clone()),
        key: SecretBytes::new(m.key.clone()),
    }
}
fn recovery(version: u64) -> TlsActionRequest {
    TlsActionRequest {
        actor: "administrator".into(),
        expected_version: version,
        action: "import-1".into(),
        confirmed: true,
    }
}
#[test]
fn real_crypto_upload_readback_completes_only_after_two_versions() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let service = TlsImportService::new(&m.policy, &c);
    let mut l = Lease::new();
    let v = Vault::new();
    service
        .import(
            &mut l,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(l.e.state.version, 2);
    assert!(!l.e.needs_recovery());
    assert_eq!(
        l.e.state.active_revision,
        crate::StoredState::default().active_revision
    );
    assert_eq!(v.put_count.get(), 2);
    let persisted = serde_json::to_vec(&l.e).unwrap();
    assert!(!persisted.windows(11).any(|w| w == b"PRIVATE KEY"));
}
#[test]
fn policy_authorization_confirmation_stale_cas_and_binding_fail_before_writes() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let service = TlsImportService::new(&m.policy, &c);
    for case in 0..5 {
        let mut l = Lease::new();
        let v = Vault::new();
        let mut r = request(&m);
        match case {
            0 => r.actor = "other".into(),
            1 => r.confirmed = false,
            2 => r.expected_version = 1,
            3 => v.wrong_binding.set(true),
            _ => {
                r.key = SecretBytes::new(KeyPair::generate().unwrap().serialize_pem().into_bytes())
            }
        };
        assert!(service
            .import(&mut l, &v, r, deadline(), &CancellationToken::default())
            .is_err());
        assert_eq!(l.e.state.version, 0);
        assert_eq!(v.put_count.get(), 0);
    }
}
#[test]
fn intent_failure_writes_nothing_and_partial_write_requires_explicit_reupload() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let service = TlsImportService::new(&m.policy, &c);
    let mut l = Lease::new();
    let v = Vault::new();
    l.fail = Some(1);
    assert!(service
        .import(
            &mut l,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert_eq!(v.put_count.get(), 0);
    l.fail = None;
    v.fail.set(2);
    assert!(service
        .import(
            &mut l,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert!(l.e.needs_recovery());
    assert_eq!(l.e.state.version, 1);
    assert!(service
        .recover(
            &mut l,
            &v,
            recovery(1),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert_eq!(v.put_count.get(), 2);
    service
        .reupload_missing(
            &mut l,
            &v,
            recovery(1),
            SecretBytes::new(m.chain.clone()),
            SecretBytes::new(m.key.clone()),
            deadline(),
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(v.put_count.get(), 3);
    assert_eq!(l.e.state.version, 2);
}
#[test]
fn failed_completion_recovers_exact_records_without_rewrite() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let service = TlsImportService::new(&m.policy, &c);
    let mut l = Lease::new();
    let v = Vault::new();
    l.fail = Some(2);
    assert!(service
        .import(
            &mut l,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert_eq!(l.e.state.version, 1);
    l.fail = None;
    service
        .recover(
            &mut l,
            &v,
            recovery(1),
            deadline(),
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(v.put_count.get(), 2);
    assert_eq!(l.e.state.version, 2);
}
#[test]
fn readback_wrong_metadata_or_changed_policy_cannot_complete() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let service = TlsImportService::new(&m.policy, &c);
    let mut l = Lease::new();
    let v = Vault::new();
    v.wrong_version.set(true);
    assert!(service
        .import(
            &mut l,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert_eq!(l.e.state.version, 1);
    v.wrong_version.set(false);
    let other = material(true, 2024, 2026);
    assert!(TlsImportService::new(&other.policy, &c)
        .recover(
            &mut l,
            &v,
            recovery(1),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert_eq!(l.e.state.version, 1);
    service
        .recover(
            &mut l,
            &v,
            recovery(1),
            deadline(),
            &CancellationToken::default(),
        )
        .unwrap();
}
#[test]
fn exact_leaf_signed_inclusive_equal_endpoints_and_absent_eku() {
    let c = clock();
    for eku in [true, false] {
        let m = material(eku, 2025, 2025);
        let f = super::super::validation::verify(
            &SecretBytes::new(m.chain),
            &SecretBytes::new(m.key),
            &m.policy,
            c.now_ms().unwrap(),
            deadline(),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(f.not_before, f.not_after);
        assert_eq!(f.not_before, 1_735_689_600);
    }
}
#[test]
fn verifier_unsupported_pre_epoch_date_fails_closed_without_unsigned_cast() {
    let m = material(false, 1960, 2026);
    let c = clock();
    let result = super::super::validation::verify(
        &SecretBytes::new(m.chain),
        &SecretBytes::new(m.key),
        &m.policy,
        c.now_ms().unwrap(),
        deadline(),
        &CancellationToken::default(),
    );
    // Metadata preserves signed dates; cached webpki explicitly refuses pre-1970
    // dates (time.rs). Do not cast/wrap or bypass verification to accept them.
    assert!(matches!(result, Err(ControlError::InvalidConfiguration)));
}
#[test]
fn wrong_pair_signature_name_time_and_bounds_fail_without_intent() {
    let good = material(true, 2024, 2026);
    let c = clock();
    for case in 0..5 {
        let mut m = material(true, 2024, 2026);
        match case {
            0 => m.key = good.key.clone(),
            1 => m.chain.extend_from_slice(b"junk"),
            2 => {
                m.policy = TlsBackendPolicy::new(
                    "administrator".into(),
                    vec![m.policy.anchors[0].to_vec()],
                    "wrong.invalid".into(),
                )
                .unwrap()
            }
            3 => m.chain = vec![b'x'; 65537],
            _ => m = material(true, 2026, 2027),
        }
        let mut l = Lease::new();
        let v = Vault::new();
        assert!(TlsImportService::new(&m.policy, &c)
            .import(
                &mut l,
                &v,
                request(&m),
                deadline(),
                &CancellationToken::default()
            )
            .is_err());
        assert_eq!(l.e.state.version, 0);
    }
}
#[test]
fn canceled_expired_and_regressed_clock_preserve_pending() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let service = TlsImportService::new(&m.policy, &c);
    let mut l = Lease::new();
    let v = Vault::new();
    let cancel = CancellationToken::default();
    cancel.cancel();
    assert!(service
        .import(&mut l, &v, request(&m), deadline(), &cancel)
        .is_err());
    assert!(service
        .import(
            &mut l,
            &v,
            request(&m),
            Instant::now(),
            &CancellationToken::default()
        )
        .is_err());
    v.fail.set(2);
    assert!(service
        .import(
            &mut l,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    c.0.store(1_735_689_599_000, std::sync::atomic::Ordering::SeqCst);
    assert!(service
        .reupload_missing(
            &mut l,
            &v,
            recovery(1),
            SecretBytes::new(m.chain.clone()),
            SecretBytes::new(m.key.clone()),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert_eq!(v.put_count.get(), 2);
    assert_eq!(l.e.state.version, 1);
}
#[test]
fn abort_retains_refs_and_preexisting_material_is_not_adopted() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let service = TlsImportService::new(&m.policy, &c);
    let mut l = Lease::new();
    let v = Vault::new();
    v.fail.set(2);
    assert!(service
        .import(
            &mut l,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    service
        .abort(
            &mut l,
            recovery(1),
            deadline(),
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(l.e.state.version, 2);
    assert!(service
        .recover(
            &mut l,
            &v,
            recovery(2),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    let mut fresh = Lease::new();
    assert!(service
        .import(
            &mut fresh,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert_eq!(fresh.e.state.version, 0);
}
#[test]
fn retirement_pending_commit_fault_resumes_exact_tombstones() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let s = TlsImportService::new(&m.policy, &c);
    let mut l = Lease::new();
    let v = Vault::new();
    let cancel = CancellationToken::default();
    s.import(&mut l, &v, request(&m), deadline(), &cancel)
        .unwrap();
    l.fail = Some(4);
    assert!(s
        .retire(
            &mut l,
            &v,
            TlsRetireRequest {
                actor: "administrator".into(),
                expected_version: 2,
                action: "retire-1".into(),
                idempotency: "retire-request".into(),
                asset: "certificate-1".into(),
                asset_revision: 1,
                confirmed: true,
                confirm_history_loss: false
            },
            deadline(),
            &cancel
        )
        .is_err());
    assert_eq!(l.e.state.version, 3);
    assert!(l.e.needs_recovery());
    assert_eq!(v.dead.borrow().len(), 2);
    l.fail = None;
    s.recover_retirement(
        &mut l,
        &v,
        TlsActionRequest {
            actor: "administrator".into(),
            expected_version: 3,
            action: "retire-1".into(),
            confirmed: true,
        },
        deadline(),
        &cancel,
    )
    .unwrap();
    assert_eq!(l.e.state.version, 4);
    assert!(!l.e.needs_recovery());
    assert!(l.e.certificate_assets.get("certificate-1").unwrap().phase == AssetPhase::Retired);
}
#[test]
fn reupload_wrong_public_identity_cannot_fill_missing_key() {
    let m = material(true, 2024, 2026);
    let other = material(true, 2024, 2026);
    let c = clock();
    let s = TlsImportService::new(&m.policy, &c);
    let mut l = Lease::new();
    let v = Vault::new();
    v.fail.set(2);
    assert!(s
        .import(
            &mut l,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert!(s
        .reupload_missing(
            &mut l,
            &v,
            recovery(1),
            SecretBytes::new(other.chain),
            SecretBytes::new(other.key),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert_eq!(v.put_count.get(), 2);
    assert_eq!(l.e.state.version, 1);
}
#[test]
fn same_leaf_signature_tamper_is_not_metadata_authority() {
    let mut m = material(true, 2024, 2026);
    let end = m.chain.windows(8).position(|w| w == b"-----END").unwrap();
    let i = (0..end)
        .rev()
        .filter(|i| m.chain[*i].is_ascii_alphanumeric())
        .nth(4)
        .unwrap();
    m.chain[i] = if m.chain[i] == b'A' { b'B' } else { b'A' };
    let c = clock();
    let mut l = Lease::new();
    let v = Vault::new();
    assert!(TlsImportService::new(&m.policy, &c)
        .import(
            &mut l,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert_eq!(l.e.state.version, 0);
}
#[test]
fn unused_intermediate_semantics_and_canonical_chain_identity_are_explicit() {
    let m = material(false, 2024, 2026);
    let c = clock();
    let cancel = CancellationToken::default();
    let key = SecretBytes::new(m.key.clone());
    let base = super::super::validation::verify(
        &SecretBytes::new(m.chain.clone()),
        &key,
        &m.policy,
        c.now_ms().unwrap(),
        deadline(),
        &cancel,
    )
    .unwrap();
    let extra = rcgen::generate_simple_self_signed(vec!["unrelated.invalid".into()]).unwrap();
    let full = [m.chain, extra.cert.pem().into_bytes()].concat();
    let with_extra = super::super::validation::verify(
        &SecretBytes::new(full),
        &key,
        &m.policy,
        c.now_ms().unwrap(),
        deadline(),
        &cancel,
    )
    .unwrap();
    assert!(base.leaf_digest == with_extra.leaf_digest);
    assert!(base.spki_digest == with_extra.spki_digest);
    assert!(base.chain_digest != with_extra.chain_digest);
    assert!(base.chain_size < with_extra.chain_size);
}
#[test]
fn actual_intermediate_path_required_and_client_only_eku_rejected() {
    let root_k = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec!["root.invalid".into()]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = p.self_signed(&root_k).unwrap();
    let int_k = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec!["intermediate.invalid".into()]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let intermediate = p.signed_by(&int_k, &root, &root_k).unwrap();
    let policy = TlsBackendPolicy::new(
        "administrator".into(),
        vec![root.der().to_vec()],
        "localhost".into(),
    )
    .unwrap();
    let c = clock();
    let cancel = CancellationToken::default();
    for usage in [
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ] {
        let k = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["localhost".into()]).unwrap();
        p.extended_key_usages = vec![usage.clone()];
        let leaf = p.signed_by(&k, &intermediate, &int_k).unwrap();
        let key = SecretBytes::new(k.serialize_pem().into_bytes());
        assert!(super::super::validation::verify(
            &SecretBytes::new(leaf.pem().into_bytes()),
            &key,
            &policy,
            c.now_ms().unwrap(),
            deadline(),
            &cancel
        )
        .is_err());
        let result = super::super::validation::verify(
            &SecretBytes::new([leaf.pem().as_bytes(), intermediate.pem().as_bytes()].concat()),
            &key,
            &policy,
            c.now_ms().unwrap(),
            deadline(),
            &cancel,
        );
        assert_eq!(result.is_ok(), usage == ExtendedKeyUsagePurpose::ServerAuth);
    }
}

#[test]
fn initial_import_requires_exact_bytes_not_just_reencoded_matching_key() {
    let m = material(true, 2024, 2026);
    let c = clock();
    let s = TlsImportService::new(&m.policy, &c);
    let mut l = Lease::new();
    let v = Vault::new();
    v.whitespace.set(true);
    assert!(s
        .import(
            &mut l,
            &v,
            request(&m),
            deadline(),
            &CancellationToken::default()
        )
        .is_err());
    assert_eq!(l.e.state.version, 1);
    assert!(l.e.needs_recovery());
    v.whitespace.set(false);
    s.recover(
        &mut l,
        &v,
        recovery(1),
        deadline(),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(l.e.state.version, 2);
    assert_eq!(v.put_count.get(), 2);
}

#[path = "material_tests.rs"]
mod material_tests;
