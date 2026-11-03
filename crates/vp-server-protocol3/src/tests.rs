#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use vp_product_domain::*;
fn digest(s: &str) -> HexDigest { HexDigest::public_bytes(s.as_bytes()) }
fn worker() -> WorkerInstance { WorkerInstance::try_from("worker_3".to_owned()).unwrap() }
fn reference(s: &str) -> SecretRef { SecretRef::new(s).unwrap() }
fn release() -> ReleaseIdentity {
    ReleaseIdentity { release_id: ReleaseId::new("source-test").unwrap(), product_version: "0.1-test".into(), adapter_version: "0.1-test".into(), core_commit: "a".repeat(40), patchset_hash: Some("b".repeat(64)), build_target: "x86_64-linux".into(), toolchain: "unit-only".into(), schema_read: CompatibilityRange { minimum: 1, maximum: 1 }, schema_write: CompatibilityRange { minimum: 1, maximum: 1 }, abi: VersionPair { major: ABI_MAJOR, minor: ABI_MINOR }, api: VersionPair { major: 1, minor: 0 }, evidence_manifest_hash: None }
}
fn recipe() -> (ServerCompilerV2, Vec<u8>) {
    let release = release();
    let compiler = ServerCompilerV2::for_loopback_development(release.clone()).unwrap();
    let config = ProductConfig { schema_version: 1, minimum_reader_version: 1, nodes: vec![], subscriptions: vec![], listeners: vec![ServerListener { schema_version: 1, id: ListenerId::new("listener").unwrap(), name: "source test".into(), enabled: true, bind: BindAddress { address: "127.0.0.1".parse().unwrap(), port: 24443 }, protocol: ServerProtocol::Proxy { protocol: Protocol::Trojan {}, users: vec![ListenerUser { id: UserId::new("user").unwrap(), credential_ref: reference("password"), enabled: true }] }, transport: Transport::Tcp {}, security: ServerSecurity::Tls { certificate_ref: CertificateId::new("certificate").unwrap(), private_key_ref: reference("key"), alpn: vec![] }, requirements: vec![CapabilityKey::TrojanTls] }] };
    let recipe = compiler.compile(&config, &release).unwrap();
    (compiler, serde_json::to_vec(&recipe).unwrap())
}
fn manifest(recipe: &[u8]) -> PreparationManifest {
    let records = [
        MaterialIdentity { role: Role::CertificateChain, recipe_reference: "certificate".into(), record_reference: reference("chain"), kind: 6, version: 1, chain_digest: Some(digest("chain")) },
        MaterialIdentity { role: Role::PrivateKey, recipe_reference: reference("key").as_str().into(), record_reference: reference("key"), kind: 2, version: 1, chain_digest: None },
        MaterialIdentity { role: Role::Password, recipe_reference: reference("password").as_str().into(), record_reference: reference("password"), kind: 1, version: 1, chain_digest: None },
    ];
    PreparationManifest { protocol: 3, instance_id: worker(), generation: 1, recipe_digest: HexDigest::public_bytes(recipe), release_digest: release_digest(&release()).unwrap(), associations: records.into_iter().map(|material| Association { listener_index: 0, user_index: (material.role == Role::Password).then_some(0), asset_revision: (material.role == Role::CertificateChain).then_some(1), material }).collect() }
}
fn admission(manifest: &PreparationManifest) -> Admission {
    let mut a = Admission { protocol: 3, mode: Mode::Activate, instance_id: worker(), generation: 1, recipe_digest: manifest.recipe_digest.clone(), preparation_manifest_digest: manifest.digest().unwrap(), prepared_nonce: digest("synthetic-nonce-not-random-runtime"), transition_operation_id: OperationId::new("op").unwrap(), revision_owner_operation_id: OperationId::new("op").unwrap(), transition_plan_hash: digest("plan"), revision_owner_plan_hash: digest("plan"), target_revision: 1, config_digest: digest("config"), release_digest: manifest.release_digest.clone(), artifact_digest: digest("artifact"), aggregate_version: 4, policy_fingerprint: digest("policy"), issued_at_ms: 100_000, expires_at_ms: 110_000, max_startup_ms: 10_000, allowed_clock_skew_ms: 0, paths: vec![SelectedPath { listener_index: 0, chain_digest: digest("chain"), anchor_digest: digest("anchor"), certificate_digests: vec![digest("leaf"), digest("intermediate")] }], admission_digest: digest("placeholder") };
    sign(&mut a); a
}
fn sign(a: &mut Admission) { a.admission_digest = a.computed_digest().unwrap(); }
fn prepared() -> (PreparedAssociation, Admission) {
    let (compiler, recipe) = recipe(); let manifest = manifest(&recipe); let a = admission(&manifest);
    let records: Vec<_> = manifest.associations.iter().map(|a| a.material.clone()).collect();
    let chain = PreparedChain { listener_index: 0, chain_digest: digest("chain"), leaf_digest: digest("leaf"), certificates: [(digest("leaf"), Some((90, 200))), (digest("intermediate"), Some((80, 105))), (digest("unused"), None)].into_iter().collect() };
    let p = PreparedAssociation::checked(manifest, a.prepared_nonce.clone(), &recipe, &compiler, &records, vec![chain]).unwrap(); (p, a)
}
#[test] fn instance_grammar_is_not_widened() {
    for invalid in ["".to_owned(), "a".repeat(65), "slash/path".into(), "é".into()] { assert!(WorkerInstance::try_from(invalid).is_err()); }
    assert!(WorkerInstance::try_from("a".repeat(64)).is_ok());
}
#[test] fn strict_digest_spelling() {
    assert!(HexDigest::try_from("f".repeat(64)).is_ok());
    for invalid in ["F".repeat(64), "a".repeat(63), "g".repeat(64)] { assert!(HexDigest::try_from(invalid).is_err()); }
}
#[test] fn canonical_order_and_domains_are_distinct() {
    let a: serde_json::Value = serde_json::from_str(r#"{"z":1,"a":2}"#).unwrap();
    let b: serde_json::Value = serde_json::from_str(r#"{"a":2,"z":1}"#).unwrap();
    assert!(canonical_bytes(&a).unwrap() == canonical_bytes(&b).unwrap());
    assert!(domain_digest(ADMISSION_DOMAIN, &a).unwrap() != domain_digest(MANIFEST_DOMAIN, &a).unwrap());
}
#[test] fn strict_admission_decode_rejects_duplicate_unknown_and_old_protocol() {
    let (_, a) = prepared(); let bytes = serde_json::to_vec(&a).unwrap(); assert!(Admission::decode(&bytes).is_ok());
    let text = String::from_utf8(bytes).unwrap();
    for extra in ["\"protocol\":3,", "\"unknown\":1,"] { let altered = format!("{{{}{}", extra, &text[1..]); assert!(Admission::decode(altered.as_bytes()).is_err()); }
    let mut old = a.clone(); old.protocol = 2; sign(&mut old); assert!(matches!(Admission::decode(&serde_json::to_vec(&old).unwrap()), Err(Failure::UnsupportedProtocol)));
}
#[test] fn wire_byte_cap_includes_whitespace() {
    let (_, a) = prepared(); let mut bytes = serde_json::to_vec(&a).unwrap(); bytes.resize(MAX_ACTIVATE_BYTES, b' '); assert!(Admission::decode(&bytes).is_ok()); bytes.push(b' '); assert!(matches!(Admission::decode(&bytes), Err(Failure::FrameTooLarge)));
}
#[test] fn max_path_frame_calculation_and_max_plus_one() {
    let (_, mut a) = prepared();
    a.paths = (0..128).map(|i| SelectedPath { listener_index: i, chain_digest: digest("chain"), anchor_digest: digest("anchor"), certificate_digests: (0..8).map(|j| digest(&format!("cert-{j}"))).collect() }).collect(); sign(&mut a);
    assert_eq!(canonical_bytes(&a.paths[127]).unwrap().len(), 747);
    // Earlier indices use fewer digits: 95,745 is the conservative all-127 bound.
    assert!(canonical_bytes(&a.paths).unwrap().len() <= 95_745);
    assert!(canonical_bytes(&a).unwrap().len() <= 103_937); assert!(a.validate().is_ok());
    a.paths.push(a.paths[0].clone()); sign(&mut a); assert_eq!(a.validate(), Err(Failure::StructuralLimit));
}
#[test] fn path_count_duplicates_and_leaf_position_rejected() {
    let (p, a) = prepared();
    for variant in 0..5 { let mut b = a.clone(); match variant { 0 => { b.paths[0].certificate_digests.remove(0); }, 1 => b.paths[0].certificate_digests.reverse(), 2 => b.paths[0].certificate_digests.push(digest("leaf")), 3 => b.paths[0].certificate_digests.push(digest("absent")), _ => b.paths[0].certificate_digests.push(digest("unused")) }; sign(&mut b); assert!(p.match_admission(&b).is_err()); }
    let mut b = a; b.paths[0].certificate_digests = (0..9).map(|i| digest(&i.to_string())).collect(); sign(&mut b); assert_eq!(b.validate(), Err(Failure::StructuralLimit));
}
#[test] fn exact_manifest_and_material_set_no_detached_assertions() {
    let (compiler, recipe) = recipe(); let m = manifest(&recipe); let records: Vec<_> = m.associations.iter().map(|a| a.material.clone()).collect();
    assert!(m.verify_preparation(&recipe, &compiler, &records).is_ok());
    for i in 0..records.len() { let mut r = records.clone(); r.remove(i); assert!(m.verify_preparation(&recipe, &compiler, &r).is_err()); }
    let mut r = records.clone(); r.push(r[0].clone()); assert!(m.verify_preparation(&recipe, &compiler, &r).is_err());
    let mut m2 = m.clone(); m2.associations[2].material.recipe_reference = reference("detached").as_str().into(); m2.associations[2].material.record_reference = reference("detached"); let detached: Vec<_> = m2.associations.iter().map(|a| a.material.clone()).collect(); assert!(m2.verify_preparation(&recipe, &compiler, &detached).is_err());
    let mut r = records; r[2].role = Role::PrivateKey; r[2].kind = 2; assert!(m.verify_preparation(&recipe, &compiler, &r).is_err());
}
#[test] fn preparation_wrong_identity_or_version_rejected() {
    let (compiler, recipe) = recipe(); let m = manifest(&recipe); let mut records: Vec<_> = m.associations.iter().map(|a| a.material.clone()).collect(); records[0].version += 1; assert!(m.verify_preparation(&recipe, &compiler, &records).is_err());
    let (p, a) = prepared();
    for i in 0..5 { let mut b = a.clone(); match i { 0 => b.prepared_nonce = digest("other"), 1 => b.recipe_digest = digest("other"), 2 => b.preparation_manifest_digest = digest("other"), 3 => b.generation += 1, _ => b.instance_id = WorkerInstance::try_from("other".to_owned()).unwrap() }; sign(&mut b); assert_eq!(p.match_admission(&b), Err(Failure::PreparationMismatch)); }
}
#[test] fn time_intersects_selected_intermediate_not_unused_chain() {
    let (p, a) = prepared(); assert_eq!(p.check_time(&a, 100_000, 90_000, 99_999, 30_000), Ok(6000)); assert_eq!(p.check_time(&a, 105_999, 90_000, 100_000, 30_000), Ok(1)); assert_eq!(p.check_time(&a, 106_000, 90_000, 100_000, 30_000), Err(Failure::CertificateExpired));
}
#[test] fn time_expiry_regression_and_prepared_timeout() {
    let (p, a) = prepared(); assert_eq!(p.check_time(&a, 100_000, 90_000, 100_001, 30_000), Err(Failure::ClockRegression)); assert_eq!(p.check_time(&a, 99_999, 90_000, 90_000, 30_000), Err(Failure::ClockRegression)); assert_eq!(p.check_time(&a, 110_000, 90_000, 100_000, 30_000), Err(Failure::AdmissionExpired)); assert_eq!(p.check_time(&a, 100_000, 90_000, 99_999, 0), Err(Failure::PreparedExpired)); assert_eq!(p.check_time(&a, 100_000, 90_000, 99_999, 20), Ok(20));
}
#[test] fn mode_owner_and_bounds_are_fail_closed() {
    let (_, a) = prepared();
    for i in 0..5 { let mut b = a.clone(); match i { 0 => b.allowed_clock_skew_ms = 1, 1 => b.max_startup_ms = 10_001, 2 => b.expires_at_ms = b.issued_at_ms, 3 => b.generation = MAX_WIRE_COUNTER + 1, _ => b.revision_owner_operation_id = OperationId::new("previous").unwrap() }; sign(&mut b); assert!(b.validate().is_err()); }
    let mut restore = a; restore.mode = Mode::Restore; restore.revision_owner_operation_id = OperationId::new("previous").unwrap(); sign(&mut restore); assert!(restore.validate().is_ok());
}
#[test] fn digest_mutation_not_authorized_by_syntax() {
    let (_, mut a) = prepared(); a.policy_fingerprint = digest("changed"); assert_eq!(a.validate(), Err(Failure::AdmissionDigestMismatch));
    // Rehashing restores public correlation only, NOT parent registry authority.
    sign(&mut a); assert!(a.validate().is_ok());
}
#[test] fn reserved_generation_has_no_double_increment() {
    assert_eq!(validate_reserved_generation(4, 5), Ok(())); assert_eq!(validate_reserved_generation(4, 6), Err(Failure::GenerationConflict)); assert_eq!(validate_reserved_generation(MAX_WIRE_COUNTER, MAX_WIRE_COUNTER), Err(Failure::GenerationExhausted));
}
#[test] fn exact_manifest_count_and_duplicate_associations() {
    let (_, recipe) = recipe(); let mut m = manifest(&recipe); m.associations.push(m.associations[0].clone()); assert_eq!(m.validate_shape(), Err(Failure::PreparationMismatch)); m.associations = vec![m.associations[0].clone(); MAX_ASSOCIATIONS + 1]; assert_eq!(m.validate_shape(), Err(Failure::StructuralLimit));
}
#[test] fn exactly_512_associations_fit_but_do_not_invent_recipe_authority() {
    let (_, recipe) = recipe(); let base = manifest(&recipe); let mut m = base.clone(); m.associations.clear();
    for listener in 0..128 {
        for a in &base.associations { let mut a = a.clone(); a.listener_index = listener; m.associations.push(a); }
        let mut second_user = base.associations[2].clone(); second_user.listener_index = listener; second_user.user_index = Some(1); m.associations.push(second_user);
    }
    assert_eq!(m.associations.len(), 512); assert!(m.validate_shape().is_ok()); assert!(canonical_bytes(&m).unwrap().len() <= MAX_MANIFEST_BYTES);
    let (compiler, _) = recipe_fixture();
    let records: Vec<_> = base.associations.iter().map(|a| a.material.clone()).collect();
    // A structurally valid manifest cannot add listeners/users absent from recipe.
    assert!(m.verify_preparation(&recipe, &compiler, &records).is_err());
}
fn recipe_fixture() -> (ServerCompilerV2, Vec<u8>) { recipe() }
#[test] fn temporal_future_certificate_and_overflow_fail_closed() {
    let (mut p, a) = prepared();
    p.chains[0].certificates.insert(digest("leaf"), Some((101, 200)));
    assert_eq!(p.check_time(&a, 100_000, 90_000, 99_999, 30_000), Err(Failure::CertificateNotYetValid));
    p.chains[0].certificates.insert(digest("leaf"), Some((0, i64::MAX)));
    assert_eq!(p.check_time(&a, 100_000, 90_000, 99_999, 30_000), Err(Failure::ClockUnavailable));
}
#[test] fn receipt_binds_exact_preparation() {
    let (_, recipe) = recipe(); let m = manifest(&recipe);
    let mut receipt = PreparedReceipt { protocol: 3, instance_id: worker(), generation: m.generation, recipe_digest: m.recipe_digest.clone(), preparation_manifest_digest: m.digest().unwrap(), prepared_nonce: digest("synthetic") };
    assert!(receipt.validate_for(&m).is_ok());
    assert!(PreparedReceipt::decode(&serde_json::to_vec(&receipt).unwrap()).is_ok());
    let array = positional(&serde_json::to_value(&receipt).unwrap(), &["protocol", "instance_id", "generation", "recipe_digest", "preparation_manifest_digest", "prepared_nonce"]);
    assert!(matches!(PreparedReceipt::decode(&serde_json::to_vec(&array).unwrap()), Err(Failure::MalformedFrame)));
    receipt.generation += 1; assert_eq!(receipt.validate_for(&m), Err(Failure::PreparationMismatch));
}
fn shared_certificate_fixture() -> (ServerCompilerV2, Vec<u8>, PreparationManifest, Vec<MaterialIdentity>) {
    let (compiler, original_bytes) = recipe();
    let original: ServerRecipeV2 = serde_json::from_slice(&original_bytes).unwrap();
    let mut config = original.source;
    let mut second = config.listeners[0].clone();
    second.id = ListenerId::new("second-listener").unwrap();
    second.bind.port += 1;
    config.listeners.push(second);
    let compiled = compiler.compile(&config, &release()).unwrap();
    let bytes = serde_json::to_vec(&compiled).unwrap();
    let mut m = manifest(&bytes);
    let records: Vec<_> = m.associations.iter().map(|a| a.material.clone()).collect();
    let second_associations: Vec<_> = m.associations.iter().cloned().map(|mut a| { a.listener_index = 1; a }).collect();
    m.associations.extend(second_associations);
    (compiler, bytes, m, records)
}
#[test] fn shared_recipe_reference_requires_consistent_full_identity_and_revision() {
    let (compiler, bytes, m, records) = shared_certificate_fixture();
    assert!(m.verify_preparation(&bytes, &compiler, &records).is_ok());
    let mut changed_revision = m.clone();
    changed_revision.associations[3].asset_revision = Some(2);
    assert_eq!(changed_revision.verify_preparation(&bytes, &compiler, &records), Err(Failure::PreparationMismatch));
}
#[test] fn shared_certificate_ref_cannot_alias_other_backing_record_or_version() {
    let (compiler, bytes, m, records) = shared_certificate_fixture();
    for change_version in [false, true] {
        let mut altered = m.clone();
        altered.associations[3].material.record_reference = reference("other-chain");
        if change_version { altered.associations[3].material.version = 2; }
        let mut observations = records.clone();
        observations.push(altered.associations[3].material.clone());
        // Both records genuinely appear in the observation set: mere set
        // equality is insufficient because one recipe ref cannot name both.
        assert_eq!(altered.verify_preparation(&bytes, &compiler, &observations), Err(Failure::PreparationMismatch));
    }
}
fn positional(value: &serde_json::Value, fields: &[&str]) -> serde_json::Value {
    serde_json::Value::Array(fields.iter().map(|field| value[*field].clone()).collect())
}
#[test] fn admission_requires_objects_not_positional_struct_arrays() {
    let (_, a) = prepared(); let value = serde_json::to_value(&a).unwrap();
    let fields = ["protocol", "mode", "instance_id", "generation", "recipe_digest", "preparation_manifest_digest", "prepared_nonce", "transition_operation_id", "revision_owner_operation_id", "transition_plan_hash", "revision_owner_plan_hash", "target_revision", "config_digest", "release_digest", "artifact_digest", "aggregate_version", "policy_fingerprint", "issued_at_ms", "expires_at_ms", "max_startup_ms", "allowed_clock_skew_ms", "paths", "admission_digest"];
    assert!(matches!(Admission::decode(&serde_json::to_vec(&positional(&value, &fields)).unwrap()), Err(Failure::MalformedFrame)));
    let mut nested = value; nested["paths"][0] = positional(&nested["paths"][0], &["listener_index", "chain_digest", "anchor_digest", "certificate_digests"]);
    assert!(matches!(Admission::decode(&serde_json::to_vec(&nested).unwrap()), Err(Failure::MalformedFrame)));
}
#[test] fn manifest_requires_objects_for_manifest_association_and_material() {
    let (_, bytes) = recipe(); let m = manifest(&bytes); let value = serde_json::to_value(&m).unwrap();
    let fields = ["protocol", "instance_id", "generation", "recipe_digest", "release_digest", "associations"];
    assert!(matches!(PreparationManifest::decode(&serde_json::to_vec(&positional(&value, &fields)).unwrap()), Err(Failure::MalformedFrame)));
    let mut association = value.clone(); association["associations"][0] = positional(&association["associations"][0], &["listener_index", "user_index", "material", "asset_revision"]);
    assert!(matches!(PreparationManifest::decode(&serde_json::to_vec(&association).unwrap()), Err(Failure::MalformedFrame)));
    let mut material = value; material["associations"][0]["material"] = positional(&material["associations"][0]["material"], &["role", "recipe_reference", "record_reference", "kind", "version", "chain_digest"]);
    assert!(matches!(PreparationManifest::decode(&serde_json::to_vec(&material).unwrap()), Err(Failure::MalformedFrame)));
}
