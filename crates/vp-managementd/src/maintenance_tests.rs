#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixStream},
};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn directory() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn input() -> Input {
    decode_input(Zeroizing::new(format!("{{\"schemaVersion\":1,\"operationId\":\"synthetic-maintenance-only\",\"masterKeyHex\":\"{}\"}}", "11".repeat(32)).into_bytes())).unwrap()
}
fn options(action: Action, vault: &std::path::Path, state: Option<&std::path::Path>) -> Options {
    Options {
        action,
        state_root: state.map(|p| p.to_owned()),
        scratch_root: None,
        vault_root: vault.to_owned(),
        namespace: Namespace::new("maintenance-test").unwrap(),
    }
}
#[test]
fn init_is_offline_empty_only_and_receipt_never_grants_recovery() {
    let vault = directory();
    let receipt = execute(
        options(Action::VaultInit, vault.path(), None),
        input(),
        deadline(),
    )
    .unwrap();
    assert_eq!(receipt["targetMutation"], "vault_manifest_created");
    assert_eq!(receipt["vault"]["keyAuthenticated"], true);
    assert_eq!(receipt["recoveryEligible"], false);
    assert!(receipt["authorityBinding"].is_null());
    assert!(receipt["controlAuthorityId"].is_null());
    assert!(receipt["control"].is_null());
    assert!(receipt["retirementWatermark"].is_null());
    assert_eq!(receipt["operationIdRole"], "correlation_only_not_persisted");
    assert_eq!(fs::read_dir(vault.path()).unwrap().count(), 1);
    assert!(!serde_json::to_string(&receipt)
        .unwrap()
        .contains(&"11".repeat(32)));
    assert_eq!(
        execute(
            options(Action::VaultInit, vault.path(), None),
            input(),
            deadline()
        )
        .unwrap_err()
        .code,
        "ALREADY_INITIALIZED"
    );
}
#[test]
fn inspect_authenticates_the_existing_pair_but_reports_missing_authority_watermarks() {
    let vault = directory();
    let state = directory();
    let scratch = directory();
    drop(vp_product_storage::SqliteStore::open(state.path()).unwrap());
    let initialized = execute(
        options(Action::VaultInit, vault.path(), None),
        input(),
        deadline(),
    )
    .unwrap();
    let receipt = execute(
        inspection_options(vault.path(), state.path(), scratch.path()),
        input(),
        deadline(),
    )
    .unwrap();
    assert_eq!(receipt["vault"]["vaultId"], initialized["vault"]["vaultId"]);
    assert_eq!(receipt["control"]["sqlLayout"], 1);
    assert_eq!(receipt["control"]["payloadFormat"], 2);
    assert_eq!(
        receipt["controlInspectionProfile"],
        "delete_only_private_scratch_copy"
    );
    assert_eq!(receipt["authorityStatus"], "unavailable");
    assert_eq!(receipt["watermarkStatus"], "unavailable");
    assert_eq!(receipt["recoveryEligible"], false);
    assert_eq!(receipt["targetMutation"], "none");
    assert!(receipt["publicationRevocationWatermark"].is_null());
}
#[test]
fn missing_control_does_not_initialize_it_and_wrong_key_cannot_produce_receipt() {
    let vault = directory();
    let state = directory();
    execute(
        options(Action::VaultInit, vault.path(), None),
        input(),
        deadline(),
    )
    .unwrap();
    assert_eq!(
        execute(
            options(Action::Inspect, vault.path(), Some(state.path())),
            input(),
            deadline()
        )
        .unwrap_err()
        .code,
        "TARGET_MISSING"
    );
    assert_eq!(fs::read_dir(state.path()).unwrap().count(), 0);
    drop(vp_product_storage::SqliteStore::open(state.path()).unwrap());
    let scratch = directory();
    let mut wrong = input();
    wrong.master_key_hex = Zeroizing::new("22".repeat(32));
    assert_eq!(
        execute(
            inspection_options(vault.path(), state.path(), scratch.path()),
            wrong,
            deadline()
        )
        .unwrap_err()
        .code,
        "VAULT_AUTHENTICATION_FAILED"
    );
}
#[test]
fn init_never_erases_nonempty_root_and_expired_requests_do_nothing() {
    let vault = directory();
    fs::write(vault.path().join("foreign"), b"synthetic").unwrap();
    assert!(execute(
        options(Action::VaultInit, vault.path(), None),
        input(),
        deadline()
    )
    .is_err());
    assert_eq!(
        fs::read(vault.path().join("foreign")).unwrap(),
        b"synthetic"
    );
    let empty = directory();
    assert_eq!(
        execute(
            options(Action::VaultInit, empty.path(), None),
            input(),
            Instant::now()
        )
        .unwrap_err()
        .code,
        "DEADLINE_EXCEEDED"
    );
    assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);
}
#[test]
fn commands_are_mutually_exclusive_and_reject_server_or_secret_flags() {
    for values in [
        vec![
            "vault-init",
            "--vault-root",
            "/vault",
            "--vault-namespace",
            "unit",
            "--state-root",
            "/state",
        ],
        vec![
            "inspect",
            "--vault-root",
            "/vault",
            "--vault-namespace",
            "unit",
        ],
        vec![
            "vault-init",
            "--vault-root",
            "/vault",
            "--vault-namespace",
            "unit",
            "--bind",
            "127.0.0.1:1234",
        ],
        vec![
            "vault-init",
            "--vault-root",
            "/vault",
            "--vault-namespace",
            "unit",
            "--worker",
            "/worker",
        ],
        vec![
            "vault-init",
            "--vault-root",
            "/vault",
            "--vault-namespace",
            "unit",
            "--master-key-hex",
            "secret-value",
        ],
        vec![
            "inspect",
            "--state-root",
            "/vault",
            "--vault-root",
            "/vault",
            "--vault-namespace",
            "unit",
        ],
        vec![
            "vault-init",
            "--vault-root",
            "/vault",
            "--vault-root",
            "/other",
            "--vault-namespace",
            "unit",
        ],
    ] {
        assert_eq!(
            options_from(values.into_iter().map(String::from))
                .err()
                .unwrap()
                .code,
            "INVALID_ARGUMENTS"
        );
    }
    assert!(options_from(
        [
            "vault-init",
            "--vault-root",
            "/vault",
            "--vault-namespace",
            "unit"
        ]
        .into_iter()
        .map(String::from)
    )
    .is_ok());
}
#[test]
fn strict_secret_input_rejects_unknown_duplicate_and_oversized_data_without_echo() {
    for value in [
        r#"{"schemaVersion":1,"operationId":"test","masterKeyHex":"DO_NOT_ECHO","fallbackGenerate":true}"#,
        r#"{"schemaVersion":1,"operationId":"test","masterKeyHex":"DO_NOT_ECHO","masterKeyHex":"again"}"#,
        r#"{"schemaVersion":2,"operationId":"test","masterKeyHex":"DO_NOT_ECHO"}"#,
        r#"{"schemaVersion":1,"operationId":"test","masterKeyHex":"DO_NOT_ECHO"} trailing"#,
        r#"{"schemaVersion":1,"operationId":"test","masterKeyHex":"\u0031\u0031DO_NOT_ECHO"}"#,
    ] {
        let failure = decode_input(Zeroizing::new(value.as_bytes().to_vec()))
            .err()
            .unwrap();
        assert!(!format!("{failure:?}").contains("DO_NOT_ECHO"));
    }
    assert_eq!(
        decode_input(Zeroizing::new(vec![b'x'; MAX_INPUT + 1]))
            .err()
            .unwrap()
            .code,
        "INPUT_LIMIT"
    );
    assert!(master_key(&"z".repeat(64)).is_err());
}
#[test]
fn stdin_reader_requires_eof_and_enforces_limit_and_deadline() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(b"synthetic-stdin").unwrap();
    drop(writer);
    assert_eq!(
        &*read_sensitive(&reader, deadline()).unwrap(),
        b"synthetic-stdin"
    );
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&vec![b'x'; MAX_INPUT + 1]).unwrap();
    drop(writer);
    assert_eq!(
        read_sensitive(&reader, deadline()).unwrap_err().code,
        "INPUT_LIMIT"
    );
    let (reader, _writer) = UnixStream::pair().unwrap();
    assert_eq!(
        read_sensitive(&reader, Instant::now() + Duration::from_millis(1))
            .unwrap_err()
            .code,
        "DEADLINE_EXCEEDED"
    );
}
#[test]
fn uncertain_initialization_and_cleanup_failures_are_explicit_and_never_retry_authority() {
    let failure = vault_failure(VaultError::RecoveryRequired, true);
    assert_eq!(failure.target_mutation, "uncertain_do_not_retry_initialize");
    assert_eq!(
        control_failure(InspectionError::CleanupRequired).code,
        "PRIVATE_TEMPORARY_CLEANUP_REQUIRED"
    );
    assert!(HELP.contains("DELETE-only"));
    assert!(HELP.contains("recoveryEligible=false"));
}

fn bound_input(path: &std::path::Path) -> Input {
    use std::os::unix::fs::MetadataExt;
    let mut request = input();
    let stat = fs::metadata(path).unwrap();
    request.expected_vault_directory = Some(ExpectedVaultDirectory {
        device: stat.dev(),
        inode: stat.ino(),
    });
    request
}
#[test]
fn bound_init_requires_exact_input_and_refuses_binding_for_other_actions() {
    let vault = directory();
    assert_eq!(
        execute(
            options(Action::VaultInitBound, vault.path(), None),
            input(),
            deadline()
        )
        .unwrap_err(),
        Failure::none("TARGET_BINDING_REQUIRED_OR_UNEXPECTED")
    );
    assert_eq!(
        execute(
            options(Action::VaultInit, vault.path(), None),
            bound_input(vault.path()),
            deadline()
        )
        .unwrap_err(),
        Failure::none("TARGET_BINDING_REQUIRED_OR_UNEXPECTED")
    );
    let state = directory();
    assert_eq!(
        execute(
            options(Action::Inspect, vault.path(), Some(state.path())),
            bound_input(vault.path()),
            deadline()
        )
        .unwrap_err(),
        Failure::none("TARGET_BINDING_REQUIRED_OR_UNEXPECTED")
    );
    assert_eq!(fs::read_dir(vault.path()).unwrap().count(), 0);
    assert_eq!(fs::read_dir(state.path()).unwrap().count(), 0);
    for binding in [
        "null",
        r#"{"device":18446744073709551616,"inode":2}"#,
        r#"{"device":true,"inode":2}"#,
        r#"{"device":1,"inode":2,"unknown":3}"#,
        r#"{"device":-1,"inode":2}"#,
        r#"{"device":1,"inode":2.0}"#,
        r#"{"device":1,"device":1,"inode":2}"#,
    ] {
        let raw = format!(
            r#"{{"schemaVersion":1,"operationId":"bound-test","masterKeyHex":"{}","expectedVaultDirectory":{binding}}}"#,
            "11".repeat(32)
        );
        assert!(decode_input(Zeroizing::new(raw.into_bytes())).is_err());
    }
}
#[test]
fn bound_init_swapped_target_fails_before_write_then_exact_target_succeeds() {
    let root = directory();
    let vault = root.path().join("vault");
    let moved = root.path().join("moved");
    fs::create_dir(&vault).unwrap();
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o700)).unwrap();
    let request = bound_input(&vault);
    fs::rename(&vault, &moved).unwrap();
    fs::create_dir(&vault).unwrap();
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        execute(
            options(Action::VaultInitBound, &vault, None),
            request,
            deadline()
        )
        .unwrap_err(),
        Failure::none("TARGET_BINDING_MISMATCH")
    );
    assert_eq!(fs::read_dir(&vault).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
    fs::remove_dir(&vault).unwrap();
    fs::rename(&moved, &vault).unwrap();
    let receipt = execute(
        options(Action::VaultInitBound, &vault, None),
        bound_input(&vault),
        deadline(),
    )
    .unwrap();
    assert_eq!(receipt["command"], "vault-init-bound");
    assert_eq!(receipt["targetBindingValidated"], true);
    assert_eq!(receipt["targetMutation"], "vault_manifest_created");
    assert_eq!(receipt["recoveryEligible"], false);
    assert!(!serde_json::to_string(&receipt).unwrap().contains("device"));
    let before = fs::read(vault.join("vault.v1")).unwrap();
    assert_eq!(
        execute(
            options(Action::VaultInitBound, &vault, None),
            bound_input(&vault),
            deadline()
        )
        .unwrap_err()
        .code,
        "ALREADY_INITIALIZED"
    );
    assert_eq!(before, fs::read(vault.join("vault.v1")).unwrap());
}

#[test]
fn explicit_private_scratch_inspection_is_positive_without_relaxing_default_profile() {
    let vault = directory();
    let state = directory();
    let scratch = directory();
    drop(vp_product_storage::SqliteStore::open(state.path()).unwrap());
    execute(
        options(Action::VaultInit, vault.path(), None),
        input(),
        deadline(),
    )
    .unwrap();
    let mut selected = options(Action::Inspect, vault.path(), Some(state.path()));
    selected.scratch_root = Some(scratch.path().to_owned());
    let receipt = execute(selected, input(), deadline()).unwrap();
    assert_eq!(
        receipt["controlInspectionProfile"],
        "delete_only_private_scratch_copy"
    );
    assert_eq!(receipt["targetMutation"], "none");
    assert_eq!(receipt["recoveryEligible"], false);
    assert!(receipt["authorityBinding"].is_null());
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
    assert!(!serde_json::to_string(&receipt)
        .unwrap()
        .contains(scratch.path().to_str().unwrap()));
}
#[test]
fn explicit_scratch_flag_is_inspect_only_absolute_unique_and_optional() {
    let base = [
        "inspect",
        "--state-root",
        "/state",
        "--vault-root",
        "/vault",
        "--vault-namespace",
        "test",
    ];
    let plain = options_from(base.iter().map(|s| s.to_string())).unwrap();
    assert!(plain.scratch_root.is_none());
    let accepted = base.into_iter().chain(["--scratch-root", "/scratch"]);
    assert_eq!(
        options_from(accepted.map(str::to_owned))
            .unwrap()
            .scratch_root,
        Some(PathBuf::from("/scratch"))
    );
    for args in [
        vec![
            "vault-init",
            "--vault-root",
            "/vault",
            "--vault-namespace",
            "test",
            "--scratch-root",
            "/scratch",
        ],
        vec![
            "inspect",
            "--state-root",
            "/state",
            "--vault-root",
            "/vault",
            "--vault-namespace",
            "test",
            "--scratch-root",
            "relative",
        ],
        vec![
            "inspect",
            "--state-root",
            "/state",
            "--vault-root",
            "/vault",
            "--vault-namespace",
            "test",
            "--scratch-root",
            "/one",
            "--scratch-root",
            "/two",
        ],
    ] {
        assert!(options_from(args.into_iter().map(str::to_owned)).is_err());
    }
}

fn inspection_options(
    vault: &std::path::Path,
    state: &std::path::Path,
    scratch: &std::path::Path,
) -> Options {
    let mut options = options(Action::Inspect, vault, Some(state));
    options.scratch_root = Some(scratch.to_owned());
    options
}
#[test]
fn default_profile_admission_matches_host_policy_without_fallback() {
    use std::os::unix::fs::MetadataExt;
    let vault = directory();
    let state = directory();
    drop(vp_product_storage::SqliteStore::open(state.path()).unwrap());
    execute(
        options(Action::VaultInit, vault.path(), None),
        input(),
        deadline(),
    )
    .unwrap();
    let outcome = execute(
        options(Action::Inspect, vault.path(), Some(state.path())),
        input(),
        deadline(),
    );
    let temporary = fs::metadata("/tmp").unwrap();
    if temporary.uid() == 0 && temporary.mode() & 0o7777 == 0o1777 {
        assert_eq!(
            outcome.unwrap()["controlInspectionProfile"],
            "delete_only_private_copy"
        );
    } else {
        assert_eq!(outcome.unwrap_err().code, "INSPECTION_UNAVAILABLE");
    }
}
