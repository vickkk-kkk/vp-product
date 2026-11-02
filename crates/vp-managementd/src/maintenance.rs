//! Private maintenance protocol v1. Not a server bootstrap, key generator,
//! recovery/restore command, migration, checkpoint or production service profile.
use rustix::{
    event::{poll, PollFd, PollFlags, Timespec},
    fd::AsFd,
    io::Errno,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
    time::{Duration, Instant},
};
use vp_product_control::ContentDigest;
use vp_product_domain::{OperationId, SecretBytes};
use vp_product_secrets::{
    inspect_vault_read_only, inspect_vault_read_only_at_identity, DurableSecretStore, Limits,
    MasterKey, Namespace, VaultDirectoryIdentity, VaultError, VaultInspectionReceipt,
};
use vp_product_storage::{
    inspect_control_read_only, inspect_control_read_only_in_scratch, InspectionError,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_INPUT: usize = 4096;
const HELP: &str = "Offline maintenance protocol v1 (Linux, source candidate):\n  vp-product-maintenance vault-init --vault-root ABS --vault-namespace NAME\n  vp-product-maintenance vault-init-bound --vault-root ABS --vault-namespace NAME\n  vp-product-maintenance inspect --state-root ABS --vault-root ABS --vault-namespace NAME [--scratch-root ABS]\nstdin: one strict JSON object (<=4096 bytes), then EOF; schemaVersion=1, operationId, masterKeyHex.\nvault-init-bound additionally requires expectedVaultDirectory:{device:u64,inode:u64} in stdin; rejected for other actions. Verified on actual locked vault descriptor before writes.\nNo secrets in argv/environment; no generated key/token/credential. No HTTP, runtime, worker, migration or restore.\nvault-init: existing owned 0700 empty vault only; no control DB initialization.\ninspect: existing DELETE-only DB+lock; refuses WAL/SHM/journal/unknown/pending. Writes a new private temporary metadata copy, never the target state; removes the copy explicitly.\nReceipts are observations, not backup/anti-rollback authority. authority/watermarks unavailable; recoveryEligible=false.\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    VaultInit,
    VaultInitBound,
    Inspect,
}
struct Options {
    action: Action,
    state_root: Option<PathBuf>,
    scratch_root: Option<PathBuf>,
    vault_root: PathBuf,
    namespace: Namespace,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    schema_version: u16,
    #[serde(default, deserialize_with = "expected_directory")]
    expected_vault_directory: Option<ExpectedVaultDirectory>,
    // Correlation only: the current vault format does not persist this ID.
    operation_id: OperationId,
    #[serde(deserialize_with = "secret_text")]
    master_key_hex: Zeroizing<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedVaultDirectory {
    device: u64,
    inode: u64,
}
fn expected_directory<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<ExpectedVaultDirectory>, D::Error> {
    // Missing is allowed for legacy actions; explicit null is never an identity.
    ExpectedVaultDirectory::deserialize(d).map(Some)
}
fn secret_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Failure {
    code: &'static str,
    target_mutation: &'static str,
}
impl Failure {
    fn none(code: &'static str) -> Self {
        Self {
            code,
            target_mutation: "none",
        }
    }
}
fn options_from(mut args: impl Iterator<Item = String>) -> Result<Options, Failure> {
    let action = match args.next().as_deref() {
        Some("vault-init") => Action::VaultInit,
        Some("vault-init-bound") => Action::VaultInitBound,
        Some("inspect") => Action::Inspect,
        _ => return Err(Failure::none("INVALID_ARGUMENTS")),
    };
    let mut flags = BTreeMap::new();
    while let Some(flag) = args.next() {
        if ![
            "--state-root",
            "--vault-root",
            "--vault-namespace",
            "--scratch-root",
        ]
        .contains(&flag.as_str())
        {
            return Err(Failure::none("INVALID_ARGUMENTS"));
        }
        let value = args.next().ok_or(Failure::none("INVALID_ARGUMENTS"))?;
        if flags.insert(flag, value).is_some() {
            return Err(Failure::none("INVALID_ARGUMENTS"));
        }
    }
    let vault_root = PathBuf::from(
        flags
            .remove("--vault-root")
            .ok_or(Failure::none("INVALID_ARGUMENTS"))?,
    );
    let namespace = Namespace::new(
        &flags
            .remove("--vault-namespace")
            .ok_or(Failure::none("INVALID_ARGUMENTS"))?,
    )
    .map_err(|_| Failure::none("INVALID_ARGUMENTS"))?;
    let state_root = flags.remove("--state-root").map(PathBuf::from);
    let scratch_root = flags.remove("--scratch-root").map(PathBuf::from);
    if !vault_root.is_absolute()
        || state_root
            .as_ref()
            .is_some_and(|p| !p.is_absolute() || p == &vault_root)
        || (action == Action::Inspect) != state_root.is_some()
        || scratch_root
            .as_ref()
            .is_some_and(|p| !p.is_absolute() || action != Action::Inspect)
        || !flags.is_empty()
    {
        return Err(Failure::none("INVALID_ARGUMENTS"));
    }
    Ok(Options {
        action,
        state_root,
        scratch_root,
        vault_root,
        namespace,
    })
}
fn read_sensitive(fd: &impl AsFd, deadline: Instant) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_INPUT + 1));
    let mut chunk = Zeroizing::new([0u8; 512]);
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|t| !t.is_zero())
            .ok_or(Failure::none("DEADLINE_EXCEEDED"))?;
        let timeout =
            Timespec::try_from(remaining).map_err(|_| Failure::none("DEADLINE_EXCEEDED"))?;
        let mut fds = [PollFd::new(fd, PollFlags::IN)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => return Err(Failure::none("DEADLINE_EXCEEDED")),
            Ok(_) => (),
            Err(Errno::INTR) => continue,
            Err(_) => return Err(Failure::none("INPUT_UNAVAILABLE")),
        }
        if fds[0]
            .revents()
            .intersects(PollFlags::ERR | PollFlags::NVAL)
        {
            return Err(Failure::none("INPUT_UNAVAILABLE"));
        }
        let capacity = (MAX_INPUT + 1 - bytes.len()).min(chunk.len());
        let count = match rustix::io::read(fd, &mut chunk[..capacity]) {
            Ok(n) => n,
            Err(Errno::INTR | Errno::AGAIN) => continue,
            Err(_) => return Err(Failure::none("INPUT_UNAVAILABLE")),
        };
        if count == 0 {
            break;
        }
        if bytes.len() + count > MAX_INPUT {
            return Err(Failure::none("INPUT_LIMIT"));
        }
        bytes.extend_from_slice(&chunk[..count]);
        chunk.zeroize();
    }
    if bytes.is_empty() {
        return Err(Failure::none("INVALID_INPUT"));
    }
    Ok(bytes)
}
fn decode_input(bytes: Zeroizing<Vec<u8>>) -> Result<Input, Failure> {
    if bytes.is_empty() || bytes.len() > MAX_INPUT {
        return Err(Failure::none("INPUT_LIMIT"));
    }
    // This v1 envelope needs only ASCII field names, an opaque ASCII ID and
    // literal hex. Reject escapes before serde_json can decode secret text into
    // its ordinary (non-zeroizing) scratch buffer. Do not accept \u aliases.
    if bytes.contains(&b'\\') {
        return Err(Failure::none("INVALID_INPUT"));
    }
    let input: Input =
        serde_json::from_slice(&bytes).map_err(|_| Failure::none("INVALID_INPUT"))?;
    if input.schema_version != 1 {
        return Err(Failure::none("UNSUPPORTED_INPUT_VERSION"));
    }
    Ok(input)
}
fn master_key(hex: &str) -> Result<MasterKey, Failure> {
    if hex.len() != 64 {
        return Err(Failure::none("INVALID_INPUT"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(32));
    for pair in hex.as_bytes().chunks_exact(2) {
        let digit = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        bytes.push(
            digit(pair[0]).ok_or(Failure::none("INVALID_INPUT"))? << 4
                | digit(pair[1]).ok_or(Failure::none("INVALID_INPUT"))?,
        );
    }
    MasterKey::new(SecretBytes::new(std::mem::take(&mut *bytes)))
        .map_err(|_| Failure::none("INVALID_INPUT"))
}
fn vault_json(receipt: &VaultInspectionReceipt) -> Value {
    json!({"vaultId": receipt.vault_id, "namespaceDigest": receipt.namespace_digest,
        "formatVersion": receipt.format_version, "manifestDigest": receipt.manifest_digest,
        "inventoryDigest": receipt.inventory_digest, "keyAuthenticated": true})
}
fn execute(options: Options, mut input: Input, deadline: Instant) -> Result<Value, Failure> {
    if (options.action == Action::VaultInitBound) != input.expected_vault_directory.is_some() {
        return Err(Failure::none("TARGET_BINDING_REQUIRED_OR_UNEXPECTED"));
    }
    let key = master_key(&input.master_key_hex)?;
    input.master_key_hex.zeroize();
    if Instant::now() >= deadline {
        return Err(Failure::none("DEADLINE_EXCEEDED"));
    }
    let (vault, control, mutation, profile) = match options.action {
        Action::VaultInit | Action::VaultInitBound => {
            let store = if let Some(expected) = input.expected_vault_directory {
                DurableSecretStore::initialize_bound(
                    &options.vault_root,
                    options.namespace,
                    key,
                    Limits::default(),
                    VaultDirectoryIdentity {
                        device: expected.device,
                        inode: expected.inode,
                    },
                    deadline,
                )
            } else {
                DurableSecretStore::initialize(
                    &options.vault_root,
                    options.namespace,
                    key,
                    Limits::default(),
                    deadline,
                )
            }
            .map_err(|error| {
                if options.action == Action::VaultInitBound && error == VaultError::MetadataMismatch
                {
                    Failure::none("TARGET_BINDING_MISMATCH")
                } else {
                    vault_failure(error, true)
                }
            })?;
            let receipt = store.inspect_read_only(deadline).map_err(|error| Failure {
                code: vault_failure(error, true).code,
                target_mutation: "uncertain_do_not_retry_initialize",
            })?;
            (
                vault_json(&receipt),
                Value::Null,
                "vault_manifest_created",
                "not_requested",
            )
        }
        Action::Inspect => {
            let root = options
                .state_root
                .ok_or(Failure::none("INVALID_ARGUMENTS"))?;
            // One bounded nonblocking lock order: control writer -> vault lifetime.
            // No daemon is started/stopped here. A running holder causes Busy.
            let state = match &options.scratch_root {
                Some(scratch) => inspect_control_read_only_in_scratch(
                    &root,
                    &options.vault_root,
                    scratch,
                    deadline,
                ),
                None => inspect_control_read_only(&root, deadline),
            }
            .map_err(control_failure)?;
            let vault = match state.expected_vault_directory() {
                Some(expected) => inspect_vault_read_only_at_identity(
                    &options.vault_root,
                    options.namespace,
                    key,
                    expected,
                    deadline,
                ),
                None => {
                    inspect_vault_read_only(&options.vault_root, options.namespace, key, deadline)
                }
            }
            .map_err(|error| vault_failure(error, false))?;
            state.recheck(deadline).map_err(control_failure)?;
            let receipt = state.receipt();
            let control = json!({"sqlLayout": receipt.sql_layout, "payloadFormat": receipt.payload_format,
                "stateVersion": receipt.state_version, "activeRevision": receipt.active_revision,
                "payloadDigest": receipt.payload_digest, "journalDigest": receipt.journal_digest,
                "databaseDigest": receipt.database_digest, "recoveryState": "no_pending_recovery_observed"});
            (
                vault_json(vault.receipt()),
                control,
                "none",
                if options.scratch_root.is_some() {
                    "delete_only_private_scratch_copy"
                } else {
                    "delete_only_private_copy"
                },
            )
        }
    };
    let mut result = json!({"protocolVersion":1, "receiptVersion":1,
        "command": match options.action { Action::VaultInit => "vault-init", Action::VaultInitBound => "vault-init-bound", Action::Inspect => "inspect" },
        "operationId": input.operation_id, "operationIdRole":"correlation_only_not_persisted",
        "targetMutation":mutation, "controlInspectionProfile":profile,
        "vault":vault, "control":control,
        "controlAuthorityId":null, "authorityBinding":null, "authorityStatus":"unavailable",
        "retirementWatermark":null, "publicationRevocationWatermark":null, "watermarkStatus":"unavailable",
        "recoveryEligible":false,
        "blockingReasons":["STABLE_CONTROL_AUTHORITY_UNAVAILABLE", "INDEPENDENT_REVOCATION_WATERMARK_UNAVAILABLE", "TRUSTED_EXTERNAL_CHECKPOINT_NOT_VERIFIED"],
        "leaseScope":"observation_only_released_before_exit"});
    if options.action == Action::VaultInitBound {
        result["targetBindingValidated"] = json!(true);
    }
    let digest =
        ContentDigest::of("vp.maintenance.observation.v1", &result).map_err(|_| Failure {
            code: "RECEIPT_UNAVAILABLE",
            target_mutation: if matches!(options.action, Action::VaultInit | Action::VaultInitBound)
            {
                "uncertain_do_not_retry_initialize"
            } else {
                "none"
            },
        })?;
    result["observationDigest"] = json!(digest.as_str());
    Ok(result)
}
fn vault_failure(error: VaultError, initializing: bool) -> Failure {
    let code = match error {
        VaultError::InvalidInput => "INVALID_INPUT",
        VaultError::PermissionDenied => "PERMISSION_DENIED",
        VaultError::Busy => "BUSY",
        VaultError::DeadlineExceeded => "DEADLINE_EXCEEDED",
        VaultError::NotFound => "TARGET_MISSING",
        VaultError::AlreadyExists => "ALREADY_INITIALIZED",
        VaultError::Retired | VaultError::MetadataMismatch | VaultError::Integrity => {
            "VAULT_AUTHENTICATION_FAILED"
        }
        VaultError::UnsupportedVersion => "UNSUPPORTED_VAULT_FORMAT",
        VaultError::LimitExceeded => "LIMIT_EXCEEDED",
        VaultError::StorageUnavailable => "STORAGE_UNAVAILABLE",
        VaultError::RecoveryRequired => "RECOVERY_REQUIRED",
    };
    let uncertain = initializing
        && matches!(
            error,
            VaultError::RecoveryRequired
                | VaultError::DeadlineExceeded
                | VaultError::StorageUnavailable
        );
    Failure {
        code,
        target_mutation: if uncertain {
            "uncertain_do_not_retry_initialize"
        } else {
            "none"
        },
    }
}
fn control_failure(error: InspectionError) -> Failure {
    Failure::none(match error {
        InspectionError::InvalidInput => "INVALID_INPUT",
        InspectionError::PermissionDenied => "PERMISSION_DENIED",
        InspectionError::Missing => "TARGET_MISSING",
        InspectionError::Busy => "BUSY",
        InspectionError::DeadlineExceeded => "DEADLINE_EXCEEDED",
        InspectionError::Unsupported => "DELETE_ONLY_INSPECTION_UNSUPPORTED",
        InspectionError::RecoveryRequired => "RECOVERY_REQUIRED",
        InspectionError::Integrity => "STATE_INTEGRITY_FAILED",
        InspectionError::LimitExceeded => "LIMIT_EXCEEDED",
        InspectionError::Unavailable => "INSPECTION_UNAVAILABLE",
        InspectionError::CleanupRequired => "PRIVATE_TEMPORARY_CLEANUP_REQUIRED",
    })
}
pub fn main_entry() -> ExitCode {
    let arguments: Result<Vec<String>, Failure> = std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|_| Failure::none("INVALID_ARGUMENTS"))
        })
        .collect();
    if arguments.as_ref().is_ok_and(|args| args == &["--help"]) {
        return if std::io::stdout().lock().write_all(HELP.as_bytes()).is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    let outcome = (|| {
        let options = options_from(arguments?.into_iter())?;
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            return Err(Failure::none("NONINTERACTIVE_STDIN_REQUIRED"));
        }
        let input = decode_input(read_sensitive(&stdin, deadline)?)?;
        execute(options, input, deadline)
    })();
    let success = outcome.is_ok();
    let response = outcome.unwrap_or_else(|failure| {
        json!({"protocolVersion":1,
        "error": failure.code, "targetMutation": failure.target_mutation, "recoveryEligible":false})
    });
    let mut encoded = match serde_json::to_vec(&response) {
        Ok(bytes) => bytes,
        Err(_) => return ExitCode::FAILURE,
    };
    encoded.push(b'\n');
    if std::io::stdout().lock().write_all(&encoded).is_err() {
        return ExitCode::FAILURE;
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod tests;
