use serde::{
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use vp_product_domain::{
    ErrorCode, ErrorStage, NodeId, NodeProfile, ProductError, SecretBytes, SecretRef, SourceId,
};
use vp_product_import::{
    AllocatedSecrets, Credential, CredentialKind, ImportBatch, ImportFormat, SecretBundle,
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_WIRE_BYTES: usize = 8_388_608;
const MAX_PENDING: usize = 16;
const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;
const PENDING_TTL: Duration = Duration::from_secs(900);
type Result<T> = std::result::Result<T, ProductError>;

fn error(code: ErrorCode, path: &'static str) -> ProductError {
    ProductError::new(code, ErrorStage::Decode).at(path)
}
fn invalid() -> ProductError {
    error(ErrorCode::ConfigInvalid, "codec.request")
}
fn version(v: u16) -> Result<()> {
    if v == 1 {
        Ok(())
    } else {
        Err(error(ErrorCode::AbiIncompatible, "schemaVersion"))
    }
}
fn confirm(confirmed: bool) -> Result<()> {
    if confirmed {
        Ok(())
    } else {
        Err(error(ErrorCode::ConfirmationRequired, "confirmed"))
    }
}

// Do not let serde_json::Value collapse duplicate fields before typed decoding.
struct StrictJson(usize);
impl<'de> DeserializeSeed<'de> for StrictJson {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<(), D::Error> {
        if self.0 > 48 {
            return Err(serde::de::Error::custom("JSON depth limit"));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for StrictJson {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        let mut count = 0;
        while seq.next_element_seed(StrictJson(self.0 + 1))?.is_some() {
            count += 1;
            if count > 65_536 {
                return Err(serde::de::Error::custom("array limit"));
            }
        }
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 128 || keys.len() >= 64 || !keys.insert(key) {
                return Err(serde::de::Error::custom("object field limit or duplicate"));
            }
            map.next_value_seed(StrictJson(self.0 + 1))?;
        }
        Ok(())
    }
}
fn decode<T: for<'de> Deserialize<'de>>(input: &[u8]) -> Result<T> {
    let mut d = serde_json::Deserializer::from_slice(input);
    StrictJson(0).deserialize(&mut d).map_err(|_| invalid())?;
    d.end().map_err(|_| invalid())?;
    serde_json::from_slice(input).map_err(|_| invalid())
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Response<T: Serialize> {
    schema_version: u16,
    result: Option<T>,
    error: Option<ProductError>,
}
fn response<T: Serialize>(result: Result<T>) -> Result<Zeroizing<Vec<u8>>> {
    let response = match result {
        Ok(value) => Response {
            schema_version: 1,
            result: Some(value),
            error: None,
        },
        Err(error) => Response {
            schema_version: 1,
            result: None,
            error: Some(error),
        },
    };
    let bytes = Zeroizing::new(
        serde_json::to_vec(&response).map_err(|_| error(ErrorCode::Internal, "codec.response"))?,
    );
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(error(ErrorCode::InputTooLarge, "codec.response"));
    }
    Ok(bytes)
}
fn encode<T: Serialize>(result: Result<T>) -> Zeroizing<Vec<u8>> {
    response(result).unwrap_or_else(|_| Zeroizing::new(b"{\"schemaVersion\":1,\"result\":null,\"error\":{\"code\":\"INTERNAL\",\"messageKey\":\"error.action_failed\",\"safeArgs\":{},\"fieldPath\":null,\"retryable\":false,\"stage\":\"decode\",\"capabilityKey\":null,\"remediation\":null,\"diagnosticId\":null}}".to_vec()))
}

// Secret-bearing strings/bytes never implement Debug or ordinary DTO Serialize.
#[derive(Deserialize)]
#[serde(transparent)]
struct InputText(String);
impl Drop for InputText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(transparent)]
struct TransferBytes(Vec<u8>);
impl Drop for TransferBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Preview,
    Transfer,
    Materialize,
    Release,
}
#[derive(Deserialize)]
struct OperationOnly {
    operation: Operation,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviewRequest {
    schema_version: u16,
    operation: Operation,
    format: ImportFormat,
    input: InputText,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransferRequest {
    schema_version: u16,
    operation: Operation,
    pending_id: String,
    confirmed: bool,
    indices: Vec<u32>,
    accept_node_extraction: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    index: u32,
    id: NodeId,
    source_ref: Option<SourceId>,
    credential_ref: SecretRef,
    obfuscation_ref: Option<SecretRef>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MaterializeRequest {
    schema_version: u16,
    operation: Operation,
    pending_id: String,
    confirmed: bool,
    bindings: Vec<Binding>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseRequest {
    schema_version: u16,
    operation: Operation,
    pending_id: String,
}

struct Pending {
    charged_bytes: usize,
    batch: ImportBatch,
    created: Instant,
    transferred: BTreeSet<u32>,
}
#[derive(Default)]
struct Registry {
    pending: BTreeMap<String, Pending>,
}
static PENDING: OnceLock<Mutex<Registry>> = OnceLock::new();
fn prune_expired() {
    if let Some(registry) = PENDING.get() {
        if let Ok(mut registry) = registry.lock() {
            registry
                .pending
                .retain(|_, p| p.created.elapsed() < PENDING_TTL);
        }
    }
}
fn registry() -> Result<std::sync::MutexGuard<'static, Registry>> {
    let mut guard = PENDING
        .get_or_init(|| Mutex::new(Registry::default()))
        .lock()
        .map_err(|_| error(ErrorCode::Internal, "codec.pending"))?;
    guard
        .pending
        .retain(|_, p| p.created.elapsed() < PENDING_TTL);
    Ok(guard)
}
fn missing() -> ProductError {
    error(ErrorCode::PlanExpired, "pendingId")
}
fn valid_pending_id(id: &str) -> Result<()> {
    if id.len() != 40
        || !id.starts_with("pending-")
        || !id[8..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    Ok(())
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewResponse {
    pending_id: String,
    expires_in_seconds: u32,
    report: vp_product_domain::ImportReport,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferEnvelope<'a> {
    schema_version: u16,
    purpose: &'static str,
    pending_id: &'a str,
    entries: Vec<TransferEntry<'a>>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferEntry<'a> {
    index: u32,
    preview: &'a vp_product_import::NodePreview,
    secrets: BorrowedSecrets<'a>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BorrowedSecrets<'a> {
    kind: &'static str,
    primary: &'a [u8],
    secondary: Option<&'a [u8]>,
    obfuscation: Option<&'a [u8]>,
}
impl<'a> From<&'a SecretBundle> for BorrowedSecrets<'a> {
    fn from(s: &'a SecretBundle) -> Self {
        Self {
            kind: match s.credential.kind {
                CredentialKind::None => "none",
                CredentialKind::Password => "password",
                CredentialKind::Uuid => "uuid",
                CredentialKind::UsernamePassword => "username_password",
                CredentialKind::UuidPassword => "uuid_password",
            },
            primary: s.credential.primary.expose(),
            secondary: s.credential.secondary.as_ref().map(SecretBytes::expose),
            obfuscation: s.obfuscation.as_ref().map(SecretBytes::expose),
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferResponse<'a> {
    secret_transfer: TransferEnvelope<'a>,
}
#[derive(Serialize)]
struct Materialized {
    nodes: Vec<NodeProfile>,
}
#[derive(Serialize)]
struct Released {
    released: bool,
}

pub fn parse_request(input: &[u8]) -> Zeroizing<Vec<u8>> {
    prune_expired();
    let operation = match decode::<OperationOnly>(input) {
        Ok(r) => r.operation,
        Err(e) => return encode::<()>(Err(e)),
    };
    match operation {
        Operation::Preview => encode(preview(input)),
        Operation::Transfer => transfer(input).unwrap_or_else(|e| encode::<()>(Err(e))),
        Operation::Materialize => encode(materialize(input)),
        Operation::Release => encode(release(input)),
    }
}
fn preview(input: &[u8]) -> Result<PreviewResponse> {
    let req: PreviewRequest = decode(input)?;
    version(req.schema_version)?;
    if !matches!(req.operation, Operation::Preview) {
        return Err(invalid());
    }
    let batch =
        vp_product_import::parse(req.input.0.as_bytes(), req.format).map_err(|e| e.error)?;
    let report = batch.review_report();
    // A conservative budget charge, including input size, serialized public
    // shape, all secret bytes and 4 KiB/entry for fixed/collection overhead.
    let public_bytes = serde_json::to_vec(&report).map_err(|_| invalid())?.len();
    let secret_bytes: usize = batch
        .entries
        .iter()
        .filter_map(|e| e.candidate.as_ref())
        .map(|c| {
            let s = c.secrets();
            s.credential.primary.expose().len()
                + s.credential
                    .secondary
                    .as_ref()
                    .map_or(0, |v| v.expose().len())
                + s.obfuscation.as_ref().map_or(0, |v| v.expose().len())
        })
        .sum();
    let charged_bytes =
        req.input.0.len() + public_bytes + secret_bytes + batch.entries.len() * 4096;
    let mut r = registry()?;
    if r.pending.len() >= MAX_PENDING
        || r.pending
            .values()
            .map(|p| p.charged_bytes)
            .sum::<usize>()
            .saturating_add(charged_bytes)
            > MAX_PENDING_BYTES
    {
        return Err(error(ErrorCode::QueueFull, "codec.pending"));
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| error(ErrorCode::Internal, "codec.entropy"))?;
    let id = format!(
        "pending-{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    if r.pending.contains_key(&id) {
        return Err(error(ErrorCode::Internal, "codec.entropy"));
    }
    r.pending.insert(
        id.clone(),
        Pending {
            charged_bytes,
            batch,
            created: Instant::now(),
            transferred: BTreeSet::new(),
        },
    );
    Ok(PreviewResponse {
        pending_id: id,
        expires_in_seconds: PENDING_TTL.as_secs() as u32,
        report,
    })
}
fn transfer(input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let req: TransferRequest = decode(input)?;
    version(req.schema_version)?;
    confirm(req.confirmed)?;
    valid_pending_id(&req.pending_id)?;
    if !matches!(req.operation, Operation::Transfer)
        || req.indices.is_empty()
        || req.indices.len() > 1024
    {
        return Err(invalid());
    }
    let indices: BTreeSet<_> = req.indices.iter().copied().collect();
    if indices.len() != req.indices.len() {
        return Err(invalid());
    }
    let mut r = registry()?;
    let pending = r.pending.get_mut(&req.pending_id).ok_or_else(missing)?;
    if pending.batch.has_unimported_fields && !req.accept_node_extraction {
        return Err(error(
            ErrorCode::ConfirmationRequired,
            "acceptNodeExtraction",
        ));
    }
    if !pending.transferred.is_empty() && pending.transferred != indices {
        return Err(error(ErrorCode::IdempotencyConflict, "indices"));
    }
    let mut entries = Vec::new();
    for index in &req.indices {
        let entry = pending
            .batch
            .entries
            .iter()
            .find(|e| e.index == *index)
            .and_then(|e| e.candidate.as_ref())
            .ok_or_else(invalid)?;
        entries.push(TransferEntry {
            index: *index,
            preview: entry.preview(),
            secrets: entry.secrets().into(),
        });
    }
    let bytes = response(Ok(TransferResponse {
        secret_transfer: TransferEnvelope {
            schema_version: 1,
            purpose: "vault_import",
            pending_id: &req.pending_id,
            entries,
        },
    }))?;
    pending.transferred = indices;
    Ok(bytes)
}
fn materialize(input: &[u8]) -> Result<Materialized> {
    let req: MaterializeRequest = decode(input)?;
    version(req.schema_version)?;
    confirm(req.confirmed)?;
    valid_pending_id(&req.pending_id)?;
    if !matches!(req.operation, Operation::Materialize)
        || req.bindings.is_empty()
        || req.bindings.len() > 1024
    {
        return Err(invalid());
    }
    let mut r = registry()?;
    let pending = r.pending.get(&req.pending_id).ok_or_else(missing)?;
    let mut indices = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut refs = BTreeSet::new();
    for b in &req.bindings {
        if !indices.insert(b.index)
            || !ids.insert(b.id.clone())
            || !refs.insert(b.credential_ref.clone())
            || !pending.transferred.contains(&b.index)
        {
            return Err(invalid());
        }
        if let Some(obfs) = &b.obfuscation_ref {
            if !refs.insert(obfs.clone()) {
                return Err(invalid());
            }
        }
        let candidate = pending
            .batch
            .entries
            .iter()
            .find(|e| e.index == b.index)
            .and_then(|e| e.candidate.as_ref())
            .ok_or_else(invalid)?;
        if candidate.secrets().obfuscation.is_some() != b.obfuscation_ref.is_some() {
            return Err(error(ErrorCode::ConfigInvalid, "bindings.obfuscationRef"));
        }
    }
    if indices != pending.transferred {
        return Err(error(ErrorCode::ConfigInvalid, "bindings"));
    }
    // All bindings are checked before any candidate is moved. Materialization
    // consumes this pending import; transaction rollback remains the vault host's duty.
    let mut pending = r.pending.remove(&req.pending_id).ok_or_else(missing)?;
    let mut nodes = Vec::new();
    for b in req.bindings {
        let candidate = pending
            .batch
            .entries
            .iter_mut()
            .find(|e| e.index == b.index)
            .and_then(|e| e.candidate.take())
            .ok_or_else(invalid)?;
        nodes.push(
            candidate
                .materialize(
                    b.id,
                    b.source_ref,
                    AllocatedSecrets {
                        credential_ref: b.credential_ref,
                        obfuscation_ref: b.obfuscation_ref,
                    },
                )
                .map_err(|e| e.error)?,
        );
    }
    Ok(Materialized { nodes })
}
fn release(input: &[u8]) -> Result<Released> {
    let req: ReleaseRequest = decode(input)?;
    version(req.schema_version)?;
    valid_pending_id(&req.pending_id)?;
    if !matches!(req.operation, Operation::Release) {
        return Err(invalid());
    }
    registry()?.pending.remove(&req.pending_id);
    Ok(Released { released: true })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ValidateRequest {
    schema_version: u16,
    node: NodeProfile,
}
#[derive(Serialize)]
struct Validated {
    valid: bool,
}
pub fn validate_request(input: &[u8]) -> Zeroizing<Vec<u8>> {
    prune_expired();
    encode((|| {
        let req: ValidateRequest = decode(input)?;
        version(req.schema_version)?;
        req.node.validate()?;
        Ok(Validated { valid: true })
    })())
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransferKind {
    None,
    Password,
    Uuid,
    UsernamePassword,
    UuidPassword,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InputSecrets {
    kind: TransferKind,
    primary: TransferBytes,
    secondary: Option<TransferBytes>,
    obfuscation: Option<TransferBytes>,
}
impl InputSecrets {
    fn into_bundle(mut self) -> Result<SecretBundle> {
        if self.primary.0.len() > 4096
            || self.secondary.as_ref().is_some_and(|v| v.0.len() > 4096)
            || self.obfuscation.as_ref().is_some_and(|v| v.0.len() > 4096)
        {
            return Err(error(ErrorCode::InputTooLarge, "secretTransfer"));
        }
        Ok(SecretBundle {
            credential: Credential {
                kind: match self.kind {
                    TransferKind::None => CredentialKind::None,
                    TransferKind::Password => CredentialKind::Password,
                    TransferKind::Uuid => CredentialKind::Uuid,
                    TransferKind::UsernamePassword => CredentialKind::UsernamePassword,
                    TransferKind::UuidPassword => CredentialKind::UuidPassword,
                },
                primary: SecretBytes::new(std::mem::take(&mut self.primary.0)),
                secondary: self
                    .secondary
                    .as_mut()
                    .map(|v| SecretBytes::new(std::mem::take(&mut v.0))),
            },
            obfuscation: self
                .obfuscation
                .as_mut()
                .map(|v| SecretBytes::new(std::mem::take(&mut v.0))),
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportRequest {
    schema_version: u16,
    confirmed: bool,
    node: NodeProfile,
    secret_transfer: InputSecrets,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportResponse<'a> {
    secret_export: ExportText<'a>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportText<'a> {
    schema_version: u16,
    purpose: &'static str,
    format: &'static str,
    text: &'a str,
}
pub fn export_request(input: &[u8]) -> Zeroizing<Vec<u8>> {
    prune_expired();
    let result = (|| {
        let req: ExportRequest = decode(input)?;
        version(req.schema_version)?;
        confirm(req.confirmed)?;
        let bundle = req.secret_transfer.into_bundle()?;
        let text = vp_product_import::export_uri(&req.node, &bundle).map_err(|e| e.error)?;
        response(Ok(ExportResponse {
            secret_export: ExportText {
                schema_version: 1,
                purpose: "user_export",
                format: "node_uri",
                text: text.expose(),
            },
        }))
    })();
    result.unwrap_or_else(|e| encode::<()>(Err(e)))
}
pub fn abi_info() -> Zeroizing<Vec<u8>> {
    prune_expired();
    Zeroizing::new(br#"{"schemaVersion":1,"abiMajor":1,"abiMinor":0,"library":"vp-product-codec-ffi","maxInputBytes":8388608,"maxParserInputBytes":1048576,"maxPendingImports":16,"maxPendingChargedBytes":8388608,"pendingTtlSeconds":900,"secretTransferVersion":1,"operations":["preview","transfer","materialize","release","validate","export_uri"],"network":false,"filesystem":false,"runtime":false}"#.to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    static TEST: Mutex<()> = Mutex::new(());
    fn request(value: Value) -> Value {
        serde_json::from_slice(&parse_request(&serde_json::to_vec(&value).unwrap())).unwrap()
    }
    fn preview_uri(uri: &str) -> Value {
        request(json!({"schemaVersion":1,"operation":"preview","format":"node_uri","input":uri}))
    }
    fn id(value: &Value) -> String {
        value["result"]["pendingId"].as_str().unwrap().into()
    }
    fn transfer(id: &str, indices: &[u32]) -> Value {
        request(
            json!({"schemaVersion":1,"operation":"transfer","pendingId":id,"confirmed":true,"indices":indices,"acceptNodeExtraction":false}),
        )
    }
    fn release_id(id: &str) {
        request(json!({"schemaVersion":1,"operation":"release","pendingId":id}));
    }
    fn bind(id: &str, indices: &[u32]) -> Value {
        request(
            json!({"schemaVersion":1,"operation":"materialize","pendingId":id,"confirmed":true,"bindings":indices.iter().map(|i|json!({"index":i,"id":format!("node-{i}"),"sourceRef":null,"credentialRef":format!("secret:allocated-{i}"),"obfuscationRef":null})).collect::<Vec<_>>()}),
        )
    }
    #[test]
    fn preview_has_no_secret_or_fabricated_reference() {
        let _guard = TEST.lock().unwrap();
        let value = preview_uri("socks5://synthetic-user:synthetic-password@127.0.0.1:1080#test");
        let text = value.to_string();
        assert!(!text.contains("synthetic-user"));
        assert!(!text.contains("synthetic-password"));
        assert!(!text.contains("secret:"));
        assert_eq!(
            value["result"]["report"]["entries"][0]["disposition"],
            "needs_review"
        );
        release_id(&id(&value));
    }
    #[test]
    fn explicit_transfer_materialize_and_export_round_trip() {
        let _guard = TEST.lock().unwrap();
        let value = preview_uri("socks5://synthetic-user:synthetic-password@127.0.0.1:1080#test");
        let pending = id(&value);
        assert_eq!(bind(&pending, &[0])["error"]["code"], "CONFIG_INVALID");
        let denied = request(
            json!({"schemaVersion":1,"operation":"transfer","pendingId":pending,"confirmed":false,"indices":[0],"acceptNodeExtraction":false}),
        );
        assert_eq!(denied["error"]["code"], "CONFIRMATION_REQUIRED");
        let secrets = transfer(&pending, &[0]);
        assert_eq!(secrets, transfer(&pending, &[0]));
        assert_eq!(
            secrets["result"]["secretTransfer"]["entries"][0]["secrets"]["kind"],
            "username_password"
        );
        let materialized = bind(&pending, &[0]);
        let node = &materialized["result"]["nodes"][0];
        assert_eq!(node["credentialRef"], "secret:allocated-0");
        assert!(!materialized.to_string().contains("synthetic-password"));
        assert_eq!(bind(&pending, &[0])["error"]["code"], "PLAN_EXPIRED");
        let export = json!({"schemaVersion":1,"confirmed":true,"node":node,"secretTransfer":secrets["result"]["secretTransfer"]["entries"][0]["secrets"]});
        let result: Value =
            serde_json::from_slice(&export_request(&serde_json::to_vec(&export).unwrap())).unwrap();
        assert_eq!(
            result["result"]["secretExport"]["text"],
            "socks5://synthetic-user:synthetic-password@127.0.0.1:1080#test"
        );
        let mut denied = export;
        denied["confirmed"] = false.into();
        let result: Value =
            serde_json::from_slice(&export_request(&serde_json::to_vec(&denied).unwrap())).unwrap();
        assert_eq!(result["error"]["code"], "CONFIRMATION_REQUIRED");
    }
    #[test]
    fn selection_locks_and_materialization_requires_exact_set() {
        let _guard = TEST.lock().unwrap();
        let value = request(
            json!({"schemaVersion":1,"operation":"preview","format":"uri_list","input":"socks5://127.0.0.1:1080#one\nsocks5://127.0.0.1:1081#two"}),
        );
        let pending = id(&value);
        assert!(transfer(&pending, &[0, 1])["error"].is_null());
        assert_eq!(
            transfer(&pending, &[0])["error"]["code"],
            "IDEMPOTENCY_CONFLICT"
        );
        assert_eq!(bind(&pending, &[0])["error"]["code"], "CONFIG_INVALID");
        assert!(bind(&pending, &[0, 1])["error"].is_null());
    }
    #[test]
    fn expiry_and_release_drop_candidates_and_revoke_authority() {
        let _guard = TEST.lock().unwrap();
        let pending = id(&preview_uri("socks5://127.0.0.1:1080#one"));
        registry()
            .unwrap()
            .pending
            .get_mut(&pending)
            .unwrap()
            .created = Instant::now() - Duration::from_secs(901);
        abi_info();
        assert!(!PENDING
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .pending
            .contains_key(&pending));
        assert_eq!(transfer(&pending, &[0])["error"]["code"], "PLAN_EXPIRED");
        assert!(!registry().unwrap().pending.contains_key(&pending));
        release_id(&pending);
        release_id(&pending);
        let pending = id(&preview_uri("socks5://127.0.0.1:1080#one"));
        release_id(&pending);
        assert_eq!(transfer(&pending, &[0])["error"]["code"], "PLAN_EXPIRED");
    }
    #[test]
    fn unknown_duplicate_invalid_and_unsupported_inputs_fail_safely() {
        let _guard = TEST.lock().unwrap();
        let duplicate = br#"{"schemaVersion":1,"operation":"preview","format":"node_uri","input":"synthetic-secret","input":"other"}"#;
        let result: Value = serde_json::from_slice(&parse_request(duplicate)).unwrap();
        assert_eq!(result["error"]["code"], "CONFIG_INVALID");
        assert!(!result.to_string().contains("synthetic-secret"));
        let unknown = request(
            json!({"schemaVersion":1,"operation":"preview","format":"node_uri","input":"socks5://127.0.0.1:1080","unknown":true}),
        );
        assert_eq!(unknown["error"]["code"], "CONFIG_INVALID");
        let unsupported = preview_uri("tuic://synthetic-secret@localhost:443");
        assert_eq!(
            unsupported["result"]["report"]["entries"][0]["disposition"],
            "rejected"
        );
        assert_eq!(
            unsupported["result"]["report"]["entries"][0]["diagnostics"][0]["code"],
            "IMPORT_UNSUPPORTED"
        );
        release_id(&id(&unsupported));
        let insecure = preview_uri("trojan://synthetic-secret@localhost:443?allowInsecure=1");
        assert_eq!(
            insecure["result"]["report"]["entries"][0]["disposition"],
            "rejected"
        );
        release_id(&id(&insecure));
    }
    #[test]
    fn extraction_requires_a_distinct_confirmation() {
        let _guard = TEST.lock().unwrap();
        let value = request(
            json!({"schemaVersion":1,"operation":"preview","format":"sing_box_outbounds","input":"{\"outbounds\":[{\"type\":\"socks\",\"server\":\"127.0.0.1\",\"server_port\":1080,\"version\":\"5\"}],\"route\":{}}"}),
        );
        let pending = id(&value);
        assert!(value["result"]["report"]["hasUnimportedFields"]
            .as_bool()
            .unwrap());
        assert_eq!(
            transfer(&pending, &[0])["error"]["code"],
            "CONFIRMATION_REQUIRED"
        );
        release_id(&pending);
    }
    #[test]
    fn count_and_charged_memory_budgets_are_bounded() {
        let _guard = TEST.lock().unwrap();
        let mut ids = Vec::new();
        for _ in 0..MAX_PENDING {
            ids.push(id(&preview_uri("socks5://127.0.0.1:1080#one")));
        }
        assert_eq!(
            preview_uri("socks5://127.0.0.1:1080#one")["error"]["code"],
            "QUEUE_FULL"
        );
        for id in ids {
            release_id(&id);
        }
        let pending = id(&preview_uri("socks5://127.0.0.1:1080#one"));
        registry()
            .unwrap()
            .pending
            .get_mut(&pending)
            .unwrap()
            .charged_bytes = MAX_PENDING_BYTES;
        assert_eq!(
            preview_uri("socks5://127.0.0.1:1080#one")["error"]["code"],
            "QUEUE_FULL"
        );
        release_id(&pending);
    }
    #[test]
    fn pending_tokens_are_unpredictable_fixed_shape_and_distinct() {
        let _guard = TEST.lock().unwrap();
        let a = id(&preview_uri("socks5://127.0.0.1:1080#one"));
        let b = id(&preview_uri("socks5://127.0.0.1:1080#one"));
        assert_ne!(a, b);
        assert_eq!(a.len(), 40);
        assert!(valid_pending_id(&a).is_ok());
        release_id(&a);
        release_id(&b);
    }
}
