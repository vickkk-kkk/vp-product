//! Independent v2 stdio protocol. V1 WorkerConfig/Request are not extended.
//! Material is a bounded numeric-byte array, never a serde String/Value: this
//! avoids unzeroized JSON string scratch containing plaintext credentials/PEM.
use super::{server_v2::ServerInputsV2, Failure, StopReport, WorkerSnapshot};
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    fmt,
    io::{self, Read, Write},
};
use vp_product_compiler::server_v2::ServerRecipeV2;
use vp_product_domain::{CertificateId, ReleaseIdentity, SecretBytes, SecretRef, MAX_WIRE_COUNTER};
use zeroize::{Zeroize, Zeroizing};

pub const VERSION_V2: u16 = 2;
pub const MAX_REQUEST_FRAME_V2: usize = 16 * 1024 * 1024;
pub const MAX_RESPONSE_FRAME_V2: usize = 64 * 1024;
pub const MAX_RECIPE_JSON_V2: usize = 1024 * 1024;
pub const MAX_MATERIAL_BYTES_V2: usize = 2 * 1024 * 1024;
pub const MAX_MATERIAL_RECORDS_V2: usize = 512;
pub const MAX_CERTIFICATE_BYTES_V2: usize = 128 * 1024;
pub const PREPARED_LEASE_SECONDS_V2: u64 = 30;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct WorkerInstanceV2(String);
impl WorkerInstanceV2 {
    pub fn new(value: &str) -> Result<Self, Failure> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(Failure::InvalidConfig);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for WorkerInstanceV2 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = WorkerInstanceV2;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded worker instance")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                WorkerInstanceV2::new(value).map_err(|_| E::custom("invalid worker instance"))
            }
        }
        d.deserialize_str(V)
    }
}

/// No Debug/Clone/Serialize on decoded secrets or whole requests. Partial decode
/// failures drop these buffers through Zeroizing. Best effort, not swap/process-
/// compromise protection; upstream authenticated protocol state remains in RAM.
pub(crate) struct SecretBufferV2(Zeroizing<Vec<u8>>);
impl<'de> Deserialize<'de> for SecretBufferV2 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = SecretBufferV2;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded secret byte array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut bytes = Zeroizing::new(Vec::new());
                while let Some(byte) = seq.next_element::<u8>()? {
                    if bytes.len() == MAX_CERTIFICATE_BYTES_V2 {
                        return Err(de::Error::custom("material entry exceeds bound"));
                    }
                    scrubbed_extend(&mut bytes, &[byte], MAX_CERTIFICATE_BYTES_V2)
                        .map_err(|_| de::Error::custom("material entry exceeds bound"))?;
                }
                Ok(SecretBufferV2(bytes))
            }
        }
        d.deserialize_seq(V)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MaterialKindV2 {
    Credential,
    CertificateChain,
    PrivateKey,
}
struct BoundedReferenceV2(String);
impl<'de> Deserialize<'de> for BoundedReferenceV2 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = BoundedReferenceV2;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded immutable reference")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.is_empty() || v.len() > 160 {
                    return Err(E::custom("invalid material reference"));
                }
                Ok(BoundedReferenceV2(v.to_owned()))
            }
        }
        d.deserialize_str(V)
    }
}
// Plain structs deliberately avoid internally tagged secret-bearing enums:
// serde's Content buffering for such enums would not zeroize secret arrays.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MaterialRecordV2 {
    kind: MaterialKindV2,
    reference: BoundedReferenceV2,
    value: SecretBufferV2,
}
pub(crate) struct MaterialRecordsV2(Vec<MaterialRecordV2>);
impl<'de> Deserialize<'de> for MaterialRecordsV2 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = MaterialRecordsV2;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded material records")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut records = Vec::new();
                let mut total = 0_usize;
                while let Some(record) = seq.next_element::<MaterialRecordV2>()? {
                    total = total
                        .checked_add(record.value.0.len())
                        .ok_or_else(|| de::Error::custom("material budget"))?;
                    if records.len() == MAX_MATERIAL_RECORDS_V2 || total > MAX_MATERIAL_BYTES_V2 {
                        return Err(de::Error::custom("material budget"));
                    }
                    records.push(record);
                }
                Ok(MaterialRecordsV2(records))
            }
        }
        d.deserialize_seq(V)
    }
}
impl MaterialRecordsV2 {
    fn into_inputs(self) -> Result<ServerInputsV2, Failure> {
        let mut inputs = ServerInputsV2::default();
        for mut record in self.0 {
            let value = SecretBytes::new(std::mem::take(&mut *record.value.0));
            match record.kind {
                MaterialKindV2::Credential => {
                    let reference = SecretRef::try_from(record.reference.0)
                        .map_err(|_| Failure::InvalidConfig)?;
                    if value.expose().is_empty()
                        || value.expose().len() > 4096
                        || inputs.credentials.contains_key(&reference)
                    {
                        return Err(Failure::InvalidConfig);
                    }
                    inputs.credentials.insert(reference, value);
                }
                MaterialKindV2::CertificateChain => {
                    let reference = CertificateId::new(&record.reference.0)
                        .map_err(|_| Failure::InvalidConfig)?;
                    if value.expose().is_empty()
                        || inputs.certificate_chains.contains_key(&reference)
                    {
                        return Err(Failure::InvalidConfig);
                    }
                    inputs.certificate_chains.insert(reference, value);
                }
                MaterialKindV2::PrivateKey => {
                    let reference = SecretRef::try_from(record.reference.0)
                        .map_err(|_| Failure::InvalidConfig)?;
                    if value.expose().is_empty()
                        || value.expose().len() > 65536
                        || inputs.private_keys.contains_key(&reference)
                    {
                        return Err(Failure::InvalidConfig);
                    }
                    inputs.private_keys.insert(reference, value);
                }
            }
        }
        validate_material_budget(&inputs)?;
        Ok(inputs)
    }
}
pub(crate) struct RecipeJsonV2(Zeroizing<String>);
impl<'de> Deserialize<'de> for RecipeJsonV2 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RecipeJsonV2;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded reference-only recipe JSON")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.len() > MAX_RECIPE_JSON_V2 || v.is_empty() {
                    return Err(E::custom("recipe JSON bound"));
                }
                Ok(RecipeJsonV2(Zeroizing::new(v.to_owned())))
            }
        }
        d.deserialize_str(V)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct StartServerV2 {
    schema_version: u16,
    recipe_json: RecipeJsonV2,
    materials: MaterialRecordsV2,
    pub startup_ms: u64,
}
impl StartServerV2 {
    pub fn into_materialized(self) -> Result<(ServerRecipeV2, ServerInputsV2, u64), Failure> {
        if self.schema_version != VERSION_V2 || self.startup_ms == 0 || self.startup_ms > 30_000 {
            return Err(Failure::InvalidConfig);
        }
        let recipe =
            serde_json::from_str(&self.recipe_json.0).map_err(|_| Failure::InvalidConfig)?;
        Ok((recipe, self.materials.into_inputs()?, self.startup_ms))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum CommandV2 {
    #[serde(rename = "negotiate_server_v2")]
    Negotiate,
    #[serde(rename = "prepare_server_v2")]
    Prepare,
    #[serde(rename = "activate_server_v2")]
    Activate,
    #[serde(rename = "snapshot_server_v2")]
    Snapshot,
    #[serde(rename = "stop_server_v2")]
    Stop,
    #[serde(rename = "discard_server_v2")]
    Discard,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RequestV2 {
    pub version: u16,
    pub kind: CommandV2,
    pub instance: WorkerInstanceV2,
    pub generation: u64,
    pub start_server_v2: Option<StartServerV2>,
    pub drain_ms: Option<u64>,
}
impl RequestV2 {
    pub fn validate_shape(&self) -> Result<(), Failure> {
        if self.version != VERSION_V2 || self.generation > MAX_WIRE_COUNTER {
            return Err(Failure::ProtocolViolation);
        }
        let valid = match self.kind {
            CommandV2::Negotiate => {
                self.generation == 0 && self.start_server_v2.is_none() && self.drain_ms.is_none()
            }
            CommandV2::Prepare => {
                self.generation > 0 && self.start_server_v2.is_some() && self.drain_ms.is_none()
            }
            CommandV2::Stop => {
                self.generation > 0
                    && self.start_server_v2.is_none()
                    && self.drain_ms.is_some_and(|v| v <= 5000)
            }
            _ => self.generation > 0 && self.start_server_v2.is_none() && self.drain_ms.is_none(),
        };
        if valid {
            Ok(())
        } else {
            Err(Failure::ProtocolViolation)
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseV2 {
    HelloServerV2 {
        version: u16,
        pid: u32,
        release: ReleaseIdentity,
        max_request_bytes: usize,
        #[serde(default)]
        test_fixture: bool,
    },
    NegotiatedServerV2 {
        version: u16,
        instance: WorkerInstanceV2,
        pid: u32,
    },
    PreparedServerV2 {
        instance: WorkerInstanceV2,
        generation: u64,
        pid: u32,
    },
    StartedServerV2 {
        instance: WorkerInstanceV2,
        snapshot: WorkerSnapshot,
    },
    SnapshotServerV2 {
        instance: WorkerInstanceV2,
        snapshot: WorkerSnapshot,
    },
    StoppedServerV2 {
        instance: WorkerInstanceV2,
        report: StopReport,
    },
    DiscardedServerV2 {
        instance: WorkerInstanceV2,
        generation: u64,
        pid: u32,
    },
    FailedServerV2 {
        failure: Failure,
    },
}

pub(crate) fn validate_material_budget(inputs: &ServerInputsV2) -> Result<(), Failure> {
    let count = inputs
        .credentials
        .len()
        .checked_add(inputs.certificate_chains.len())
        .and_then(|n| n.checked_add(inputs.private_keys.len()))
        .ok_or(Failure::InvalidConfig)?;
    if count > MAX_MATERIAL_RECORDS_V2
        || inputs
            .credentials
            .keys()
            .any(|id| inputs.private_keys.contains_key(id))
    {
        return Err(Failure::InvalidConfig);
    }
    let mut total = 0_usize;
    for (values, limit) in [
        (inputs.credentials.values().collect::<Vec<_>>(), 4096),
        (
            inputs.certificate_chains.values().collect(),
            MAX_CERTIFICATE_BYTES_V2,
        ),
        (inputs.private_keys.values().collect(), 65536),
    ] {
        for value in values {
            let len = value.expose().len();
            total = total.checked_add(len).ok_or(Failure::InvalidConfig)?;
            if len == 0 || len > limit || total > MAX_MATERIAL_BYTES_V2 {
                return Err(Failure::InvalidConfig);
            }
        }
    }
    Ok(())
}
struct SecretBorrow<'a>(&'a SecretBytes);
impl Serialize for SecretBorrow<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0.expose())
    }
}
#[derive(Serialize)]
struct RecordBorrow<'a> {
    kind: MaterialKindV2,
    reference: &'a str,
    value: SecretBorrow<'a>,
}
struct MaterialsBorrow<'a>(&'a ServerInputsV2);
impl Serialize for MaterialsBorrow<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(
            self.0.credentials.len() + self.0.certificate_chains.len() + self.0.private_keys.len(),
        ))?;
        for (reference, value) in &self.0.credentials {
            seq.serialize_element(&RecordBorrow {
                kind: MaterialKindV2::Credential,
                reference: reference.as_str(),
                value: SecretBorrow(value),
            })?;
        }
        for (reference, value) in &self.0.certificate_chains {
            seq.serialize_element(&RecordBorrow {
                kind: MaterialKindV2::CertificateChain,
                reference: reference.as_str(),
                value: SecretBorrow(value),
            })?;
        }
        for (reference, value) in &self.0.private_keys {
            seq.serialize_element(&RecordBorrow {
                kind: MaterialKindV2::PrivateKey,
                reference: reference.as_str(),
                value: SecretBorrow(value),
            })?;
        }
        seq.end()
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartBorrow<'a> {
    schema_version: u16,
    recipe_json: &'a str,
    materials: MaterialsBorrow<'a>,
    startup_ms: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestBorrow<'a> {
    version: u16,
    kind: CommandV2,
    instance: &'a WorkerInstanceV2,
    generation: u64,
    start_server_v2: Option<StartBorrow<'a>>,
    drain_ms: Option<u64>,
}
struct Counter {
    len: usize,
    max: usize,
}
impl Write for Counter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.len = self
            .len
            .checked_add(b.len())
            .filter(|n| *n <= self.max)
            .ok_or_else(|| io::Error::other("frame bound"))?;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct BoundedWriter {
    bytes: Zeroizing<Vec<u8>>,
    max: usize,
}
impl Write for BoundedWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() > self.max.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("frame bound"));
        }
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bounded_json(value: &impl Serialize, max: usize) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut count = Counter { len: 0, max };
    serde_json::to_writer(&mut count, value).map_err(|_| Failure::InvalidConfig)?;
    let mut out = BoundedWriter {
        bytes: Zeroizing::new(Vec::with_capacity(count.len + 1)),
        max: count.len,
    };
    serde_json::to_writer(&mut out, value).map_err(|_| Failure::InvalidConfig)?;
    if out.bytes.len() != count.len {
        return Err(Failure::InvalidConfig);
    }
    Ok(out.bytes)
}
/// No Debug/Serialize: only the dedicated pipe transport may expose bytes.
pub(crate) struct SecretFrameV2(Zeroizing<Vec<u8>>);
impl SecretFrameV2 {
    pub fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&self.0).and_then(|_| out.flush())
    }
}
fn frame(value: &impl Serialize, max: usize) -> Result<SecretFrameV2, Failure> {
    let mut bytes = bounded_json(value, max - 1)?;
    bytes.push(b'\n');
    Ok(SecretFrameV2(bytes))
}
pub(crate) fn encode_prepare(
    instance: &WorkerInstanceV2,
    generation: u64,
    recipe: &ServerRecipeV2,
    inputs: &ServerInputsV2,
    startup_ms: u64,
) -> Result<SecretFrameV2, Failure> {
    validate_material_budget(inputs)?;
    let json = bounded_json(recipe, MAX_RECIPE_JSON_V2)?;
    let recipe_json = std::str::from_utf8(&json).map_err(|_| Failure::InvalidConfig)?;
    frame(
        &RequestBorrow {
            version: VERSION_V2,
            kind: CommandV2::Prepare,
            instance,
            generation,
            start_server_v2: Some(StartBorrow {
                schema_version: VERSION_V2,
                recipe_json,
                materials: MaterialsBorrow(inputs),
                startup_ms,
            }),
            drain_ms: None,
        },
        MAX_REQUEST_FRAME_V2,
    )
}
pub(crate) fn encode_control(
    kind: CommandV2,
    instance: &WorkerInstanceV2,
    generation: u64,
    drain_ms: Option<u64>,
) -> Result<SecretFrameV2, Failure> {
    frame(
        &RequestBorrow {
            version: VERSION_V2,
            kind,
            instance,
            generation,
            start_server_v2: None,
            drain_ms,
        },
        MAX_REQUEST_FRAME_V2,
    )
}
pub(crate) fn encode_response(response: &ResponseV2) -> Result<SecretFrameV2, Failure> {
    frame(response, MAX_RESPONSE_FRAME_V2)
}

// Vec growth normally frees an unscrubbed prior allocation even inside
// Zeroizing<Vec<_>>. Explicitly copy into a bounded replacement, scrub the old
// allocation before dropping it, and never call reserve/realloc on secret data.
fn scrubbed_extend(bytes: &mut Zeroizing<Vec<u8>>, extra: &[u8], max: usize) -> io::Result<()> {
    let required = bytes
        .len()
        .checked_add(extra.len())
        .filter(|n| *n <= max)
        .ok_or_else(|| io::Error::other("buffer bound"))?;
    if required > bytes.capacity() {
        let capacity = bytes
            .capacity()
            .max(16)
            .saturating_mul(2)
            .max(required)
            .min(max);
        let mut replacement = Zeroizing::new(Vec::with_capacity(capacity));
        replacement.extend_from_slice(bytes);
        bytes.zeroize();
        *bytes = replacement;
    }
    bytes.extend_from_slice(extra);
    Ok(())
}

/// Owns a zeroizing read-ahead buffer; do not wrap secret input in BufReader.
/// Both raw frames and read-ahead storage are scrubbed on all return/error paths.
pub(crate) struct FrameReaderV2<R> {
    inner: R,
    buffer: Zeroizing<[u8; 8192]>,
    start: usize,
    end: usize,
}
impl<R: Read> FrameReaderV2<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: Zeroizing::new([0; 8192]),
            start: 0,
            end: 0,
        }
    }
    pub fn read_frame(&mut self, max: usize) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        let mut bytes = Zeroizing::new(Vec::new());
        loop {
            if self.start == self.end {
                self.buffer.zeroize();
                self.start = 0;
                self.end = loop {
                    match self.inner.read(&mut *self.buffer) {
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        result => break result?,
                    }
                };
                if self.end == 0 {
                    return if bytes.is_empty() {
                        Ok(None)
                    } else {
                        Err(io::Error::other("truncated frame"))
                    };
                }
            }
            let unread = &self.buffer[self.start..self.end];
            let newline = unread.iter().position(|b| *b == b'\n');
            let count = newline.map_or(unread.len(), |n| n + 1);
            if count > max.saturating_sub(bytes.len()) {
                return Err(io::Error::other("frame bound"));
            }
            scrubbed_extend(&mut bytes, &unread[..count], max)?;
            self.buffer[self.start..self.start + count].zeroize();
            self.start += count;
            if newline.is_some() {
                return Ok(Some(bytes));
            }
        }
    }
}
pub(crate) fn decode_request(bytes: &[u8]) -> Result<RequestV2, Failure> {
    if bytes.len() > MAX_REQUEST_FRAME_V2 || bytes.last() != Some(&b'\n') {
        return Err(Failure::ProtocolViolation);
    }
    let request: RequestV2 = serde_json::from_slice(bytes).map_err(|_| Failure::InvalidConfig)?;
    request.validate_shape()?;
    Ok(request)
}

#[cfg(test)]
#[path = "protocol_v2_tests.rs"]
mod tests;
