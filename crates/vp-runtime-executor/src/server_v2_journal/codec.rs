use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Envelope {
    schema_version: u16,
    genesis: ContentDigest,
    digest: ContentDigest,
    journal: Journal,
}
/// Allocation-free lexical budget before typed serde. JSON syntax is checked by
/// serde next. Limits also bound escaped strings, nesting and total value count.
pub(super) fn budget(
    bytes: &[u8],
    max: usize,
    string_max: usize,
    depth_max: usize,
    tokens_max: usize,
) -> Result<(), ControlError> {
    require(!bytes.is_empty() && bytes.len() <= max && depth_max <= 64)?;
    let mut arrays = [false; 64];
    let mut elements = [0_u16; 64];
    let mut string = false;
    let mut escape = false;
    let mut length = 0usize;
    let mut depth = 0usize;
    let mut tokens = 0usize;
    for &b in bytes {
        if string {
            if !escape && b == b'"' {
                string = false;
                continue;
            }
            length += 1;
            require(length <= string_max)?;
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            }
        } else {
            match b {
                b'"' => {
                    string = true;
                    length = 0;
                    tokens += 1;
                }
                b'{' | b'[' => {
                    require(depth < depth_max)?;
                    arrays[depth] = b == b'[';
                    elements[depth] = 1;
                    depth += 1;
                    tokens += 1;
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or(ControlError::CorruptState)?;
                }
                b',' => {
                    tokens += 1;
                    if depth > 0 && arrays[depth - 1] {
                        elements[depth - 1] += 1;
                        require(elements[depth - 1] <= 128)?;
                    }
                }
                b':' => tokens += 1,
                _ => {}
            }
            require(tokens <= tokens_max)?;
        }
    }
    require(!string && depth == 0)
}
pub(super) fn encode(j: &Journal) -> Result<Vec<u8>, ControlError> {
    j.validate()?;
    let e = Envelope {
        schema_version: SCHEMA,
        genesis: j.identity.genesis.clone(),
        digest: ContentDigest::of(DOMAIN, &(&j.identity.genesis, j))?,
        journal: j.clone(),
    };
    let bytes = serde_json::to_vec(&e).map_err(|_| ControlError::CorruptState)?;
    budget(&bytes, MAX_JOURNAL_BYTES, 1024, 16, 4096)?;
    Ok(bytes)
}
pub(super) fn decode(bytes: &[u8], expected: &Identity) -> Result<Journal, ControlError> {
    expected.validate()?;
    budget(bytes, MAX_JOURNAL_BYTES, 1024, 16, 4096)?;
    let e: Envelope = serde_json::from_slice(bytes).map_err(|_| ControlError::CorruptState)?;
    require(
        e.schema_version == SCHEMA
            && e.genesis == expected.genesis
            && e.journal.identity == *expected,
    )?;
    e.journal.validate()?;
    require(e.digest == ContentDigest::of(DOMAIN, &(&e.genesis, &e.journal))?)?;
    // Fixed, typed canonical writer form: duplicate keys, alternate whitespace,
    // escaped aliases, reordered fields and noncanonical numbers cannot be adopted.
    require(encode(&e.journal)?.as_slice() == bytes)?;
    Ok(e.journal)
}
