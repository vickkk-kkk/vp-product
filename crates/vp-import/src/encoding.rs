use crate::{invalid, issue, IssueKind, Result, MAX_COMPONENT_BYTES};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use zeroize::Zeroizing;

pub(crate) fn decode_base64(input: &str, max_decoded: usize) -> Result<Zeroizing<Vec<u8>>> {
    // Check before allocating. Each full four-character block needs three bytes.
    if input.len().saturating_mul(3) / 4 > max_decoded.saturating_add(2) {
        return Err(issue(IssueKind::InputLimit, "base64"));
    }
    if input.is_empty() || input.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(invalid("base64"));
    }
    let decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(input).ok())
        .ok_or_else(|| invalid("base64"))?;
    let decoded = Zeroizing::new(decoded);
    if decoded.len() > max_decoded {
        return Err(issue(IssueKind::InputLimit, "base64"));
    }
    Ok(decoded)
}
pub(crate) fn encode_base64(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}
pub(crate) fn encode_component(input: &str) -> String {
    let mut encoded = String::new();
    const HEX: &[u8] = b"0123456789ABCDEF";
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 15) as usize] as char);
        }
    }
    encoded
}
pub(crate) fn decode_component(input: &str) -> Result<Zeroizing<String>> {
    if input.len() > MAX_COMPONENT_BYTES * 3 {
        return Err(issue(IssueKind::InputLimit, "uri.component"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut iter = input.bytes();
    while let Some(byte) = iter.next() {
        if byte == b'%' {
            let hi = iter
                .next()
                .and_then(hex)
                .ok_or_else(|| invalid("uri.escape"))?;
            let lo = iter
                .next()
                .and_then(hex)
                .ok_or_else(|| invalid("uri.escape"))?;
            bytes.push(hi * 16 + lo);
        } else {
            bytes.push(byte);
        } // '+' is literal RFC3986, never a form space.
    }
    if bytes.len() > MAX_COMPONENT_BYTES {
        return Err(issue(IssueKind::InputLimit, "uri.component"));
    }
    let value =
        std::str::from_utf8(&bytes).map_err(|_| issue(IssueKind::InvalidUtf8, "uri.component"))?;
    if value.chars().any(char::is_control) {
        return Err(invalid("uri.component"));
    }
    Ok(Zeroizing::new(value.to_owned()))
}
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
