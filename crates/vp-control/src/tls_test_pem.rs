//! Test-only PEM encoding avoids rcgen's optional pem/serde_core dependency.
use base64::Engine;
pub(crate) fn encode(label: &str, bytes: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        for byte in chunk {
            out.push(*byte as char);
        }
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
pub(crate) trait TestPem {
    fn pem(&self) -> String;
    fn serialize_pem(&self) -> String {
        self.pem()
    }
}
impl TestPem for rcgen::Certificate {
    fn pem(&self) -> String {
        encode("CERTIFICATE", self.der().as_ref())
    }
}
impl TestPem for rcgen::KeyPair {
    fn pem(&self) -> String {
        encode("PRIVATE KEY", &self.serialize_der())
    }
}
