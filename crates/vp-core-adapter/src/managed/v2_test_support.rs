#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::server_v2::ServerInputsV2;
use vp_product_compiler::server_v2::{ServerCompilerV2, ServerRecipeV2};
use vp_product_domain::{ProductConfig, SecretBytes, SecretRef};
pub(crate) fn recipe(port: u16) -> ServerRecipeV2 {
    let source:ProductConfig=serde_json::from_value(serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{"schemaVersion":1,"id":"fixture-listener","name":"ipc-unit-fixture","enabled":true,"bind":{"address":"127.0.0.1","port":port},"protocol":{"kind":"proxy","protocol":{"kind":"vless","flow":null},"users":[{"id":"fixture-user","credentialRef":"secret:fixture-credential","enabled":true}]},"transport":{"kind":"tcp"},"security":{"kind":"none"},"requirements":[]}]})).unwrap();
    let release = crate::inspect_build().unwrap().build.release;
    ServerCompilerV2::for_loopback_server_extensions(release.clone())
        .unwrap()
        .compile(&source, &release)
        .unwrap()
}
pub(crate) fn inputs() -> ServerInputsV2 {
    let mut inputs = ServerInputsV2::default();
    inputs.credentials.insert(
        SecretRef::new("fixture-credential").unwrap(),
        SecretBytes::new(b"12345678-1234-1234-1234-123456789abc".to_vec()),
    );
    inputs
}
