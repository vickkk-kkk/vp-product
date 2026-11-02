# Public RSA test fixture — never use in production

`rsa_test_private_key_2048.p8` is deliberately public, insecure test material
from the published `ring` 0.17.14 source package, member
`ring-0.17.14/tests/rsa_test_private_key_2048.p8`.

Source archive: https://static.crates.io/crates/ring/ring-0.17.14.crate
The archive checksum was checked against the committed Cargo.lock. The fixture
is 1218 bytes and its SHA-256 is:
`a0d95a0b133b4c217bc11322b67d62eb13537b8a9f66e20b5c9b5ac31af21859`.

It exercises RSA certificate/key matching in local unit tests. It is not a user
credential, deployment key or acceptable production identity. Keep this notice
and the adjacent LICENSE, LICENSE-BoringSSL and LICENSE-other-bits files.
