# Public RSA test fixture

The deliberately insecure, publicly distributed `rsa_test_private_key_2048.p8`
fixture is copied byte-for-byte from the cached crates.io package ring 0.17.14,
path `tests/rsa_test_private_key_2048.p8`.

SHA-256: `a0d95a0b133b4c217bc11322b67d62eb13537b8a9f66e20b5c9b5ac31af21859`.

Upstream: https://github.com/briansmith/ring/tree/v0.17.14
The package license overview and its ISC and BoringSSL license texts are retained
alongside this file. This fixture is included only by Rust unit tests, never by
a production build, deployed certificate, authentication identity or signer.
