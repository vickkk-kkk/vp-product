# Product contract baseline v1

These are independently authored contracts, not proof of a working ABI library,
certified protocol list or released product. On 2026-10-30 official Rust builds,
unit tests, schema generation and C/C++ declaration compilation were executed;
see `../docs/implementation/RUST_VALIDATION.md`. API/runtime implementation is
tracked separately and these contracts do not certify it.

- `schema/v1.schema.json`: mechanically generated JSON Schema 2020-12 definitions, keyed by
  `$defs`. A consumer validates against the named definition, not the unrestricted
  definitions-only root. Cross-field Rust `validate` rules remain mandatory.
- `events/v1.schema.json`: runtime event entry point. Generation and sequence gaps
  require a new snapshot; stale events cannot overwrite a newer disconnect.
- `openapi/v1.yaml`: OpenAPI 3.1 baseline in deterministic JSON syntax (valid YAML
  1.2). All endpoints explicitly have contract-only implementation status. The
  generic envelope `payload` is dispatched to a strict method-specific type;
  arbitrary maps are not proxy-core configuration.
- `abi/vp_adapter.h`: exact ABI v1 declarations, allocator/FD/packet ownership,
  callbacks, threading, cancellation, limits and destroy contract. No implementation
  is implied. `vp_codec.h` declares only pure parsing/validation/export functions.
- `capabilities/presets.json`: all 21 required public presets, seven SS methods,
  plus Direct's explicit pending scope decision. Every row remains blocked.
- `fixtures`: synthetic `.invalid` hosts and secret references only. Files ending
  `.rejected.json` must be rejected. They contain no actual credentials.

Canonical Rust wire DTOs: `crates/vp-domain`. All are strict camelCase objects;
union tags are `kind`, enum values snake_case unless explicitly specified.
Optional values serialize as JSON null. Revision/counter values must be exact
JavaScript integers. Times are Unix epoch milliseconds. Inline password/private
key fields are forbidden in persistent node/listener DTOs. `SecretBytes` is not
serializable and must not cross ordinary API/event boundaries. Public import and
explicit secret-export bodies are intentionally separate sensitive surfaces.

`cargo run -p vp-product-domain --example export_schema --locked` emits the
canonical schema from Rust DTOs. `schema/v1.refinements.json` retains reviewed
semantic bounds and explicit nullable-output requirements; generation intersects
these with derived shapes, never substitutes a looser schema. Draft-7 references
are normalized to Draft-2020-12 `$defs`; variant fields use explicit serde renames
because schemars 0.8 does not honor `rename_all_fields`. Validated ID/counter
wrappers and reference-free import previews implement matching schema constraints.

Run `python tools/check_contracts.py` from the repository root (pinned Rust plus
`tools/contracts-requirements.txt`) to check byte-for-byte generation drift,
structural consistency, refs, fixtures, security-negative cases and inventory.
Use `--write` only after reviewing DTO/refinement changes. This gate does not
replace cross-field Rust `validate` methods or claim generated Dart DTO coverage;
Flutter remains a separately reviewed consumer with its own tests.

A valid certification descriptor is not proof: authenticate its exact release
manifest and evidence independently. Default catalog entries never become
`certified` because source exists, compiles, starts or loops back to itself.

TLS and REALITY `clientHelloFingerprint` means a ClientHello/browser profile such
as `chrome`, **not** a server certificate digest. Server trust uses the separate
`TlsTrust` union. `spki_sha256` hashes SubjectPublicKeyInfo, not the entire
certificate; certificate-pin URI properties must never be reinterpreted as SPKI.
Unsupported trust or ClientHello properties must fail import/compile/export, not
be silently dropped or weakened.

## BuildInfo requiredFeatures (2026-10-30 clarification)

`requiredFeatures` lists mandatory *consumer-understood wire extensions* beyond
that API/schema version. The current v1 baseline has none. A client must reject
unknown mandatory extensions; it must not treat the field as a list of server
implementation prerequisites. Verified worker binaries and certified protocol
probes are runtime/capability requirements reported separately and remain
unavailable/blocked until evidenced. Empty requiredFeatures does not certify a
runtime, protocol, release, or native platform. Development builds remain marked
`development: true` and uncertified capability states stay visible.

## Runtime ABI 1.1 pure connect preflight

The runtime adapter minor version is now 1.1 for the additive
`vp_adapter_validate_connect` symbol. The function validates a typed connection
payload without creating a runtime, opening sockets, taking a TUN descriptor, or
changing any OS state. Android hosts require this capability before requesting
VPN consent. No existing JSON shape or major ABI changes. A provider lacking the
preflight capability is rejected before network takeover; no fictitious FD is
used to simulate validation. The pure codec ABI has its own version identity and
is not implicitly bumped by this runtime-only addition.
