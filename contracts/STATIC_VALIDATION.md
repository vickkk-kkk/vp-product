> Historical 2026-10-29 source-stage record below. Official toolchain execution
> was authorized and performed on 2026-10-30; current measured results and remaining
> boundaries are in `../docs/implementation/RUST_VALIDATION.md`.

# WP00/WP01 source tranche — validation and handoff

Date: 2026-10-29. Scope: independently authored product foundation, not runtime
completion. No upstream research checkout or external settings modified.

## Implemented source

- Initial four-member Cargo workspace (domain, core-adapter, control, storage), product
  package namespace, declared Rust 1.85.1 baseline and exact initial dependency
  pins. Other three crate implementations belong to their respective owners.
- Pure domain DTOs: client nodes distinct from server listeners; strict tagged
  unions; seven SS methods; normalized endpoints; TLS trust without skip-verify;
  secret references and nonserializable/zeroizing/redacted secret bytes.
- Revision exact-integer limits, compatibility/read-only decisions, versioned
  request/result envelopes, stable errors, subscriptions/import projections,
  immutable-plan/operation display DTOs, truthful runtime observations and
  generation/sequence resynchronization.
- Catalog of 21 public presets plus pending explicit Direct decision. All blocked;
  no certification or functioning runtime is claimed.
- Reviewed schema/OpenAPI/event baseline, exact C ABI headers and synthetic fixtures.

## Static checks actually performed

Using existing Python standard-library JSON/TOML readers, not project scripts:

- Parsed 8 contract JSON artifacts and the JSON-syntax OpenAPI YAML document.
- Parsed root/toolchain and all four crate manifests; confirmed every member's
  manifest exists and each package uses the required namespace.
- Resolved every internal schema reference and every OpenAPI external definition
  reference against 49 definitions.
- Checked four positive fixtures and one intentionally rejected fixture against
  the baseline's structural/type/enum/pattern/required/union constraints with an
  ad hoc static checker. This is not a full JSON Schema conformance certification.
- Compared all 22 catalog keys, 21 required-public rows and exact seven SS ciphers
  to tests/acceptance-matrix.json. Every catalog status is blocked.
- Checked all OpenAPI operations advertise contract-only status; authenticated
  mutations require session-cookie + CSRF declarations. This is not implemented
  auth/session/Origin behavior and does not prove server security.
- Statically inspected domain/adapter/control DTO consumers for current field
  alignment. All owners received shared file/signature notifications.

## Not run / exact blocker

Action: official Rust/Flutter toolchain installation and repository code execution.
Target: this product workspace and pinned upstream/independent protocol runners.
Status: **authorization pending**, not denied and not attempted by this owner.

Consequently Rust compilation/rustfmt/clippy, 15 authored unit/contract tests,
compile-fail secret-serialization doctest, C/C++ header compilation/ABI tests,
schema generator, dependency resolution/security audit, lockfile generation,
independent interop, platform, packaging and release acceptance are **NOT RUN**.
The pinned toolchain/dependency versions are declarations, not verified builds.
No Cargo.lock was fabricated. No network, services, credentials, settings, push
or publication were performed.

## Remaining integration

1. Once authorized, resolve exact dependencies, retain real Cargo.lock, run
   formatting/compiler checks and all tests; repair failures before claiming pass.
2. Generate schemars schema and reconcile Draft-7 definitions with reviewed
   Draft-2020-12 `$defs`; establish mechanical drift gate and generated Dart DTOs.
   The current schema is explicitly hand-reviewed, not falsely labeled generated.
3. Compile headers as C/C++ and implement ABI ownership/cancellation/fuzz tests;
   headers alone do not export runtime functions.
4. Runtime owner must supply actual listener/socket/packet evidence. Capabilities
   remain blocked until authenticated exact-artifact independent/platform evidence.
5. Integration owner must resolve Direct inclusion/exclusion, actual OS/CPU/channel
   support and platform resources. No scope decision was silently invented here.

## Import integration addendum

The import owner identified an explicit TLS ClientHello fingerprint preservation
requirement. Added nullable `ClientSecurity::Tls.fingerprint` without inventing a
default; REALITY's existing fingerprint retained. Both reject malformed public
tokens. Schema and a preservation/round-trip test are synchronized. The compiler
must reject unsupported fingerprint implementations, never drop this field.
Server-side TLS/certificate models are unchanged. This addition is pre-release;
no deployed schema compatibility is claimed. Test count is now 16, all unrun.
Hysteria certificate-fingerprint pins are not silently mapped to SPKI pins.

Registered the actual `crates/vp-import/Cargo.toml` as fifth workspace member and
`vp-product-import` path alias after it existed. All five manifests parse with
Python tomllib; import workspace dependency names have declared aliases. This is
not Cargo dependency resolution or compilation. Import source belongs to its owner.

Root review clarified pin/fingerprint naming. Before any release, both TLS and
REALITY fields were renamed from generic `fingerprint` to Rust
`client_hello_fingerprint` / JSON `clientHelloFingerprint`. This is an explicit
pre-release wire field rename; fixtures/schema/tests changed together and consumers
were notified. It is a ClientHello/browser profile only. `TlsTrust::SpkiSha256`
remains explicitly SPKI-digest trust, not a whole-certificate digest; unsupported
whole-certificate pin imports fail rather than weakening trust. Generic canonical
`fingerprint` is now an unknown field and rejected. Import/export full round-trip
and compiler enforcement tests belong to their owners and remain unrun.

The canonical import report now has `ImportEntry.preview` with
`ImportNodePreview`, allowing real name/endpoint/protocol review before vault
binding without emitting fake NodeProfile references. Canonical preview serde
rejects Hysteria2 `obfuscationRef: Some(...)` on both encode and decode; the
baseline `PreviewProtocol` schema constrains it to null. Import owner reuses this
DTO. Node/listener `requirements` are explicitly hints only: compiler must derive
actual capability requirements, never trust an empty caller-supplied list.
Definitions now total 51; domain tests total 18, all unrun.

Final import integration static recheck: five manifest/alias sets, all 51 schema
references, four existing positive fixtures plus rejected inline-secret fixture,
constructed safe import preview and rejection of a reference-bearing preview,
catalog parity, and OpenAPI references passed the same standard-library-only
structural checks. Read importer consumers directly: canonical preview alias,
preview report field, explicit ClientHello field names, secret materialization
signatures and fail-closed trust export match current domain. No Rust execution.
