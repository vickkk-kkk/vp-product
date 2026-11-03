# Pure native codec: Rust source of truth, explicit secret transfer

This crate implements `contracts/abi/vp_codec.h` (independent codec ABI 1.0).
The exact local JSON contract is [`vp_codec.v1.md`](../../contracts/abi/vp_codec.v1.md).
It calls the existing bounded `vp-product-import` parser/exporter and
`vp-product-domain` validators. There is no duplicate Dart protocol parser,
upstream/core runtime, sing-box, Go, filesystem persistence, network fetch,
implicit subscription operation or VPN start.

## Verification snapshot — 2026-10-30 04:15 UTC

- **15 Rust tests passed**, strict clippy passed, Rust formatting passed.
- **C host ABI harness passed**, linking the actual Linux shared library.
- **11 Dart tests passed**, including real Linux FFI import/bind/export, lifecycle
  timer/dispose, schema, explicit consent and bounded secret-copy retention.
- Flutter analyzer clean; conditional Web entrypoint compiled to JavaScript and
  ran under Node with the expected unavailable-native result (not browser/UI QA).
- **Android x86_64 API26 cross-build passed**; ELF exports exactly five codec
  functions and needs only libc/libdl. Handed artifact/hash to Android owner;
  guest execution and APK journeys are **not claimed by this package**.
- Sanitizers, sustained fuzzing and Apple/Windows execution remain **not run**.

## Ownership / consent

- `preview`: opaque CSPRNG pending candidate ID + canonical redacted report.
  No secrets, no synthetic vault refs, no successful/ready product claims.
- `transfer`: deliberate consent + exact selection (separate full-config node
  extraction confirmation when necessary). An ephemeral, typed secret bundle
  envelope is the only disclosure boundary; it is not a normal domain DTO.
- The host **actually stages** the exact bundles in its encrypted vault. The
  pure codec is not a SecretAllocator and cannot verify the host's vault.
- `materialize`: real immutable allocated refs + exact transferred selection;
  emits canonical profiles and consumes the pending candidates. Host atomically
  commits its metadata/vault transaction, owns idempotency and rollback. Repeated
  materialize is not a duplicated commit: it returns `PLAN_EXPIRED`.
- `release` is idempotent; TTL is monotonic and checked on codec calls. Native
  idle erasure is lazy, not hard wall-clock erasure. Hosts timer-release and
  dispose on cancellation, commit, lifecycle inactivity and transport disposal.
- Export requires separate deliberate consent and exact authorized vault bytes.
  Unsupported dialect/trust/lossy fields fail typed; no clipboard/file/network
  side effect occurs.

Pending count and charged-memory bounds, output-allocation bounds, request size,
JSON depth/count/duplicate checks and shared parser bounds all apply. The FFI
allocator validates the entire live `{data,len,token}` triple before wiping and
freeing; stale/mismatched/cross-domain triples are not dereferenced. No C caller
may infer that arbitrary invalid pointers are safe. See the contract for exact
caller storage/lifetime/alignment and concurrency obligations.

`unsafe_code=deny` at crate scope; only the small `src/ffi.rs` boundary admits
reviewed raw-pointer operations with local safety comments. It catches unwindable
panics. OOM/abort/process compromise are not covered. No process-wide panic hook
is installed; authored panic paths never incorporate credentials/input.

## Build / tests

Rust 1.88.0; use the shared product target, not a duplicate runtime build cache:

```sh
export CARGO_TARGET_DIR="$PWD/.local-cache/product-core-target"
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
cargo test --locked -p vp-product-codec-ffi -- --test-threads=1
cargo clippy --locked -p vp-product-codec-ffi --all-targets -- -D warnings
cargo build --locked -p vp-product-codec-ffi
crates/vp-codec-ffi/tests/run-c-harness.sh
```

The crate emits `rlib`, `cdylib` and `staticlib`. Android packaging must include
`libvp_product_codec_ffi.so` for each shipped ABI; iOS process lookup requires
linking/retaining the static symbols. Host Linux evidence does not certify these
platform packaging steps.

Authored tests cover redaction, confirmation, exact selection lock, vault-ref
binding, URI round trip, expiry/release, limits, unknown/duplicate fields, typed
unsupported/insecure imports, output allocation lifecycle/exhaustion, null/huge
spans, UTF-8, a bounded arbitrary-byte smoke corpus and catchable panic conversion.
The C harness links the actual shared object. Dart tests exercise local lifecycle,
schema/consent contracts and an actual Rust shared-library FFI round trip using
only synthetic credentials. The bounded byte smoke corpus is **not fuzzing**.

Actual results/logs and source/artifact hashes are in `evidence/`; these focused
checks are not complete importer support, runtime/protocol interoperability or
whole-product acceptance. Sanitizers, sustained fuzzing, native Android/Apple/
Windows packaging and their FFI execution remain separate verification gates.

Best-effort Rust/Dart mutable-buffer zeroization is not forensic erasure: original
input, Dart immutable JSON/display strings, allocator/VM copies and authorized
vault storage remain subject to caller/platform lifecycle policy.
