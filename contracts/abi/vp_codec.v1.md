# Pure codec ABI / local JSON v1

Owner: `crates/vp-codec-ffi`; Dart consumer: `flutter/packages/vp_codec`.
Status: source implementation; test results are recorded in the crate README.
Codec ABI **1.0**, independent from the runtime adapter ABI. Only the five C
symbols in `vp_codec.h` are exported. No lifecycle, fetch, filesystem, vault,
subscription scheduling, routing, or VPN operation is performed. System CSPRNG
entropy creates ephemeral 128-bit pending IDs; entropy failure fails closed.

## Memory and failure boundary

Inputs are borrowed, strict UTF-8 JSON, at most 8,388,608 bytes. A zero-length
span requires NULL; nonempty spans require valid readable storage, not NULL.
Outputs must initially be `{NULL,0,NULL}`, live, writable and aligned, and must
not alias inputs. All participating allocations remain valid during the call.
Concurrent calls use distinct output structs. Invalid arbitrary pointers are
**not** made memory-safe by length/null checks. OOM/abort is process failure;
catchable Rust panics become VP_INTERNAL and never unwind across C.

ABI failures (null, UTF-8, size, allocation capacity, internal panic) return a
fixed-width `int32_t` `VP_*` status with empty output. Nonempty output structs
are rejected without overwriting their owner. VP_OK means a complete response
exists, **not** that an import was accepted or runtime is ready. Business errors
use this secret-safe envelope, always both `result` and `error`, exactly one null:

```json
{"schemaVersion":1,"result":null,"error":{"code":"CONFIRMATION_REQUIRED","messageKey":"error.action_failed","safeArgs":{},"fieldPath":"confirmed","retryable":false,"stage":"decode","capabilityKey":null,"remediation":null,"diagnosticId":null}}
```

`vp_codec_abi_info` is the exception: it returns a direct information object with
`schemaVersion`, `abiMajor`, `abiMinor`, `library`, input/registry limits,
`secretTransferVersion`, `operations`, and `network/filesystem/runtime:false`.
Unknown request fields, duplicate keys at every depth, invalid versions or
invalid typed values reject; no JSON object merge or silent field dropping.
Diagnostics never echo input, unknown field names, credentials or parser errors.

Only `vp_codec_bytes_free` may release this library's outputs. A private token
and exact pointer/length are checked against live allocations before release;
tokens never reuse. The free wipes provider-owned bytes, frees using its own
allocator, and zeroes the struct. NULL/empty and repeated free of the **same
zeroed struct** are no-ops. Unknown, stale, wrong-domain or altered owning triples
are ignored unchanged, never dereferencing their `data`. Copying ownership is
still a caller error, not supported shared ownership. Free must not race readers
or other frees. At most 256 outstanding outputs / 32 MiB total output bytes;
exhaustion returns VP_QUEUE_FULL, not an unbounded allocation leak. Calls are
serialized while reserving one worst-case output (8 MiB) before candidate state
changes; capacity failure cannot create an unreachable preview or consume a
materialize token. This conservative reservation may reject before every final
byte of the 32 MiB budget is occupied.

## Preview / pending candidates

`vp_codec_parse`:

```json
{"schemaVersion":1,"operation":"preview","format":"node_uri","input":"socks5://127.0.0.1:1080#Example"}
```

Formats are the exact `vp-import::ImportFormat` snake-case values: `auto`,
`node_uri`, `uri_list`, `base64_uri_list`, `clash_nodes`, `sing_box_outbounds`.
Decoded input is bounded to 1 MiB by the shared Rust parser. Unsupported schemes,
dialects, trust and fields remain typed rejected entries; all successful
candidates remain `needs_review`, never automatically accepted/selected.

`result` is `{pendingId,expiresInSeconds:900,report}`. `report` is the canonical
`ImportReport`: `schemaVersion`, `entries`, `diagnostics`,
`hasUnimportedFields`. Entry fields are `index`, `disposition`, `preview`, `node`,
`duplicateOf`, `diagnostics`. Preview has public connection parameters only;
`node` and `duplicateOf` are null before binding. No secret or synthetic vault
ref is returned. `pendingId` has shape `pending-` plus 32 lowercase hex digits.
It is process-local ephemeral authority, never a vault ID or durable import ID.
The host must not expose tokens in routes/logs or trust them as user authentication.

At most 16 pending imports and 8 MiB of **conservative charged pending bytes**
are allowed. Charge includes source byte length, serialized public report,
actual secret component lengths and 4 KiB per entry for fixed/collection overhead.
All underlying parser size/count/depth limits also apply; this is not an RSS or
allocator accounting guarantee. Expiry is monotonic, not extendable by access.
Expiry revokes access whenever checked. **Idle native zeroization is lazy at the
next codec info/parse/validate/export call**, not guaranteed erasure at the wall-clock deadline.
There is no background worker that might race dynamic-library unloading.

Hosts MUST timer-release pending imports and dispose local secret transfers on
cancel, successful commit, inactive/pause lifecycle, and transport disposal.
Dart `PendingImport` has a timer; `CodecClient.clearSensitiveState()` is the host
lifecycle adapter entrypoint. Native candidates/bundles zeroize on release or
expiry pruning. Release is idempotent even when the well-formed token is absent:

```json
{"schemaVersion":1,"operation":"release","pendingId":"pending-00000000000000000000000000000000"}
```

Result: `{released:true}`. An absent/expired/materialized token otherwise returns
`PLAN_EXPIRED`. Restart invalidates all pending imports.

## Explicit vault transfer, then actual reference binding

After deliberate user selection and confirmation only:

```json
{"schemaVersion":1,"operation":"transfer","pendingId":"pending-00000000000000000000000000000000","confirmed":true,"indices":[0],"acceptNodeExtraction":false}
```

No default true consent. `indices` must be nonempty, unique, valid candidates.
`acceptNodeExtraction:true` is separately required when top-level full config
fields were not imported. It never authorizes executing those fields.

Result is a **separate ephemeral secret boundary**, not an ordinary domain DTO:

```json
{"secretTransfer":{"schemaVersion":1,"purpose":"vault_import","pendingId":"pending-00000000000000000000000000000000","entries":[{"index":0,"preview":{"name":"Example","endpoint":{"host":"127.0.0.1","port":1080},"protocol":{"kind":"socks5"},"transport":{"kind":"tcp"},"security":{"kind":"none"},"hasObfuscation":false},"secrets":{"kind":"none","primary":[],"secondary":null,"obfuscation":null}}]}}
```

`kind`: `none`, `password`, `uuid`, `username_password`, `uuid_password`.
Each component is a JSON byte array, never delimiter-inferred auth text;
`secondary` and `obfuscation` are null when absent. Maximum component 4 KiB.
Even `none` must be explicitly stored/bound by the caller's actual vault contract
if its `NodeProfile` requires a credential reference. The codec invents no IDs.
No administrator credentials, private server keys or vault master keys accepted.

The first successful transfer locks the exact selected index set. A deliberate
retry with the **same** set returns identical bundles while the token is live;
a different set fails `IDEMPOTENCY_CONFLICT`. Failed transfer does not lock.
Host `SecretAllocator` semantics: stage **these exact typed bytes** in a real
platform encrypted vault transaction and obtain immutable vault refs. A string
that merely looks like `secret:*` is not evidence that allocation succeeded.
The codec cannot independently verify an external vault or transaction.

Only after successful staging, materialize with real refs:

```json
{"schemaVersion":1,"operation":"materialize","pendingId":"pending-00000000000000000000000000000000","confirmed":true,"bindings":[{"index":0,"id":"actual-node-id","sourceRef":null,"credentialRef":"secret:actual-vault-entry-id","obfuscationRef":null}]}
```

Bindings must match the **entire exact transferred set**, unique node IDs and
unique immutable refs; required obfuscation refs must match the candidate.
All bindings are checked before candidate movement. Result `{nodes:[NodeProfile]}`
contains only canonical normal DTOs and actual refs, no credentials. Entire
pending import is consumed/zeroized, including unselected candidates. No hidden
capability/certification inference is added; requirements remain parser output.

Materialize is **single-use**, not a storage commit and not transparently
retryable. Repeat returns PLAN_EXPIRED. Hosts must keep staged vault data and
node metadata inside their own recoverable transaction until successful atomic
commit. On any materialize/output/schema/native error, roll back uncommitted
staged vault entries. If host durable commit outcome is unknown, reconcile the
host's own idempotency journal; do not reparse/reallocate and duplicate a commit.
Losing a native response can consume a token, but cannot itself persist a node.

## Validation / deliberate export

`vp_codec_validate`:

```json
{"schemaVersion":1,"node":{"schemaVersion":1,"id":"actual-node-id","name":"Example","endpoint":{"host":"127.0.0.1","port":1080},"protocol":{"kind":"socks5"},"transport":{"kind":"tcp"},"security":{"kind":"none"},"credentialRef":"secret:actual-vault-entry-id","requirements":[],"sourceRef":null}}
```

Result `{valid:true}` means domain structural validity only: not vault existence,
network reachability, capability certification, compiler support or runtime readiness.

`vp_codec_export`: `{schemaVersion:1,confirmed:true,node:NodeProfile,
secretTransfer:{kind,primary,secondary,obfuscation}}`. Caller must authorize access
to this exact node's vault bundle and separately authorize disclosure. Result:
`{secretExport:{schemaVersion:1,purpose:"user_export",format:"node_uri",text:...}}`.
Shared Rust `export_uri` rejects lossy/unrepresentable fields and unsupported
formats/trust; no insecure fallback. Export does not copy to clipboard, write a
file, share, or network-send. Destination policy and lifetime are the host's duty.

## Limits of zeroization

Rust staging and owned wire buffers are best-effort wiped. The caller owns input
and all copies. Dart JSON decoding/encoding and display create immutable String
and VM/GC copies which cannot be guaranteed erased; `dispose` wipes owned mutable
byte arrays and prevents further exposure, **not forensic erasure**. Do not log,
cache, include in diagnostics or put either secret envelope in ordinary DTOs.
