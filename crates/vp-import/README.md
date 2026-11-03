# VP pure import/export — WP07 source tranche

**Status (2026-10-30): compiled on Linux with official Rust 1.88.0; 28 tests
and the secret-boundary compile-fail doctest passed. Strict clippy passed.**
This is a bounded first implementation, not a completed importer or acceptance
claim. No network, filesystem, QR image decoding, runtime, vault, or upstream-core
dependency is present. Root workspace registration is owned by the shared owner.

## Public boundary

- `parse(&[u8], ImportFormat) -> Result<ImportBatch, ImportIssue>` parses already
  supplied bytes. QR callers supply the decoded text. `Auto` distinguishes URI
  versus multiline and JSON `proxies` versus `outbounds`; base64 is explicit to
  avoid ambiguous content sniffing and recursive wrappers.
- Each `StagedEntry` has an index, sealed `ImportCandidate` or typed diagnostics.
  A failed line/node remains a rejected entry, not an invisible skip. Top-level
  full-config content produces `UnimportedTopLevelFields` and
  `has_unimported_fields=true`. No rules/providers/groups/scripts are executed.
- `review_report()` uses canonical `ImportNodePreview` and `ImportReport`.
  Candidates are `NeedsReview`, not `Accepted`; no certification or automatic
  node selection occurs. Preview contains no vault IDs, including obfuscation.
- `candidate.secrets()` is an explicit borrowed vault-adapter boundary.
  `SecretBundle` contains typed `CredentialKind` + zeroizing `SecretBytes`;
  username and password/UUID and password are distinct components. It cannot
  serialize or clone implicitly and its Debug output is redacted.
- After explicit selection, the caller must atomically persist the exact bundle
  and node, then provide actual `AllocatedSecrets` to `materialize`. The pure
  parser creates **no persistent vault IDs**. Private validation-only sentinels
  are used solely inside domain structural validation and never returned.
  A mismatched obfuscation binding fails. The caller owns transaction rollback,
  source/stable node IDs, deduplication, and capability derivation; requirements
  are not authority and the importer does not claim runtime readiness.
- `export_uri(&NodeProfile, &SecretBundle)` requires already authorized access to
  the exact node secrets, and returns nonserializable/redacted `SecretText` with
  explicit `.expose()`. It cannot validate a vault binding itself. User consent,
  audit, clipboard/QR/file destination policy belong at the caller boundary.
  Local IDs/source refs/capability hints are not URI connection fields.

Zeroization is best effort, not resistance to process compromise or allocator
copies. Callers still own original input, output display lifetime and any DTO
copies. Diagnostics never quote input, unknown key names, credentials, URLs or
third-party parser messages; field paths are fixed authored constants.

## Implemented connection subset

| Input | Source-authored supported subset | Explicit gaps/rejections |
|---|---|---|
| SIP002 `ss://` | Seven domain ciphers; Base64URL method/password for pre-2022; percent-escaped plain userinfo; IPv6 and names; 2022 decoded key length checks | Legacy whole-authority base64; plugins; 2022 base64 userinfo; identity-key chains |
| `socks://`, `socks5://` | RFC3986 authority dialect with explicit port; optional plain/percent-escaped user:password; unauthenticated SOCKS5 | Base64 userinfo, SOCKS4/4a/5h aliases, TLS extensions |
| `vmess://` AEAD / `vless://` | UUID; VMess four domain ciphers, alterId=0 only; VLESS encryption=none; TCP/WS/HTTPUpgrade; none/TLS; VLESS REALITY and Vision subject to domain validity | gRPC/KCP/XHTTP; ambiguous old HTTP/H2/QUIC; early data, extra headers, ECH, TLS pins, FinalMask, VLESS post-quantum encryption |
| `vmess://Base64(JSON)` | v2 string-field format; TCP or WS; aid=0; optional TLS/SNI/ALPN/fp; recognized fields only | nonzero aid; legacy HTTP/QUIC; unknown fields; non-string numeric dialects |
| `trojan://` | Password, TCP, system-verified TLS; optional `sni`; percent-escaped name | Other query dialects (`peer` included), transport and TLS extensions |
| `hysteria2://`, `hy2://` | Password/userpass auth as one string; port defaults 443; SNI; optional Salamander secret; verified TLS | Empty auth, port hopping, Gecko/Realm, certificate `pinSHA256`, ECH, tuning/extensions |
| `anytls://` | Password; port defaults 443; SNI; verified TLS; name | Empty auth, nonstandard tuning/extensions |
| `tuic://` | Recognized as unsupported scheme (no locked URI dialect in this tranche) | URI import and export pending; use strict sing-box JSON subset for staging |
| URI text/base64 list | Indexed multi-line entries, bounded single explicit wrapper | Network fetch, nested wrappers, age/encrypted wrappers, embedded comments |
| Clash nodes | JSON `proxies` extraction for SS/SOCKS5 with explicit `udp:true` | YAML; all other types; udp omitted/false (domain cannot preserve deny); transport/plugins/dialer/metadata fields |
| sing-box nodes | JSON `outbounds`; SS/SOCKS5/VMess AEAD/VLESS/Trojan/AnyTLS/HY2/TUIC; exact recognized TLS, WS, HTTPUpgrade fields | Full config behavior, route/DNS/provider execution; all unconsumed per-node fields; network restrictions, dialer/mux/QUIC tuning, file paths/trust/pins |

URI export supports the representable URI rows above (not TUIC or full structured
files). It canonicalizes aliases and field order, not byte-for-byte original
text. It rejects nonrepresentable transport/security, nonzero VMess alterId,
custom CA/SPKI trust, or missing required ClientHello semantics. No insecure
TLS variant exists. `pinSHA256` is a **certificate hash**, not an SPKI hash.

Modern XTLS TLS `fp` omission maps explicitly to `clientHelloFingerprint=chrome`
per the chosen proposal; REALITY `fp` is required. This field is ClientHello
selection, never certificate trust. A canonical TLS node with unspecified
fingerprint cannot be exported to that URI dialect without loss and is rejected.
Sing-box `utls` is mapped separately. The downstream compiler must reject any
fingerprint the chosen runtime cannot implement, not ignore it.

Clash's omitted/false UDP policy cannot be represented by today's NodeProfile;
this tranche rejects it instead of silently enabling UDP. Top-level skipped
fields always require review. General Clash compatibility is **not** claimed.

## Bounds / parser behavior

- Input: 1 MiB; URI: 16 KiB; 1,024 physical list lines or JSON array entries.
- Components/JSON strings: 4 KiB decoded; 32 query fields; JSON depth 32;
  64 object members and 128-byte JSON member names; 16 ALPN values.
- Domain bounds also apply (nonzero u16 port, DNS/IPv4/bracketed IPv6, names,
  transports, TLS, REALITY); SOCKS username/password at most 255 bytes each.
- Percent escapes and UTF-8 are strict; `+` remains plus; duplicates are rejected
  **after** query decoding and at every JSON depth. DNS lookups never occur.
- Unknown per-node fields reject the whole node. Disabled security objects with
  additional fields are not silently stripped. Literal control characters and
  control-bearing decoded components are rejected.
- Unicode labels/names need percent encoding in URI; IDN hosts must be ASCII
  punycode. IPv6 scope IDs are not accepted.

## Reviewed primary/source references

Reviewed 2026-10-29 for semantics only; no source implementation or installer
code was copied, and these moving references are not pinned interop evidence.

- [Shadowsocks SIP002](https://shadowsocks.org/doc/sip002.html)
- [XTLS VMessAEAD/VLESS sharing proposal](https://github.com/XTLS/Xray-core/discussions/716)
- [v2rayN VMess v2 share format](https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link)
- [Hysteria2 URI](https://v2.hysteria.network/docs/developers/URI-Scheme/)
- [AnyTLS URI](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md)
- [Trojan original authority shape](https://github.com/trojan-gfw/igniter/blob/master/app/src/main/java/io/github/trojan_gfw/igniter/TrojanURLHelper.java)
- [Potatso Trojan SNI query documentation](https://docs.potatso.com/protocols/trojan/)
- [LxBox documented SOCKS authority dialect](https://github.com/Leadaxe/LxBox/blob/main/docs/PROTOCOLS.md#7-socks)
- [sing-box outbounds](https://sing-box.sagernet.org/configuration/outbound/),
  [TLS](https://sing-box.sagernet.org/configuration/shared/tls/),
  [TUIC defaults](https://sing-box.sagernet.org/configuration/outbound/tuic/),
  [SOCKS](https://sing-box.sagernet.org/configuration/outbound/socks/)
- [Mihomo common node fields / UDP default](https://wiki.metacubex.one/en/config/proxies/)

## Verification and next integration

`tests/import_export.rs` contains 28 authored tests (including all seven SS
ciphers, supported URI round trips, special characters, IPv6, field duplication,
input/count/depth bounds, loss/security refusals, partial extraction reporting,
base64, legacy VMess, preview redaction and real-ref binding requirements).
There is also a compile-fail doc test for nonserializable staging objects.
**The 28 tests and compile-fail doctest, rustfmt, locked Cargo check and strict
clippy have now run successfully; logs are in `docs/implementation/evidence/rust`.
Fuzzing and actual protocol runtime/interoperability are still not run for this crate.** Base64 is the pinned `base64` dependency, not a new
cryptographic implementation. A real Cargo.lock is retained; a complete dependency security audit remains pending.

Static checks actually performed: shared-owner interface review; Python stdlib
JSON/TOML fixture/manifest parsing, duplicate-key check and fixture shape checks.
Those establish syntax/shape only, not Rust behavior.

Next: add byte-span codec FFI and vault transaction integration, then fuzz
parser/roundtrip boundaries. The existing checked subset is not full-format support.
Before broadening formats: lock dialect fixtures and model omitted security or
traffic controls, then implement and independently interop-test them. QR image
handling, subscription fetching/stable merge, VP file export, YAML, all shareable
preset coverage and whole-suite acceptance remain open WP07/product work.
