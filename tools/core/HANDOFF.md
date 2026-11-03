# Stable tested pin / native handoff — 2026-10-30 07:01 UTC

**Current core frozen:** e96584fb8c7a38aa2c24beb89dcf969e70c24c93,
tree eb339f2c485e10a6a9e32a8c1e39d8337b2b35fe;20 deterministic patches on original
a1abce2. Original/generated/private source checkouts clean. No new-upstream code
execution. Core-lock SHA2560cb955829bcf1365288c9739d20f627aa8ce55e02cd8a6af1b7fcccc005d54c7.

Terminal current-pin results (all one-job, incremental0/debug0 shared target):
- Standalone313 passed /6 intentionally excluded public-live/external probes.
  Includes actual App UoT26-suite success, config12, server-routing6, core25,
  router14, protocol136, DNS25, TUN7, SS/QUIC/stream independent peers and real
  proxyDNS/TUN. See evidence/activation-dns2/integrated-twenty/result.json.
- Root combined45 passed: mobile23, fail-closed contracts9, actual worker13.
  Strict adapter all-target Clippy PASS. Toy-Git tooling20 PASS.
- Fresh local artifacts were invalidated, exact named test counts checked, source
  and executable SHA256 captured before and unchanged after execution. Root graph
  independently tested, not inferred from standalone dependency graph.

Actual worker (not test binary), mode0555, immutable:
.local-cache/verified-workers/e96584f/5dae2017718147c6b2a5f939a398021367457790b391eec058807f4bcc163c91
SHA256 = basename. Receipt evidence/activation-dns2/root-twenty/immutable-worker.json.
API daemon owner should use this file, not rebuild or reuse old b739/f249 worker.

**Cargo lane released at07:00 UTC.** Parent will resume mobile ABI owner for
host cdylib + C ABI/sanitizer/mapping matrix, then Android x86_64 relink; Android
owner follows with exact-artifact Gradle/guest. No current-pin native .so/APK was
produced by these tests. Preserve old b739 artifact/evidence identities. Do not
repin/edit generated/mobile source during relink. Parent owns root lock.

Patch20 (private source6a900b99) fixes ignored udp-over-tcp kebab flag and routes
fully authenticated/replay-checked SS UoT v1 through bounded per-datagram Router
associations with preserved user/inbound/port. Uppercase v1 follows existing ASCII
normalization; reserved trailing/v2/nested forms never become DNS destinations.
Other raw protocol UoT remains explicitly unsupported. The App test now separates
server IN-NAME DIRECT from client MATCH SS, preventing routing recursion. Rule
provider assertions retain original rule/group as well as actual connected leaf.
Original f398 timeout, count-gate failure and case-fixture/design attempts remain
archived. This is not independent UoT certification or a public capability grant.

Further work: mobile native/guest proof; actual daemon HTTP roundtrip; optional
managed v2 recipe expansion is private source-only, no live worker/wire changes;
all21 mandatory protocol/platform release gates still apply. fa3e74320-patch
source-only upgrade check still stops at patch1; no proposed lock or execution.

---

# Integrated App blocker and repair — 2026-10-30 06:43 UTC

Current f398 (19 patches) remains clean and is NOT eligible for new native/APK
release. Fresh identity-bound standalone suites pass except App:24 passed/2 failed.
Failure logs retained in evidence/activation-dns2/integrated/. Group expectation
needs both original rule/group and selected leaf assertions. More importantly,
old `udp-over-tcp: true` App fixture was silently ignored by ProxyCfg (missing
kebab alias), so it did not prove UoT. Parent requires genuine authenticated SS
UoT positive functionality, not weakening/ignoring the test.

Private integration/app-uot-fix from f398 owns patch20 source: exact alias,
authenticated+replay-checked SS stream bridge into existing bounded routed UoT v1,
v2/nested control rejection before Router/DNS, positive App route separation,
and three actual SS authentication/per-datagram-selection/reject/cleanup tests.
Its first fresh compile is running; source not yet promoted or claimed tested.
Integration owner holds serialized Cargo lane. Mobile source frozen23 tests;
Android/data DNS2 source gates passed, no new native/APK builds until release.
No original upstream edits or new-upstream fa3e743 execution.

---

# Coordinated DNS2 activation — 2026-10-30 06:28 UTC

Current19-patch old-upstream candidate is
`f39844c38b78337f8867548231ca24a2276ed604`, tree
`af68d8de1103cdf7d459eb2b5ec01fa4e7c95850`.
DNS17=ddf05a3, Router18=a3067f7, UUID19=5cacc516 exact patch bytes replayed without
adaptation. UUID own fresh2 tests PASS before promotion. Parent approved activation
and mobile owner applied matching DNS2 source; Rust mobile now frozen23 tests.
Android/data source switch coordinated separately; NO new APK/platform claim yet.
Original upstream remains a1abce2 and clean; fa3e743 only source-audit, never executed.

Integrated standalone gate RUNNING in owned one-job shared target after13 local
vp-* artifact invalidation; no-run JSON manifest paths, expected new names/counts,
source and executable SHA256 before/after required. Runner run_current_gate.py;
logs evidence/activation-dns2/. Parent owns root Cargo.lock resolution once daemon
manifest edges settle, then root combined/mobile tests and new worker proof follow.
Do not share Cargo lane or overwrite worker binaries during hash-bound tests.

Old b739 lock, root Cargo and verification record preserved under evidence;
immutable native/worker/APK artifacts remain historical, not relabeled. New inner
Connect2 keeps ABI1.1/outer schema1 and requires explicit user selected_proxy DNS.
Full release/public capability gate remains blocked. Current status verification.json.

---

# Source-only upstream audit — 2026-10-30 05:44 UTC

New upstream candidate fa3e7430371930c440ffb1bdccc6869c63554a34 was fetched into
independent integration/upgrade-audit-fa3e743 (clean), not the original repository.
Version1.1.0,16 commits ahead,61 files changed. Normal deterministic upgrade gate
FAILS at patch1 vp-app/src/lib.rs:505; no candidate lock exists and b739/current
core-lock/native identity remain unchanged. Detailed API/lifecycle/FD/dependency
review and required rebase/test plan: UPGRADE_AUDIT_FA3E743.md, evidence/upgrade-fa3e743/.
No candidate Cargo/build.rs/Rust/benchmark/script execution occurred. Do not
promote or run this candidate until source rebase/review and scoped authorization.

---

# Active candidate update — 2026-10-30 05:00 UTC

Parent approved mandatory TUIC client reply-DNS security repin before final Android
relink. Current generated source is clean at
`b7398448b7afdce0a74b3364b9463594df316e9f`, tree
`e1c80569a756d26b8dd0771fcc3347405506602c` (16 patches).
Patch16 is exact mobile owner6c3840a export: the client-reachable UDP reply-domain
helper now uses `vp_dns::lookup_host` with scoped host DNS authority. No Cargo edges.
Deterministic replay/check PASS; TUIC6 including deny-before-DNS-send and independent
QUIC-library19 all PASS. Current adapter20+contracts9+worker13 PASS; strict all-target Clippy and fmt PASS
after narrow test-only unwrap annotations. Earlier failures remain in logs.
Python local toy-Git negative tests20 PASS. Cargo lane released to mobile owner
at05:02 UTC. Mobile owner final host/C ABI3, pure mapping18positive/10negative,
mobile-only contracts9 and Android x86_64 crossbuild now PASS on b739844.
Android .so SHA4d3683ee210945439c714133f98d989a8dc7eb56c6ccfeeb8be3809c7b9b06a3;
actual guest acceptance remains pending. Strace/LSAN unavailable, no syscall or
complete Rust memory-sanitizer claim. Source freeze extends through Android guest.
See verification.json and
evidence/sixteen-patch/source-manifest.json for exact source/log/worker hashes.

Mobile root modules are owned by mobile ABI worker; source frozen after UUID
preflight, strict original-byte JSON, full-TUN UDP gate, callback denial failure,
metadata and narrow test lint fixes. Do not repin generated source during native
relink. Older8deb Android.so/APK and f249 immutable vault worker results keep their
original identities. Vault final f24927units+realrotation/reopen1+Clippy passed.

Private `integration/core-hardening` is based on b739844 and contains only an
UNRUN UUID byte parser/redacted error + Unicode panic regression, committed as
5cacc516c5647b57fca4d460481abebfaf635cfb and exported to
integration/uuid-parser-hardening.patch (SHA2569a9e810561c50975c52be3a3fd8b973a28d110a2703ea55bbecbc83b2a7ea5e2). It is NOT in
this pin. Parent requested raw-inbound real Router enforcement as another scoped
candidate, not merely a LoopbackIpOnly fence. Full SS mixed-family source-port,
QUIC association lifecycle and routed packet semantics require explicit regression.
TUN user-DNS vs bootstrap-DNS policy also needs separate audit; protection alone
is not DNS privacy certification. Public capability/release gates remain blocked.

Shared build target `.local-cache/product-core-target`, jobs1/incremental0/debug0.
Original `/workspace/shared/vp_core` remains clean, no network host changes.

---

# Active candidate update — 2026-10-30 04:36 UTC

Parent approved stream framing/UDP promotion. Current clean frozen generated pin:
`f249f7d25989dc0f9ec3993dc60e80caa3d8cd91`, exact author tree
`2a6498321821be1bc24b4e60e16bc8029f16977c`.
Patch14=850d4d52 framing/partialIO; patch15=aa800267 bounded streamUDP + peer.
No Cargo manifest/lock edges. Deterministic replay/check and source cleanliness PASS.
Author finaltree24focused/composition+4local+2independent matrices passed; current
merged root/platform reruns are pending. Do not relabel prior13-pin results.

Mobile owner notified final source/corelock freeze. Old8deb Android.so/APK is only
old-pin debug/integration evidence. Root adapter follows up strict duplicate JSON,
TUIC explicit SNI, linkage/build metadata and mandatory fullTUNUDP preflight before
one final crossbuild. Wait for adapter freeze and parent APK quiet build lane;
then run affected matrix and combined/mobile-only contracts/strict Clippy serially.
No Cargo currently running by integration owner. Shared target=product-core-target,
jobs1, incremental0, dev/testdebug0. Go peer `.toolchains/reference-stream` expected
SHA256eca989fc22cc8d1918e7fb3e0187e24a6207de31b138574ce8b5660053b55631.

Reference Go remains test-only; no factory/public capability certification follows.
Current status `verification.json`; previous executed13-pin report preserved at
`evidence/verification-thirteen-patch-2026-10-30.json`.

---

# Active integration handoff — 2026-10-30 04:22 UTC

Current thirteen-patch generated pin is
`8deb4473ccb36ab387e3dd5ffaf36672d54d8a3f`, tree
`ac9db6915f09248c1f006ca46978dd05666c0ebd`. Original checkout remains pristine.
Deterministic replay/check and Python20 tests PASS. No source changes pending in
this generated tree; do not overwrite it while native artifacts are being built.

## Current-pin executed results

- Core24 (including protected-socket3 and chained-UDP no-bypass regression), App26.
- QUIC independent official-library19 and raw authentication/lifecycle18.
- SS independent bidirectional all7-cipher matrix2 tests, standard10 and managed3.
- DNS22;4 external DNS cases intentionally ignored. Composed carriers8.
- Transport49 with explicit experimental feature; external real-node test filtered.
- Experimental authenticated REALITY10 and test-only boundary10. No camouflage,
  Vision or full REALITY preset claim; feature remains default-disabled.
- Root combined `managed-runtime,mobile-ffi`:17 mobile +9 contracts +13 actual
  worker-process tests passed. Worker digest202fba6a29e370d6a169a6225351a85c4565d453bf86d7369e91c7ade01d1a48.
  **This last artifact predates queued adapter-only metadata/mobile followups.**

Raw logs and status: `tools/core/evidence/current-pin/`, `verification.json`.
Official-library passes are not full sing-box CLI passes; its netlink startup
restriction remains separate. No public capability/release certification enabled.

## Pending small product-adapter lane

Source is frozen after: mobile-only linkage flags now include `mobile-ffi` while
all capabilities remain Blocked; mobile TUIC honors explicit SNI; abi_info adds
buildInspection; mobile build script captures verified rustc version. These
changes need targeted combined/mobile-only contracts and strict Clippy rerun,
then mobile owner rebuilds Android artifact. No core/lock changes are needed.

Stream-UDP owner currently owns shared Cargo lane; pipeline must wait for release.
Future builds use `.local-cache/product-core-target`, single job, incremental0,
low debug. Parent reclaimed completed standalone core-target after all evidence
was recorded (source/patches/logs/reference binaries intact). Do not recreate a
second cache unnecessarily; do not overwrite worker binary during digest tests.

## Current patch ownership

Patches1–7 are the prior lifecycle/protocol/loopback-authority tranche. Patch8 is
QUIC41f39d2 explicit trust+test-only official peer; patch9 uTLS4907383 record fix;
patch10 default-disabled authenticated REALITYbffdf28; patch11 SS2a15e3f peer;
patch12 mobile288465da+f4d3abd host protection/DNS/TUN hooks with narrow QUIC
context rebase preserving explicit trust/SNI; patch13 chainUDP2f89852 fail-closed.

Stream-UDP owner has privateworktree `integration/stream-protocol-udp` and owns
vless/vmess/trojan + newstream_udp + narrow protocol lib export. Its substantive
new wire changes are **not merged**. Chained UDP guard already patch13: do not
apply that twice. Require separate exact commits, tests and independent peer
identity before merging new wire code. Mobile owner owns adapter mobile modules,
manifest and platform packaging; codec owner owns its separate nativecodec crate.

No Go reference dependency/artifact enters production. No App factory or compiler
activation is implied by helper presence. Full all21 mandatory protocol/platform
scope, general routing, native readiness and release gates remain explicit.

---

# Core integration handoff — 2026-10-30 03:22 UTC

## Stable tested tranche

- Original checkout `/workspace/shared/vp_core` remains clean at
  `a1abce2b515b199fe1120061b54654c60f4dd59c`.
- Generated `integration/vp_core` clean at
  `cae3875ad41e3bcd1c22dca765ad0e5805c098b1`, tree
  `11731bd71ed50e3af14fcdca90de61b37fce2ed2`.
- Seven ordered patches and exact digests in `core-lock.json`/`series.toml`.
  Pipeline `verify`, `check`, Python20 tests pass. Synthetic commit parent is
  ORIGINAL upstream, not the previous integration commit.
- Root adapter feature9 contract +13 real worker tests pass; strict adapter
  clippy passes. Standalone App26, core20, QUIC18, SS10+3, composition8,
  transports14 and REALITY boundary10 pass. Evidence/failed attempts retained in
  `verification.json` and `evidence/runtime/`. No complete-product claim.
- Verified test binary `.local-cache/product-core-target/debug/vp-core-managed-worker`
  SHA256 `099fba209bcc89898cf6a8611c228ffd9fa3b949fdc0bf3aedb261e8ec3be2c7`.
  Runtime bridge owner is actively using it; do not overwrite while its tests run.
  It is a debug development test artifact, not a signed release.

## APIs just delivered to runtime bridge owner

`VerifiedWorker::sha256()`; `ManagedRuntime::with_generation(worker,last)->Result`;
`start_with_spawn_observer(config,last,deadline,cancel,FnOnce(pid)->Result)`.
Observer is after verified Hello and before Start/listener IO, failure kills/reaps
child. It must perform bounded durable IO; generation is consumed for each launch
attempt. Actual parent `process::exit` bypassing Drop tested child EOF exit and
port release. The bridge journals immutable refs/PID birth identity separately.

Current WorkerConfig supports loopback raw mixed/HTTP/anonymous SOCKS5/VLESS/VMess/
single-user SS, no TLS/carriers/QUIC mappings. Auth SOCKS must fail rather than drop
credentials. A task-local policy rejects nonloopback IPs and **all domain names**
before destination DNS/IO, including direct TCP, SS/QUIC raw UDP and builtin NAT.
Authenticated VLESS hostname bypass negative and inherited policy tests pass;
full per-protocol policy-negative matrix is not claimed. General router bypass
in upstream raw protocol handlers is not fixed by pretending MATCH rules apply.

## Pending work owned elsewhere; do not lose or silently certify

1. **Ordinary uTLS correctness fix:** REALITY worker commit `4907383` in
   `integration/reality-server`, narrow `utls.rs` TLSInnerPlaintext type/padding
   parsing +2 focused tests. Not yet in these seven patches; source owner reports
   both vectors pass and it fixes legitimate trailing-zero/close_notify loss.
   Integrate separately from experimental feature. Preserve owner failing log.
2. **Experimental authenticated-only REALITY server:** REALITY worker active;
   new `reality_server.rs`, narrow lib feature gate `experimental-reality-server`,
   optional rcgen/zeroize/subtle edges (already existing crate versions) and
   x25519-dalek zeroize feature. No App factory enablement, camouflage or Vision
   success claim. Owner diagnosing H2 drain harness before final patch.
   P05 helper `1c24e3d` and boundary `8ce4fd8` are ALREADY in patch5: do not duplicate.
3. **QUIC independent peer:** QUIC worker active with approved official Go setup
   and library-only harness. Auth P10 final `d45c0a8` ALREADY in patch3. Harness
   and future corrections are separate patches. One-line managed policy guards
   now touch `tuic::resolve_udp` and Hy2 datagram target branch; preserve on rebase.
4. **SS independent peer:** SS source final `f90155a6` ALREADY in patch4, including
   all7 ciphers, socket2 edge and mixed-family UDP identity. Library harness work
   remains separate. Preserve patch7 SS UDP destination guard on future rebases.
5. **Stream transports:** worker final `920db136` ALREADY in patch6, P05 dependency
   already satisfied. Patch6 only adjusted Cargo.lock context over SS socket2;
   no dependency version/checksum changes. App/config/worker/compiler mappings
   still must be implemented with exact unsupported field handling. Full all21
   protocol scope remains; plainHTTP/QUIC/gRPC/REALITY cannot alias another mode.
6. **Mobile ABI:** Android owner has host scaffolding; C header is contract only.
   No Android Rust FFI library/all-socket protect hook/real TUN packet runtime
   exists in this tranche. Parent assigning a dedicated owner. Do not infer ready
   from a TUN FD, successful compile, or server loopback test.

## Integration discipline

Use a separate local detached source worktree, preserve original clean checkout,
export exact ordered patches, and generate a *new* candidate with
`core_pipeline.py propose-lock`. Compare candidate patched tree with staged tree
before explicitly promoting `core-lock.json` and matching clean generated HEAD.
Never broad-export previous P09 against current whole tree: it would accidentally
fold later protocol patches into it. No remote push/publication.

After any new core identity, rebuild worker + host together, refresh root lock
edges with parent, rerun root feature and affected standalone tests. Root and
standalone locks intentionally have different resolved versions; neither alone
proves the other. Keep CARGO_INCREMENTAL=0; share `.local-cache/core-target` and
serialize Cargo builds. Do not clean active worker caches. No host routes,
firewall, services, system proxies or persistent credentials are authorized.
