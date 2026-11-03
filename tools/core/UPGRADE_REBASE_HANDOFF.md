# vp_core 1.1.0 source-only rebase handoff — 2026-10-30

## Decision / execution gate

**Prepared, not executed and not promoted.** This candidate has reproducible
source, not a compilation or runtime pass. Main `core-lock.json`, generated
`integration/vp_core` at **e96584f**, and verified worker/native artifacts stay on
the already-tested old upstream. No alternative engine was introduced.

| Identity | Exact value |
|---|---|
| New upstream | `fa3e7430371930c440ffb1bdccc6869c63554a34` |
| Upstream tree | `5b08d0fded30f5d17c9299165180eb541ea717db` |
| Deterministic candidate | `af79f5eb79a574f89a61a7e2b8c095db4bd3ad32` |
| Candidate tree | `15b5f5130f2440752eae1d0395fed6814511f23d` |
| Ordered patchset SHA256 | `3be0fc257d0c3b5e9c292fc847e419e185f383d022ef59ea885c954969c0e8d8` |
| Candidate lock SHA256 | `debd944df0632327d52880e6cd6e67eacbca61fb86cd3f97a35bfc1a68b88550` |
| Candidate Cargo.lock SHA256 | `720be8054c3454634ed1eeebc7826f7d658cbd1771483ef4e6263abe366cbada` |

- Clean candidate checkout: `integration/upgrade-lane-fa3e743/integration/vp_core`.
- Authored commit stack: `integration/upgrade-rebase-fa3e743`, HEAD `7501d946`.
- Durable reproduction recipe: `tools/core/upgrade-candidates/fa3e743/`.
- Evidence: `tools/core/evidence/rebase-fa3e743/result.json`, per-patch records,
  source/dependency manifests, replay/clean-check and rustfmt parser receipts.

The parent must obtain scoped authorization for compiling/running **this exact
new upstream + patchset and its locked dependencies** before Cargo metadata,
build scripts, compilation, tests, benchmarks or candidate programs are run.
Authorization should preserve loopback-only tests and exclude route/firewall/
system-DNS changes, actual desktop TUN creation, installers and publication.

## Patch disposition: all twenty retained

No patch was dropped because it conflicted. The existing twenty were applied in
order in a private worktree, explicit source conflicts resolved, then exported as
new exact diffs. Three-way application was only an editing aid. **Final replay is
normal strict git apply from the exact new base**, without merge/fuzz/conflict
resolution. Every patch has old/new SHA256 and source commit in `patchNN-record`.

Manual adaptations:
- P01 keeps preconstruction, schema/credential validation and fatal bind failures.
- P02 retains new chain/vectored pump and upstream regression sources while adding
  mandatory flush and cancellation cleanup. New DNS/TUN handle APIs use scoped
  listeners. Health probes retain upstream bounded worker admission, but children
  are owned JoinSet tasks inheriting TaskScope, not detached JoinHandles.
- P07 keeps both upstream connection-budget RAII and destination authority; neither
  substitutes for the genuine Router selection introduced by P18.
- P18 keeps bounded route-aware per-datagram selection instead of old cached UDP
  direct behavior. Upstream UDP decision logging moved to the common routed path.
- Authentication, SS wire/replay/mixed-family behavior, explicit QUIC trust,
  carriers, protected sockets, selected-proxy DNS2, UUID hardening and real SS UoT
  remain in the series. Their **old-base test results do not transfer**.

Additional explicit patches:
1. **21 / stream API:** explicit opaque ProxyStream implementations for VLESS
   prefetched bytes, H2, server WebSocket, experimental REALITY and QUIC streams;
   external TLS/buffered streams use Opaque. No encrypted/buffered wrapper exposes
   a raw TCP socket to splice. Added source regression for opaque raw-fd exclusion.
2. **22 / splice ownership:** F_DUPFD_CLOEXEC and pipe2(O_CLOEXEC|O_NONBLOCK), both
   pipe ends owned before registration, AsyncFd<OwnedFd> cleanup on failure.
   Synchronous preparation is the only fallback boundary. A post-transfer error
   terminates the splice connection instead of restarting generic pumping after
   bytes have been consumed. Splice uses live connection counters, a tracked child
   and connection kill handles; register→attach removal races abort the late task.
3. **23 / TUN and child lifetime:** requested TUN/DNS/auto-route failures propagate;
   partial/drop ownership aborts already-started tasks. DNS and TUN share the same
   fake-IP mapping pool (upstream previously constructed separate maps). DNS query
   tasks have a 256-child JoinSet bound; health child cancellation is explicit.
4. **24 / regression source:** valid-fd checks and a loopback reset after real byte
   transfer exercise the setup-only fallback contract. **These tests are unrun.**

## What actually ran

- Our local Git replay/proposal/prepare/check pipeline: PASS, including a fresh
  clean candidate checkout and independent replay of the durable recipe.
- Verified official rustfmt, `--emit stdout --config skip_children=true`, parsed
  **125 Rust files** without errors. This is not typechecking or macro execution.
- Python TOML parsing of manifests/lock/series; no Cargo invocation.
- Our authored toy-Git negative suite: **20 passed**; it uses temporary synthetic
  files/repositories, not new-upstream code.
- No new-upstream Cargo metadata, build.rs, Rust tests, Go peers or executable ran.

## Remaining risk and acceptance plan

1. Type/bounds/feature/target correctness remains unverified. Explicit ProxyStream
   migration was reviewed at known production/test call sites, but Rust must check
   every active feature and root integration graph. New source tests must appear
   under their expected names; zero matched tests is a failure.
2. Run the new opaque, FD registration failure/CLOEXEC, post-transfer reset,
   splice live-accounting/kill, late-attach cancellation, TUN partial-owner and
   health-child cancellation tests serially (`--test-threads=1` for FD assertions).
   Add/finalize DNS-query stop fault injection and setup-resource exhaustion cases.
3. Desktop App TUN hot reconfiguration still only switches enable/disable; changing
   live MTU/range/options requires a separately validated restart transaction.
   Concurrent enable/reload serialization and legacy raw integer FD reuse need
   explicit review/proof. They are not certified by startup failure propagation.
   Current managed worker disallows desktop TUN; mobile uses its owned-device,
   selected-proxy DNS entry point. Do not test host auto-route to fill this gap.
4. New external lock entries come from upstream: arc-swap1.9.3 benchmark dependency,
   chrono0.4.45 and timezone/Windows transitive entries in the CLI graph. No shared
   registry checksum changed. Dependency sources/build scripts are not executed
   or newly certified. Begin with selected core/app/protocol/TUN packages, not the
   upstream CLI, installers or benchmarks.
5. After authorization, invalidate only local vp-* build artifacts, keep one job /
   incremental0 / debug0, and coordinate shared Cargo lane with parent. Capture
   source + exact no-run executable identities and named inventory before running;
   compare source/binary hashes afterwards. New version test counts must be read,
   not copied from e965's313 or upstream marketing totals.
6. Repeat independent SS/QUIC/stream reference matrices, auth/trust/replay negative
   cases, real Router no-I/O reject, UoT positive, protected socket/bootstrap and
   selected-proxy UDP/TCP DNS tests. Protocol references remain test-only.
7. Build a **separate product overlay** with candidate lock and matching path core;
   do not point the e965 root adapter at new code while embedding the old lock.
   Resolve its root lock under recorded supervision, then verify actual worker
   Hello/identity, control rotation/rollback/crash, ABI ownership and native builds.
   Main product/native artifacts stay immutable until an explicit atomic promotion.
8. All21 mandatory protocol/platform release gates still apply. No new upstream
   AnyTLS-REALITY claim enables full REALITY/Vision or any public capability.

A failed compile/test after authorization may require another source-only patch
and therefore a new tree/patch identity. Record it; never relabel these receipts.
