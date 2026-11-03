> Current-series recheck (2026-10-30 06:59 UTC): the old-upstream product is now
> e96584fb8c7a38aa2c24beb89dcf969e70c24c93 with20 patches. The unchanged source-only
> upgrade gate still fails at patch1; no proposed lock was written and fa3e743 was
> never executed. See evidence/upgrade-fa3e743/twenty-patch-check.log. The original
> audit below preserves its historical16-patch/b739 evidence and overlap counts.

# Source-only upstream upgrade audit: fa3e743 (2026-10-30)

## Decision

**Do not promote yet.** The normal deterministic upgrade gate correctly refuses
this revision with the unchanged product patch series. This is a reviewed upgrade
candidate, not a replacement engine or a silently changed running core. Current
product/Android identity stays `b7398448b7afdce0a74b3364b9463594df316e9f` on
upstream `a1abce2b515b199fe1120061b54654c60f4dd59c`.

- Candidate commit: `fa3e7430371930c440ffb1bdccc6869c63554a34`.
- Candidate tree: `5b08d0fded30f5d17c9299165180eb541ea717db`.
- Source: exact-commit HTTPS fetch from `https://github.com/mateo-ki/vp_core.git`.
- Independent source checkout: `integration/upgrade-audit-fa3e743` (clean).
- Original checkout, generated checkout and `core-lock.json` remain unchanged.
- Candidate is a descendant, 16 commits ahead; version 1.0.4 → 1.1.0.
- Diff: 61 files, 2,781 insertions and 374 deletions.
- Fetch/replay used disabled Git hooks/fsmonitor/global config, no submodules,
  and protocol allowlists; no original remote/ref/checkout mutation.
- No candidate Rust, Cargo metadata/build script, benchmark, installer or service
  was executed. No dependency download or host-network change was performed.
  Source identity is verified, **not a publisher-signature verification**.

## Reproducible gate result

Command (our Python/Git tooling only):

```sh
python3 tools/core/core_pipeline.py upgrade-check \
  --upstream integration/upgrade-audit-fa3e743 \
  --candidate-commit fa3e7430371930c440ffb1bdccc6869c63554a34 \
  --output integration/core-lock-fa3e743-proposal.json
```

Exit 1, first conflict: patch `0001-fail-closed-listener-startup.patch`,
`crates/vp-app/src/lib.rs:505` context does not apply. **No proposed lock was
written.** The gate stops at this first conflict rather than skipping a patch.
Later patches were not falsely recorded as replayed. `patch-overlap.json` is a
file-level overlap map only: 13 of 16 patches touch upstream-changed files, with
33 overlapping files in lifecycle patch2. Zero overlap is not proof of semantic
compatibility, compilation, or successful ordered replay.

## Material migration work

1. **Relay and stream abstraction:** upstream removes the blanket `ProxyStream`
   implementation and adds explicit raw-socket exposure plus `Opaque<S>`. Every
   added product wrapper (for example VLESS `RequestTailStream` and experimental
   authenticated REALITY streams), generic bounds, TLS/H2/WS composition and test
   doubles must be audited. Encrypted/buffered wrappers must never expose a raw
   socket and accidentally bypass framing. This is not merely patch-context drift.
2. **Cancellation and flush semantics must survive performance changes.** New
   relay uses vectored/chain reads and Linux splice. Its generic branch still
   spawns bare pump JoinHandles (`tunnel.rs:104-105`) and cleanup follows awaited
   completion rather than a drop guard. The write loop (`tunnel.rs:255-278`) has
   no flush after accepted bytes. Product cancellation cleanup and buffered-stream
   flush regressions remain mandatory; do not remove patch2 as “upstream fixed”.
3. **New Linux splice ownership needs review before execution/promotion.** Source
   inspection shows `dup` without CLOEXEC (`splice.rs:60`) and `pipe2` with only
   O_NONBLOCK (`:106`). In `Pipe::new`, if registering the read end fails at `:112`,
   the raw write end has not yet acquired an owning guard. These are static
   descriptor-inheritance/leak risks, not runtime reproductions. Require atomic
   CLOEXEC ownership, failure injection and FD-count tests. New relay registration
   also needs cancellation-safe ConnTable/stat cleanup on the splice path.
4. **Router background lifetime:** upstream retains/aborts the outer health task
   on Router replacement, a useful improvement. Its new probe worker pool still
   uses bare `tokio::spawn` handles (`group.rs:279-299`); aborting the parent while
   awaiting one handle can detach remaining workers. Adopt the product scope or
   owned children, and test cancellation during a real pending probe. Coordinate
   the independently developing genuine server-routing patch; this upgrade does
   not itself repair raw server routing bypass.
5. **TUN assembly/reload changed substantially:** `TunRuntime`, `start_with_handle`,
   retained DNS and auto-route handles, and hot enable/disable are new. New DNS or
   auto-route startup failures can remain warning-only in upstream. Review early
   failure cleanup and preserve fail-closed product admission plus transferred-FD,
   protected socket and proxy-DNS semantics. Do not run auto-route or bind host
   system DNS as an upgrade test; use isolated test devices/loopback abstractions.
6. **New configuration/API surface:** `resource-limits` and `AnytlsCfg.reality_opts`
   were added, plus per-process metadata and statistics, connection-table sharding,
   and socket-tuning snapshots. Strict product compiler/preflight must reject or
   intentionally map new fields, not accidentally inherit unsupported behavior.
   Upstream AnyTLS-REALITY is outbound wiring only, not proof of full REALITY
   camouflage/Vision or any new public capability certification.
7. **CLI managed stdin is not the product worker contract.** It is a textual stop/
   EOF facility, not our hash/Hello identity, framed control, readiness, generation,
   cancellation/drain, durable PID-before-start or rollback protocol. Retain those
   product guarantees; do not substitute the upstream CLI.

## Dependency and build review

`dependency-delta.json` records exact lock entries. All workspace packages change
1.0.4 → 1.1.0. New third-party entries are arc-swap1.9.3, chrono0.4.45 and timezone/
Windows transitive crates; existing name/version/source identities have unchanged
checksums. Arc-swap is a vp-common benchmark dev dependency; chrono is in vp-bin,
which our managed worker does not use. vp-core gains target-specific libc and
windows-sys edges. No changed/new repository `build.rs` or shell script was found;
new `scripts/bench_loopback.py` was read only as a file listing, never executed.
This does **not** review dependency build scripts: dependencies were not fetched.

Upstream release opt-level changes `z` → `3`; profile settings of a dependency
workspace do not automatically replace the root product workspace profile. Keep
root and standalone Cargo graphs/locks distinct and record both. No blanket
performance or upstream “265+ tests” claim is accepted as product evidence.

## Proposed upgrade lane and acceptance order

1. Preserve current b739 source/native artifacts and finish existing Android
   baseline. Finish/review private Router and proxy-DNS patches on the old base;
   settle ordering before rebasing so neither is dropped. UUID hardening5cacc516
   remains separate and unmerged, and must also survive migration.
2. Create a separate upgrade patch lane. Rebase P01 startup first; merge P09
   lifecycle with the new stream/relay/TUN APIs explicitly; repair new FD risks;
   then replay protocol/auth/trust/transport/mobile/DNS/routing patches. Record
   whether any patch is retained, rewritten or retired and its replacement tests.
3. Require exact full-series deterministic replay, clean checkout verification,
   candidate tree/patch identities and current pipeline negative tests. Never
   use three-way auto-merge success as semantic acceptance.
4. Obtain the scoped execution go-ahead for this **new upstream revision plus
   reviewed rebased patches/dependency delta** before any Cargo/build.rs/code
   execution. The present task authorizes source-only audit, not that execution.
5. After authorization: one-job low-debug format/check, pure core/config tests,
   strict adapter contracts and both standalone/root graphs; no host-network
   settings. Run relay partial/vectored writes, flush, half-close, cancel/drain,
   splice FD exhaustion/ownership/CLOEXEC, task/ConnTable/stats cleanup, resource
   permits and router-generation probe cancellation.
6. Repeat all affected independent protocol-library matrices and negative auth/
   replay/trust/no-fallback checks; SS mixed-family same-session source-port,
   stream UDP partial IO, real MATCH/REJECT no destination/DNS IO, protected
   socket/bootstrap/user-DNS and chained/relay rejection remain mandatory.
7. Rebuild the exact worker and rerun journaled lifecycle/rotation/rollback/crash,
   then native ABI/FD/protect/revoke, Android packet journeys and other supported
   platform gates. Do not relabel b739 or old f249 evidence as new-core evidence.
8. Only then propose coordinated product/core/adapter/schema/release identity
   changes and user-visible migration/rollback support. All 21 mandatory presets
   remain in scope; a static upgrade audit is not release eligibility.

Evidence directory: `tools/core/evidence/upgrade-fa3e743/` (source manifest,
commit log, diffstat, manifest/release diff, relay/stream diff, dependency delta,
patch-overlap map, failed deterministic gate and cleanliness snapshot).
