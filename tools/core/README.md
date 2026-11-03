# Pinned `vp_core` integration and coordinated upgrades (WP02)

**Implemented:** local source identity, ordered patch replay, deterministic generated
Git checkout, refusal of drift/conflicts, candidate lock proposals, negative
Python tooling tests, and an actual bounded Linux managed-worker lifecycle.
Selected Rust/loopback tests have run with authorization; this is **not** complete
protocol interoperability, VPN platform-host or release certification. Current
exact results and retained failed attempts are in `verification.json` and
`evidence/runtime/`. The pipeline itself only performs Git/source checks: its
`rust_execution:not-run` output describes that command, not all project evidence.

## Identity contract

`core-lock.json` schema 1 pins:

- `upstream.repository_url`, full 40-hex `commit`, exact `tree`;
- ordered `patchset.patches` (`id`, product-relative `path`, file `sha256`);
- `patchset.sha256`: SHA-256 of UTF-8 canonical JSON
  `{"upstream_commit":…, "upstream_tree":…, "patches":[…]}` using sorted object
  keys, compact separators, ASCII escaping and **preserved array order**;
- `integration.path`, expected `patched_tree`, deterministic local `commit`;
- adapter package/version and explicitly separate verification statuses.

The integration commit has the pinned upstream commit as parent, a fixed identity
and timestamp, and a message containing upstream/patchset identities. It is a
local reproducibility object, **not an upstream contribution or signed release**.
Checksums prove identity, not publisher authenticity. Release signatures and
actual platform evidence belong to WP13/WP14.

`patches/vp_core/series.toml` records patch order, rationale, ownership, test source,
limitations and removal conditions. Adding, removing or reordering a patch changes
the release identity; no patch is silently dropped during an upstream upgrade.

## Commands (Python 3.11+ and Git; standard library only)

Run from `vp-product/`:

```sh
# Hash/source checks and full replay in a disposable detached worktree.
# No compiler, Cargo, upstream scripts, network fetch or listener execution.
python tools/core/core_pipeline.py verify --upstream /workspace/shared/vp_core

# Create integration/vp_core only if absent. Existing dirty/mismatched worktrees
# are rejected and preserved, not reset. A matching clean worktree is reusable.
python tools/core/core_pipeline.py prepare --upstream /workspace/shared/vp_core

# Verify the materialized checkout against both pinned identities.
python tools/core/core_pipeline.py check --upstream /workspace/shared/vp_core

# Toy repository tests only: do NOT confuse these with Rust/protocol tests.
python -m unittest discover -s tools/core -p 'test_*.py' -v
```

The original `/workspace/shared/vp_core` HEAD, index and files remain unchanged.
Linked worktree registration and deterministic objects are added to its Git
metadata; that is the only source-repository mutation. The generated worktree is
ignored by the product repository. No branch, remote, push or publication is made.
Git hooks, configured clean/smudge/process filters, external diff, fsmonitor and
network protocols are disabled for pipeline operations. `git apply` uses the same
hash-checked bytes for its check and actual apply. Failure cleanup removes only
the pipeline's newly created disposable worktree; permanent worktrees are preserved.

## Upgrade workflow (supports upgrading core *with* the product)

1. Obtain a separately authorized, clean checkout of the proposed upstream revision.
   This tool does not fetch it or move the original research checkout. Record the
   full candidate commit and review the upstream diff, dependency/license changes
   and release notes. A new core version is never a free-floating binary replacement.
2. Replay the **unchanged** pinned patches against that explicit candidate:

   ```sh
   python tools/core/core_pipeline.py upgrade-check \
     --upstream /path/to/clean-candidate-checkout \
     --candidate-commit FULL_40_HEX_COMMIT \
     --output integration/core-lock.candidate.json
   ```

   Wrong HEAD, dirty files/index, conflict, hash drift or a pre-existing output is
   a hard failure. A candidate lock is a proposal only: root lock is not overwritten.
3. If upstream changes require patch maintenance, edit/review patch source in a
   separate product branch and local integration worktree, update `series.toml`
   with tests and rationale, then explicitly propose a new patchset identity:

   ```sh
   python tools/core/core_pipeline.py propose-lock \
     --upstream /path/to/clean-candidate-checkout \
     --candidate-commit FULL_40_HEX_COMMIT \
     --output integration/core-lock.reviewed-patches.json
   ```

   Unlike `verify`/`upgrade-check`, **only this explicit proposal command** accepts
   edited/new/removed ordered patch entries from `series.toml`. It still requires
   clean source and successful exact replay, never overwrites the root lock and
   emits `release_eligible: false`. Review the entire resulting diff/identity.
4. After execution permission exists, compile the adapter + patched core against
   the candidate, run strict-listener negative tests, all affected protocol/client
   and server interop, lifecycle rollback, API/ABI/schema compatibility, and all
   supported platform regressions. Record command, runner, digest and evidence;
   `git replay: passed` does not satisfy any of those gates.
5. Update the product/adapter/core/patch/schema/platform compatibility manifest as
   one reviewed release. Add migrations/recovery evidence and signed artifacts.
   Promote the candidate root lock only through reviewed source changes. Resolve
   or remove an old generated worktree explicitly after inspecting its cleanliness;
   the pipeline deliberately does not destroy it on mismatch.
6. Exercise upgrade and rollback from the actually supported previous release.
   Release acceptance ACC-UPG-002/004/005 remains unpassed until those real runs.

A future upstream change may require a nontrivial patch/adapter change. This
pipeline guarantees **detection, traceability and a reproducible upgrade lane**,
not an impossible promise that every future version works without engineering.

## Current patch series and runtime boundary

The ordered `series.toml` is authoritative. Current ordered series (execution status is per-pin in `verification.json`):

1. P01 strict listener-specific parsing and fail-closed startup; shared outbound
   fields are not indiscriminately rejected.
2. P09 task-local ownership, tracked JoinSet children, bounded graceful drain,
   cancellation-safe/flush-correct relays, partial-start cleanup and readiness.
3. TUIC/Hy2 authentication gates, bounded streams/datagrams and tracked lifecycle.
4. Seven-cipher Shadowsocks wire/replay/UDP corrections and owned session lifetime.
5. Explicit unsupported Vision rejection plus test-only REALITY rustls boundary.
6. Composable TLS/WebSocket/HTTPUpgrade/H2 server helpers and stream protocols.
7. Managed loopback-only destination authority before DNS/socket IO, including
   raw direct paths that bypass general router rules.
8. QUIC per-instance explicit trust roots and official-library-only peer harness.
9. Ordinary uTLS TLSInnerPlaintext trailing-zero/type correctness fix.
10. Default-disabled experimental authenticated REALITY source, no camouflage or
    Vision/factory activation.
11. Seven-cipher official-library peer harness (test/docs only).
12. Preliminary mobile per-generation socket protection, explicit DNS and TUN
    ownership hooks; selected current compilation/tests pass, actual Android guest acceptance remains separate.
13. Explicit unsupported chained-UDP refusal instead of silently bypassing the
    configured dialer; genuine packet-over-dialer transport remains separate.
14. VMess/VLESS canonical framing, bounded replay/nonce and partial IO corrections.
15. VLESS/VMess/Trojan bounded command-UDP over configured proxy streams plus
    independent official-library peer matrices. Full carrier/platform and generic
    routing-policy acceptance remain separate.

Patches1–7 have earlier pinned targeted execution evidence. Later worker evidence
must not be mistaken for a current merged-tree pass. Peer Go source stays under
upstream test directories and is not a product dependency or runtime substitute.

The source helpers in patches 3–6 do not automatically enable App factory/product
compiler mappings. A requested unsupported active transport/security option still
fails, rather than silently becoming raw TCP. Mandatory presets remain visible
and blocked until implemented and independently certified.

Explicit port 0 is retained only by the low-level managed test API; the public
product domain requires a nonzero service port. No lossy port conversion.

The optional `vp-product-core-adapter/managed-runtime` feature links the patched
core into an owned private worker process. This is real `vp_core`, not a reference
engine substitute. `ManagedApp` owns listener/work/background tasks, stop/drain
notifications and cleanup; the process is the final containment boundary for
untracked library or blocking work. Legacy unmanaged App callers retain legacy
lifetime behavior. See `crates/vp-core-adapter/README.md` for the API and limits.

## Remaining acceptance gates

- Product compiler/immutable vault/durable executor and genuinely independent
  per-listener auth, retirement and forwarding probes (separate integration).
- Full independent protocol/transport matrix, including all mandatory 21 presets;
  source helpers and same-codec tests never count as reference interoperability.
- Full REALITY target-flight camouflage/Vision support; experimental authenticated
  boundaries alone cannot satisfy these presets.
- WP11 mobile/native FD ownership, all-socket protection and VPN packet lifecycle.
- WP13 signed combined releases, verified packaging and supported-version rollback;
  WP14 real cross-platform acceptance. `release_eligible` remains false.
