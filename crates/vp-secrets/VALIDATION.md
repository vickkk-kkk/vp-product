# Server immutable vault — focused evidence, 2026-10-30

**Implementation plus focused tests passed; not complete VP/product/platform or
production deployment acceptance.** This report is explicitly tied to the frozen
`f249f7d` worker. A later mobile-network security repin is a separate current-pin
integration gate; historical results must not be relabeled as that newer pin.

## Delivered

- New `vp-product-secrets` crate only: Linux `DurableSecretStore`, externally
  supplied in-memory `MasterKey`, validated namespace, immutable exact refs,
  authenticated kind/version, typed resolution and permanent retirement.
- Actual `ImmutableSecretStore` implementation consumed by `ManagedExecutor`,
  not a synthetic map. The existing trait/domain/contracts were not changed.
- Pinned RustCrypto AES-256-GCM, OS-random nonces, bound namespace/vault/ref/kind/
  version/class/schema AAD, authenticated policy manifest; best-effort zeroizing
  keys and owned secret buffers, enabled AES/GHASH/POLYVAL zeroize features.
- Safe rustix dirfd-anchored no-follow traversal and IO, owner/mode/type/single-link
  checks, nonblocking lifetime writer lock, file+directory fsync, atomic no-replace
  publication, poisoned uncertain writes and authenticated recovery.
- Per-file/secret/count/total-byte/free-disk limits; future tombstone byte reserve.
  No ref reuse, automatic GC, key generation/loading fallback or silent migration.

Parent coordinated root workspace registration and actual lock resolution.
Only synthetic fixed test keys/credentials and ephemeral private temporary roots
were used. No real deployment credential/key, service, system/network setting,
installer, signing identity, legal acceptance, publication or original-core edit.
The actual integration used authorized isolated loopback sockets/child workers.

## Exact executed identity

- Official Rust `1.88.0 (6b00bc388 2025-06-23)`, x86_64 Linux executor.
- Original core: `a1abce2b515b199fe1120061b54654c60f4dd59c`.
- Frozen integration: `f249f7d25989dc0f9ec3993dc60e80caa3d8cd91`.
- Patchset: `24a7ed44df2770925583815f136664a294ff8b4d5d415a4409f47af88b9db6f6`.
- Immutable verified worker:
  `.local-cache/verified-workers/f249f7d/0d690efda87b46058015ba2a7967da49d113e174c93f1f6a70bd3c3be130a503`.
  SHA256 is the full final pathname component above.
- `evidence/source-manifest-f249.json` records focused source, root manifests/lock,
  domain/runtime consumer, frozen core identity, worker and actual log hashes.
  `evidence/core-lock-f249.json` preserves the old pin rather than relying on the
  mutable root file. `features-f249.txt` confirms crypto erasure feature resolution.

Environment and actual successful commands:

```sh
export RUSTUP_HOME="$PWD/.toolchains/rustup"
export CARGO_HOME="$PWD/.toolchains/cargo"
export PATH="$CARGO_HOME/bin:$PATH"
export CARGO_TARGET_DIR="$PWD/.local-cache/product-core-target"
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export VP_RUNTIME_TEST_WORKER="$PWD/.local-cache/verified-workers/f249f7d/0d690efda87b46058015ba2a7967da49d113e174c93f1f6a70bd3c3be130a503"
cargo fmt -p vp-product-secrets -- --check
cargo test -p vp-product-secrets --offline --locked
cargo clippy -p vp-product-secrets --all-targets --offline --locked -- -D warnings
cargo tree -p vp-product-secrets -e features --offline --locked
```

**PASS: 27 unit tests + 1 real-worker integration; 0 failed, ignored or filtered.**
Formatting and all-target clippy with warnings denied also passed. Shared Cargo
lane was coordinated; no duplicate target cache or worker overwrite was used.
Available disk remained about 7.2 GiB, above the 1 GiB build guard.

## What the tests establish

- Durable encrypted exact-ref roundtrip/reopen; ciphertext files contain neither
  the synthetic credential nor synthetic master-key bytes. No plaintext cache.
- Wrong key/namespace, modified ciphertext/tag/nonce/ref/kind/version/manifest,
  unknown versions, truncated/oversized files, copied records/ref relocation,
  cross-vault identity, missing/expired requests and retired refs fail closed.
- Duplicate refs never overwrite, including higher version and after retirement;
  typed lookup and runtime port reject private-key/credential confusion.
- Root/ancestor/file/staging/manifest symlinks, unsafe modes, wrong expected UID,
  hardlinks, directories/FIFOs and traversal are rejected. FIFO rejection does
  not block. Replacing a root pathname cannot redirect the held directory FD.
- Record/count/byte/free-space bounds and retirement quota reserve; concurrent
  puts reserve exactly one reference. Secrets/keys have redacted Debug output.
- Injected failures after write, after file fsync, after rename and after directory
  fsync for both put and retirement require authenticated reopen. Only committed
  final entries become visible. Incomplete bounded staging is cleaned only after
  key/integrity validation. Reopen attempts directory fsync even with no pending
  entry, completing the rename-before-directory-fsync recovery window.
- Real encrypted vault → shared `ControlService`/SQLite → `ManagedExecutor` →
  actual pinned `vp_core` worker: first apply, credential rotation, actual new
  authentication/forwarding and old-credential rejection; retire only after
  successful commit/rejection checks. A fresh worker then consumes credentials
  from a reopened authenticated vault. Runtime/control files contain no test
  credential bytes. External connectivity remains explicitly NotChecked.

The VLESS wire probe is locally authored test support adapted from the existing
runtime-executor suite, not an independently implemented protocol certification
or a production ActiveProbe.

## Findings repaired; earlier failures retained

- Initial compilation exposed two rustix API call mistakes (`&&OsStr`, `ACCES`);
  repaired. `test-initial.log` retains the failed attempt; `test-repair.log` records
  the earlier 25-unit pass before the final two additional regressions.
- A focused read-only source security review found reopen skipped directory fsync
  when no `.pending` remained after a rename. Fixed unconditional authenticated
  recovery sync, re-reviewed, and tested in the final suite. This focused review
  is not an external security audit.
- Adding the real-worker test required parent-owned root lock refresh. The honest
  blocked `--locked` attempt remains in `lock-refresh-required.log`; no wholesale
  dependency re-resolution or manually invented lock hashes was performed.
- Actual final results are `test-final-f249.log` and `clippy-final-f249.log`.
  Earlier failures are not retroactively described as passes.

## Explicit remaining gates / security limits

- New/current core pin rerun after the separate mobile DNS security change.
- Authorized master-key provisioning/inherited-FD composition, installer/service
  ownership and the default management daemon's production wiring.
- Real production probes, complete protocol/preset matrix, deployed API/browser
  journeys, native OS lifecycle, packaging and release acceptance.
- Independent cryptographic/security audit, fuzzing/sanitizers, physical disk-full/
  fsync/device-error/power-cut qualification and supported filesystem/CPU matrix.
  Injected process failures are **not** physical power-loss certification.
- Synchronous filesystem syscalls cannot have hard userspace deadlines; scoped
  bounded reads, nonblocking locks and before/after deadline checks are implemented.
- Encryption protects offline ciphertext-only copies without the separate master
  key. It does **not** protect root/service-UID or process compromise, lost keys,
  swap/core dumps, hostile storage, selective deletion or rollback. Removing a
  tombstone while retaining old ciphertext can revive it after reopen; no trusted
  monotonic/anti-rollback authority exists here. Retired ciphertext is retained,
  not securely erased. See README for the explicit retention/backup requirements.
- Master-key rotation, cross-schema migration, consistent backup/restore and
  controller-authorized garbage collection remain explicit future gates. No
  automatic migration, mutable-reference fallback or ref reuse is allowed.

No capability/acceptance row was promoted; the required full product scope is
unchanged by this focused server-secret implementation.
