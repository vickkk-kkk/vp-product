# Durable managed vp_core RuntimeExecutor

This crate implements control's real `RuntimeExecutor` over
`vp-product-core-adapter::managed`, not a second apply/rollback state machine or a
mock success adapter. It remains an **uncertified loopback development bridge**,
not a complete proxy product, production vault or independent protocol harness.

## Composition

`ManagedExecutor::open` takes an installer-provisioned absolute private 0700 root,
exact compiled adapter release identity, `VerifiedWorker` and matching SHA256,
`ImmutableSecretStore`, `ActiveProbe` and clock. It holds a nonblocking OS lock for
its lifetime. Compose it with existing `ControlService` and `SqliteStore`.
`NoHostChanges` accepts only empty resource lists and refuses every host mutation;
it does not claim routes/firewall/service resources were inspected or changed.

The supplied `UnavailableSecretStore` / `UnavailableProbe` fail honestly; no
production in-memory/password-file vault or unconditional-passing probe exists.
Vault metadata validation must establish immutable/versioned references. Resolve
returns `SecretBytes`, only immediately before the bounded worker pipe or active
credential probe; raw credentials never enter this crate's durable files.
The managed adapter zeroizes its private IPC/active-config copies best effort.

The application must provide approved, deadline-bounded real probes for each
listener: successful authentication, invalid/retired credentials with zero target
forwarding, endpoint release, and actual forwarding. `Process` alone uses a fresh
worker snapshot plus PID/birth identity; a snapshot never fabricates any network
oracle. `external_connectivity` remains NotChecked. Test probes are local authored
VLESS encoders and target counters, **not independent implementation certification**.

## Durable boundaries and recovery

- Pure recipe compilation is bound to the exact full release and binary digest.
- Stage publishes immutable content-addressed reference-only artifacts with fsync.
- An atomic fsync/rename/checksummed 0600 journal records operation/plan hash,
  revision/config/release/artifact digests, previous references and generation.
- Generation high-water is fsynced before every launch attempt. The adapter's
  spawn observer fsyncs PID + Linux start ticks + boot ID **before** a Start frame
  can create listeners. Missing-PID launch intent therefore precedes any listener.
- On restart, a saved active marker is not readiness. Reuse is blocked until the
  exact saved process identity is absent and active probes establish release of
  the old endpoints. No PID guessing, unrelated-process kill, route modification,
  system proxy, TUN, privileged helper, installation or external target is used.
- Candidate stop is operation/revision/generation scoped. Late cleanup cannot
  stop a restored previous generation. Failed verification restores and freshly
  probes the previous recipe, including rejection of the candidate's credentials.
- `reconcile_committed` is an explicit startup action after shared control
  recovery; it restarts the durable committed configuration and runs fresh probes.
  Failed health is stopped, not returned as successful startup.
- `observe_committed` is read-only: it cannot stage or launch. It verifies the
  exact committed operation/config/release/artifact and currently owned process,
  then performs fresh probes; persisted receipts cannot be reused as observation.
  Shared control serializes it with transactions using its existing writer lease.
- `shutdown` stops/reaps only the owned generation and verifies endpoint release;
  the committed control record remains available for explicit restart reconciliation.
- Corrupt/incompatible storage, uncertain fsync, stale process ownership, missing
  secrets or missing probe evidence fail closed. Pending external process exit
  returns RecoveryRequired; the composition may retry once process exit is proved.

Root permissions and ancestor ACL ownership must be guaranteed by composition;
mode bits do not establish owner identity. The crate does not repair permissions.
Durable IO calls rely on a functioning bounded local filesystem; the traits require
vault/probe deadlines. Uninterruptible kernel filesystem IO cannot be given a
hard user-space deadline, so this is not a claim against a failed/hung filesystem.

The current journal pins one release+worker; cross-release slot migration and
rollback are intentionally rejected, not silently reinterpreted. Coordinated
core/product upgrade is still a separate required release gate. Encrypted `vp-product-secrets` and the explicit managementd development profile
now supply composition source, with validation tracked separately. This does not
establish public deployment, coordinated upgrade or all-21-preset acceptance.
Independent protocol and native lifecycle evidence belong to their separate gates.

## Focused checks

```sh
# Read docs/implementation/RUST_VALIDATION.md for the local official toolchain.
export CARGO_INCREMENTAL=0
cargo build --locked -p vp-product-core-adapter --features managed-runtime \
  --bin vp-core-managed-worker
export VP_RUNTIME_TEST_WORKER="$PWD/target/debug/vp-core-managed-worker"
cargo test --locked -p vp-product-compiler -p vp-product-runtime-executor
cargo clippy --locked -p vp-product-compiler -p vp-product-runtime-executor \
  --all-targets -- -D warnings
```

Set `VP_RUNTIME_TEST_WORKER` to the actual verified worker path when using another
Cargo target directory. Missing/stale binaries fail tests, never skip them.
Check the implementation evidence report for actual executed results; commands in
this README alone are not evidence of a pass.
