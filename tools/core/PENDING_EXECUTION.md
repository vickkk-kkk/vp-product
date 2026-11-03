# Current execution boundary — 2026-10-30 07:38 UTC

Active e96584f (20patches, old upstream a1abce2) passed313 standalone and45 root
adapter/runtime tests; mobile owner has relinked exact native artifacts and Android
acceptance is coordinated by parent. Main generated/core-lock remain frozen.

New upstream fa3e743/v1.1.0 candidate af79f5e is SOURCE-ONLY:24 deterministic
patches, clean replay,125 files rustfmt-parsed; no Cargo/build.rs/tests/execution.
See UPGRADE_REBASE_HANDOFF.md for exact identity and required scoped authorization.
Do not confuse old upstream execution permission or old test receipts with this
new version. Public release and all21 mandatory gates remain separate.

The following older queue is preserved as historical context, not current status.

---

# Pending selected execution and next-candidate work

At05:02 UTC current16-patch b739844 passes TUIC6/protected DNS denial, official
QUIC-library19, combined adapter20+contracts9+worker13, strict Clippy/fmt and
Python20/replay/source-clean. Final native host/C ABI/Android relink belongs to
mobile owner and is running next. Do not mutate generated source/core-lock during
that lane. The fifteen-patch f249 vault gate passed27units+1actualworker journey,
but stays old-pin evidence. Current merged streamUDP/local/reference tests and
bridge/vault rechecks remain queued; author final stream tree passed separately.

Next private candidate: UUID parser UTF-8 panic/secret-redaction patch5cacc516 is
authored, not executed/promoted. Real Router enforcement for raw protocol TCP/UDP
is separate mandatory work; current LoopbackIpOnly authority is only a test fence,
not a routing-policy repair. TUN bootstrap/user-DNS policy audit is also separate;
protected sockets do not prove DNS privacy. Keep public capabilities blocked.

Capture source/lock digests, check free disk, and use the shared product target
(single job, low debug, incremental0). Never rebuild/overwrite a verified worker
binary while its digest-bound process tests are using it. Parent reclaimed the
completed standalone cache after evidence capture; do not recreate duplicate caches.

Suggested bounded order, with Rust1.88.0, `CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=1`
and parent-requested low-debug profile. A profile change rebuilds dependencies;
coordinate memory/disk and the mobile cross-target build with parent first.

1. Source replay/check; root `cargo metadata --locked` (no silent lock/version bump).
2. Host hook focused tests: standalone `vp-core --lib host_network::tests`, then
   core full library and DNS affected tests, with original default behavior intact.
3. Product adapter check/tests with `managed-runtime,mobile-ffi` on host; actual
   C ABI/native lifecycle tests owned by mobile worker. A host build does not
   prove Android ABI or VpnService packet/protect behavior.
4. Standalone App listener/lifecycle, SS standard/managed, QUIC auth/lifecycle,
   composed stream carriers and transport tests; use explicit filters so tests
   cannot accidentally select zero and be recorded as a pass.
5. Independent protocol-library peers on the *current integrated* source:
   - `VP_QUIC_REFERENCE=$PWD/.local-cache/reference-quic`
   - `VP_SS_REFERENCE=$PWD/.toolchains/reference-ss`
   - `cargo test --locked -p vp-protocol --test quic_library_interop -- --include-ignored --test-threads=1`
   - `cargo test --locked -p vp-protocol --test ss_library_interop -- --include-ignored --test-threads=1`
   Verify binary digests against `docs/implementation/evidence/reference/quic-library-peer.json`
   and `docs/implementation/evidence/ss/reference-peer.json` before executing.
   Library peer success is not full sing-box CLI success (CLI netlink still blocked).
6. Experimental transport remains default-disabled: run its explicit-feature
   unit/integration boundary tests, default-disabled check and affected ordinary
   uTLS zero-padding/close_notify tests. No factory/preset enablement follows.
7. Root runtime bridge uses rebuilt exact-current-pin worker; rerun real auth/
   retirement/rollback tests rather than reusing stale binary evidence. A new
   core/patch hash requires a new worker Hello/digest; notify bridge owner first.
8. Strict adapter lint; scoped upstream lint with any existing unrelated baseline
   failures retained separately. Formatting checks must not silently alter a
   pinned generated tree: any source corrections belong in a new reviewed patch.
9. Update verification manifest with exact commands, per-suite counts, log/source/
   binary/lock digests; keep all21 presets blocked unless their complete gates pass.

Separate next gate: Android owner cross-compilation, symbol/JNI/FD/protect callback
and actual guest lifecycle/packet evidence. No system routes/firewall/proxy/service
changes on the host. Go reference programs remain test-only artifacts.
