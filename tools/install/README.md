# Linux local-bundle installer and shared-API CLI

**Implemented source + isolated filesystem/CLI tests, not a completed public VPS release.**
This directory is independently authored; no code/templates from the GPL reference
installer were copied. The production engine remains **vp_core only**.

## Separate private fresh-runtime path

`install.sh fresh-local` and `build_fresh_bundle.py` implement a distinct strict
schema-2 / descriptorVersion-2 development path. See [usage](FRESH_LOCAL_USAGE.md)
and [contract](FRESH_BUNDLE_CONTRACT.md). It requires explicit preparation, bound
vault initialization and first activation; supervised foreground only. It has no
upgrade/rollback/recovery/adoption. Its action named `uninstall` only disables
this local profile and retains ALL files, including executable/Web artifacts;
separate explicit `remove-program-files` can remove only exact manifest-owned
program files after deactivation, retaining data/provenance with no partial-failure
resume. Archive-bound `deactivate` permits metadata-only cleanup on runtime-ineligible
hosts without weakening runtime action gates. See the usage document for the one-shot intent boundary. The existing
schema-1 lifecycle capabilities below do **not** transfer to this profile.

## What exists now

- `install.sh` / `vpctl.py`: executable local entry point, TTY wizard or explicit commands.
- `vp_install.py`: read-only preflight and deterministic plan; exact plan-hash confirmation;
  verified local ZIP release slots; atomic activation; exclusive writer lock; durable
  journal; interrupted-operation recovery; update/rollback; constrained systemd
  integration; status; uninstall retaining data unless explicitly purged.
- `build_bundle.py`: packages **existing real local artifacts**, deterministic metadata,
  per-file digests and whole-bundle SHA256. No build/download/signing/publishing step.
- `vp_api.py`: administrator login/session/CSRF in memory; shared draft → validate →
  plan → apply → operation observation. No direct core configuration writes.
- `vp_form.py`: interactive input from the **shared generated JSON Schema**, not a
  second set of protocol templates. All 21 public presets remain listed; seven SS
  ciphers come from the shared catalog/schema. Direct remains explicitly undecided.
- `export`: delegates to `/api/v1/exports`; writes a successful sensitive response
  only to a new private file. An unimplemented endpoint returns a visible error,
  **never a fabricated subscription URL, QR, credential or fallback encoder**.

An installation marked `installed:true` means verified artifacts were installed.
`serviceActive` is service-manager observation, **not protocol readiness**;
`forwarding` remains `not_verified`. No GUI/CLI display may promote these to certified
21-preset runtime support.

## Local artifact/trust contract

There is no configured published distribution URL or signing identity. Installation
**requires both a local bundle and an independently trusted expected SHA256**.
A checksum printed beside an untrusted archive does not establish authenticity.
The operator must obtain the expected digest through a trusted channel. This is an
explicit unsigned local-development distribution contract, not signature validation.

Build a bundle only after the responsible build lane supplies real artifacts:

```sh
python3 tools/install/build_bundle.py \
  --managementd /absolute/path/vp-product-managementd \
  --worker /absolute/path/vp-core-managed-worker \
  --web-root flutter/apps/vp_admin/build/web \
  --core-lock core-lock.json \
  --presets contracts/capabilities/presets.json \
  --release-id local-review-1 --product-version 0.1.0-local \
  --output /absolute/private/path/vp-local-review-1.zip
```

`--worker` is optional in management-only mode and mandatory for the explicit
runtime profile. The daemon additionally verifies worker Hello/core/patch identity;
a matching file hash alone is not core compatibility certification.

Bundle v1 contains exactly a `manifest.json` and allowlisted files:

- `bin/vp-product-managementd` (matching Linux ELF64)
- optional `bin/vp-core-managed-worker` (matching Linux ELF64)
- `web/*` including `web/index.html`
- `core-lock.json`
- `contracts/capabilities/presets.json`

Manifest fields: `schemaVersion=1`, `releaseId`, `productVersion`, `engine=vp_core`,
`architecture=x86_64|aarch64`, `coreLockSha256`, `storageSchema=1`, and
`files:[{path,size,sha256,executable}]`. Unknown fields/components are rejected.
No archive script is executed. The local CLI source kit is currently run from this
checkout; automatic installation into `/usr/local/bin` is not implemented.

Bounds: 256 MiB archive, 512 MiB total expanded content, 128 MiB/file, 4096 ZIP
members, 2 MiB central directory, 128 KiB manifest; no ZIP64, encrypted members,
archive comments, duplicate paths, symlinks/hardlinks/devices, parent/absolute paths,
setuid/setgid bits, unlisted files, unsupported compression or high compression ratios.
The packager uses stored ZIP members and omits only Flutter's root-local
`.last_build_id` build marker (other hidden/unsafe paths are rejected). A bounded copy is first made into an
installer-owned 0600 anonymous temporary snapshot
while computing the externally trusted digest. The source descriptor is then closed;
parsing and extraction use only that exact private snapshot. Retaining a source FD
alone is not a trust boundary because its owner can overwrite the inode. Per-file
content is additionally rehashed while staging.

## Sealed runtime host prerequisite gate

A selected runtime profile now requires native Linux x86_64/aarch64 with kernel
**6.3 or newer**, allowed executable memfd, all required executable/write/size
seals, and working `/proc/self/fd` access. Older kernels are explicitly unsupported
for this worker; no distribution-wide compatibility claim or path-execution
fallback is made. Management-only file installation is unaffected.

`preflight --runtime-profile loopback-vless-v1 --vault-namespace NAME` checks the
actual anonymous memfd/seal/proc facilities without launching any executable,
creating files or credentials, invoking services, or modifying host policy. Its
successful status is `prerequisites_present_not_execution_certified`: final MAC
and proc-fd **execution policy remains unverified** until the real worker starts.
The worker independently verifies/seals its exact bytes and refuses unsafe spawn.

Confirmed install/update/rollback/start/recover operations with a runtime profile
repeat this prerequisite gate **before creating the installation root, ownership
marker, lock or journal**. Execution-capable recovery checks both pending and previous runtime
settings. Verified interrupted-uninstall and already-committed journal cleanup
branches are exempt because they cannot launch a worker. An unsupported host returns a clear failure without installer state
mutation. Stop/uninstall remain available for cleanup. This gate is not a first-
boot credential initializer, public-server deployment or all-protocol acceptance.

## Safe file-only trial (no services or network changes)

Python 3.10+ and Linux x86_64/aarch64 are required. The root's parent must already
exist, be protected against other-user writes and have no symlink ancestors.
Private temporary directories under sticky `/tmp` are supported for tests. A bundle-bearing
`--dry-run` uses a bounded anonymous temporary verification snapshot, but leaves no
installation, service or network state; `preflight` without a bundle performs reads only.

```sh
sh tools/install/install.sh preflight --root /absolute/private/test-parent/vp
sh tools/install/install.sh install \
  --root /absolute/private/test-parent/vp \
  --bundle /absolute/private/path/vp-local-review-1.zip \
  --sha256 TRUSTED_64_HEX_DIGEST --dry-run
```

Noninteractive callers read the complete JSON plan and rerun the same command with
`--confirm-plan-sha256 PLAN_HASH` instead of `--dry-run` (`--confirm` remains an alias).
No generic `--yes` exists. Without confirmation, noninteractive mode only prints a
plan. A TTY presents a Chinese numbered menu and a directory/version/action/risk
summary, then accepts the short explicit action `安装` / `更新` / `卸载` (or its English
command). Enter cancels. The program binds that consent to the full displayed hash;
users need not copy it. Rechecking under the writer lock rejects drift, discards old
consent, displays the new plan and asks again. `--json` keeps machine-readable output
available in a TTY. Purging requires a separate `清除数据` / `purge data` confirmation. Identical installed releases are a no-op, including
when the service is already running.

```sh
sh tools/install/install.sh status --root /absolute/private/test-parent/vp
sh tools/install/install.sh update --root ... --bundle ... --sha256 ... --dry-run
sh tools/install/install.sh rollback --root ... --release PREVIOUS_RELEASE --dry-run
sh tools/install/install.sh recover --root ... --dry-run
sh tools/install/install.sh uninstall --root ... --dry-run
```

Each mutation remains bound to its exact displayed hash; automation supplies it
explicitly and the TTY confirmation binds it internally. `recover` exists only for a pending
journal. New work is refused until recovery resolves the prior operation. Install/
update failure restores the former activation and former service-running state;
validated newly staged releases may remain as inactive rollback slots. Partial
private staging is removed, unknown directories are never guessed/deleted.

Uninstall removes the owned service registration, activation and tracked release
files, preserving installer metadata and `data/`, `runtime/`, `vault/` by default.
`--purge-data` explicitly includes all three state directories in the confirmed plan;
it never deletes the operator's external bootstrap input. Interrupted uninstall is
idempotent forward cleanup, not a claim that deleted data can be rolled back.

Only storage schema 1 is accepted. **No database/schema migration, snapshot restore,
or general application-data downgrade is implemented.** Code rollback does not mean
a new schema can be loaded by an old binary. Future schema changes must be blocked
until the shared release/control migration contract exists. The proposed
[v2 handoff](BUNDLE_V2_CONTRACT.md) separates SQL layout from control payload versions;
it is not currently accepted by the installer and does not authorize old-vault restoration.

## Systemd source path (real host acceptance pending)

`--service-mode systemd` is an explicit privileged deployment choice. It is not run
by the test suite. Requirements before applying the plan:

1. A supported systemd environment (the credential mechanism requires systemd 247+
   and target-distribution acceptance), `/usr/bin/systemctl`, and root authority.
2. An externally provisioned non-root/non-login `vp` user and matching `vp` group.
   This installer does not silently add users or install packages.
3. A trusted private bootstrap JSON supplied by the operator, root-owned and not
   group/world-readable. `--bootstrap-file /absolute/path` is a **path**, never secret
   bytes on argv. No default usable account/token/master key is generated.
4. A suitable protected deployment path such as `/opt/vp`; service-account traversal
   and distribution-specific MAC/sandbox behavior still need real host validation.

`preflight --service-mode systemd` aggregates authority, service-manager presence,
user/group, private bootstrap metadata, optional bundled worker and vault prerequisites
**before installation changes**. It neither reads credential contents nor invokes
systemctl. Missing/invalid dependencies include repair guidance and return failure,
rather than discovering each one midway through installation. Systemd version and
actual runtime validity remain explicitly unverified, not inferred from file presence.

First-time runtime-profile service provisioning is still a blocker: the safe account,
bootstrap and encrypted-vault initialization UX is not complete. The preflight says
so explicitly. Do not fake an ownership marker or silently switch immutable file-only
settings to systemd; a future coordinated provision transaction must close this gap.
Management-only systemd installation still requires externally supplied account and
bootstrap. No account, production credential or vault key is generated by this code.

The generated unit uses `LoadCredential` and `StandardInput=file:%d/bootstrap`, a
non-root service account, private state directories, and no shell hooks. See the
[official systemd execution documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredential=)
for credential semantics. The external JSON remains outside the installation ledger
and is never copied into a release, log or unit. Python cannot promise comprehensive
in-memory zeroization; the API client keeps token/session strings only for its process.

Installation links the unit but does not start it. `--enable-on-boot` is optional,
explicit and included in the immutable settings/plan. Then `start` and `stop` use
separate confirmed plans. Systemctl calls have a finite timeout, fixed verbs and one
owned unit; foreign unit ownership fails closed. No firewall, route, DNS, sysctl,
system proxy, package-manager or arbitrary command/hook interface exists.

### Explicit development runtime profile

When the daemon/runtime implementation and matching worker are actually built,
`--runtime-profile loopback-vless-v1 --vault-namespace OPERATOR_NAMESPACE` adds the
agreed worker SHA/runtime/vault/probe flags. It is **not enabled automatically**.
`data/`, `runtime/` and `vault/` are separate 0700 roots.

The unit always uses `--vault-action open`: an absent/uninitialized vault must fail,
not generate keys or fall back to initialization on boot. One-time vault initialization
and the externally supplied master key/credential records belong to the daemon's
explicit provision flow. This profile has owned loopback probes only; it is not
public VPS protocol certification and does not shrink the 21-preset first-release scope.

Management binds only `127.0.0.1:PORT` with an exact local Origin. Browser Secure-cookie
behavior and a trusted public HTTPS edge have not been accepted by these tests.
OpenRC, IPv6 management binding, public edge/ACME, full TLS certificate lifecycle,
and vendor-specific service packaging remain required separate work.

## Protocol wizard and subscription/export delegation

```sh
python3 tools/install/vpctl.py protocols
python3 tools/install/vpctl.py build --origin http://127.0.0.1:18080
python3 tools/install/vpctl.py configure --origin http://127.0.0.1:18080
```

Interactive configuration selects a preset by number, explains protocol/port/TLS
prerequisites in Chinese and walks the shared `ServerListener` schema (no hand-written
JSON needed), and appends the DTO to the active shared `ProductConfig`. It asks only for
existing immutable vault/certificate references; it cannot issue certificates or
invent passwords/UUID secrets. The backend performs exact protocol/transport/security
validation, capability gating, plan creation and runtime changes. A catalog entry or
successful form collection is never treated as runtime support. Direct cannot be
silently substituted for another protocol. Unsupported combinations remain explicit.
In the normal TTY path, a selected preset lacking backend certification stops before
collecting credential/certificate references and displays the backend dependency code.
The separate explicit DTO path supports authorized internal integration; it still
requires the same API validation and never bypasses capability checks.

Noninteractive input uses shared DTO JSON and a stable idempotency key:

```sh
python3 tools/install/vpctl.py configure \
  --origin http://127.0.0.1:18080 --credential-stdin \
  --config /absolute/private/config-with-references.json \
  --request-key operator-change-001 --dry-run < /operator/private/api-login.json
```

API login JSON is `{username,token}`; it is **not** a subscription token or full daemon
bootstrap object. Never put credential bytes in command-line parameters. API
`--dry-run` creates a **persistent draft and plan**, but never applies runtime work;
it is distinct from the installer's completely read-only filesystem preflight.
`apply-plan` accepts the API's exact plan ID/hash/base revision and stable key.
Timeout/pending or rolled-back operations do not return success. Ambiguous HTTP
failures are not automatically replayed; inspect/reuse the stable request key.

```sh
python3 tools/install/vpctl.py export --origin http://127.0.0.1:18080 \
  --credential-stdin --request-file /private/shared-export-request.json \
  --output /private/new-export-result.json < /private/api-login.json
```

An absent export backend returns its structured rejection (currently expected until
that pipeline is implemented). The CLI does not reuse the administrator login token
as a subscription credential. Subscription issuance/rotation/revocation, QR rendering,
mobile preview/import/refresh and failure retention remain shared API/mobile delivery
requirements, not locally fabricated fallback behavior.

## Executed validation and known blockers

```sh
python3 -m unittest discover -s tools/install/tests -v
python3 -m py_compile tools/install/*.py
sh -n tools/install/install.sh
```

Current evidence: **52 tests passed**. Real temporary-filesystem installation,
repeat/update/rollback, stale-plan rejection, synthetic process-interruption journal,
atomic-pointer interruption, partial uninstall recovery, integrity drift, traversal/
symlink/duplicate archive denial, deterministic packaging, actual CLI subprocesses and real PTY numbered-menu/short-consent/cancel/plan-drift/purge flows,
21 schema form branches, API delegation and explicit pending/503 behavior are covered.

Test bundles contain clearly synthetic minimal ELF headers and never execute them.
`FakeService` is only dependency injection inside tests and has no production CLI
selector. It does not constitute systemd, daemon or proxy-protocol acceptance.

`tests/live_cli.py` is a separate opt-in harness, **not part of those 52 tests**.
It requires the exact daemon/worker build paths and independently recorded SHA256s,
plus actual built Web assets. It packages these artifacts, confirms a temporary
file-only installation, launches the installed loopback-only runtime explicitly,
and exercises the real CLI's draft/validate/plan/apply, observation, export rejection
and retaining uninstall. Its runtime credentials are synthetic and temporary.
Run it only inside the authorized isolated integration environment:

```sh
python3 tools/install/tests/live_cli.py \
  --daemon /exact/build/vp-product-managementd --daemon-sha256 RECORDED_SHA256 \
  --worker /exact/build/vp-core-managed-worker --worker-sha256 RECORDED_SHA256 \
  --web-root flutter/apps/vp_admin/build/web \
  --evidence /private/test-evidence.json
```

The first three live attempts are retained in `tests/live-cli-attempts.json` and
per-attempt logs, not overwritten as success: a CLI idempotency-key contract bug was
fixed, then port-release and optional-process-interface assumptions in the harness
were corrected. The fourth complete run **passed at 2026-10-30 08:03:41–08:03:49 UTC**, using the
unchanged e965 daemon `e302257e…` and worker `5dae2017…`.
`tests/live-cli-results.json` binds exact source/binary/bundle/core/fixture hashes.
It proves the temporary file-only install → real loopback API apply/forwarding probe
→ process exit and port release → retaining-uninstall gate. It does not establish
public service, independent VLESS certification or the full 21-preset release.

An attempted offline `systemd-analyze verify` of the temporary unit was **blocked**:
the tool tried to create `/run/systemd/`, which is read-only in this environment.
It exited 1; no successful host write/service action occurred, and no workaround or
escalation was used. `tests/unit-verify.log` records this separately from passing tests.

Pending: real systemd/root distro tests, complete first-time account/bootstrap/vault
provisioning, OpenRC, safe public network exposure, all preset runtime gates, certificate/ACME,
credential provisioning UX, protocol exports/subscription lifecycle, installed CLI
packaging, signed public release trust, schema migration/snapshot rollback and the
complete install → protocol → mobile import → forwarding → upgrade → uninstall journey.

### Confirmed review finding and bounded fix

A separate review confirmed that holding a source archive FD did not prevent its
owner rewriting the inode between outer SHA verification and manifest parsing. The
implementation now snapshots first as described above. Regressions overwrite the
source in-place at the former boundary or replace its pathname; extraction still
uses the original trusted private snapshot. Test payloads are never executed.

The independent review terminated after this finding and did **not** complete a
full audit. The fix plus passing regressions is not a general security certification.
No blocked review action was retried or expanded.

## Managed UUID credentials and independent subscription URLs (candidate extension)

This candidate consumes the **already implemented** `secret_http.rs` routes and
`management_secrets.rs` DTOs; it does not add a second issuer/codec or change the
installer's older bundle-v1 compatibility. The preceding historical 52-test/live
installer evidence remains unchanged. The new publication CLI requires the actual
payload2 daemon described in `MANAGEMENT_PUBLICATION_VALIDATION.md`; do **not** put
that daemon into the old bundle-v1 package or claim migration compatibility.

```sh
python3 tools/install/vpctl.py manage-subscriptions --origin https://ADMIN_ORIGIN
python3 tools/install/vpctl.py credentials --origin https://ADMIN_ORIGIN
python3 tools/install/vpctl.py publications --origin https://ADMIN_ORIGIN
python3 tools/install/vpctl.py publication --publication-id PUBLICATION_ID --origin https://ADMIN_ORIGIN
```

The Chinese menu offers one deliberate action per invocation: inspect metadata and
expiry, create/update/republish, issue/rotate/revoke, list/generate UUID credentials,
and retire unused records. Interactive create/update selects an enabled committed
listener/user, then asks for the **explicit** client endpoint/security using shared
schema fields. It never guesses a public endpoint from wildcard bind, management
Origin or HTTP Host. TLS/REALITY public settings are not inferred from private refs;
the daemon refuses mappings it cannot faithfully verify/export. UUID generation
availability is not protocol certification; all 21 preset requirements remain.

`configure` uses inventory selection or a deliberate “生成” action for UUID-based
VLESS/VMess credential fields. The daemon returns an immutable reference, never raw
UUID bytes. A generated record is **not applied** until the existing shared draft →
validate → plan → apply flow succeeds. Unused records can remain after cancellation;
retirement must be a separate explicit action and can be refused because recovery
history still references a record. Non-UUID protocols retain the original existing-
reference schema workflow and shared capability gating; no UUID fallback is added.

### Noninteractive metadata mutations

All mutations require a stable `--request-key`, the exact observed `--revision`, and
an action-specific confirmation flag. Credentials from stdin still mean the existing
bounded login JSON `{username,token}`—not subscription tokens. Examples use symbolic
IDs/revisions and never real secret bytes on argv:

```sh
python3 tools/install/vpctl.py credential-create --origin https://ADMIN_ORIGIN \
  --credential-stdin --revision 3 --request-key uuid-create-001 --confirm-generate < /private/login.json
python3 tools/install/vpctl.py publication-create --origin https://ADMIN_ORIGIN \
  --credential-stdin --revision 3 --request-key publish-001 \
  --request-file /private/publication-create.json --confirm-publish-connection-secrets < /private/login.json
python3 tools/install/vpctl.py publication-update --origin https://ADMIN_ORIGIN \
  --credential-stdin --publication-id PUBLICATION_ID --revision 2 --request-key publish-update-001 \
  --request-file /private/publication-replace.json --confirm-publish-connection-secrets < /private/login.json
python3 tools/install/vpctl.py publication-republish --origin https://ADMIN_ORIGIN \
  --credential-stdin --publication-id PUBLICATION_ID --revision 2 --source-revision 4 \
  --request-key republish-001 --confirm-publish-connection-secrets < /private/login.json
python3 tools/install/vpctl.py publication-revoke --origin https://ADMIN_ORIGIN \
  --credential-stdin --publication-id PUBLICATION_ID --revision 3 \
  --request-key revoke-001 --confirm-revoke-access < /private/login.json
```

Create JSON is the exact `PublicationCreatePayload`: `name`, `enabled`,
`format:"uri_list"`, `sources`, `confirmPublishConnectionSecrets:true`. Each source is
`{listenerId,userId,endpoint,clientSecurity}`. Replace additionally requires the exact
current `sourceRevision`; all security fields, including `clientHelloFingerprint`,
remain intact. Republish preserves all existing source fields and deliberately moves
the pinned revision. There is no invented `/republish`, `/rotate` or `/expiry` route:
republish uses full `PUT publication_replace`; rotation/expiry changes use the real
`POST publication_token_issue`. Disable is an explicit full replacement with
`enabled:false`; it revokes the URL. Re-enable does not automatically issue one.

### One-time URL display, expiry and uncertain outcomes

```sh
python3 tools/install/vpctl.py publication-issue --origin https://ADMIN_ORIGIN \
  --publication-id PUBLICATION_ID --revision 1 --request-key issue-001 \
  --expires-in-seconds 3600 --show-secret-url
python3 tools/install/vpctl.py publication-rotate --origin https://ADMIN_ORIGIN \
  --publication-id PUBLICATION_ID --revision 2 --request-key rotate-001 \
  --expires-in-seconds 86400 --show-secret-url
```

These commands require a real terminal stdout **before issuing**. No redirected
file/pipe, `--output`, `--json`, `--dry-run` or secret-envelope receipt is supported.
The URL appears exactly once in that terminal; only safe publication metadata
follows. The operator must explicitly approve display (flag or Chinese confirmation)
and avoid recorded terminal sessions. Python cannot guarantee memory zeroization or
protect a compromised/recording terminal. The transport requires the daemon's
no-store/no-cache/no-referrer response headers. HTTP is allowed only for explicit
loopback development, with a warning that the URL is **not phone-reachable**.

Expiry must be 300..2592000 seconds. Inspect `token.state` and `expiresAt` (Unix ms)
through metadata; the CLI does not infer expiry from its local clock. Changing expiry
requires deliberate rotation and invalidates the previous URL on successful commit.
`publication-issue` refuses a record that has already issued a token instead of
silently rotating it; use the explicit rotation action after inspecting metadata.

On transport loss, malformed sensitive response, terminal loss, or
`SECRET_RESULT_UNAVAILABLE`, the CLI returns **3**, never success. It only attempts a
safe metadata GET—**not another issuance, not a new key**. An `active` token in that
metadata does not mean this terminal received its URL. Retain the original request
key, inspect current state, and explicitly authorize a new-key rotation if a new URL
is needed. That next successful rotation revokes the previously issued URL. Reusing
the same issuance key cannot retrieve raw secret bytes or mint another token.

**Subscription URL revoke/rotate/expiry only stops future subscription downloads.**
Previously downloaded node credentials and existing VPN sessions remain valid under
the separate node-user policy. Revoking node access needs a real config draft/plan/
apply; retiring an unused vault record is neither user revocation nor session eviction.
This CLI does not claim node rotation acceptance from merely creating a UUID record.

No services, host network settings, certificates or signing identity are provisioned
by these commands. On **2026-10-30 13:28:09 UTC**, the separate isolated real daemon
CLI+PTY journey passed: 21 real CLI invocations, 5 real PTYs, 3 actual Rust codec
checks, 3 real forwarding checks and one old-node credential rejection. It covered
URL rotation/revoke while cached credentials still forward, new-node apply with
old-auth rejection, stale-source HTTP 412 followed by explicit republish, and a
test-only post-success-response discard yielding exit 3/metadata-only recovery
without automatic reissuance. All 27 exact owned process identities ended; 15
private files and 21 CLI memory captures passed secret scans. No raw URL/credential
was persisted in evidence. The final auth schedule respected the real server
limit without resetting/changing it; earlier failed attempts remain recorded.

Production CLI consumer suite: **89 tests passed** (52 existing + 37 added).
The separate private harness additionally has 8 fake-clock pacing tests (private
total 97), not part of the six-file production merge or its 89-test count.
Detailed scope, immutable daemon/worker/codec/source hashes, three retained failed
attempts and final passing receipt are in the candidate's `CLI_E2E_VALIDATION.md`
and `evidence/live-publications-paced.json`. These tests do not establish public
HTTPS deployment, installer/bundle-v2 acceptance, wall-clock HTTP expiry, mobile
subscription reachability, all 21 protocol presets or complete product acceptance.
