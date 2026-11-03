# Private fresh runtime bundle contract (private development implementation)

This is a separate schema-2/profile `fresh-runtime-v1` path. Schema-1 tooling is
unchanged and must reject this bundle. This is not the generic migration/rollback
contract in BUNDLE_V2_CONTRACT.md and does not enable production installation.

Exact top-level keys: `schemaVersion`, `profile`, `releaseId`, `productVersion`,
`engine`, `architecture`, `files`, `coreLockSha256`, `controlState`,
`runtimeJournalPayload`, `vaultBindingKind`, `compatibilityDescriptor`, `maintenance`,
`hostRequirements`. Host requirements explicitly require Linux >=6.3, sealed
executables and no pathname-execution fallback. Read-only host preflight runs
before packaging descriptor execution or installation/material writes.

The descriptor is obtained by executing the operator-pinned daemon through a
sealed ELF with `describe --worker ABS --worker-sha256 SHA`; this command neither
creates state nor starts service. It is not supplied as arbitrary caller JSON.
DescriptorVersion 2 is mandatory. Exact capability fields are
`publicationDelivery:true`, `publicationNetworkPolicy:explicit_same_origin_loopback`,
`explicitWebRoot:true`, `managementApiVersion:1`. Older descriptorVersion 1 is
rejected, never silently upgraded. Web bytes are bound by bundle file inventory,
not by Rust genesis; all are rehashed before launch, which supplies explicit
`--web-root` and same-origin `--publication-base`.
The exact descriptor metadata binds daemon and worker hashes, core integration
commit and ABI, SQL layout, private payload, binding kind and runtime journal.
The digest uses SHA256(domain `vp.fresh-artifact-set.v1`, NUL, canonical metadata).
All redundant manifest compatibility claims must equal that descriptor.

`controlState` contains `sqlLayout` and `payload`, each with `readVersions` and
`writeVersion`. Supported values are SQL [1]/1 and payload [3]/3, not a guessed
range. `runtimeJournalPayload` is 2; `vaultBindingKind` is 5.
`maintenance` is exactly `{ "action":"vault-init-bound", "protocolVersion":1,
"controlInspectionSupported":false }`: maintenance can create the bound vault
manifest but has not advertised payload-3 inspection or migration compatibility.
Its exact ELF is separately pinned by its files record.

Required files are `bin/vp-product-fresh-runtime`, `bin/vp-product-maintenance`,
`bin/vp-core-managed-worker`, `core-lock.json`,
`contracts/capabilities/presets.json`, and `web/index.html`. Other `web/` assets
are allowed. Every executable must be ELF for the advertised local architecture;
all members use the schema-1 secure snapshot/archive reader rules.

Lifecycle metadata lives separately from bootstrap material roots, whose known
inventory remains unchanged. Preparation and bound vault initialization retain
existing explicit confirmation hashes and durable consumed intents. A new
activation uses its own explicit confirmation and intent and starts only the
exact descriptor-bound artifact set. Restart is paired, not fresh/adoption.
An owned foreground supervisor stops only children it created, never PID-file
claims. The action spelled `uninstall` only disables this local profile and retains ALL
files, including executable/Web release files, materials and receipts. It is not an artifact-removing uninstall; separate explicit `remove-program-files`
now removes only verified manifest-owned programs, retaining data and provenance.
The `uninstall` deactivation receipt remains `profile-disabled-all-files-retained.json`;
the separate removal action uses `program-removal-intent.json` and
`program-removal-receipt.json`.
No generic restore, automatic retry, admin-only reservation adoption, key
regeneration, binary update, code rollback, systemd registration or host changes.

Verified in isolated synthetic loopback gates: strict schema validation, sealed
descriptor extraction, actual bundle-to-empty-credential preparation/init/start,
authenticated UUID API creation, normal subscription delivery, actual VLESS
forwarding and wrong-credential refusal, paired restart, owned-process cleanup,
and profile deactivation retaining all files (not artifact-removing uninstall). Runtime05 exact artifact and real current admin Web
were used; see evidence/VALIDATION.md for exact hashes and limitations. Independent
backend QA/final review remain separate integration gates; this is not production
or all-protocol acceptance.

### Explicit private removal reader

`RemovalBundle` uses the same bounded archive/member/manifest admission as
`FreshBundle`, but checks ELF architecture against the declared release
architecture rather than the current host. It is read-only and cannot be used
for installation. This permits safe removal on a runtime-ineligible host without
executing artifacts. Archive-bound `deactivate` shares this read-only admission and all data-root locks,
adding only the disabled marker without requiring a runnable host.
`remove-program-files` retains the installed manifest and
original archive; the existing `uninstall` action still only disables the profile.
See `FRESH_LOCAL_USAGE.md` for one-shot intent and partial-failure semantics.
