# Durable Linux server secret store

`vp-product-secrets::DurableSecretStore` implements the real runtime executor's
`ImmutableSecretStore`. It persists AES-256-GCM encrypted immutable credential
records, not a map or a plaintext password file. It deliberately does not create
keys, directories, services, deployment configuration or an automatic fallback.
No test credential/key is suitable for deployment.

## Composition and provisioning contract

1. An authorized installer/operator provisions an **existing empty** dedicated
   0700 directory owned by the effective service UID, under trusted ancestors.
   The directory must be on a local filesystem supporting Linux `flock`,
   `renameat2(RENAME_NOREPLACE)`, file fsync and directory fsync. Provisioning must
   durably create the root itself. This crate does not repair ownership/modes.
2. Supply an externally provisioned, cryptographically random, dedicated 32-byte
   master key as
   `MasterKey::new(SecretBytes)`. Composition can obtain those bytes from an
   explicitly inherited system-credential FD or an in-memory secret service;
   this crate never finds keys in environment variables, argv, the vault,
   defaults, plaintext files or a generated persistent fallback. A password is
   not a master key; no password KDF/provisioning UI is provided.
3. Call `initialize(root, Namespace, MasterKey, Limits, deadline)` **once**.
   Normal startup uses `open(root, Namespace, MasterKey, deadline)`. An open
   failure must never trigger initialization. Namespace and policy are frozen
   by the authenticated manifest. Changing them requires an explicit migration.
4. `put(&SecretRef, SecretKind, version, SecretBytes, deadline)` consumes the
   secret and reserves the exact reference forever. The nonzero `version` is
   authenticated immutable metadata, not a mutable `latest` alias. Ref strings
   are opaque domain IDs, never paths. Use a new ref for each rotation.
5. Share `Arc<DurableSecretStore>` with `ManagedExecutor::open`. The runtime port
   validates and resolves only `SecretKind::Credential`; private keys,
   subscription URLs and management tokens cannot be substituted. Other callers
   use `get_exact` to require a kind/version; `get` returns authenticated metadata
   and `SecretBytes`, never a serializable credential DTO.
6. `retire(ref, kind, version, deadline)` writes a permanent authenticated
   tombstone. Retire **only after control commits rotation and no recovery,
   rollback or retired-authentication rejection probe still needs the bytes**.
   The vault cannot infer operation/revision reachability. Retirement is an
   irreversible explicit action, not an automatic consequence of creating a
   replacement. Repeated retirement of the exact metadata is idempotent.

**Retirement is not secure deletion.** Original encrypted records and tombstones
remain and count against the lifetime quota. `put` never overwrites an existing
ref, even with identical bytes, a higher version or after retirement. There is
no purge, unretire, mutable alias, automatic GC or stale-credential fallback.
Unknown schemas fail explicitly; master-key rotation, cross-release migration,
backup/restore consistency and controller-authorized GC are separate gates,
not silently performed in place.

## Storage and cryptography

- Pinned [RustCrypto aes-gcm 0.10.3](https://docs.rs/aes-gcm/0.10.3/aes_gcm/)
  supplies AES-256-GCM with a 128-bit authentication tag. This is a composition
  over the vetted AEAD, not a new cryptographic primitive. Its documented CPU
  constant-time multiplication requirements still apply; platform qualification
  remains necessary.
- Every encryption obtains a new 96-bit nonce from OS `getrandom`; failures are
  errors. A random 128-bit public vault identity separates independently
  initialized roots. The master key must be dedicated to this vault; do not
  initialize multiple vaults with the same production key. Random-nonce collision
  risk is nonzero; the hard lifetime quota is at most 1,000,000 committed refs,
  each with at most one tombstone. Defaults are 65,536 refs/128 MiB. Failed
  publication attempts also consume random nonces, without reusing them.
- AAD domain-separates the format and binds the explicit namespace, vault ID,
  schema, record/tombstone class, kind, exact SecretRef, credential version and
  nonce. The fixed-width binary header is fully authenticated. No unknown fields
  can be silently ignored. Records are named by SHA-256 of the reference, and
  the authenticated header reference must match that filename. Hashes are not
  used to conceal low-entropy identifiers. Non-secret refs/metadata remain visible
  in headers; encrypted credentials do not.
- The authenticated manifest persists limits and proves the supplied key even
  for an empty vault. Open verifies **every** committed record and tombstone,
  including class/ref/kind/version pairing. Wrong keys, altered ciphertext,
  foreign files, partial committed files and unknown versions fail closed.
- `MasterKey`, source `SecretBytes`, encryption/decryption buffers and returned
  secrets use best-effort zeroization. Temporary plaintext is preallocated before
  copying; AES/GHASH/POLYVAL zeroize features are enabled for expanded keys and
  intermediate key buffers. There is no plaintext cache, Debug/Serialize of
  vault contents, raw OS error propagation or secret-bearing logging.

## Filesystem, durability and bounds

All product code is safe Rust (`forbid(unsafe_code)`). Safe rustix APIs walk the
absolute root from `/` with `openat(O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` at **every**
component. Dot/dot-dot, relative roots and symlink ancestors are refused. Trusted
ancestors must be root/current-UID owned and not group/world writable; a root-owned
sticky directory (such as standard `/tmp` for temporary tests) is permitted.
The final root must be service-owned exactly 0700. Owner/mode/link/type checks use
opened descriptor metadata, not a check-then-open path. ACLs must not grant access
outside these mode constraints. All subsequent operations remain rooted at that
same directory descriptor even if a containing path is renamed or replaced.

A nonblocking lifetime directory `flock` excludes other cooperating processes;
nonblocking mutex acquisition serializes threads without unbounded waiting. All
regular files must be owner-matching 0600, non-symlinks and single-link. Reads use
`O_NOFOLLOW|O_NONBLOCK` and reject directories/devices/FIFOs/hardlinks. The crate
neither follows attacker paths nor performs chmod/chown repairs. Compromised
same-UID writers/root and hostile mounts are outside this boundary.

Publication is `create_new(.pending)` → bounded ciphertext write → fsync(file) →
atomic no-replace rename → fsync(root). It cannot replace an existing record.
The store is poisoned after any uncertain write/sync/deadline outcome and must be
closed/reopened. A post-publication error is **not proof the ref is unused**.
Authenticated reopen keeps committed data, discards only the bounded private
staging file, and always fsyncs the directory—even if no staging file remains—to
complete a prior rename-before-directory-fsync crash window. A crash during very first initialization before manifest publication
requires explicit operator recovery of that uninitialized root, never a new key.

The policy bounds secret bytes (at most 64 KiB), immutable ref count, directory
entry count, per-file reads, total encoded bytes and free-disk reserve. Each put
reserves future tombstone bytes so quota exhaustion does not itself prevent
retirement. Free-space checks are only preflight, not disk reservations; failures
still poison uncertain publication. Limits count encoded bytes, not filesystem
block/metadata overhead; free-disk headroom is checked separately. No unbounded
recursive scan, password parser, decompressor or imported path is used.

Deadlines are checked before/after bounded IO/crypto and between records; locks
are nonblocking. A hung filesystem syscall, kernel or storage device cannot be
preempted by this synchronous trait. This is not a hard-real-time IO guarantee;
use a healthy bounded local filesystem and supervised service process.

## What this protects, and what it does not

Encryption protects offline **ciphertext-only** copies when the separately
managed master key is unavailable. It does not protect against root, service-UID
or process-memory compromise, key plus ciphertext theft, swap/core dumps,
allocator/compiler/kernel copies, aborts, tampering that deletes data, or malicious
rollback of an entire previously valid vault/tombstone set. Deleting a single
tombstone while retaining its old ciphertext can likewise revive that credential
after reopen; filesystem writers must not delete or selectively restore these
files. AEAD is not a trusted monotonic counter or anti-rollback hardware. Recovery/backups must include
consistent control records plus ciphertext/tombstones, with a separately authorized
key-retention policy. Restoring old snapshots can restore old credentials unless
an external monotonic/revocation authority prevents it.

This Linux server adapter is not Android Keystore, Apple Keychain or Windows
DPAPI support, an installer, a provisioned service, a full security audit or a
complete-product acceptance result. No production key or real credential was
created during implementation. Focused evidence is in `VALIDATION.md` after
executed checks; source/tests alone are not evidence of a pass. Fault-injection
tests model process-level publication failures and authenticated reopen, not an
actual power-cut, failed-device/fsync or filesystem durability certification.
