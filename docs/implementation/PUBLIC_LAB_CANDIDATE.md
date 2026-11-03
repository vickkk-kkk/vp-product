# VP public lab candidate

**Status: development candidate, not a GitHub Release and not VPS-validated.**
The foreground lab entry point is intended to make a bounded first-install test
possible without Git or a Rust toolchain. It does not yet provide automatic
restart, upgrades, a system service, or a general-purpose VPN. Do not describe a
successful local unit test as a successful VPS deployment.

## What this experiment covers

- One fresh, isolated foreground instance with Trojan TLS/TCP, VLESS WebSocket
  over TLS, and Shadowsocks AES-128-GCM/TCP.
- Exact, explicitly listed public IPv4 and port destinations only. Domains,
  IPv6, UDP and arbitrary public destinations are not supported by this profile.
- A short-lived test CA and leaf certificate, generated for `vp-lab.invalid`.
  Clients must trust the generated test CA and use that TLS server name. The
  certificate expires after two days; it is not a public CA certificate.
- A process-local authentication challenge plus a separate HTTPS egress probe.
  Cloudflare is the default; alternatively the operator can explicitly supply
  a numeric HTTPS target, server name, request path, expected status and DER CA.

A public-IP bind, full external connectivity, independent client compatibility,
VPS OS support and lifecycle behavior must still be tested on the actual host.
The `local-probe-test` feature is a debug-only fixture, forbidden in release
profiles, and must never be included in a deliverable.

## Safety and consent

The lab creates three credentials that permit access to the test listeners. The
operator must obtain the user's explicit action-time approval before generating
those credentials. The program also requires an explicit flag acknowledging
that the chosen HTTPS probe receives a request and can see the server's source
IP. Do not infer consent from the existence of a command-line flag.

The lab creates a vault master key and, after a successful apply, a client
credential export. Both are stored in mode 0600 files inside a mode 0700 output
directory. They are sensitive. Never put their contents in a script, command
line, chat, terminal transcript, support report, GitHub issue or Release. The
SSH login secret is unrelated and must be provided separately through an
appropriate secure channel. The program does not stop or modify an existing
proxy service, firewall, routes, or systemd units.

Use an empty private 0700 session directory. The lab creates its own control,
vault, runtime and output children only after it has verified the worker and
reserved the requested TCP ports. Existing or overlapping state is refused.
Errors retain any newly created lab state for inspection; do not blindly delete,
retry, or overwrite it. Port reservation is a check, not a guarantee against a
race; an activation failure is treated as a failure and rolled back when safe.

## Host check and run shape

Use the exact binary and worker hashes provided by the eventual reviewed bundle.
First invoke `vp-public-lab --check-host --worker ABSOLUTE_PATH --worker-sha256
SHA256`. It briefly starts and reaps the sealed worker without configuration,
listeners, or secret material. It does not prove public connectivity or full
platform compatibility. A bundle must also check architecture, libc, kernel
and all file hashes before executing its binaries.

After consent, the foreground command takes `--session-root`, `--worker`,
`--worker-sha256`, `--bind-ip`, three explicit TCP ports, any additional
`--target IPV4:PORT` destinations, `--confirm-test-access`, and either
`--confirm-cloudflare-probe` or the complete custom probe parameters and
`--confirm-custom-probe`. Run `vp-public-lab --help` for the full argument list.
The bind address must be assigned on the VPS itself; an external NAT address
that is not locally assigned cannot be bound by this version.

On success, private `output/client-secrets.json` contains the test CA, SNI,
ports, WebSocket path and ALPN, credentials, certificate expiry and the exact
allowed targets. `output/vault-master.key` is the separate vault key. Read them
only through private file access when configuring an authorized test client.
The local agent's report should contain protocol, pass/fail, timestamps, sanitized
error codes, target reachability and cleanup status, never either file's content.

The foreground process owns the worker. SIGINT or SIGTERM stops the foreground
session; reopening the saved state and automatic restart are **not implemented**.
An abnormal outcome requires preserving the state and reporting the exact
failure rather than guessing which process or file to remove. Existing VPS
services should remain untouched unless the user separately authorizes a
specific action.

## Before any distribution

The actual archive, executable hashes, compatibility floor, third-party notices,
VP-Core license/copyright provenance, GitHub Release permissions, and source
identity must be verified. The fixed VP-Core source declares MIT, but the exact
source snapshot did not contain a complete LICENSE file; do not invent a
copyright line. No version or download address is assigned until an actual
reviewed GitHub Release exists.

The current target-specific dependency-tree candidate has 287 package
identities, including 262 registry identities and 25 local identities. This is
not an artifact-exact SBOM. Registry notice candidates have been collected, but
`ring` 0.16.20 uses a composite license file rather than a Cargo SPDX license
expression; nested and native code still require review. VP-Core's missing
complete upstream license and copyright notice remain an open distribution gate.
