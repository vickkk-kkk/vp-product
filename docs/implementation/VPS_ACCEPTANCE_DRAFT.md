# VPS acceptance instructions: draft only

This document is not an acceptance-ready prompt. There is no published release
version, download URL, or validated artifact checksum yet. Fill these only from
a real, reviewed GitHub Release. Do not turn the local development archive into
a release by assigning it a version string.

## Acceptance scope

Use the released VP deployment entry point and the precompiled binaries from
that release. Do not clone a repository, compile source, manually write a
replacement server configuration, substitute another core, or call an
isolated protocol-component test a product test. Check the release checksum
through a separately trusted release page, then run its documented host
preflight. Stop and report if architecture, libc, worker execution, or integrity
checks fail. Check locally assigned IPv4, available ports, existing services,
and host constraints without changing them.

Ask the owner for explicit approval at the time of creating test credentials
and listeners. Explain the chosen HTTPS probe and that the endpoint sees the
VPS source IP. Do not interpret a command flag as the owner's approval. Get a
specific approval before any separate security, firewall, routing or service
change. SSH credentials are supplied independently through an appropriate
secure channel; never record them in shell commands, scripts, logs or reports.

Run the published deployment command using a new private empty session
folder and three unused TCP ports. The current candidate supports these three
listener combinations only: Trojan over TLS/TCP, VLESS over WebSocket and TLS,
and Shadowsocks AES-128-GCM over TCP. Its forwarding scope is only explicitly
allowed public IPv4:port TCP destinations, not general internet access, DNS,
UDP or IPv6. The test CA is private and short-lived. The process runs in the
foreground and does not currently support restart or upgrade. Do not claim
these unsupported functions passed.

Validate each listener with a genuine compatible client and the product's
own created credentials. Positive authentication and an independent HTTPS
request through each tunnel must both be measured. Where safely possible,
verify wrong credentials are rejected and verify forbidden targets are blocked.
Distinguish a local process check from a request entering over the public VPS
address. Public reachability requires an independent network vantage point; if
none is available, report it as untested. Do not put credentials, client
configuration, CA private material, the vault key, or authentication tokens in
commands, transcripts or reports. Obtain separate approval for any necessary
credential sharing or external action.

Record the exact release and artifact hashes, host OS/kernel/libc and CPU,
test time, listener/protocol, client and version, vantage point, target and
port, sanitized result, and any failure stage. Distinguish passed, failed,
blocked and not run. Preserve isolated state on an uncertain result; do not
blindly retry, delete state, stop unrelated processes, or change the existing
sing-box service. At the end, stop only the test session using its supported
method and verify its listeners have closed. Report whether the original service
remained unchanged. Obtain appropriate approval before deleting test state or
revoking access and verify the requested cleanup.
