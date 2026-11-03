# Single-IP server probe experiment

Status: experimental source and local tests only. This is not a Release, VPS
acceptance, production readiness claim, or a general-purpose VPN. The current
public experiment permits only explicitly listed public IPv4 TCP destinations;
it does not support domain targets, IPv6, or UDP.

The health design separates two checks:

1. Authentication and inbound TLS use a process-local challenge sink. Its
   reserved address is intercepted without a network socket. The worker keeps
   a bounded ledger of SHA-256 hashes of random challenges. The parent requires
   exact worker identity, a non-saturated ledger, a correct-credential control
   before and after the incorrect-credential attempt, and a bounded observation
   window. Only this in-process delivery is observed; it does not prove that
   traffic can leave the VPS.
2. Forwarding uses HTTPS through the tunnel to an explicitly approved numeric
   destination. The client validates the target's TLS name and trust roots and
   checks a bounded HTTP status response. It does not log the response body.
   This checks that target only, not general Internet availability or an
   independent third-party client implementation.

An optional preset is Cloudflare's `1.1.1.1:443`, TLS name
`one.one.one.one`, path `/cdn-cgi/trace`, expected HTTP 200, with embedded
WebPKI trust roots. Enabling it sends a request to Cloudflare, which sees the
VPS's source IP. Operators may instead choose a different approved HTTPS
endpoint and explicit trust. The endpoint must be in the configured egress
allowlist. The preset is not a claim that the VPS can reach it. Cloudflare
explains its [trace endpoint](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/)
and [1.1.1.1 HTTPS service](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/).

The virtual sink has a 64-entry limit and retains observations for 60 seconds.
Overflow is reported and causes verification to fail closed. Each verification
must complete within a shorter bounded window; no token or credential is
persisted as an observation. The sink is available only with the experimental
public process floor; real network connections to its reserved address remain
blocked, as does UDP in this profile.

Local tests cover the sink, its overflow and network floor, HTTPS over Trojan,
VLESS and Shadowsocks to an independent local TLS server, and authentication
checks for all three through a dedicated loopback-only debug fixture. The
`local-probe-test` feature is forbidden in non-debug builds and must not be
included in a Release. No VPS, public HTTPS target, external client,
installation, restart recovery, or end-to-end product acceptance has been
verified by those tests. The restart checkpoint and health code are not yet
connected to a production management command.

Before distribution, generate an artifact-exact dependency and license bundle,
including the applicable CDLA-Permissive-2.0 notice for embedded WebPKI roots,
and review the product's own license and upstream provenance. Verify the
actual platform's kernel, libc, executable behavior, and complete lifecycle;
source-level glibc inspection is only an early compatibility check.
