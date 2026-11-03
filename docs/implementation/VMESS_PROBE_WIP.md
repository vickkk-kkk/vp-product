# VMess probe work in progress

This branch is **not a release**. It adds experimental VMess over WebSocket and
TLS to the public-profile compiler and to the internal probe client. It does
not yet add a VMess listener to `vp-public-lab`, create/export its credentials,
or add VMess to the packaged external validation client. No VPS or public
network test was performed.

Local evidence recorded in the originating workspace:

- Public-profile compiler test accepts VMess WebSocket/TLS while continuing to
  reject the existing unencrypted VMess TCP fixture.
- A real local worker plus local HTTPS endpoint exercised the three original
  protocol combinations and VMess WebSocket/TLS. It checked a valid response,
  unexpected status and untrusted certificate. The test name still says three,
  but its loop contains four cases.
- A debug-only loopback fixture exercised valid and invalid credential probes
  for those four cases. This fixture is forbidden in release builds and is not
  external or independent interoperability evidence.

Continue by integrating VMess into the deployment entry, credential generation
and private export, and the external client. Preserve existing three-protocol
behavior and test wrong-auth handling, rollback, TLS identity, actual forwarding
and credential redaction. Review resource limits and the fixed public egress
policy before widening them. Do not claim VMess is available in the published
`v0.1.0-lab.1` asset: that release remains three-protocol only.
