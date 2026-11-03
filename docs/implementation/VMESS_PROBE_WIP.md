# VMess WebSocket/TLS work in progress

This development branch is **not a release**. VMess over WebSocket/TLS is an
optional fourth listener selected by `--vmess-port`. Its UUID is generated as a
separate typed credential and included only in the private client export. The
external lab client can test it when the export contains both VMess fields.
Existing three-listener operation remains the default.

Local evidence in the originating workspace:

- The public-profile compiler accepts VMess WebSocket/TLS and continues to
  reject the unencrypted VMess TCP fixture. The material-admission test checks
  plan binding, typed UUID, malformed values and wrong credential kinds.
- Local worker and HTTPS endpoint tests exercised four protocol combinations,
  including VMess WebSocket/TLS, with valid response, wrong status and
  untrusted CA checks. Debug-only loopback probes exercised valid and invalid
  credentials. This is not independent interoperability evidence.
- A four-protocol deployment fixture confirmed that an occupied fourth port
  is refused without affecting the existing listener or creating state. A
  separate unassigned-address fixture reached the four-protocol plan, failed
  activation, and rolled back without printing credentials.
- The deployment and external client unit tests cover optional VMess fields,
  port conflicts, paired credential fields and backward-compatible omission.

No VPS or public network test has been performed for VMess. Do not claim VMess
is available in the published `v0.1.0-lab.1` asset; that release remains limited
to its original three protocol combinations. Before release, test the built
package and actual VPS, review the failure and stop/recovery paths, verify
external clients and publish only with clear limitations.

## Committed journal finalization candidate

The foreground lab now asks the attached runtime to finalize a strictly paired
committed operation before exporting client material. This moves the journal
from `candidate_started` to `idle` while retaining the historical owned-process
record. The record is not a live-status claim; process absence must be observed
separately. Uncommitted, mismatched, already-finalized or poisoned states are
rejected. A failed or uncertain publication remains for inspection; no automatic
retry or restart is performed. The guard has synthetic-state tests, but this
change has **not** yet been validated in a successful VPS deployment. In
particular, it does not claim to implement automatic restart or a durable
shutdown receipt.
