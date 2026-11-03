# sing-box in-memory start experiment

This is an **unintegrated experiment**, not a working Android engine. It pins
sing-box v1.14.4 and exposes a small serialized lifecycle. With build tag
`singbox`, `Bind` calls the exported `CommandServer.StartedService` method
directly, rather than `CommandServer.StartOrReloadService`, which writes a
configuration snapshot. The wrapper never starts the command server listener.

This only avoids that particular snapshot write. Upstream setup can still write
crash reports and platform metadata, and reports may copy an old snapshot if one
exists. Logs, paths, process lifetime and memory can expose secrets; Go strings
are not securely erasable. Never use an existing data directory or treat this
source as proof of no disk writes. The included module checksum was obtained from
the local module cache, not independently verified here, and the tagged build's
complete dependency lock has not yet been established.

The caller must supply an actual platform implementation that establishes a TUN,
protects every relevant TCP/UDP/DNS socket, handles Android network changes and
revocation, and independently confirms teardown. Upstream `CloseService`
discards an instance-close error, so `Bind` requires a separate `confirmClosed`
callback. An unconfirmed stop blocks another start. The Android UI does not bind
this experiment and still reports sing-box unavailable.

`go test` without tags tests only the local lifecycle with synthetic callbacks;
it does not compile sing-box or prove upstream behavior. Source was formatted
and parsed with Go 1.26.10. Tests were attempted but stopped at the temporary
disk-space safety floor; they have not passed here. Tagged compilation, actual
JNI/Android integration, traffic, DNS and leak tests remain outstanding.

The binding is offered under GPL-3.0-or-later, with the full license in COPYING.
UPSTREAM-LICENSE preserves sing-box's notice, including its naming restriction.
Distribution and integration obligations require review before release.
