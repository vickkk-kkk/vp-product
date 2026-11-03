# sing-box in-memory start experiment

This is an **unintegrated experiment**, not a working Android engine. It pins
sing-box v1.14.4 and exposes a small serialized lifecycle. With build tag
`singbox`, the private `bindUnverified` calls the exported `CommandServer.StartedService` method
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
discards an instance-close error, so binding requires a separate `confirmClosed`
callback. An unconfirmed stop blocks another start. The Android UI does not bind
this experiment and still reports sing-box unavailable.
The confirmation callback must be side-effect-free and must return true only
with fresh, exact evidence that the owned engine and TUN are absent. It must be
thread-safe because interruption and final cleanup run on different goroutines.

Binding requires an initially confirmed stopped engine/TUN, a config validator,
and exclusive ownership of the started-service instance. The package refuses a
second binding of that instance for the process lifetime; it cannot stop code outside this
package from using a retained server pointer. Stopping during startup requests
context cancellation and upstream interruption, then waits for startup and the
interrupt worker before another stop and independent confirmation. If the first
interrupt returns before the backend actually starts, the worker retries while
startup remains pending. An individual upstream stop can itself block on its
lifecycle lock, preventing further retries. Neither Go
context cancellation nor upstream interruption guarantees a hung start returns.
Because upstream discards its instance reference and ignores close errors, a
later stop might not recover leaked resources; an unconfirmed state requires
host-level recovery and must never be reported as stopped. The host also remains
responsible for eventual full CommandServer/recorder destruction.
The binding is deliberately private because nothing yet proves that the exact
platform guard was installed when that server was constructed.
Start and stop may block and must run on a dedicated control executor, not the
Android UI thread. A hung upstream operation can still require process-level
recovery; no such recovery mechanism is implemented here.

The validator must be pure, must reject unsupported routes, listeners, DNS,
storage and insecure TLS, and must not retain or log the supplied configuration.
The same immutable string that passed validation is sent to the starter. The
caller must not mutate its byte buffer while `Start` is making its private copy.
Neither a production validator nor Android platform implementation exists yet.
Cancellation while validation is running prevents the backend from starting,
but cannot interrupt a stuck validator; the host must supply a bounded one.

The `android/` directory adds a TUN-descriptor lease and a `VpnService.protect`
adapter. It keeps the original descriptor owned until an independent check says
the exact engine and any in-flight start are gone; a close exception is marked
uncertain and never blindly retried. Protection or descriptor failure is sticky
and invokes a nonblocking fatal callback so the host can schedule shutdown. The
host must serialize start, absence verification, and closure: returning a raw
borrowed FD alone cannot prevent a concurrent start/close race. Its callbacks
must be bounded and must not block the Android UI thread. These files do not create routes or
implement libbox's full PlatformInterface and are not wired into an APK. Kotlin
2.0.21 compilation against Android API 35 and JVM checks with fake descriptors,
including a protect/close overlap, passed. They do not test real OS descriptors.
The tagged Go `AndroidPlatform` also forwards protection, TUN and interface
monitor requests to a required host, fails closed on errors and exposes a sticky
health failure. The Android host implementation, continuous health supervision,
and proof that every outbound uses the hook are not implemented or tested.
The host must validate the requested TUN addresses, routes and DNS and keep the
borrowed descriptor alive; it must also stop the engine on any sticky platform
failure. DNS-cache invalidation is not implemented and marks the guard failed.

`AndroidNetworkMonitor` is an unintegrated Android source component that reports
only a system-selected non-VPN interface. It refuses to guess another interface
when the system reports none, discards stale callbacks after closure, and marks
registration/observer errors unhealthy. It carries the Android Network object and
a generation with each observation, and revokes the observation before unregister.
Fatal errors call a nonblocking host callback, which must schedule engine shutdown;
the callback and successful unregister do not prove shutdown. A host must require
both a healthy monitor and a non-null current network before starting; the monitor
itself does not start an engine. Socket binding to the selected Network is not
implemented, and INTERNET capability does not prove validated connectivity. On API 28–30 its network request needs CHANGE_NETWORK_STATE;
the included permission overlay is not merged into the app. Kotlin compilation
against Android 35 and pure observation-policy checks passed, but registration,
permission behavior, network switching and VPN interaction are not device-tested.

`go test` without tags tests only the local lifecycle with synthetic callbacks;
it does not compile sing-box or prove upstream behavior. Both the lifecycle and
tagged binding sources were typechecked with small local API stubs, not actual
dependencies, and formatted with Go 1.26.10. Tests were attempted but stopped at the temporary
disk-space safety floor; they have not passed here. Tagged compilation, actual
JNI/Android integration, traffic, DNS and leak tests remain outstanding.

The binding is offered under GPL-3.0-or-later, with the full license in COPYING.
UPSTREAM-LICENSE preserves sing-box's notice, including its naming restriction.
Distribution and integration obligations require review before release.
