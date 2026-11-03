# Android egui host bridge: work in progress

These sources adapt the existing `vp_runtime_android` service and vp_core JNI
transport for an egui host, without importing Flutter. `HostState.kt` replaces
the Flutter event-channel state projection; `EguiVpnBridge.kt` exposes explicit
permission preparation, an explicit consent-only Activity, preflight, one-shot
in-process start, stop, and snapshot entry points. Start acceptance means only that a service request was queued.
Consent requests and start both require the native adapter's validation of the
exact supplied payload; the JNI boundary rechecks it before TUN acquisition.
No credentials are put into Intents, and a TUN or service does not establish a
healthy connection. Payloads are JVM strings and are not securely erased.

Compile the three production files here alongside these existing sources, not the Flutter
`HostState.kt` or plugin: `VpVpnService.kt`, `NativeRuntime.kt`,
`NotificationPublication.kt`, and `RuntimeIdentity.kt`, all under
`flutter/packages/vp_runtime_android/android/src/main/kotlin/org/vp/product/runtime/`.
The optional Gradle library module stages these sources and merges
`AndroidManifest.xml`, declaring a non-exported consent Activity and the
permission-protected service. It is enabled only by the client build's explicit
`vpEguiRuntimeRoot` property. The host also needs the JNI host library and matching
vp_core adapter library. The experimental `egui-app` Rust entry now connects
the UI to this bridge and maps a selected strict URI into a typed payload. It
only attempts vp_core and does not implement six engines. None of this should be
inferred to be working from a successful Kotlin compilation.

`vp-product-import::mobile::encode_ephemeral` now produces an ABI-v2 request
from a selected strict import, explicit numeric bootstrap and proxied-user DNS,
and a caller-provided node identity. It carries credentials separately, uses a
non-vault sentinel only within the request, redacts Debug and zeroizes the Rust
JSON buffer on drop. It rejects obfuscation it cannot preserve; the adapter
must still validate all protocol and full-TUN capabilities. Never persist this
request or treat its sentinel as a real vault entry. Kotlin/JNI string copies
are not securely erasable. The import crate's 31 integration tests and one
compile-fail doc test pass; this is not JNI or VPN interoperability evidence.

Source compilation against Android API 35 passed using Kotlin 2.0.21 and 2.2.20/JVM 17;
the JNI host separately compiled to AArch64 with seven expected JNI entry
symbols. Isolated HostState checks cover unavailable/starting state, identity,
stale observations and invalid schema. The Android process, permission flow,
network forwarding, DNS, IPv6 and lifecycle remain untested for this bridge.
JVM checks also confirm empty, oversized, and missing-adapter inputs fail closed;
they do not exercise a real Android permission dialog or a loaded native core.

`native/android/egui-jni` provides the Rust-side JNI calls. It loads the bridge
class using the current Activity's class loader, borrows (never owns) the
Activity's JNI global reference, and bounds request sizes before JNI. Its unsafe
constructor requires the caller to keep the Activity/AndroidApp alive for the
entire bridge lifetime. A locked offline host compile and two input/pointer
tests pass; no JVM round-trip or Android target build has been performed.
The Gradle module and APK manifest merge have not yet been built.
The egui runtime entry's AndroidHost implementation also passed a host-side
typecheck and two tests with a stub AndroidApp; that does not test Android JNI.
The rendering UI passed source parsing and an isolated connection-method
typecheck with egui stubs. Neither is an Android compilation or device test.
