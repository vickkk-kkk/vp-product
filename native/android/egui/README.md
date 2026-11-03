# Android egui host bridge: work in progress

These sources adapt the existing `vp_runtime_android` service and vp_core JNI
transport for an egui host, without importing Flutter. `HostState.kt` replaces
the Flutter event-channel state projection; `EguiVpnBridge.kt` exposes explicit
permission preparation, an explicit consent-only Activity, preflight, one-shot
in-process start, stop, and snapshot entry points. Start acceptance means only that a service request was queued.
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
vp_core adapter library. This module does **not** connect the consent Activity to the UI, map imported
profiles into the typed payload, or implement six engines. None of those missing
steps should be inferred from a successful Kotlin compilation.

Source compilation against Android API 35 passed using Kotlin 2.0.21 and 2.2.20/JVM 17;
the JNI host separately compiled to AArch64 with seven expected JNI entry
symbols. Isolated HostState checks cover unavailable/starting state, identity,
stale observations and invalid schema. The Android process, permission flow,
network forwarding, DNS, IPv6 and lifecycle remain untested for this bridge.
The Gradle module and APK manifest merge have not yet been built.
