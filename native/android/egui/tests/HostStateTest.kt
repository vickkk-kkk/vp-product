package org.vp.product.runtime

fun main() {
    check(HostState.snapshot()["phase"] == "unavailable")
    HostState.set("starting", "not connected", newGeneration = true)
    check(HostState.snapshot()["phase"] == "starting")
    val identity = HostState.currentIdentity()
    check(HostState.matchesIdentity(identity.first, identity.second))
    check(!HostState.matchesIdentity("other", identity.second))
    fun snapshot(sequence: Long) = mapOf<String, Any?>("schemaVersion" to 1,
        "instanceId" to "core", "generation" to 3L, "sequence" to sequence, "phase" to "verifying")
    HostState.applyNative(snapshot(10))
    HostState.applyNative(snapshot(9))
    check((HostState.snapshot()["nativeSnapshot"] as Map<*, *>)["sequence"] == 10L)
    check(runCatching { HostState.applyNative(mapOf("schemaVersion" to 2)) }.isFailure)
    println("EGUI_HOST_STATE_CHECKS_PASS")
}
