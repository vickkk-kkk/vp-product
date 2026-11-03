package org.vp.product.runtime

/** JVM-only fail-closed checks; no Android consent or runtime is exercised. */
fun main() {
    check(!EguiVpnBridge.preflight(""))
    check(!EguiVpnBridge.preflight("{}")) // no loaded native adapter
    check(!EguiVpnBridge.preflight("x".repeat(1048577)))
    println("BRIDGE_PREFLIGHT_FAIL_CLOSED_PASS")
}
