// SPDX-License-Identifier: GPL-3.0-or-later
package org.vp.product.singbox

fun main() {
    val network = checkedUnderlyingNetwork("wlan0", 4, true, true, false, false)
    check(network == UnderlyingNetwork("wlan0", 4, false, false))
    check(checkedUnderlyingNetwork("tun0", 5, false, true, false, false) == null)
    check(checkedUnderlyingNetwork("wlan0", 4, true, false, false, false) == null)
    check(checkedUnderlyingNetwork("", 4, true, true, false, false) == null)
    check(checkedUnderlyingNetwork("wlan0", 0, true, true, false, false) == null)
    check(checkedUnderlyingNetwork("bad\nname", 4, true, true, false, false) == null)
    println("UNDERLYING_NETWORK_POLICY_CHECKS_PASS")
}
