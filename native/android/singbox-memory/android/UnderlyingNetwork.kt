// SPDX-License-Identifier: GPL-3.0-or-later
package org.vp.product.singbox

/** Minimal, non-sensitive interface observation. No Wi-Fi name or IP list. */
data class UnderlyingNetwork(val name: String, val index: Int, val metered: Boolean, val constrained: Boolean)

fun checkedUnderlyingNetwork(name: String?, index: Int, notVpn: Boolean, internet: Boolean,
                             metered: Boolean, constrained: Boolean): UnderlyingNetwork? {
    if (name.isNullOrBlank() || name.length > 128 || name.any { it.isISOControl() } || index <= 0 || !notVpn || !internet) return null
    return UnderlyingNetwork(name, index, metered, constrained)
}
