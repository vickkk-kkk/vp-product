// SPDX-License-Identifier: GPL-3.0-or-later
package org.vp.product.singbox

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.net.NetworkInterface

/** The Network identity and epoch must travel together; interface names can be reused. */
data class SelectedNetwork(val network: Network, val generation: Long, val description: UnderlyingNetwork)

/** Reports only a system-selected non-VPN network. No arbitrary fallback. */
class AndroidNetworkMonitor(context: Context, private val observer: (SelectedNetwork?) -> Unit,
                            private val onFatal: () -> Unit) {
    private val manager = context.applicationContext.getSystemService(ConnectivityManager::class.java)
    private val handler = Handler(Looper.getMainLooper())
    private val lock = Any()
    private enum class Phase { NEW, ACTIVE, CLOSING, CLOSED, UNCERTAIN }
    private var phase = Phase.NEW
    private var selected: Network? = null
    private var generation = 0L
    private var current: SelectedNetwork? = null
    private var healthy = true
    private val request = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()

    private fun failLocked() {
        current = null
        if (!healthy) return
        healthy = false
        try { onFatal() } catch (_: Exception) { }
    }
    private fun advanceLocked(): Boolean {
        if (generation == Long.MAX_VALUE) { selected = null; emitLocked(null); failLocked(); return false }
        generation++
        return true
    }
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            synchronized(lock) {
                if (phase != Phase.ACTIVE || !healthy) return
                if (selected != network) {
                    if (!advanceLocked()) return
                    selected = network
                    emitLocked(null)
                    if (!healthy) return
                }
            }
            refresh(network, null, null)
        }
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = refresh(network, caps, null)
        override fun onLinkPropertiesChanged(network: Network, links: LinkProperties) = refresh(network, null, links)
        override fun onLost(network: Network) {
            synchronized(lock) {
                if (phase == Phase.ACTIVE && selected == network) {
                    selected = null; advanceLocked(); emitLocked(null)
                }
            }
        }
        override fun onUnavailable() {
            synchronized(lock) {
                if (phase == Phase.ACTIVE) { selected = null; advanceLocked(); emitLocked(null) }
            }
        }
    }

    /** API 28–30 requires CHANGE_NETWORK_STATE. Registration failure is final. */
    fun start(): Boolean = synchronized(lock) {
        if (phase != Phase.NEW) return false
        if (Build.VERSION.SDK_INT < 26) { phase = Phase.UNCERTAIN; failLocked(); return false }
        phase = Phase.ACTIVE
        try {
            when {
                Build.VERSION.SDK_INT >= 31 -> manager.registerBestMatchingNetworkCallback(request, callback, handler)
                Build.VERSION.SDK_INT >= 28 -> manager.requestNetwork(request, callback, handler)
                else -> manager.registerDefaultNetworkCallback(callback, handler)
            }
            phase == Phase.ACTIVE && healthy
        } catch (_: Exception) {
            selected = null; emitLocked(null)
            try { manager.unregisterNetworkCallback(callback) } catch (_: Exception) { }
            phase = Phase.UNCERTAIN; failLocked(); false
        }
    }
    fun isHealthy(): Boolean = synchronized(lock) { phase == Phase.ACTIVE && healthy }
    fun current(): SelectedNetwork? = synchronized(lock) { if (phase == Phase.ACTIVE && healthy) current else null }

    /** Revokes the observation first. A failed notification or unregister is uncertain. */
    fun close(): Boolean = synchronized(lock) {
        when (phase) {
            Phase.NEW -> { phase = Phase.CLOSED; true }
            Phase.CLOSED -> true
            Phase.UNCERTAIN, Phase.CLOSING -> false
            Phase.ACTIVE -> {
                phase = Phase.CLOSING
                selected = null
                emitLocked(null)
                val notified = healthy
                val unregistered = try { manager.unregisterNetworkCallback(callback); true } catch (_: Exception) { false }
                if (notified && unregistered) { phase = Phase.CLOSED; true }
                else { phase = Phase.UNCERTAIN; failLocked(); false }
            }
        }
    }
    private fun refresh(network: Network, providedCaps: NetworkCapabilities?, providedLinks: LinkProperties?) {
        val epoch = synchronized(lock) {
            if (phase != Phase.ACTIVE || !healthy || selected != network) return
            generation
        }
        val observation = try {
            val caps = providedCaps ?: manager.getNetworkCapabilities(network)
            val links = providedLinks ?: manager.getLinkProperties(network)
            val name = links?.interfaceName
            val index = if (name.isNullOrBlank()) -1 else NetworkInterface.getByName(name)?.index ?: -1
            checkedUnderlyingNetwork(name, index,
                caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true,
                caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true,
                caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) != true,
                if (Build.VERSION.SDK_INT >= 28) caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED) != true else true)
        } catch (_: Exception) { null }
        synchronized(lock) {
            if (phase == Phase.ACTIVE && healthy && selected == network && generation == epoch)
                emitLocked(observation?.let { SelectedNetwork(network, epoch, it) })
        }
    }
    // Callbacks execute under lock and must be bounded/non-blocking. onFatal
    // schedules engine shutdown; neither this callback nor unregister proves it.
    private fun emitLocked(value: SelectedNetwork?) {
        current = value
        try { observer(value) } catch (_: Exception) { failLocked() }
    }
}
