// SPDX-License-Identifier: GPL-3.0-or-later
package org.vp.product.singbox

/** Owner of the original TUN descriptor. The engine borrows its integer FD;
 * the host must retain this owner until the engine has independently stopped. */
interface TunDescriptor {
    fun descriptor(): Int
    fun close()
}

fun interface SocketProtector { fun protect(fd: Int): Boolean }

/** This guard does not establish routes, a VPN, or sing-box itself. */
class TunLease(private val tun: TunDescriptor, private val protector: SocketProtector,
               private val onFatal: () -> Unit) {
    enum class State { ACTIVE, CLOSING, CLOSED, CLOSE_UNCERTAIN, RECONCILING }
    private var state = State.ACTIVE
    private var healthy = true

    @Synchronized fun state(): State = state
    @Synchronized fun isHealthy(): Boolean = state == State.ACTIVE && healthy
    private fun failLocked() {
        if (!healthy) return
        healthy = false
        try { onFatal() } catch (_: Exception) { }
    }
    /** The returned FD is borrowed, never transferred. The caller must keep
     * the lease alive until all engine use, including startup, has ceased. */
    @Synchronized fun borrowedFd(): Int? {
        if (state != State.ACTIVE || !healthy) return null
        val fd = try { tun.descriptor() } catch (_: Exception) { -1 }
        if (fd < 0) { failLocked(); return null }
        return if (state == State.ACTIVE && healthy) fd else null
    }
    /** Called before a sing-box outbound socket connects or sends. */
    @Synchronized fun protect(fd: Int): Boolean {
        if (state != State.ACTIVE || !healthy) return false
        val protected = if (fd < 0) false else try { protector.protect(fd) } catch (_: Exception) { false }
        if (!protected) failLocked()
        return protected && state == State.ACTIVE && healthy
    }
    /** Confirm exact engine absence before closing the original descriptor.
     * A close exception is uncertain and must never cause a blind retry. */
    @Synchronized fun closeAfterConfirmedStop(confirm: () -> Boolean): Boolean {
        if (state != State.ACTIVE) return state == State.CLOSED
        state = State.CLOSING
        val stopped = try { confirm() } catch (_: Exception) { false }
        if (!stopped) { state = State.ACTIVE; return false }
        return try { tun.close(); state = State.CLOSED; true }
        catch (_: Exception) { state = State.CLOSE_UNCERTAIN; failLocked(); false }
    }
    /** No second close is issued. The host must independently prove that the
     * original descriptor is no longer owned, including FD reuse concerns. */
    @Synchronized fun reconcileClosed(confirmAbsent: () -> Boolean): Boolean {
        if (state != State.CLOSE_UNCERTAIN) return state == State.CLOSED
        state = State.RECONCILING
        val absent = try { confirmAbsent() } catch (_: Exception) { false }
        state = if (absent) State.CLOSED else State.CLOSE_UNCERTAIN
        return absent
    }
}
