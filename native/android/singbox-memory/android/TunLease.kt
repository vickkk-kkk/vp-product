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
class TunLease(private val tun: TunDescriptor, private val protector: SocketProtector) {
    enum class State { ACTIVE, CLOSED, CLOSE_UNCERTAIN }
    private var state = State.ACTIVE

    @Synchronized fun state(): State = state
    /** The returned FD is borrowed, never transferred. The caller must keep
     * the lease alive until all engine use, including startup, has ceased. */
    @Synchronized fun borrowedFd(): Int? {
        if (state != State.ACTIVE) return null
        return try { tun.descriptor().takeIf { it >= 0 } } catch (_: Exception) { null }
    }
    /** Called before a sing-box outbound socket connects or sends. */
    @Synchronized fun protect(fd: Int): Boolean {
        if (state != State.ACTIVE || fd < 0) return false
        return try { protector.protect(fd) } catch (_: Exception) { false }
    }
    /** Confirm exact engine absence before closing the original descriptor.
     * A close exception is uncertain and must never cause a blind retry. */
    @Synchronized fun closeAfterConfirmedStop(confirm: () -> Boolean): Boolean {
        if (state != State.ACTIVE) return state == State.CLOSED
        val stopped = try { confirm() } catch (_: Exception) { false }
        if (!stopped) return false
        return try { tun.close(); state = State.CLOSED; true }
        catch (_: Exception) { state = State.CLOSE_UNCERTAIN; false }
    }
    /** No second close is issued. The host must independently prove that the
     * original descriptor is no longer owned, including FD reuse concerns. */
    @Synchronized fun reconcileClosed(confirmAbsent: () -> Boolean): Boolean {
        if (state != State.CLOSE_UNCERTAIN) return state == State.CLOSED
        val absent = try { confirmAbsent() } catch (_: Exception) { false }
        if (absent) state = State.CLOSED
        return absent
    }
}
