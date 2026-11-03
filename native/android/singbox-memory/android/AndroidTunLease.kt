// SPDX-License-Identifier: GPL-3.0-or-later
package org.vp.product.singbox

import android.net.VpnService
import android.os.ParcelFileDescriptor

/** Owns the original system descriptor; never detaches it or closes a duplicate. */
class AndroidTunDescriptor(private val tun: ParcelFileDescriptor) : TunDescriptor {
    override fun descriptor(): Int = tun.fd
    override fun close() = tun.close()
}

/** The Android system must have already granted consent and established TUN. */
fun androidTunLease(service: VpnService, tun: ParcelFileDescriptor, onFatal: () -> Unit): TunLease =
    TunLease(AndroidTunDescriptor(tun), SocketProtector { fd -> service.protect(fd) }, onFatal)
