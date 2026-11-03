// SPDX-License-Identifier: GPL-3.0-or-later
package org.vp.product.singbox

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

private class FakeTun(var shouldFail: Boolean = false) : TunDescriptor {
    var closes = 0
    override fun descriptor(): Int = 42
    override fun close() { closes++; if (shouldFail) error("synthetic") }
}

fun main() {
    val fd = FakeTun()
    var fatalities = 0
    val lease = TunLease(fd, SocketProtector { it == 9 }, { fatalities++ })
    check(lease.borrowedFd() == 42 && lease.protect(9) && !lease.protect(8) && !lease.protect(9))
    check(!lease.isHealthy() && fatalities == 1)
    check(!lease.closeAfterConfirmedStop { false } && fd.closes == 0)
    check(lease.closeAfterConfirmedStop { true } && fd.closes == 1)
    check(lease.state() == TunLease.State.CLOSED && lease.borrowedFd() == null && !lease.protect(9))
    val failing = FakeTun(true)
    val uncertain = TunLease(failing, SocketProtector { true }, {})
    check(!uncertain.closeAfterConfirmedStop { true } && failing.closes == 1)
    check(uncertain.state() == TunLease.State.CLOSE_UNCERTAIN)
    check(!uncertain.closeAfterConfirmedStop { true } && failing.closes == 1)
    check(!uncertain.reconcileClosed { false } && uncertain.reconcileClosed { true })
    check(uncertain.state() == TunLease.State.CLOSED && failing.closes == 1)
    val throwing = TunLease(FakeTun(), SocketProtector { throw IllegalStateException() }, {})
    check(!throwing.protect(5) && !throwing.closeAfterConfirmedStop { throw IllegalStateException() })
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    val closeReturned = CountDownLatch(1)
    val concurrentFd = FakeTun()
    val concurrent = TunLease(concurrentFd, SocketProtector {
        entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); true
    }, {})
    val protectThread = thread { check(concurrent.protect(7)) }
    check(entered.await(5, TimeUnit.SECONDS))
    val closeThread = thread { check(concurrent.closeAfterConfirmedStop { true }); closeReturned.countDown() }
    check(!closeReturned.await(100, TimeUnit.MILLISECONDS) && concurrentFd.closes == 0)
    release.countDown()
    check(closeReturned.await(5, TimeUnit.SECONDS))
    protectThread.join(5000); closeThread.join(5000)
    check(!protectThread.isAlive && !closeThread.isAlive && concurrentFd.closes == 1)
    lateinit var reentrant: TunLease
    reentrant = TunLease(FakeTun(), SocketProtector {
        check(reentrant.closeAfterConfirmedStop { true }); true
    }, {})
    check(!reentrant.protect(3) && reentrant.state() == TunLease.State.CLOSED)
    val confirmLease = TunLease(FakeTun(), SocketProtector { true }, {})
    check(confirmLease.closeAfterConfirmedStop {
        check(!confirmLease.closeAfterConfirmedStop { true }); true
    })
    println("SINGBOX_TUN_LEASE_CHECKS_PASS")
}
