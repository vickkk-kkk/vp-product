package org.vp.product.runtime

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Owns the original TUN descriptor. Rust owns only a detached duplicate. */
open class VpVpnService : VpnService() {
    companion object {
        @Volatile internal var current: VpVpnService? = null
        // Authorized in-process request from the typed channel or debug harness; never an exported Intent extra.
        @Volatile internal var pendingStart: NativeStartRequest? = null
        @Volatile private var lastProtectionCounters = ProtectionCounters()
        internal fun protectionStats(): Map<String, Long> = lastProtectionCounters.snapshot()
        private const val CHANNEL = "vp-vpn-state"
        private const val NOTIFICATION = 7411
        private const val STOP_ACTION = "org.vp.product.runtime.STOP_VPN"
    }
    private class ProtectionCounters {
        private val tcp = java.util.concurrent.atomic.AtomicLong()
        private val udp = java.util.concurrent.atomic.AtomicLong()
        private val dns = java.util.concurrent.atomic.AtomicLong()
        private val bootstrap = java.util.concurrent.atomic.AtomicLong()
        private val accepted = java.util.concurrent.atomic.AtomicLong()
        private val denied = java.util.concurrent.atomic.AtomicLong()
        fun record(ok: Boolean, protocol: Int, purpose: Int) {
            if (protocol == 1) tcp.incrementAndGet()
            if (protocol == 2) udp.incrementAndGet()
            if (purpose == 2) dns.incrementAndGet()
            if (purpose == 3) bootstrap.incrementAndGet()
            if (ok) accepted.incrementAndGet() else denied.incrementAndGet()
        }
        fun snapshot(): Map<String, Long> = mapOf("tcp" to tcp.get(), "udp" to udp.get(),
            "dns" to dns.get(), "bootstrap" to bootstrap.get(), "accepted" to accepted.get(), "denied" to denied.get())
    }
    private val protectionCounters = ProtectionCounters()
    private val control = Executors.newSingleThreadScheduledExecutor()
    private var tun: ParcelFileDescriptor? = null
    private var handle = 0L
    private val polling = AtomicBoolean(false)
    private val startAccepted = AtomicBoolean(false)
    private val stopping = AtomicBoolean(false)
    private val snapshotQueued = AtomicBoolean(false)
    private var pump: Thread? = null
    @Volatile private var cleaned = false
    @Volatile private var destroyed = false
    private val closedPublished = AtomicBoolean(false)
    private var nativeFailureCode: String? = null
    private var completionPhase = "failed"
    private var completionSummary = "启动未完成；内核和系统设备已释放。"
    private var completionOperation: String? = null
    private val notificationPublication = NotificationPublication()
    private val notificationRefreshQueued = AtomicBoolean(false)

    override fun onCreate() {
        super.onCreate(); current = this; lastProtectionCounters = protectionCounters
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "VPN 连接状态", NotificationManager.IMPORTANCE_LOW))
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP_ACTION) {
            if (HostState.matchesIdentity(intent.getStringExtra("expectedInstanceId"),
                    intent.getLongExtra("expectedGeneration", -1))) {
                requestStop("user", null)
            } else if (!startAccepted.get()) requestStop("missing_request", null)
            return START_NOT_STICKY
        }
        if (!startAccepted.compareAndSet(false, true)) return START_NOT_STICKY
        // Never auto-replay a lost credential/config after process death.
        showForeground("准备本机 VPN；尚未验证连接")
        val request = pendingStart.also { pendingStart = null }
        if (request == null || stopping.get()) {
            HostState.set("failed", "缺少受权启动请求；未建立 VPN。")
            requestStop("missing_request", null)
        } else control.execute { startCore(request) }
        return START_NOT_STICKY
    }
    private fun showForeground(text: String) {
        val target = HostState.currentIdentity()
        val identity = "${target.first}:${target.second}"
        val enabled = getSystemService(NotificationManager::class.java).areNotificationsEnabled()
        if (!notificationPublication.needsPublication(text, target.first, target.second, enabled)) return
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        val pending = launch?.let { PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT) }
        // Immutable, explicit, application-owned action; no config or credentials in Intent.
        val stopIntent = Intent(this, javaClass).setAction(STOP_ACTION)
            .setData(android.net.Uri.parse("vp-internal://stop/$identity"))
            .putExtra("expectedInstanceId", target.first).putExtra("expectedGeneration", target.second)
        val stop = PendingIntent.getService(this, 1, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning).setContentTitle("VP · 本机 VPN")
            .setContentText(text).setContentIntent(pending).setOngoing(true).setOnlyAlertOnce(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .addAction(Notification.Action.Builder(null, "断开连接", stop).build()).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(NOTIFICATION, notification)
        notificationPublication.recordPublished(text, target.first, target.second, enabled)
    }
    /** Permission observation can republish an existing notice, never start/reconnect a VPN. */
    internal fun notificationPermissionMayHaveChanged() {
        if (!notificationRefreshQueued.compareAndSet(false, true)) return
        try {
            control.execute {
                try {
                    if (!NotificationPublication.mayRefresh(current === this, stopping.get(), destroyed, handle != 0L)) return@execute
                    val enabled = getSystemService(NotificationManager::class.java).areNotificationsEnabled()
                    val text = notificationPublication.lastText
                    if (text != null && notificationPublication.permissionChanged(enabled)) {
                        // Last authoritative phase text only. No new health evidence/native request,
                        // credential replay, channel unblocking or service resurrection.
                        showForeground(text)
                    }
                } catch (_: Exception) {
                    // Do not let an optional notice refresh crash the VPN process. The
                    // publication cache was not committed, so a later explicit read may retry.
                    android.util.Log.w("VpVpnService", "Notification refresh failed; runtime ownership unchanged.")
                } finally { notificationRefreshQueued.set(false) }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            notificationRefreshQueued.set(false) // stopped service: no retry/resurrection
        }
    }
    private fun startCore(request: NativeStartRequest) {
        if (handle != 0L || tun != null) { HostState.set("failed", "已有运行实例，拒绝重复启动。"); return }
        HostState.set("starting", "正在启动 vp_core；VPN 设备不代表数据面可用。", newGeneration = true)
        try {
            if (!NativeRuntime.available()) throw IllegalStateException("RUNTIME_UNAVAILABLE")
            if (!NativeRuntime.validatePayload(request.payload)) throw IllegalArgumentException("CONFIG_INVALID")
            if (prepare(this) != null) throw SecurityException("PERMISSION_DENIED")
            // Static guest packet network only, no host OS routes, no allowBypass or self-app exclusion.
            // IPv6 is captured to prevent silent bypass, but remains unverified until native evidence.
            tun = Builder().setSession("VP").setMtu(1500)
                .addAddress("10.89.0.1", 30).addAddress("fd89:7670::1", 126)
                .addRoute("0.0.0.0", 0).addRoute("::", 0)
                .addDnsServer("10.89.0.2").setBlocking(false).establish()
                ?: throw SecurityException("PERMISSION_DENIED")
            if (stopping.get()) throw SecurityException("PERMISSION_REVOKED")
            val duplicate = ParcelFileDescriptor.dup(tun!!.fileDescriptor).detachFd()
            // Native consumes duplicate on every call, including exceptions. Do not close it here.
            handle = NativeRuntime.create(this, duplicate, 1500, filesDir.absolutePath)
            if (handle == 0L) throw IllegalStateException("RUNTIME_CREATE_FAILED")
            val response = org.json.JSONObject(NativeRuntime.request(handle, request.envelope))
            if (response.has("error") && !response.isNull("error")) throw IllegalStateException("RUNTIME_START_FAILED")
            if (stopping.get()) throw SecurityException("PERMISSION_REVOKED")
            // No ready/connected transition from create, request acceptance or TUN establishment.
            refreshNativeSnapshot()
            polling.set(true)
            pump = Thread({
                try {
                    while (polling.get()) {
                        val event = NativeRuntime.nextEvent(handle, 250) ?: continue
                        // A typed canonical event prompts an authoritative snapshot. Never infer ready.
                        val parsed = org.json.JSONObject(event)
                        require(parsed.getInt("schemaVersion") == 1)
                        if (snapshotQueued.compareAndSet(false, true)) control.execute {
                            try { if (handle != 0L && !stopping.get()) refreshNativeSnapshot() }
                            catch (_: Exception) {
                                HostState.set("failed", "无法验证内核状态；正在关闭 VPN。")
                                requestStop("snapshot_failed", null)
                            }
                            finally { snapshotQueued.set(false) }
                        }
                    }
                } catch (_: Exception) {
                    HostState.set("failed", "vp_core 事件通道中断，正在关闭 VPN。")
                    requestStop("event_channel_lost", null)
                }
            }, "vp-core-events").also { it.start() }
        } catch (_: Exception) {
            HostState.set("failed", "vp_core 启动失败；不会把 VPN 设备误报为连接成功。")
            stopping.set(true)
            cleanup()
        }
    }
    /** Explicit observations run on the same control executor as request/destroy. */
    internal fun querySnapshot(complete: (Map<String, Any?>) -> Unit) {
        val main = android.os.Handler(android.os.Looper.getMainLooper())
        try {
            control.execute {
                try {
                    if (handle != 0L && !stopping.get()) refreshNativeSnapshot()
                } catch (_: Exception) {
                    HostState.set("failed", "无法读取权威内核状态；正在关闭 VPN。")
                    requestStop("snapshot_failed", null)
                } finally { main.post { complete(HostState.snapshot()) } }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            main.post { complete(HostState.snapshot()) }
        }
    }
    private fun refreshNativeSnapshot() {
        val request = org.json.JSONObject().put("schemaVersion", 1)
            .put("requestId", "android-snapshot-${java.util.UUID.randomUUID()}")
            .put("idempotencyKey", org.json.JSONObject.NULL).put("expectedRevision", org.json.JSONObject.NULL)
            .put("method", "snapshot").put("payload", org.json.JSONObject())
        val response = org.json.JSONObject(NativeRuntime.request(handle, request.toString()))
        if (response.has("error") && !response.isNull("error")) throw IllegalStateException("RUNTIME_SNAPSHOT_FAILED")
        val snapshot = response.getJSONObject("result")
        HostState.applyNative(jsonObject(snapshot))
        // Never upgrade health based on service existence. Avoid a stale preparing
        // notice, while keeping detailed evidence/expiry in the authoritative UI.
        if (!stopping.get()) showForeground(when (snapshot.optString("phase")) {
            "failed" -> "VPN 出现错误；正在关闭"
            "stopping" -> "正在断开 VPN"
            "verifying", "preparing", "starting" -> "VPN 正在验证；尚未确认转发"
            else -> "VPN 服务运行中；打开应用查看连接状态"
        })
        if (snapshot.optString("phase") == "failed" && !stopping.get()) {
            nativeFailureCode = snapshot.optJSONObject("error")?.optString("code")
            requestStop("core_failed", null)
        }
    }
    private fun jsonValue(value: Any?): Any? = when (value) {
        null, org.json.JSONObject.NULL -> null
        is org.json.JSONObject -> jsonObject(value)
        is org.json.JSONArray -> (0 until value.length()).map { jsonValue(value.get(it)) }
        else -> value
    }
    private fun jsonObject(value: org.json.JSONObject): Map<String, Any?> =
        value.keys().asSequence().associateWith { jsonValue(value.get(it)) }
    /** Called synchronously by JNI on arbitrary attached Rust threads, before connect/send. */
    @Suppress("unused") open fun protectSocket(fd: Int, protocol: Int, purpose: Int): Boolean {
        val accepted = try { !stopping.get() && protect(fd) } catch (_: Exception) { false }
        recordProtection(accepted, protocol, purpose)
        return accepted
    }
    protected fun recordProtection(accepted: Boolean, protocol: Int, purpose: Int) {
        protectionCounters.record(accepted, protocol, purpose)
    }
    internal fun requestStop(reason: String, operation: String?) {
        if (!stopping.compareAndSet(false, true)) return
        HostState.set(if (reason == "revoked") "failed" else "stopping",
            if (reason == "revoked") "系统已撤销 VPN 授权；正在关闭内核。" else "正在停止 VPN。", operation = operation)
        control.execute {
            completionPhase = if (reason == "user") "disconnected" else "failed"
            completionSummary = if (reason == "user") "VPN 已停止；设备已释放。"
                else if (reason == "revoked") "系统已撤销 VPN；内核和设备已关闭。"
                else if (nativeFailureCode == "PERMISSION_DENIED") "内核套接字保护被拒绝；VPN 和内核已关闭。"
                else "VPN 已关闭；需要重新读取状态后发起连接。"
            completionOperation = operation
            cleanup()
        }
    }
    private fun cleanup(): Boolean {
        polling.set(false)
        pump?.join(1500)
        if (pump?.isAlive == true) {
            HostState.set("recoveryRequired", "内核事件线程未退出；保留句柄等待安全关闭。")
            scheduleCleanup()
            return false
        }
        pump = null
        if (handle != 0L) {
            val status = NativeRuntime.destroy(handle)
            if (status != 0) {
                HostState.set("recoveryRequired", "内核关闭尚未确认；不会重复释放句柄。")
                // Do not leak the system route while native teardown remains blocked.
                tun?.close(); tun = null
                scheduleCleanup()
                return false
            }
            handle = 0L
        }
        tun?.close(); tun = null
        cleaned = true
        stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
        publishClosed()
        control.shutdown()
        return true
    }
    private fun scheduleCleanup() {
        if (!control.isShutdown) control.schedule({ cleanup() }, 500, java.util.concurrent.TimeUnit.MILLISECONDS)
    }
    private fun publishClosed() {
        if (!destroyed || !cleaned || !closedPublished.compareAndSet(false, true)) return
        android.os.Handler(android.os.Looper.getMainLooper()).post {
            if (current === this) current = null
            HostState.set(completionPhase, completionSummary, operation = completionOperation)
        }
    }
    override fun onRevoke() { requestStop("revoked", null) }
    override fun onTaskRemoved(rootIntent: Intent?) {
        // Dismissing the UI task is not a disconnect. The started foreground
        // service and Rust runtime remain owners; no timer/alarm resurrects an
        // explicitly stopped or OS-killed process.
        super.onTaskRemoved(rootIntent)
    }
    override fun onDestroy() {
        destroyed = true
        if (!cleaned && !stopping.get()) requestStop("destroyed", null)
        publishClosed()
        super.onDestroy()
    }
}
