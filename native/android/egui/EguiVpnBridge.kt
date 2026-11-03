package org.vp.product.runtime

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject

/** Explicit in-process boundary for the egui host. No Intent carries credentials.
 * Call prepareIntent on the Activity/UI thread and start only after user consent. */
object EguiVpnBridge {
    internal val consentInFlight = AtomicBoolean(false)
    @Volatile internal var consentResult: String = "unknown"
    @JvmStatic fun prepareIntent(context: Context): Intent? = VpnService.prepare(context)
    @JvmStatic fun available(): Boolean = NativeRuntime.available()

    /** User-initiated only. Consent never starts a tunnel automatically. */
    @JvmStatic fun requestConsent(context: Context): Boolean {
        if (!NativeRuntime.available() || !consentInFlight.compareAndSet(false, true)) return false
        consentResult = "pending"
        return try {
            val intent = Intent(context, EguiVpnConsentActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
            true
        } catch (_: Exception) {
            consentResult = "unavailable"
            consentInFlight.set(false)
            false
        }
    }

    @JvmStatic fun consentStatus(context: Context): String = try {
        if (VpnService.prepare(context) == null) "granted" else consentResult
    } catch (_: Exception) { "unavailable" }

    @Synchronized @JvmStatic fun startWithPayload(context: Context, payload: String): Boolean {
        if (VpVpnService.current != null || VpVpnService.pendingStart != null) return false
        if (payload.isEmpty() || payload.length > 1048576 ||
            payload.toByteArray(Charsets.UTF_8).size > 1048576 || !NativeRuntime.available()) return false
        if (!NativeRuntime.validatePayload(payload) || VpnService.prepare(context) != null) return false
        val request = NativeRuntime.startRequest(payload, UUID.randomUUID().toString(), UUID.randomUUID().toString())
        VpVpnService.pendingStart = request
        return try {
            val intent = Intent(context, VpVpnService::class.java)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
            true // request queued only; never interpreted as connected
        } catch (_: Exception) {
            if (VpVpnService.pendingStart === request) VpVpnService.pendingStart = null
            false
        }
    }

    @Synchronized @JvmStatic fun stop(): Boolean {
        val service = VpVpnService.current
        if (service != null) {
            service.requestStop("user", null)
            return true
        }
        if (VpVpnService.pendingStart != null) {
            VpVpnService.pendingStart = null
            return true
        }
        return false
    }

    /** This JSON is an observation, not independent proof of data-plane health. */
    @JvmStatic fun snapshotJson(): String = JSONObject(HostState.snapshot()).toString()
}
