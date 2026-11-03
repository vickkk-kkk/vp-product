package org.vp.product.runtime

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
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

    /** The core validates the exact request before the system prompt or TUN. */
    @JvmStatic fun preflight(payload: String): Boolean = try {
        payload.isNotEmpty() && payload.length <= 1048576 &&
            payload.toByteArray(Charsets.UTF_8).size <= 1048576 &&
            NativeRuntime.available() && NativeRuntime.validatePayload(payload)
    } catch (_: Exception) { false }

    /** User-initiated only. Consent never starts a tunnel automatically. */
    @JvmStatic fun requestConsent(context: Context, payload: String): Boolean {
        if (!preflight(payload) || !consentInFlight.compareAndSet(false, true)) return false
        consentResult = "pending"
        val app = context.applicationContext
        val queued = Handler(Looper.getMainLooper()).post {
            try {
                val intent = Intent(app, EguiVpnConsentActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                app.startActivity(intent)
            } catch (_: Exception) {
                consentResult = "unavailable"
                consentInFlight.set(false)
            }
        }
        if (!queued) {
            consentResult = "unavailable"
            consentInFlight.set(false)
        }
        return queued
    }

    @JvmStatic fun consentStatus(context: Context): String = try {
        if (VpnService.prepare(context) == null) "granted" else consentResult
    } catch (_: Exception) { "unavailable" }
    @JvmStatic fun consentGranted(context: Context): Boolean = try {
        VpnService.prepare(context) == null
    } catch (_: Exception) { false }

    @Synchronized @JvmStatic fun startWithPayload(context: Context, payload: String): Boolean {
        if (VpVpnService.current != null || VpVpnService.pendingStart != null) return false
        if (!preflight(payload) || VpnService.prepare(context) != null) return false
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
