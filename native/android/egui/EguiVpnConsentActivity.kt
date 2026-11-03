package org.vp.product.runtime

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

/** Transient, non-exported Activity for the system consent dialog only. */
class EguiVpnConsentActivity : Activity() {
    companion object { private const val REQUEST_VPN = 7621 }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Reject recreation/foreign invocation instead of launching duplicate dialogs.
        if (!EguiVpnBridge.consentInFlight.get() || savedInstanceState != null) {
            finish()
            return
        }
        try {
            val intent = VpnService.prepare(this)
            if (intent == null) complete("granted")
            else @Suppress("DEPRECATION") startActivityForResult(intent, REQUEST_VPN)
        } catch (_: Exception) { complete("unavailable") }
    }

    @Deprecated("Android Activity callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) complete(if (resultCode == RESULT_OK) "granted" else "denied")
    }

    private fun complete(result: String) {
        EguiVpnBridge.consentResult = result
        EguiVpnBridge.consentInFlight.set(false)
        finish()
    }

    override fun onDestroy() {
        if (EguiVpnBridge.consentInFlight.compareAndSet(true, false)) EguiVpnBridge.consentResult = "cancelled"
        super.onDestroy()
    }
}
