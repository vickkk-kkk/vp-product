package org.vp.product.runtime

/** Ephemeral validated bytes plus generated envelope; never persisted or placed in Intent extras. */
internal class NativeStartRequest private constructor(val payload: String, val envelope: String) {
    companion object {
        fun create(payload: String, requestId: String, key: String): NativeStartRequest {
            val header = org.json.JSONObject().put("schemaVersion", 1).put("requestId", requestId)
                .put("idempotencyKey", key).put("expectedRevision", 0).put("method", "connect").toString()
            // Preserve the exact payload validated by Rust; no copy/constructor can substitute it.
            val envelope = header.dropLast(1) + ",\"payload\":" + payload + "}"
            require(envelope.toByteArray(Charsets.UTF_8).size <= 1048576)
            return NativeStartRequest(payload, envelope)
        }
    }
}

/** Only JNI transport: all data plane, parsing and validation belongs to vp_core adapter. */
internal object NativeRuntime {
    private val loadError: Throwable? = try {
        System.loadLibrary("vp_android_host")
        null
    } catch (error: LinkageError) { error }

    private val componentAvailable: Boolean by lazy {
        inspectAvailability()
    }
    fun available(): Boolean = componentAvailable
    private fun inspectAvailability(): Boolean {
        if (loadError != null) return false
        return try {
            if (!nativeAvailable()) false
            else {
                val info = org.json.JSONObject(abiInfo())
                val modes = info.getJSONArray("platformModes")
                val payloads = info.getJSONArray("connectPayloadVersions")
                info.getInt("abiMajor") == 1 && info.getInt("abiMinor") >= 1 && info.getInt("schemaVersion") == 1 &&
                    info.getString("engine") == "vp_core" && info.getLong("requiredHooks") == 1L &&
                    info.getLong("maximumControlBytes") == 1048576L &&
                    (0 until modes.length()).any { modes.getInt(it) == 2 } &&
                    (0 until payloads.length()).any { payloads.getInt(it) == 2 }
            }
        } catch (_: Exception) { false } catch (_: LinkageError) { false }
    }
    external fun nativeAvailable(): Boolean
    external fun abiInfo(): String
    /** Pure Rust validation of the exact typed connect payload; no FD, runtime, network or secrets output. */
    external fun validateConnect(payload: String): String
    fun validatePayload(payload: String): Boolean {
        if (!available()) return false
        return try {
            val report = org.json.JSONObject(validateConnect(payload))
            report.getInt("schemaVersion") == 1 && report.getBoolean("valid") && report.isNull("error")
        } catch (_: Exception) { false }
    }
    fun startRequest(payload: String, requestId: String, key: String): NativeStartRequest =
        NativeStartRequest.create(payload, requestId, key)
    /** Consumes duplicateFd on every invocation, including errors. Never pass original. */
    external fun create(service: VpVpnService, duplicateFd: Int, mtu: Int, root: String): Long
    external fun request(handle: Long, request: String): String
    external fun nextEvent(handle: Long, timeoutMs: Int): String?
    /** Only after joining event reader. 0 invalidates the native handle. */
    external fun destroy(handle: Long): Int
}
