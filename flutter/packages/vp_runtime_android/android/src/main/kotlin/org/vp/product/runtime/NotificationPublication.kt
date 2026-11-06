package org.vp.product.runtime

/** Deduplication of actual notification publications, not VPN/health state. */
internal class NotificationPublication {
    private data class Key(val text: String, val instance: String, val generation: Long, val enabled: Boolean)
    private var published: Key? = null
    val lastText: String? get() = published?.text

    fun needsPublication(text: String, instance: String, generation: Long, enabled: Boolean): Boolean =
        published != Key(text, instance, generation, enabled)

    /** Call only after Android accepts startForeground; exceptions must remain retryable. */
    fun recordPublished(text: String, instance: String, generation: Long, enabled: Boolean) {
        published = Key(text, instance, generation, enabled)
    }

    fun permissionChanged(enabled: Boolean): Boolean = published?.let { it.enabled != enabled } ?: false

    companion object {
        fun mayRefresh(isCurrent: Boolean, stopping: Boolean, destroyed: Boolean, hasRuntime: Boolean): Boolean =
            isCurrent && !stopping && !destroyed && hasRuntime
    }
}
