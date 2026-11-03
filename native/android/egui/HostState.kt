package org.vp.product.runtime

import java.util.UUID

/** Flutter-free, process-local observations for the egui Android host.
 * A service or TUN descriptor alone never means the tunnel is healthy. */
internal object HostState {
    private val instance = UUID.randomUUID().toString()
    private var generation = 0L
    private var sequence = 0L
    private var phase = "unavailable"
    private var summary = "vp_core Android 运行组件尚未验证。"
    private var operationId: String? = null
    private var nativeSnapshot: Map<String, Any?>? = null

    @Synchronized fun snapshot(): Map<String, Any?> {
        nativeSnapshot?.let { return mapOf("schemaVersion" to 1, "nativeSnapshot" to it) }
        val now = System.currentTimeMillis()
        return mapOf("schemaVersion" to 1, "instanceId" to instance,
            "generation" to generation, "sequence" to sequence, "phase" to phase,
            "summary" to summary, "operationId" to operationId,
            "observedAt" to now, "validUntil" to now + 30000L, "evidence" to emptyList<Any>())
    }

    @Synchronized fun set(phase: String, summary: String, operation: String? = null,
                          newGeneration: Boolean = false) {
        nativeSnapshot = null
        if (newGeneration) generation++
        sequence++
        this.phase = phase
        this.summary = summary
        operationId = operation
    }

    @Synchronized fun applyNative(next: Map<String, Any?>) {
        require(next["schemaVersion"] == 1)
        val nextSequence = (next["sequence"] as Number).toLong()
        val nextGeneration = (next["generation"] as Number).toLong()
        val previous = nativeSnapshot
        if (previous != null && previous["instanceId"] == next["instanceId"] &&
            ((previous["sequence"] as Number).toLong() > nextSequence ||
             (previous["generation"] as Number).toLong() > nextGeneration)) return
        nativeSnapshot = next
        generation = nextGeneration
    }

    @Synchronized fun currentIdentity(): Pair<String, Long> =
        ((nativeSnapshot?.get("instanceId") as? String) ?: instance) to generation

    @Synchronized fun matchesIdentity(expectedInstance: Any?, expectedGeneration: Any?): Boolean {
        val current = currentIdentity()
        return RuntimeIdentity.matches(expectedInstance, expectedGeneration, current.first, current.second)
    }
}
