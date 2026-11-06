package org.vp.product.runtime

/** Native generations are local to one handle, so compare the epoch as well. */
internal object RuntimeIdentity {
    fun matches(expectedInstance: Any?, expectedGeneration: Any?, currentInstance: String, currentGeneration: Long): Boolean =
        expectedInstance is String && expectedInstance == currentInstance &&
            (expectedGeneration is Int || expectedGeneration is Long) &&
            (expectedGeneration as Number).toLong() == currentGeneration
}

/** Process-epoch cache: never evict a key and allow a stale request to act again. */
internal class OperationLedger(private val capacity: Int = 128) {
    private data class Record(val operation: String, val fingerprint: String)
    private val records = LinkedHashMap<String, Record>()
    fun canRemember(key: String): Boolean = key in records || records.size < capacity
    fun remember(key: String, operation: String, fingerprint: String) {
        check(canRemember(key))
        val old = records[key]
        check(old == null || old == Record(operation, fingerprint))
        records[key] = Record(operation, fingerprint)
    }
    fun matches(key: String, fingerprint: String): Boolean? = records[key]?.let { it.fingerprint == fingerprint }
    fun reconcile(key: String): String? = records[key]?.operation
}
