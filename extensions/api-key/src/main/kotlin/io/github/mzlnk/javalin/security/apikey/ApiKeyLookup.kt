package io.github.mzlnk.javalin.security.apikey

/**
 * Resolves a raw API key to [ApiKeyDetails] carrying the caller's own identity.
 *
 * Returns the [ApiKeyDetails] to attach on success, or `null` when the key is unknown. Must
 * return `null` for unknown keys rather than throw. Storage and comparison — including hashing
 * and constant-time equality — are the caller's responsibility. Register via the `apiKey { }`
 * block (`lookup`).
 */
fun interface ApiKeyLookup {

    /** Returns the [ApiKeyDetails] for [rawKey], or `null` when no such key exists. */
    fun lookup(rawKey: String): ApiKeyDetails?

}
