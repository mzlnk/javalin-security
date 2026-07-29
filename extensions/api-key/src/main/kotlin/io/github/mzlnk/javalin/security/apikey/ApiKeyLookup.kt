package io.github.mzlnk.javalin.security.apikey

/**
 * Resolves an [ApiKeyPrincipal] from a raw API key string.
 *
 * Returns the stored [ApiKeyPrincipal] (name and granted roles), or `null` when the key is
 * unknown. Must return `null` for unknown keys rather than throw. Storage and comparison —
 * including hashing and constant-time equality — are the caller's responsibility. Register via
 * the `apiKey { }` block (`apiKeyLookup`).
 */
fun interface ApiKeyLookup {

    /** Returns the [ApiKeyPrincipal] for [rawKey], or `null` when no such key exists. */
    fun lookup(rawKey: String): ApiKeyPrincipal?

}
