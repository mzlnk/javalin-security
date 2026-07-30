package io.github.mzlnk.javalin.security.apikey

import io.github.mzlnk.javalin.security.authentication.Identity

/**
 * Resolves a raw API key to the caller's own identity.
 *
 * Returns the identity to attach on success, or `null` when the key is unknown. Must return
 * `null` for unknown keys rather than throw. Storage and comparison — including hashing and
 * constant-time equality — are the caller's responsibility. Register via the `apiKey { }` block
 * (`lookup`).
 */
fun interface ApiKeyLookup {

    /** Returns the [Identity] for [rawKey], or `null` when no such key exists. */
    fun lookup(rawKey: String): Identity?

}
