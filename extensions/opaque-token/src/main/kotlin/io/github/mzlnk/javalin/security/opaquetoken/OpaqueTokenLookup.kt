package io.github.mzlnk.javalin.security.opaquetoken

/**
 * Resolves a raw opaque token to its stored [TokenRecord], carrying the caller's own identity.
 *
 * Returns the stored [TokenRecord] (identity and optional expiry), or `null` when the token is
 * unknown or revoked. Must return `null` for unknown tokens rather than throw. Storage and
 * comparison — including hashing and constant-time equality — are the caller's responsibility.
 * Register via the `opaqueToken { }` block (`lookup`).
 */
fun interface OpaqueTokenLookup {

    /** Returns the [TokenRecord] for [rawToken], or `null` when no such token exists. */
    fun lookup(rawToken: String): TokenRecord?

}
