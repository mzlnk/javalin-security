package io.github.mzlnk.javalin.security.opaquetoken

/**
 * Resolves an [OpaqueTokenDetails] from a raw opaque token string.
 *
 * Returns the stored [OpaqueTokenDetails] (subject, roles, optional expiry), or `null`
 * when the token is unknown or revoked. Must return `null` for unknown tokens rather than throw.
 * Storage and comparison — including hashing and constant-time equality — are the caller's
 * responsibility. Register via the `opaqueToken { }` block (`tokenLookup`).
 */
fun interface OpaqueTokenLookup {

    /** Returns the [OpaqueTokenDetails] for [rawToken], or `null` when no such token exists. */
    fun lookup(rawToken: String): OpaqueTokenDetails?

}
