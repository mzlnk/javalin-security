package io.github.mzlnk.javalin.security.jwt

/**
 * A library-agnostic view of a successfully verified JWT.
 *
 * Adapter modules (e.g. `javalin-security-jwt-nimbus`) populate this via [SimpleDecodedJwt] after
 * completing their library-specific verification.
 *
 * All standard JWT string claims (iss, sub, aud, etc.) that were not present in the token are
 * absent from [claims]; callers should not distinguish between absent and null when reading optional
 * claims.
 */
interface DecodedJwt {

    /** The `sub` (subject) claim. Blank string when the token carried no `sub` claim. */
    val subject: String

    /** All claims from the token payload as a raw map. Values may be strings, numbers, booleans, lists, or maps. */
    val claims: Map<String, Any?>

    /**
     * Returns the claim value cast to [T], or `null` when the claim is absent or not of the expected type.
     *
     * Example: `token.claim<String>("role")`, `token.claim<List<*>>("roles")`
     */
    @Suppress("UNCHECKED_CAST")
    fun <T> claim(name: String): T? = claims[name] as? T

}

/**
 * Concrete, immutable implementation of [DecodedJwt]. Adapter modules create instances of this
 * class after completing verification with their underlying JWT library.
 */
data class SimpleDecodedJwt(
    override val subject: String,
    override val claims: Map<String, Any?>,
) : DecodedJwt
