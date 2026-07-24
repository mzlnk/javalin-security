package io.github.mzlnk.javalin.security.jwt

/**
 * A library-agnostic view of a successfully verified JWT.
 *
 * Adapter modules populate this via [SimpleDecodedJwt] after verification. Standard string claims
 * absent from the token are absent from [claims]; callers should treat missing optional claims as
 * absent rather than distinguishing null.
 */
interface DecodedJwt {

    /** The `sub` (subject) claim. Blank string when the token carried no `sub` claim. */
    val subject: String

    /** All claims from the token payload. Values may be strings, numbers, booleans, lists, or maps. */
    val claims: Map<String, Any?>

    /**
     * Returns the claim value cast to [T], or `null` when the claim is absent or not of the
     * expected type.
     */
    @Suppress("UNCHECKED_CAST")
    fun <T> claim(name: String): T? = claims[name] as? T

}

/**
 * Immutable [DecodedJwt] implementation created by adapter modules after library-specific
 * verification.
 */
data class SimpleDecodedJwt(
    override val subject: String,
    override val claims: Map<String, Any?>,
) : DecodedJwt
