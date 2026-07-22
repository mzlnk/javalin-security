package io.github.mzlnk.javalin.security.jwt

/**
 * The single pluggable hook for JWT verification.
 *
 * Implementations verify the token's signature against the key(s) described by the given
 * [JwtVerification.keySource] and check standard claims (expiry, issuer, audience, etc.) as
 * described by the rest of [JwtVerification]. They return a [DecodedJwt] on success. Any
 * validation failure — expired token, bad signature, missing required claim — must be signalled
 * by throwing an exception; the [JwtAuthenticator] catches it and converts it to an
 * [io.github.mzlnk.javalin.security.authentication.AuthenticationResult.Failure].
 *
 * The implementation is deliberately thin: it does only verification and decoding for the given
 * [JwtVerification] spec — it does not decide *which* key source or claim checks to use (that is
 * the addon's job, configured via the `jwt { }` DSL). It does not decide how extracted claims map
 * to authorities (see [JwtAuthoritiesMapper]) and does not interact with the request context.
 *
 * Library-specific adapters (e.g. `NimbusJwtDecoder`) are expected to be stateless Kotlin
 * `object`s — analogous to how Javalin's `JavalinJackson` implements `JsonMapper` — since all
 * configuration lives in [JwtVerification], not in the adapter itself.
 *
 * Register via the `jwt { }` block (`decoder` field) or pass to [JwtAuthenticator.Builder].
 */
fun interface JwtDecoder {

    /**
     * Verify and decode the raw [token] string according to [verification].
     *
     * @throws Exception on any validation failure (expired, bad signature, malformed, issuer mismatch, etc.)
     */
    fun decode(token: String, verification: JwtVerification): DecodedJwt

}
