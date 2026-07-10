package io.github.mzlnk.javalin.security.jwt

/**
 * The single pluggable hook for JWT verification.
 *
 * Implementations verify the token's signature and standard claims (expiry, issuer, audience, etc.)
 * and return a [DecodedJwt] on success. Any validation failure — expired token, bad signature,
 * missing required claim — must be signalled by throwing an exception; the [JwtAuthenticationManager]
 * catches it and converts it to an [io.github.mzlnk.javalin.security.authentication.AuthenticationResult.Failure].
 *
 * The implementation is deliberately thin: it does only verification and decoding. It does not
 * decide how extracted claims map to authorities (see [JwtAuthoritiesMapper]) and does not interact
 * with the request context.
 *
 * Register via the `jwt { decoder = ... }` DSL block or pass to [JwtAuthenticationManager.Builder].
 */
fun interface JwtDecoder {

    /**
     * Verify and decode the raw [token] string.
     *
     * @throws Exception on any validation failure (expired, bad signature, malformed, issuer mismatch, etc.)
     */
    fun decode(token: String): DecodedJwt

}
