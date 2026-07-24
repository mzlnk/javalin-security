package io.github.mzlnk.javalin.security.jwt

/**
 * Verifies and decodes a raw JWT according to a [JwtVerification] specification.
 *
 * Implementations verify the signature against [JwtVerification.keySource] and check standard
 * claims described by the rest of [JwtVerification], returning a [DecodedJwt] on success. Any
 * validation failure must be signalled by throwing; [JwtAuthenticator] converts that into
 * [io.github.mzlnk.javalin.security.authentication.AuthenticationResult.Failure]. Register via the
 * `jwt { }` block (`decoder`) or pass to [JwtAuthenticator.Builder].
 */
fun interface JwtDecoder {

    /**
     * Verifies and decodes the raw [token] according to [verification].
     *
     * Throws on any validation failure (expired token, bad signature, malformed token, claim
     * mismatch, and similar).
     */
    fun decode(token: String, verification: JwtVerification): DecodedJwt

}
