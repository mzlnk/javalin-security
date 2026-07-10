package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.http.HttpConfigDsl

/**
 * Kotlin DSL receiver for the `jwt { }` block inside `http { }`.
 *
 * Configures JWT bearer-token authentication and wires it into the HTTP security pipeline.
 * [decoder] and [keySource] are the only required fields; all other settings have defaults.
 *
 * The addon (this DSL) owns the decision of *where the verification key comes from* and *which
 * claims are checked* — [keySource], [issuer], [audiences], [clockSkewSeconds]. The [decoder] is
 * a thin, stateless adapter (e.g. `NimbusJwtDecoder`) that only performs the actual signature
 * verification and claim checks for the [JwtVerification] built from these fields.
 *
 * What this block does explicitly:
 * - Builds a [JwtVerification] from [keySource], [issuer], [audiences] and [clockSkewSeconds].
 * - Sets [HttpConfigDsl.authenticationManager] to a [JwtAuthenticationManager] built from
 *   [decoder], that [JwtVerification], and [authoritiesMapper].
 * - When [bearerChallenge] is `true`, also sets [HttpConfigDsl.unauthorizedHandler] to a
 *   [BearerChallengeUnauthorizedHandler]. This is the only additional side-effect and is opt-in.
 *
 * What this block does NOT do:
 * - It does not configure authorization rules — use `authorizeRequests { }` alongside `jwt { }`.
 * - It does not override [HttpConfigDsl.accessDeniedHandler] — configure it separately if needed.
 */
class JwtDsl internal constructor() {

    /**
     * The [JwtDecoder] adapter used to verify and decode incoming bearer tokens. **Required.**
     *
     * Expected to be a stateless implementation (e.g. the `NimbusJwtDecoder` object) that performs
     * verification purely from the [JwtVerification] built from this block's other fields.
     *
     * Throws [SecurityConfigurationException] if `null` when the manager is built.
     */
    var decoder: JwtDecoder? = null

    /**
     * Describes where the key(s) used to verify the token's signature come from — a local public
     * key, a PEM-encoded key, an HMAC secret, or a remote JWKS endpoint. **Required.**
     *
     * See [JwtKeySource]'s factory methods (`publicKey`, `pem`, `pemFile`, `secret`, `jwks`, ...).
     *
     * Throws [SecurityConfigurationException] if `null` when the manager is built.
     */
    var keySource: JwtKeySource? = null

    /**
     * Validates that the token's `iss` claim matches this value.
     *
     * Defaults to `null` (issuer not checked). Tokens with a different or absent issuer are
     * rejected when set.
     */
    var issuer: String? = null

    /**
     * Validates that the token's `aud` claim contains at least one of these values.
     *
     * Defaults to an empty set (audience not checked).
     */
    var audiences: Set<String> = emptySet()

    /**
     * The maximum acceptable clock skew, in seconds, for `exp` and `nbf` validation.
     *
     * Defaults to `60` seconds. Set to `0` to disable clock skew tolerance.
     */
    var clockSkewSeconds: Int = 60

    /**
     * Maps a verified [DecodedJwt] to the caller's granted authorities.
     *
     * Defaults to [JwtAuthoritiesMapper.noAuthorities] (empty set). Authorization rules that rely
     * on specific authorities (e.g. `hasAuthority("ADMIN")`) require a non-default mapper.
     */
    var authoritiesMapper: JwtAuthoritiesMapper = JwtAuthoritiesMapper.noAuthorities()

    /**
     * When `true`, failed or absent authentication responds with a
     * `WWW-Authenticate: Bearer ...` header alongside the 401.
     *
     * Defaults to `false`. Enable when clients need the challenge to discover the authentication
     * scheme (e.g. OAuth 2.0 resource servers per RFC 6750).
     */
    var bearerChallenge: Boolean = false

    /**
     * The `realm` attribute included in the `WWW-Authenticate` header when [bearerChallenge] is `true`.
     *
     * Defaults to `"API"`.
     */
    var realm: String = "API"

    internal fun buildManager(): JwtAuthenticationManager {
        val d = decoder ?: throw SecurityConfigurationException(
            "jwt.decoder is required but was not configured. " +
                "Set 'decoder = NimbusJwtDecoder' (or another JwtDecoder adapter) inside the 'jwt { }' block.",
        )
        val ks = keySource ?: throw SecurityConfigurationException(
            "jwt.keySource is required but was not configured. " +
                "Set 'keySource = JwtKeySource.publicKey(...)' (or another JwtKeySource factory) " +
                "inside the 'jwt { }' block.",
        )
        val verification = JwtVerification.builder(ks)
            .apply { issuer?.let { issuer(it) } }
            .apply { if (audiences.isNotEmpty()) audience(*audiences.toTypedArray()) }
            .clockSkew(clockSkewSeconds)
            .build()
        return JwtAuthenticationManager.builder(d, verification)
            .authoritiesMapper(authoritiesMapper)
            .build()
    }

    internal fun buildChallenge(): BearerChallengeUnauthorizedHandler =
        BearerChallengeUnauthorizedHandler(realm)

}

/**
 * Configures JWT bearer-token authentication inside an `http { }` block.
 *
 * This is a Kotlin convenience extension on [HttpConfigDsl]; Java users construct a
 * [JwtAuthenticationManager] directly via [JwtAuthenticationManager.builder] and pass it to
 * `http.authenticationManager(...)`.
 *
 * The [JwtDsl.decoder] field is the only required setting.
 */
fun HttpConfigDsl.jwt(init: JwtDsl.() -> Unit) {
    val dsl = JwtDsl().apply(init)
    authenticationManager = dsl.buildManager()
    if (dsl.bearerChallenge) {
        unauthorizedHandler = dsl.buildChallenge()
    }
}
