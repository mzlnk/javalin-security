package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.http.HttpConfigDsl

/**
 * Kotlin DSL receiver for the `jwt { }` block inside `http { }`.
 *
 * Configures JWT bearer-token authentication and wires it into the HTTP security pipeline.
 * [decoder] is the only required field; all other settings have defaults.
 *
 * What this block does explicitly:
 * - Sets [HttpConfigDsl.authenticationManager] to a [JwtAuthenticationManager] built from
 *   [decoder] and [authoritiesMapper].
 * - When [bearerChallenge] is `true`, also sets [HttpConfigDsl.unauthorizedHandler] to a
 *   [BearerChallengeUnauthorizedHandler]. This is the only additional side-effect and is opt-in.
 *
 * What this block does NOT do:
 * - It does not configure authorization rules — use `authorizeRequests { }` alongside `jwt { }`.
 * - It does not override [HttpConfigDsl.accessDeniedHandler] — configure it separately if needed.
 */
class JwtDsl internal constructor() {

    /**
     * The [JwtDecoder] used to verify and decode incoming bearer tokens. **Required.**
     *
     * Throws [SecurityConfigurationException] if `null` when [build] is called.
     */
    var decoder: JwtDecoder? = null

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
                "Set 'decoder = myDecoder' inside the 'jwt { }' block.",
        )
        return JwtAuthenticationManager.builder(d)
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
