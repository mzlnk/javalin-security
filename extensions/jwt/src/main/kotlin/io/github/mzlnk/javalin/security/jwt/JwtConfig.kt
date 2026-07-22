@file:JvmName("JwtSecurity")

package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AuthenticationScheme
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import java.util.function.Consumer

/**
 * Configuration object for the [jwt] scheme factory.
 *
 * Configures JWT bearer-token authentication. [decoder] and [keySource] are the only required
 * fields; all other settings have defaults.
 *
 * The addon (this config) owns the decision of *where the verification key comes from* and *which
 * claims are checked* — [keySource], [issuer], [audiences], [clockSkewSeconds] — as well as
 * *where the raw token is located in the request* — [tokenResolver]. The [decoder] is a thin,
 * stateless adapter (e.g. `NimbusJwtDecoder`) that only performs the actual signature
 * verification and claim checks for the [JwtVerification] built from these fields.
 *
 * What [jwt] builds from this config:
 * - A [JwtVerification] from [keySource], [issuer], [audiences] and [clockSkewSeconds].
 * - A [JwtAuthenticator] from [decoder], that [JwtVerification], and [rolesMapper] — the
 *   [AuthenticationScheme.Sync.authenticator] of the returned scheme. The roles resolved by
 *   [rolesMapper] land directly on [io.github.mzlnk.javalin.security.authentication.Authentication.roles].
 * - The scheme's [AuthenticationScheme.forbiddenHandler] directly from [forbiddenHandler].
 * - The scheme's [AuthenticationScheme.unauthorizedHandler]: a [BearerChallengeUnauthorizedHandler]
 *   when [bearerChallenge] is `true`, otherwise [UnauthorizedHandler.DEFAULT].
 *
 * This config does not configure the rule table — use `http.rules { }` / `ws.rules { }` alongside
 * `http.authentication = jwt { }`.
 */
class JwtConfig internal constructor() {

    /**
     * The [JwtDecoder] adapter used to verify and decode incoming bearer tokens. **Required.**
     *
     * Expected to be a stateless implementation (e.g. the `NimbusJwtDecoder` object) that performs
     * verification purely from the [JwtVerification] built from this block's other fields.
     *
     * Throws [SecurityConfigurationException] if `null` when the scheme is built.
     */
    @JvmField
    var decoder: JwtDecoder? = null

    /**
     * Describes where the key(s) used to verify the token's signature come from — a local public
     * key, a PEM-encoded key, an HMAC secret, or a remote JWKS endpoint. **Required.**
     *
     * See [JwtKeySource]'s factory methods (`publicKey`, `pem`, `pemFile`, `secret`, `jwks`, ...).
     *
     * Throws [SecurityConfigurationException] if `null` when the scheme is built.
     */
    @JvmField
    var keySource: JwtKeySource? = null

    /**
     * Validates that the token's `iss` claim matches this value.
     *
     * Defaults to `null` (issuer not checked). Tokens with a different or absent issuer are
     * rejected when set.
     */
    @JvmField
    var issuer: String? = null

    /**
     * Validates that the token's `aud` claim contains at least one of these values.
     *
     * Defaults to an empty set (audience not checked).
     */
    @JvmField
    var audiences: Set<String> = emptySet()

    /**
     * The maximum acceptable clock skew, in seconds, for `exp` and `nbf` validation.
     *
     * Defaults to `60` seconds. Set to `0` to disable clock skew tolerance.
     */
    @JvmField
    var clockSkewSeconds: Int = 60

    /**
     * Maps a verified [DecodedJwt] to the caller's granted [io.javalin.security.RouteRole]s.
     *
     * Defaults to [JwtRolesMapper.noRoles] (empty set). Routes/endpoints that declare
     * [io.javalin.security.RouteRole]s directly, and authorization rules that rely on specific
     * roles (e.g. `hasRole(Role.ADMIN)`), require a non-default mapper — see
     * [JwtRolesMapper.fromClaim] / [JwtRolesMapper.fromScope].
     */
    @JvmField
    var rolesMapper: JwtRolesMapper = JwtRolesMapper.noRoles()

    /**
     * The scheme's [AuthenticationScheme.forbiddenHandler].
     *
     * Overrides how access-denied for an authenticated caller is rendered. Defaults to a bare
     * HTTP 403.
     */
    @JvmField
    var forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT

    /**
     * When `true`, failed or absent authentication responds with a
     * `WWW-Authenticate: Bearer ...` header alongside the 401.
     *
     * Defaults to `false`. Enable when clients need the challenge to discover the authentication
     * scheme (e.g. OAuth 2.0 resource servers per RFC 6750).
     */
    @JvmField
    var bearerChallenge: Boolean = false

    /**
     * The `realm` attribute included in the `WWW-Authenticate` header when [bearerChallenge] is `true`.
     *
     * Defaults to `"API"`.
     */
    @JvmField
    var realm: String = "API"

    /**
     * Locates the raw token within the incoming request.
     *
     * Defaults to [TokenResolver.DEFAULT], i.e. the `Authorization: Bearer ...` header. Swap
     * in [TokenResolver.cookie] for browser/SPA flows that store the JWT in a cookie instead:
     *
     * ```kotlin
     * http.authentication = jwt { jwt ->
     *     jwt.decoder = myDecoder
     *     jwt.tokenResolver = TokenResolver.cookie("access_token")
     * }
     * ```
     */
    @JvmField
    var tokenResolver: TokenResolver = TokenResolver.DEFAULT

    internal fun buildAuthenticator(): JwtAuthenticator {
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
        return JwtAuthenticator.builder(d, verification)
            .rolesMapper(rolesMapper)
            .tokenResolver(tokenResolver)
            .build()
    }

    internal fun buildUnauthorizedHandler(): UnauthorizedHandler =
        if (bearerChallenge) BearerChallengeUnauthorizedHandler(realm) else UnauthorizedHandler.DEFAULT

}

/**
 * Builds an [AuthenticationScheme.Sync] configured for JWT bearer-token authentication.
 *
 * The same one-stop configuration works from both languages — the [JwtConfig] arrives as an
 * explicit `Consumer` parameter, just like every other configuration block in this library, and
 * the returned scheme is assigned directly to `http.authentication` / `ws.authentication`:
 *
 * ```kotlin
 * http.authentication = jwt { jwt ->
 *     jwt.decoder = NimbusJwtDecoder
 *     jwt.keySource = JwtKeySource.pemFile(path)
 * }
 * ```
 *
 * ```java
 * http.authentication = JwtSecurity.jwt(jwt -> {
 *     jwt.decoder = NimbusJwtDecoder.INSTANCE;
 *     jwt.keySource = JwtKeySource.pemFile(path);
 * });
 * ```
 *
 * The same scheme works for both `http.authentication` and `ws.authentication`.
 * **Browser clients cannot set an `Authorization` header on a WebSocket handshake.** For
 * browser/SPA flows, set `tokenResolver = TokenResolver.cookie("...")` and pair it with
 * `ws.allowedOrigins` on the surrounding `ws { }` block — WebSocket handshakes are not
 * protected by the browser same-origin policy or CORS, so an explicit origin allowlist is the
 * CSWSH defense when authenticating via a cookie:
 *
 * ```kotlin
 * ws { ws ->
 *     ws.authentication = jwt { jwt ->
 *         jwt.decoder = NimbusJwtDecoder
 *         jwt.keySource = JwtKeySource.publicKey(rsaPublicKey)
 *         jwt.tokenResolver = TokenResolver.cookie("access_token")
 *     }
 *     ws.allowedOrigins = listOf("https://app.example.com")
 *     ws.rules { r -> r.add("/ws/chat", r.authenticated) }
 * }
 * ```
 *
 * Users who want the [JwtAuthenticator] object itself (e.g. to share it between blocks) can build
 * one via [JwtAuthenticator.builder] and wrap it in a custom [AuthenticationScheme.Sync]
 * implementation.
 *
 * The [JwtConfig.decoder] and [JwtConfig.keySource] fields are the only required settings.
 */
fun jwt(configure: Consumer<JwtConfig>): AuthenticationScheme.Sync {
    val config = JwtConfig().also(configure::accept)
    val authenticator = config.buildAuthenticator()
    val unauthorizedHandlerValue = config.buildUnauthorizedHandler()
    val forbiddenHandlerValue = config.forbiddenHandler
    return object : AuthenticationScheme.Sync {
        override val unauthorizedHandler: UnauthorizedHandler get() = unauthorizedHandlerValue
        override val forbiddenHandler: ForbiddenHandler get() = forbiddenHandlerValue
        override fun authenticator() = authenticator
    }
}
