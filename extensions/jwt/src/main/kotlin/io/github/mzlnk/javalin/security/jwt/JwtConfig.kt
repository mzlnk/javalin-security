@file:JvmName("JwtSecurity")

package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import java.util.function.Consumer

/**
 * Configuration for the [jwt] strategy factory.
 *
 * Configures JWT bearer-token authentication. [decoder] and [keySource] are required; other
 * settings have defaults. Leave [identityMapper] unset to get the default [Jwt] identity (with
 * roles from [rolesMapper]), or set it to map verified tokens to your own domain identity.
 * Builds a [JwtVerification] and [JwtAuthenticator] for the returned strategy, and selects a
 * [BearerChallengeUnauthorizedHandler] when [bearerChallenge] is `true`. Does not configure
 * authorization rules — set those via `security.rules`.
 */
class JwtConfig internal constructor() {

    /**
     * The [JwtDecoder] used to verify and decode bearer tokens. Required.
     *
     * Throws [SecurityConfigurationException] if unset when the strategy is built.
     */
    @JvmField
    var decoder: JwtDecoder? = null

    /**
     * Where verification keys come from (local public key, PEM, HMAC secret, or JWKS). Required.
     *
     * See [JwtKeySource] factory methods. Throws [SecurityConfigurationException] if unset when
     * the strategy is built.
     */
    @JvmField
    var keySource: JwtKeySource? = null

    /**
     * When set, requires the token's `iss` claim to match this value.
     *
     * Defaults to `null` (issuer not checked). A different or absent issuer is rejected when set.
     */
    @JvmField
    var issuer: String? = null

    /**
     * When non-empty, requires the token's `aud` claim to contain at least one of these values.
     *
     * Defaults to an empty set (audience not checked).
     */
    @JvmField
    var audiences: Set<String> = emptySet()

    /**
     * Maximum acceptable clock skew in seconds for `exp` and `nbf` validation.
     *
     * Defaults to `60`. Set to `0` to disable clock-skew tolerance.
     */
    @JvmField
    var clockSkewSeconds: Int = 60

    /**
     * Maps a verified [DecodedJwt] to the caller's [io.javalin.security.RouteRole]s, for the
     * default [Jwt] identity.
     *
     * Defaults to [JwtRolesMapper.noRoles]. Routes and rules that require specific roles need a
     * non-default mapper such as [JwtRolesMapper.fromClaim] or [JwtRolesMapper.fromScope].
     * Mutually exclusive with [identityMapper] — throws [SecurityConfigurationException] if both
     * are set, since a mapped identity supplies its own roles.
     */
    @JvmField
    var rolesMapper: JwtRolesMapper = JwtRolesMapper.noRoles()

    /**
     * Maps a verified [DecodedJwt] to your own [io.github.mzlnk.javalin.security.authentication.Identity],
     * replacing the default [Jwt] wrapper.
     *
     * Defaults to `null` (handlers see a [Jwt] identity). Mutually exclusive with [rolesMapper] —
     * throws [SecurityConfigurationException] if both are set.
     */
    @JvmField
    var identityMapper: JwtIdentityMapper? = null

    /**
     * Handler for access denied to an authenticated caller.
     *
     * Defaults to [ForbiddenHandler.DEFAULT] (HTTP 403).
     */
    @JvmField
    var forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT

    /**
     * When `true`, failed or absent authentication includes a `WWW-Authenticate: Bearer` header
     * with the 401 response.
     *
     * Defaults to `false`.
     */
    @JvmField
    var bearerChallenge: Boolean = false

    /**
     * Realm attribute included in the `WWW-Authenticate` header when [bearerChallenge] is `true`.
     *
     * Defaults to `"API"`.
     */
    @JvmField
    var realm: String = "API"

    /**
     * Locates the raw token in the incoming request.
     *
     * Defaults to [TokenResolver.DEFAULT] (`Authorization: Bearer ...`). Use
     * [TokenResolver.cookie] when the JWT is carried in a cookie.
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
        if (identityMapper != null && rolesMapper !== JwtRolesMapper.noRoles()) {
            throw SecurityConfigurationException(
                "jwt.identityMapper and jwt.rolesMapper are mutually exclusive. " +
                    "rolesMapper only resolves roles for the default Jwt identity; when identityMapper " +
                    "is set, roles should come from the mapped identity's own 'roles' property.",
            )
        }
        val verification = JwtVerification.builder(ks)
            .apply { issuer?.let { issuer(it) } }
            .apply { if (audiences.isNotEmpty()) audience(*audiences.toTypedArray()) }
            .clockSkew(clockSkewSeconds)
            .build()
        return JwtAuthenticator.builder(d, verification)
            .rolesMapper(rolesMapper)
            .identityMapper(identityMapper)
            .tokenResolver(tokenResolver)
            .build()
    }

    internal fun buildUnauthorizedHandler(): UnauthorizedHandler =
        if (bearerChallenge) BearerChallengeUnauthorizedHandler(realm) else UnauthorizedHandler.DEFAULT

}

/**
 * Builds an [AuthenticationStrategy.Sync] for JWT bearer-token authentication, and returns it
 * for assignment to `http.authentication` or `ws.authentication`.
 *
 * Accepts a [JwtConfig] consumer; [JwtConfig.decoder] and [JwtConfig.keySource] are required.
 * By default handlers see the built-in [Jwt] identity (with roles from [JwtConfig.rolesMapper]);
 * set [JwtConfig.identityMapper] to map verified tokens to your own domain [io.github.mzlnk.javalin.security.authentication.Identity]
 * instead. Browser WebSocket clients cannot set an `Authorization` header on the handshake —
 * use [TokenResolver.cookie] and pair with `ws.allowedOrigins` when authenticating via cookie.
 */
fun jwt(configure: Consumer<JwtConfig>): AuthenticationStrategy.Sync {
    val config = JwtConfig().also(configure::accept)
    return AuthenticationStrategy.sync(
        authenticator = config.buildAuthenticator(),
        unauthorizedHandler = config.buildUnauthorizedHandler(),
        forbiddenHandler = config.forbiddenHandler,
    )
}
