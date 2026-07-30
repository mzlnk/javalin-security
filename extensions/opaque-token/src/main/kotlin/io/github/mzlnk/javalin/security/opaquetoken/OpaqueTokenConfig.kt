@file:JvmName("OpaqueTokenSecurity")

package io.github.mzlnk.javalin.security.opaquetoken

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import java.time.Clock
import java.util.function.Consumer

/**
 * Configuration for the [opaqueToken] strategy factory.
 *
 * [tokenLookup] is required. Roles come from [OpaqueTokenDetails.roles]. Builds an
 * [OpaqueTokenAuthenticator], and selects a [BearerChallengeUnauthorizedHandler] when
 * [bearerChallenge] is `true`.
 */
class OpaqueTokenConfig internal constructor() {

    /**
     * Resolves a raw opaque token to its stored [OpaqueTokenDetails]. Required; throws
     * [SecurityConfigurationException] if unset when the strategy is built.
     */
    @JvmField
    var tokenLookup: OpaqueTokenLookup? = null

    /**
     * Locates the raw token in the request.
     * Defaults to [TokenResolver.DEFAULT] (`Authorization: Bearer ...`).
     */
    @JvmField
    var resolver: TokenResolver = TokenResolver.DEFAULT

    /**
     * Clock used for [OpaqueTokenDetails.expiresAt] validation.
     * Defaults to [Clock.systemUTC].
     */
    @JvmField
    var clock: Clock = Clock.systemUTC()

    /** Renders 403 responses for authenticated callers denied by authorization. Defaults to a bare 403. */
    @JvmField
    var forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT

    /**
     * Renders 401 responses for failed or absent authentication.
     * Defaults to [UnauthorizedHandler.DEFAULT] (bare HTTP 401). Ignored when
     * [bearerChallenge] is `true`.
     */
    @JvmField
    var unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT

    /**
     * When `true`, failed or absent authentication includes a `WWW-Authenticate: Bearer` header
     * with the 401 response (via [BearerChallengeUnauthorizedHandler]).
     *
     * Defaults to `false`. When enabled, takes precedence over [unauthorizedHandler].
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

    internal fun buildAuthenticator(): OpaqueTokenAuthenticator {
        val lookup = tokenLookup ?: throw SecurityConfigurationException(
            "opaqueToken.tokenLookup is required but was not configured. " +
                "Set 'tokenLookup = ...' inside the 'opaqueToken { }' block.",
        )
        return OpaqueTokenAuthenticator.builder(lookup)
            .resolver(resolver)
            .clock(clock)
            .build()
    }

    internal fun buildUnauthorizedHandler(): UnauthorizedHandler =
        if (bearerChallenge) BearerChallengeUnauthorizedHandler(realm) else unauthorizedHandler

}

/**
 * Builds an [AuthenticationStrategy.Sync] for opaque bearer-token authentication.
 *
 * Assign the result to `http.authentication`. Only [OpaqueTokenConfig.tokenLookup] is required.
 * To use [OpaqueTokenAuthenticator] directly, call [OpaqueTokenAuthenticator.builder] and wrap it
 * in a custom [AuthenticationStrategy.Sync].
 */
fun opaqueToken(configure: Consumer<OpaqueTokenConfig>): AuthenticationStrategy.Sync {
    val config = OpaqueTokenConfig().also(configure::accept)
    val authenticator = config.buildAuthenticator()
    val unauthorizedHandlerValue = config.buildUnauthorizedHandler()
    val forbiddenHandlerValue = config.forbiddenHandler
    return object : AuthenticationStrategy.Sync {
        override val unauthorizedHandler: UnauthorizedHandler get() = unauthorizedHandlerValue
        override val forbiddenHandler: ForbiddenHandler get() = forbiddenHandlerValue
        override fun authenticator() = authenticator
    }
}
