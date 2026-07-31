@file:JvmName("ApiKeySecurity")

package io.github.mzlnk.javalin.security.apikey

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import java.util.function.Consumer

/**
 * Configuration for the [apiKey] strategy factory.
 *
 * [lookup] is required. The identity type your [ApiKeyLookup] returns is your own — bring your
 * own type; roles come from [ApiKeyDetails.roles]. Builds an [ApiKeyAuthenticator]. HTTP-only —
 * there is no WebSocket variant.
 */
class ApiKeyConfig internal constructor() {

    /**
     * Resolves a raw API key to its owner's [ApiKeyDetails]. Required; throws
     * [SecurityConfigurationException] if unset when the strategy is built.
     */
    @JvmField
    var lookup: ApiKeyLookup? = null

    /**
     * Locates the raw API key in the request.
     * Defaults to [ApiKeyResolver.DEFAULT] (`X-Api-Key` header).
     */
    @JvmField
    var resolver: ApiKeyResolver = ApiKeyResolver.DEFAULT

    /** Renders 403 responses for authenticated callers denied by authorization. Defaults to a bare 403. */
    @JvmField
    var forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT

    /**
     * Renders 401 responses for failed or absent authentication.
     * Defaults to [UnauthorizedHandler.DEFAULT] (bare HTTP 401).
     */
    @JvmField
    var unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT

    internal fun buildAuthenticator(): ApiKeyAuthenticator {
        val keyLookup = lookup ?: throw SecurityConfigurationException(
            "apiKey.lookup is required but was not configured. " +
                "Set 'lookup = ...' inside the 'apiKey { }' block.",
        )
        return ApiKeyAuthenticator(lookup = keyLookup, resolver = resolver)
    }

}

/**
 * Builds an [AuthenticationStrategy.Sync] for opaque API-key authentication.
 *
 * Assign the result to `http.authentication`. Only [ApiKeyConfig.lookup] is required. The
 * identity type flowing through the extension is entirely yours — the extension attaches
 * whichever identity and roles your [ApiKeyLookup] returns via [ApiKeyDetails]. To use
 * [ApiKeyAuthenticator] directly, construct it and wrap it in a custom
 * [AuthenticationStrategy.Sync] (or [AuthenticationStrategy.sync]).
 */
fun apiKey(configure: Consumer<ApiKeyConfig>): AuthenticationStrategy.Sync {
    val config = ApiKeyConfig().also(configure::accept)
    return AuthenticationStrategy.sync(
        authenticator = config.buildAuthenticator(),
        unauthorizedHandler = config.unauthorizedHandler,
        forbiddenHandler = config.forbiddenHandler,
    )
}
