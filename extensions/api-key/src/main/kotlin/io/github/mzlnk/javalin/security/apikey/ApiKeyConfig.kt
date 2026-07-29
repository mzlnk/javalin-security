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
 * [apiKeyLookup] is required. Roles come from [ApiKeyPrincipal.roles]. Builds an
 * [ApiKeyAuthenticator]. HTTP-only — there is no WebSocket variant.
 */
class ApiKeyConfig internal constructor() {

    /**
     * Resolves a raw API key to its stored [ApiKeyPrincipal]. Required; throws
     * [SecurityConfigurationException] if unset when the strategy is built.
     */
    @JvmField
    var apiKeyLookup: ApiKeyLookup? = null

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
        val lookup = apiKeyLookup ?: throw SecurityConfigurationException(
            "apiKey.apiKeyLookup is required but was not configured. " +
                "Set 'apiKeyLookup = ...' inside the 'apiKey { }' block.",
        )
        return ApiKeyAuthenticator.builder(lookup)
            .resolver(resolver)
            .build()
    }

}

/**
 * Builds an [AuthenticationStrategy.Sync] for opaque API-key authentication.
 *
 * Assign the result to `http.authentication`. Only [ApiKeyConfig.apiKeyLookup] is required.
 * To use [ApiKeyAuthenticator] directly, call [ApiKeyAuthenticator.builder] and wrap it in a
 * custom [AuthenticationStrategy.Sync].
 */
fun apiKey(configure: Consumer<ApiKeyConfig>): AuthenticationStrategy.Sync {
    val config = ApiKeyConfig().also(configure::accept)
    val authenticator = config.buildAuthenticator()
    val unauthorizedHandlerValue = config.unauthorizedHandler
    val forbiddenHandlerValue = config.forbiddenHandler
    return object : AuthenticationStrategy.Sync {
        override val unauthorizedHandler: UnauthorizedHandler get() = unauthorizedHandlerValue
        override val forbiddenHandler: ForbiddenHandler get() = forbiddenHandlerValue
        override fun authenticator() = authenticator
    }
}
