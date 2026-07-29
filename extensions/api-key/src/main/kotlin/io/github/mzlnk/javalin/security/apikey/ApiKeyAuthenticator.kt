package io.github.mzlnk.javalin.security.apikey

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.http.Context
import org.slf4j.LoggerFactory

/**
 * Implements opaque API-key authentication.
 *
 * Extracts a raw key via [ApiKeyResolver]: missing credentials yield
 * [AuthenticationResult.NotAuthenticated]. Looks up the key via [ApiKeyLookup]; an unknown key
 * yields [AuthenticationResult.Failure]. On success, returns [AuthenticationResult.Success] with
 * an [ApiKeyIdentity] and the principal's roles. Construct via `apiKey { }` or [Builder].
 */
class ApiKeyAuthenticator private constructor(
    private val apiKeyLookup: ApiKeyLookup,
    private val resolver: ApiKeyResolver,
) : Authenticator {

    override fun authenticate(context: Context): AuthenticationResult {
        val rawKey = resolver.resolve(context) ?: return AuthenticationResult.NotAuthenticated

        val principal = apiKeyLookup.lookup(rawKey)
        if (principal == null) {
            log.debug("API key authentication failed: unknown key")
            return AuthenticationResult.Failure(message = "invalid api key")
        }

        val identity = ApiKeyIdentity(principal.name)
        return AuthenticationResult.Success(Authentication.authenticated(identity, principal.roles))
    }

    /** Fluent builder for constructing an [ApiKeyAuthenticator]. */
    class Builder(private val apiKeyLookup: ApiKeyLookup) {

        private var resolver: ApiKeyResolver = ApiKeyResolver.DEFAULT

        /**
         * Overrides how the API key is located in the request.
         *
         * Defaults to [ApiKeyResolver.DEFAULT] (`X-Api-Key` header).
         */
        fun resolver(resolver: ApiKeyResolver): Builder {
            this.resolver = resolver
            return this
        }

        /** Builds an [ApiKeyAuthenticator] with the configured settings. */
        fun build(): ApiKeyAuthenticator = ApiKeyAuthenticator(
            apiKeyLookup = apiKeyLookup,
            resolver = resolver,
        )

    }

    companion object {

        private val log = LoggerFactory.getLogger(ApiKeyAuthenticator::class.java)

        /**
         * Creates a [Builder] pre-loaded with the required [apiKeyLookup].
         *
         * [apiKeyLookup] is the only required argument; other settings use defaults.
         */
        @JvmStatic
        fun builder(apiKeyLookup: ApiKeyLookup): Builder = Builder(apiKeyLookup)

        /** Creates an [ApiKeyAuthenticator] with the given [apiKeyLookup] and default settings. */
        @JvmStatic
        fun of(apiKeyLookup: ApiKeyLookup): ApiKeyAuthenticator = Builder(apiKeyLookup).build()

    }

}
