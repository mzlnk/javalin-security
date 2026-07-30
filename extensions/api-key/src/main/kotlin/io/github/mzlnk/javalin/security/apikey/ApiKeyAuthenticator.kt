package io.github.mzlnk.javalin.security.apikey

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.http.Context
import org.slf4j.LoggerFactory

/**
 * Implements opaque API-key authentication.
 *
 * Extracts a raw key via [resolver]: missing credentials yield
 * [AuthenticationResult.NotAuthenticated]. Looks up the key via [lookup]; an unknown key yields
 * [AuthenticationResult.Failure]. On success, returns [AuthenticationResult.Success] with the
 * looked-up identity as the identity. Construct directly, or via `apiKey { }` for the
 * plug-and-play path.
 */
class ApiKeyAuthenticator @JvmOverloads constructor(
    private val lookup: ApiKeyLookup,
    private val resolver: ApiKeyResolver = ApiKeyResolver.DEFAULT,
) : Authenticator {

    override fun authenticate(context: Context): AuthenticationResult {
        val rawKey = resolver.resolve(context) ?: return AuthenticationResult.NotAuthenticated

        val identity = lookup.lookup(rawKey)
        if (identity == null) {
            log.debug("API key authentication failed: unknown key")
            return AuthenticationResult.Failure(message = "invalid api key")
        }

        return AuthenticationResult.Success(Authentication.authenticated(identity))
    }

    private companion object {
        val log = LoggerFactory.getLogger(ApiKeyAuthenticator::class.java)
    }

}
