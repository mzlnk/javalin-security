package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context

/**
 * The single pluggable extension point for authentication.
 *
 * A provider inspects the incoming request and decides whether it can authenticate it. Companion
 * libraries implement this interface (for example, by extracting a token and verifying it) and
 * register it through the security DSL.
 *
 * Only one provider is supported by design. To combine multiple authentication strategies, compose
 * them into a single provider that delegates as needed - the framework intentionally keeps that
 * logic out of the core.
 */
fun interface AuthenticationProvider {

    /**
     * Attempts to authenticate the request represented by [context].
     *
     * Implementations must not throw for the "no credentials present" case; they should return
     * [AuthenticationResult.NotAuthenticated] instead and let the authorization rules decide.
     */
    fun resolve(context: Context): AuthenticationResult

    companion object {

        /**
         * The default provider used when none is configured. It never authenticates, so every
         * request is treated as anonymous. Having a real instance keeps the provider non-nullable
         * throughout the framework.
         */
        val NONE: AuthenticationProvider = AuthenticationProvider { AuthenticationResult.NotAuthenticated }

    }

}
