package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context

/**
 * The single pluggable extension point for authentication.
 *
 * A provider inspects the incoming request and decides whether it can authenticate it. Companion
 * libraries implement this interface (for example, by extracting a token and verifying it) and
 * register it through the security DSL.
 *
 * Multiple providers may be registered; the default [AuthenticationManager] tries them in
 * registration order and the first decisive result wins. For bespoke orchestration, supply a custom
 * [AuthenticationManager] instead.
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
         * A no-op provider that never authenticates, so every request is treated as anonymous.
         * Useful as an explicit placeholder or in tests.
         */
        val NONE: AuthenticationProvider = AuthenticationProvider { AuthenticationResult.NotAuthenticated }

    }

}
