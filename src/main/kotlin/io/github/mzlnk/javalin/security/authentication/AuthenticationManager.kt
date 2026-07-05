package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context

/**
 * Orchestrates how an incoming request is authenticated.
 *
 * This is the top-level, fully pluggable authentication hook. The default implementation drives one
 * or more [AuthenticationProvider]s (see [ProviderAuthenticationManager]), but applications may
 * supply an entirely custom manager through the security DSL (`http { authenticationManager(...) }`)
 * when they need bespoke orchestration.
 *
 * Implementations must not throw for the "no credentials present" case; they should return
 * [AuthenticationResult.NotAuthenticated] and let the authorization rules decide.
 */
fun interface AuthenticationManager {

    fun authenticate(context: Context): AuthenticationResult

}

/**
 * The default [AuthenticationManager]: tries each configured [AuthenticationProvider] in order.
 *
 * The first provider that returns a decisive result ([AuthenticationResult.Success] or
 * [AuthenticationResult.Failure]) short-circuits and wins. If every provider reports
 * [AuthenticationResult.NotAuthenticated], the request is treated as anonymous.
 *
 * This is what lets multiple companion libraries (e.g. a JWT plugin and an API-key plugin) each
 * contribute a provider without silently clobbering one another.
 */
internal class ProviderAuthenticationManager(
    private val providers: List<AuthenticationProvider>,
) : AuthenticationManager {

    override fun authenticate(context: Context): AuthenticationResult {
        for (provider in providers) {
            when (val result = provider.resolve(context)) {
                is AuthenticationResult.Success -> return result
                is AuthenticationResult.Failure -> return result
                is AuthenticationResult.NotAuthenticated -> Unit
            }
        }
        return AuthenticationResult.NotAuthenticated
    }

}
