package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context
import java.util.concurrent.CompletableFuture

/**
 * Internal [AsyncAuthenticationManager] implementation that chains a list of
 * [AsyncAuthenticationProvider]s with the same first-match-wins semantics as
 * [ProviderAuthenticationManager]: the first [AuthenticationResult.Success] or
 * [AuthenticationResult.Failure] short-circuits the chain; if every provider returns
 * [AuthenticationResult.NotAuthenticated] the request is treated as anonymous.
 */
internal class AsyncProviderAuthenticationManager(
    private val providers: List<AsyncAuthenticationProvider>,
) : AsyncAuthenticationManager {

    override fun authenticate(context: Context): CompletableFuture<AuthenticationResult> =
        chainProviders(context, providers)

    private fun chainProviders(
        context: Context,
        remaining: List<AsyncAuthenticationProvider>,
    ): CompletableFuture<AuthenticationResult> {
        if (remaining.isEmpty()) {
            return CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated)
        }
        return remaining.first().resolve(context).thenCompose { result ->
            when (result) {
                is AuthenticationResult.Success, is AuthenticationResult.Failure -> CompletableFuture.completedFuture(result)
                AuthenticationResult.NotAuthenticated -> chainProviders(context, remaining.drop(1))
            }
        }
    }
}
