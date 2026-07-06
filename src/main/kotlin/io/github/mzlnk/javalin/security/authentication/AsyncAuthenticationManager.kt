package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context
import java.util.concurrent.CompletableFuture

/**
 * Orchestrates one or more [AsyncAuthenticationProvider]s for a request, returning the resolved
 * [AuthenticationResult] as a [CompletableFuture].
 *
 * The default implementation ([AsyncProviderAuthenticationManager]) chains providers with
 * first-match-wins semantics identical to the synchronous [AuthenticationManager].
 */
fun interface AsyncAuthenticationManager {
    fun authenticate(context: Context): CompletableFuture<AuthenticationResult>
}
