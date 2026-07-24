package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context
import java.util.concurrent.CompletableFuture

/**
 * Asynchronous counterpart of [Authenticator] for remote I/O such as JWKS or database lookups.
 *
 * Returns a [CompletableFuture] of [AuthenticationResult]. Exceptional completion (or a
 * synchronous throw) is treated as [AuthenticationResult.Failure]. Register via
 * [AuthenticationStrategy.Async.authenticator].
 */
fun interface AsyncAuthenticator {

    /** Authenticates [context] asynchronously. */
    fun authenticate(context: Context): CompletableFuture<AuthenticationResult>
}
