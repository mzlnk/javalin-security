package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context
import java.util.concurrent.CompletableFuture

/**
 * The async counterpart of [AuthenticationManager] for authentication that performs remote I/O
 * (e.g. JWKS endpoint, database lookup).
 *
 * Implementations inspect the incoming request and return a [CompletableFuture] that resolves to
 * a decisive [AuthenticationResult]: [AuthenticationResult.Success] when valid credentials are
 * present, [AuthenticationResult.Failure] when credentials are present but invalid, or
 * [AuthenticationResult.NotAuthenticated] when no credentials are present at all.
 *
 * The security guard integrates with Javalin's async machinery ([io.javalin.http.Context.future])
 * to release the request thread while the future is in flight. If the future completes
 * exceptionally (or the implementation throws synchronously), the guard treats it as an
 * [AuthenticationResult.Failure] and returns a logged 401, preserving fail-closed semantics.
 *
 * Register via `http { asyncAuthenticationManager = { ctx -> ... } }` inside the security DSL,
 * or via the fluent Java builder: `.asyncAuthenticationManager(ctx -> ...)`.
 *
 * For `config.useVirtualThreads = true` applications the blocking [AuthenticationManager] is
 * usually sufficient — virtual threads make blocking I/O cheap. Async is an advanced option.
 */
fun interface AsyncAuthenticationManager {
    fun authenticate(context: Context): CompletableFuture<AuthenticationResult>
}
