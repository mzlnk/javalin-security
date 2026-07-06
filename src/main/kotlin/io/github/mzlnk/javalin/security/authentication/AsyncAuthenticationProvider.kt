package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context
import java.util.concurrent.CompletableFuture

/**
 * An opt-in, asynchronous variant of [AuthenticationProvider].
 *
 * Use this when authentication requires I/O (remote IdP, JWKS endpoint, database lookup) that would
 * otherwise block the request thread. The security guard integrates with Javalin's async machinery
 * ([Context.future]) so the request thread is released while authentication is in flight.
 *
 * This is an advanced option. For most applications, especially those running with
 * `config.useVirtualThreads = true`, the blocking [AuthenticationProvider] is simpler and equally
 * acceptable — virtual threads make blocking I/O cheap.
 *
 * Register via `asyncAuthenticationProvider { ctx -> CompletableFuture.supplyAsync { ... } }`
 * inside the `http { }` DSL block.
 *
 * **Constraints:**
 * - Mutually exclusive with [AuthenticationManager] and blocking [AuthenticationProvider]s.
 * - Authorization and fail-closed semantics are preserved across the async boundary.
 * - CRLF-sanitized logging and no-message-leak behaviour are maintained in the async path.
 */
fun interface AsyncAuthenticationProvider {
    /** Resolves the authentication for [context] asynchronously. */
    fun resolve(context: Context): CompletableFuture<AuthenticationResult>
}
