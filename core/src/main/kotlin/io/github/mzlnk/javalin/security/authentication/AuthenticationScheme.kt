package io.github.mzlnk.javalin.security.authentication

import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler

/**
 * A complete, self-contained authentication strategy: how to authenticate a caller, resolving
 * the [io.javalin.security.RouteRole]s the caller holds directly onto [Authentication.roles],
 * and how to render authentication/authorization failures.
 *
 * This is the single value assigned to `http.authentication` / `ws.authentication` — the only way
 * to wire up authentication for a security block. There is exactly one authentication mechanism
 * per block: assigning [AuthenticationScheme] again simply replaces the previous one (the same
 * last-write-wins style Javalin itself uses for `var` configuration fields), rather than the two
 * mechanisms silently combining or one leaking through a shared field.
 *
 * A scheme is either [Sync] (a blocking [Authenticator]) or [Async] (a non-blocking
 * [AsyncAuthenticator]) — never both. This makes the two paths mutually exclusive by
 * construction, so there is no configuration state to validate at startup.
 *
 * Companion libraries (e.g. `javalin-security-jwt`, `javalin-security-basic-auth`) provide ready-
 * made schemes via factory functions — `jwt { }`, `basicAuth { }` — that return a [Sync] instance
 * built from their own configuration block. Applications may also implement [Sync] or [Async]
 * directly for a fully custom authentication mechanism:
 *
 * ```kotlin
 * http.authentication = object : AuthenticationScheme.Sync {
 *     override fun authenticator() = Authenticator { ctx -> ... }
 * }
 * ```
 *
 * ```java
 * http.authentication = new AuthenticationScheme.Sync() {
 *     public Authenticator authenticator() {
 *         return ctx -> ...;
 *     }
 * };
 * ```
 */
sealed interface AuthenticationScheme {

    /** Overrides how failed/absent authentication is rendered. Defaults to a bare HTTP 401. */
    val unauthorizedHandler: UnauthorizedHandler get() = UnauthorizedHandler.DEFAULT

    /** Overrides how access-denied for an authenticated caller is rendered. Defaults to a bare HTTP 403. */
    val forbiddenHandler: ForbiddenHandler get() = ForbiddenHandler.DEFAULT

    /**
     * A scheme backed by a blocking [Authenticator].
     *
     * This is the default, zero-overhead path. Use [Async] instead when authentication performs
     * remote I/O (JWKS endpoint, database) and you want to release the request thread while it is
     * in flight.
     */
    interface Sync : AuthenticationScheme {

        /** The blocking authenticator used to resolve the caller's identity. */
        fun authenticator(): Authenticator

    }

    /**
     * A scheme backed by an opt-in, non-blocking [AsyncAuthenticator], for authentication that
     * performs remote I/O.
     *
     * The security guard integrates with Javalin's async machinery ([io.javalin.http.Context.future])
     * on the HTTP path to release the request thread while authentication is in flight. On the
     * WebSocket upgrade path (which is inherently synchronous), the returned future is resolved
     * via a blocking `join()` instead — see [AsyncAuthenticator] for the trade-offs.
     *
     * With `config.concurrency.useVirtualThreads = true`, the blocking [Sync] path is usually
     * sufficient — virtual threads make blocking I/O cheap. [Async] is an advanced option.
     */
    interface Async : AuthenticationScheme {

        /** The non-blocking authenticator used to resolve the caller's identity. */
        fun asyncAuthenticator(): AsyncAuthenticator

    }

}
