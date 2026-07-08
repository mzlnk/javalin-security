package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticationManager
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.http.authorization.AccessDeniedHandler

/**
 * Kotlin DSL receiver for the `http { }` security block.
 *
 * Companion libraries contribute their authentication strategy by assigning
 * [authenticationManager] or [asyncAuthenticationManager] from their own extension functions
 * on this receiver, for example a future `jwt { }` extension.
 */
class HttpConfigDsl internal constructor() {

    private val builder = HttpConfig.Builder()

    /** Configures the request authorization rules. */
    fun authorizeRequests(init: AuthorizeRequestsConfigDsl.() -> Unit) {
        builder.authorizeRequests(AuthorizeRequestsConfigDsl().apply(init).build())
    }

    /**
     * Registers a blocking [AuthenticationManager].
     *
     * Mutually exclusive with [asyncAuthenticationManager].
     */
    var authenticationManager: AuthenticationManager? = null
        set(manager) {
            field = manager
            manager?.let { builder.authenticationManager(it) }
        }

    /**
     * Registers an opt-in async [AsyncAuthenticationManager] for I/O-bound authentication.
     *
     * Mutually exclusive with [authenticationManager].
     */
    var asyncAuthenticationManager: AsyncAuthenticationManager? = null
        set(manager) {
            field = manager
            manager?.let { builder.asyncAuthenticationManager(it) }
        }

    /** Overrides how failed/absent authentication is rendered (HTTP 401 by default). */
    var unauthorizedHandler: UnauthorizedHandler? = null
        set(handler) {
            field = handler
            handler?.let { builder.unauthorizedHandler(it) }
        }

    /** Overrides how access-denied for an authenticated caller is rendered (HTTP 403 by default). */
    var accessDeniedHandler: AccessDeniedHandler? = null
        set(handler) {
            field = handler
            handler?.let { builder.accessDeniedHandler(it) }
        }

    internal fun build(): HttpConfig = builder.build()

}
