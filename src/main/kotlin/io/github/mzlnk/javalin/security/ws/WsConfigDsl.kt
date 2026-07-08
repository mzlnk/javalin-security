package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler

/**
 * Kotlin DSL receiver for the WebSocket `ws { }` security block.
 *
 * Companion libraries contribute their authentication strategy by assigning
 * [authenticationManager] or [asyncAuthenticationManager] from their own extension functions
 * on this receiver, for example a future `jwt { }` extension.
 */
class WsConfigDsl internal constructor() {

    private val builder = WsConfig.Builder()

    /** Configures the WebSocket authorization rules. */
    fun authorizeRequests(init: WsAuthorizeConfigDsl.() -> Unit) {
        builder.authorizeRequests(WsAuthorizeConfigDsl().apply(init).build())
    }

    /**
     * Registers a blocking [AuthenticationManager] for WebSocket upgrade authentication.
     *
     * Mutually exclusive with [asyncAuthenticationManager].
     */
    var authenticationManager: AuthenticationManager? = null
        set(manager) {
            field = manager
            manager?.let { builder.authenticationManager(it) }
        }

    /**
     * Registers an opt-in async [AsyncAuthenticationManager] for I/O-bound WebSocket
     * authentication.
     *
     * Mutually exclusive with [authenticationManager].
     */
    var asyncAuthenticationManager: AsyncAuthenticationManager? = null
        set(manager) {
            field = manager
            manager?.let { builder.asyncAuthenticationManager(it) }
        }

    /** Overrides how failed/absent WebSocket authentication is rendered (HTTP 401 by default). */
    var unauthorizedHandler: UnauthorizedHandler? = null
        set(handler) {
            field = handler
            handler?.let { builder.unauthorizedHandler(it) }
        }

    /** Overrides how WebSocket access-denied for an authenticated caller is rendered (HTTP 403 by default). */
    var accessDeniedHandler: AccessDeniedHandler? = null
        set(handler) {
            field = handler
            handler?.let { builder.accessDeniedHandler(it) }
        }

    internal fun build(): WsConfig = builder.build()

}
