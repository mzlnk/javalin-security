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
     *
     * **Blocking trade-off:** Unlike the HTTP async path (which releases the request thread via
     * `ctx.future`), the WebSocket handshake is synchronous — `ctx.future` deferral is not a
     * supported Javalin pattern for WS upgrades. The returned [java.util.concurrent.CompletableFuture]
     * is therefore resolved via a blocking `join()` on the upgrade thread. This is safe and correct,
     * but it pins an upgrade thread for the duration of the I/O call.
     *
     * Recommendations to avoid Jetty thread-pool pressure under load:
     * - Enable `config.useVirtualThreads = true` (virtual threads make blocking I/O cheap), or
     * - Use a pre-fetched token cache so lookups are in-memory rather than remote.
     *
     * For most applications the blocking [authenticationManager] is sufficient; async is an
     * advanced option for I/O-heavy identity providers.
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

    /**
     * Restricts WebSocket upgrades to requests whose `Origin` header matches one of the given
     * origins exactly (e.g. `"https://app.example.com"`).
     *
     * **CSWSH protection:** WebSocket handshakes are not protected by the browser same-origin
     * policy or CORS. When this allowlist is set, a missing or unlisted `Origin` header causes
     * the upgrade to be rejected before authentication runs via the configured
     * [accessDeniedHandler] (403 by default, customizable). When unset (the default), no
     * Origin check is performed.
     *
     * Each entry must be a non-blank full origin string. An empty or all-blank collection is
     * rejected at configuration time to avoid silently denying all upgrades.
     */
    var allowedOrigins: Collection<String>? = null
        set(origins) {
            field = origins
            origins?.let { builder.allowedOrigins(it) }
        }

    internal fun build(): WsConfig = builder.build()

}
