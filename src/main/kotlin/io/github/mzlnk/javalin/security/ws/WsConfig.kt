package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler
import java.util.function.Consumer

/**
 * The WebSocket security configuration: upgrade-time authorization rules, authentication
 * orchestration, and how authentication/authorization failures are rendered.
 *
 * Security is enforced once — during the HTTP upgrade request, before the WebSocket handshake
 * completes — via Javalin's `wsBeforeUpgrade` hook. Once the connection is established, individual
 * WS events (connect, message, close, error) are not subject to further authorization by this
 * library (though handlers may read the [io.github.mzlnk.javalin.security.authentication.Authentication]
 * from `ctx.authentication()` to make per-message decisions if desired).
 *
 * **Authorization scope:** authorization is enforced once at upgrade. A long-lived connection is
 * not re-checked if a token later expires mid-session. To re-validate credentials on individual
 * messages, read `ctx.authentication()` inside your `onMessage` handler and close the session if
 * the principal is no longer valid.
 *
 * **Deny-by-default:** upgrade requests that match no configured rule are denied (anonymous → 401,
 * authenticated → 403). Use `anyRequest = permitAll` inside `authorizeRequests` to open paths
 * explicitly.
 *
 * **CSWSH protection:** WebSocket handshakes are not subject to the browser same-origin policy
 * or CORS. If you authenticate via cookies, configure [Builder.allowedOrigins] to restrict which
 * origins may upgrade. When set, upgrades with a missing or unlisted `Origin` header are rejected
 * via the configured [Builder.accessDeniedHandler] (403 by default) before authentication runs.
 *
 * The authentication managers configured here are independent from the HTTP security block.
 * If no manager is set, all callers are treated as anonymous and authorization rules decide access.
 *
 * Use [Builder] to construct an instance.
 */
class WsConfig internal constructor(
    val authorizeConfig: WsAuthorizeConfig,
    internal val authenticationManager: AuthenticationManager?,
    internal val asyncAuthenticationManager: AsyncAuthenticationManager?,
    internal val unauthorizedHandler: UnauthorizedHandler,
    internal val accessDeniedHandler: AccessDeniedHandler,
    internal val allowedOrigins: Set<String>?,
) {

    class Builder {

        private var authorizeConfig: WsAuthorizeConfig = WsAuthorizeConfig.Builder().build()
        private var authenticationManager: AuthenticationManager? = null
        private var asyncAuthenticationManager: AsyncAuthenticationManager? = null
        private var unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT
        private var accessDeniedHandler: AccessDeniedHandler = AccessDeniedHandler.DEFAULT
        private var allowedOrigins: Set<String>? = null

        private var authorizeRequestsSet = false
        private var authenticationManagerSet = false
        private var asyncAuthenticationManagerSet = false
        private var unauthorizedHandlerSet = false
        private var accessDeniedHandlerSet = false
        private var allowedOriginsSet = false

        /** Configures the WebSocket authorization rules. */
        fun authorizeRequests(configure: Consumer<WsAuthorizeConfig.Builder>): Builder {
            if (authorizeRequestsSet) {
                throw SecurityConfigurationException(
                    "authorizeRequests was already configured; it may only be set once.",
                )
            }
            authorizeRequestsSet = true
            val builder = WsAuthorizeConfig.Builder()
            configure.accept(builder)
            this.authorizeConfig = builder.build()
            return this
        }

        internal fun authorizeRequests(config: WsAuthorizeConfig): Builder {
            if (authorizeRequestsSet) {
                throw SecurityConfigurationException(
                    "authorizeRequests was already configured; it may only be set once.",
                )
            }
            authorizeRequestsSet = true
            this.authorizeConfig = config
            return this
        }

        /**
         * Registers a blocking [AuthenticationManager] for WebSocket upgrade authentication.
         *
         * Mutually exclusive with [asyncAuthenticationManager].
         *
         * May only be called once; a second call throws [SecurityConfigurationException].
         */
        fun authenticationManager(manager: AuthenticationManager): Builder {
            if (authenticationManagerSet) {
                throw SecurityConfigurationException(
                    "authenticationManager was already configured; it may only be set once.",
                )
            }
            authenticationManagerSet = true
            this.authenticationManager = manager
            return this
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
         *
         * May only be called once; a second call throws [SecurityConfigurationException].
         */
        fun asyncAuthenticationManager(manager: AsyncAuthenticationManager): Builder {
            if (asyncAuthenticationManagerSet) {
                throw SecurityConfigurationException(
                    "asyncAuthenticationManager was already configured; it may only be set once.",
                )
            }
            asyncAuthenticationManagerSet = true
            this.asyncAuthenticationManager = manager
            return this
        }

        /**
         * Overrides how failed/absent WebSocket authentication is rendered (HTTP 401 by default).
         *
         * May only be called once; a second call throws [SecurityConfigurationException].
         */
        fun unauthorizedHandler(handler: UnauthorizedHandler): Builder {
            if (unauthorizedHandlerSet) {
                throw SecurityConfigurationException(
                    "unauthorizedHandler was already configured; it may only be set once.",
                )
            }
            unauthorizedHandlerSet = true
            this.unauthorizedHandler = handler
            return this
        }

        /**
         * Overrides how WebSocket access-denied for an authenticated caller is rendered
         * (HTTP 403 by default).
         *
         * May only be called once; a second call throws [SecurityConfigurationException].
         */
        fun accessDeniedHandler(handler: AccessDeniedHandler): Builder {
            if (accessDeniedHandlerSet) {
                throw SecurityConfigurationException(
                    "accessDeniedHandler was already configured; it may only be set once.",
                )
            }
            accessDeniedHandlerSet = true
            this.accessDeniedHandler = handler
            return this
        }

        /**
         * Restricts WebSocket upgrades to requests whose `Origin` header matches one of the
         * given [origins] exactly (e.g. `"https://app.example.com"`).
         *
         * **CSWSH protection:** WebSocket handshakes are not protected by the browser same-origin
         * policy or CORS. When this allowlist is set, a missing or unlisted `Origin` header causes
         * the upgrade to be rejected before authentication runs via the configured
         * [accessDeniedHandler] (403 by default, customizable). When unset (the default), no
         * Origin check is performed (backward-compatible).
         *
         * Each entry must be a non-blank full origin string. An empty or all-blank collection is
         * rejected at configuration time to avoid silently denying all upgrades.
         *
         * May only be called once; a second call throws [SecurityConfigurationException].
         */
        fun allowedOrigins(origins: Collection<String>): Builder {
            if (allowedOriginsSet) {
                throw SecurityConfigurationException(
                    "allowedOrigins was already configured; it may only be set once.",
                )
            }
            if (origins.isEmpty()) {
                throw SecurityConfigurationException(
                    "allowedOrigins must not be empty; providing an empty collection would deny " +
                        "all WebSocket upgrades. Remove allowedOrigins to disable the Origin check.",
                )
            }
            val blanks = origins.filter { it.isBlank() }
            if (blanks.isNotEmpty()) {
                throw SecurityConfigurationException(
                    "allowedOrigins contains blank entries; each entry must be a non-blank full " +
                        "origin string (e.g. \"https://app.example.com\").",
                )
            }
            allowedOriginsSet = true
            this.allowedOrigins = origins.toSet()
            return this
        }

        /**
         * Restricts WebSocket upgrades to requests whose `Origin` header matches one of the
         * given [origins] exactly (e.g. `"https://app.example.com"`).
         *
         * Convenience vararg overload; delegates to [allowedOrigins].
         */
        fun allowedOrigins(vararg origins: String): Builder = allowedOrigins(origins.toList())

        fun build(): WsConfig {
            if (authenticationManager != null && asyncAuthenticationManager != null) {
                throw SecurityConfigurationException(
                    "Both a blocking authenticationManager and an asyncAuthenticationManager were " +
                        "configured for the WS block, but they are mutually exclusive: choose one " +
                        "authentication path (blocking or async) per security configuration.",
                )
            }

            return WsConfig(
                authorizeConfig = authorizeConfig,
                authenticationManager = authenticationManager,
                asyncAuthenticationManager = asyncAuthenticationManager,
                unauthorizedHandler = unauthorizedHandler,
                accessDeniedHandler = accessDeniedHandler,
                allowedOrigins = allowedOrigins,
            )
        }

    }

}
