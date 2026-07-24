package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import io.github.mzlnk.javalin.security.http.HttpSecurityConfig
import io.github.mzlnk.javalin.security.http.authorization.AuthorizationManager
import io.github.mzlnk.javalin.security.ws.WsAuthorizationManager
import io.github.mzlnk.javalin.security.ws.WsSecurityConfig
import io.github.mzlnk.javalin.security.ws.WsSecurityGuard
import io.javalin.config.JavalinState
import io.javalin.http.Context
import io.javalin.plugin.ContextPlugin
import io.javalin.plugin.PluginPriority
import java.util.function.Consumer

/**
 * Javalin plugin that installs HTTP and WebSocket security guards.
 *
 * Register via `config.registerPlugin(JavalinSecurityPlugin { ... })` or [security]. Each guard is
 * installed only when its block (`http` / `ws`) is configured. Wiring runs in [onStart]. Resolved
 * authentication is available via `ctx.with(JavalinSecurityPlugin::class)` and the package extensions.
 * HTTP uses `beforeMatched` at [PluginPriority.EARLY]; WebSocket uses `wsBeforeUpgrade`.
 */
class JavalinSecurityPlugin(userConfig: Consumer<Config>) :
    ContextPlugin<JavalinSecurityPlugin.Config, SecurityContext>(userConfig, Config()) {

    /** Runs before other plugins' `beforeMatched` handlers so the guard executes early. */
    override fun priority(): PluginPriority = PluginPriority.EARLY

    /** Creates the per-request [SecurityContext] extension. */
    override fun createExtension(context: Context): SecurityContext = SecurityContext(context)

    /** Validates config and registers the HTTP and/or WebSocket guards. */
    override fun onStart(state: JavalinState) {
        val http = pluginConfig.http
        val ws = pluginConfig.ws
        val router = state.router

        ws?.validate()

        val pathNormalizer = PathNormalizer(contextPath = router.contextPath)

        // ── WebSocket guard ───────────────────────────────────────────────

        if (ws != null) {
            val wsAuthorizationManager = WsAuthorizationManager(
                entries = ws.rules.entries.map { entry ->
                    WsAuthorizationManager.Entry(pattern = entry.pattern, rule = entry.rule, routerConfig = router)
                },
                fallback = ws.rules.fallback,
            )

            val strategy = ws.authentication
            val wsGuard = WsSecurityGuard(
                authenticator = strategy.resolvedAuthenticator(),
                asyncAuthenticator = strategy.resolvedAsyncAuthenticator(),
                authorizationManager = wsAuthorizationManager,
                pathNormalizer = pathNormalizer,
                unauthorizedHandler = strategy.resolvedUnauthorizedHandler(),
                forbiddenHandler = strategy.resolvedForbiddenHandler(),
                allowedOrigins = ws.allowedOrigins?.toSet(),
            )

            state.routes.wsBeforeUpgrade(wsGuard::handle)
        }

        // ── HTTP guard ────────────────────────────────────────────────────

        if (http != null) {
            val authorizationManager = AuthorizationManager(
                entries = http.rules.entries.map { entry ->
                    AuthorizationManager.Entry(
                        pattern = entry.pattern,
                        method = entry.method,
                        rule = entry.rule,
                        routerConfig = router,
                    )
                },
                fallback = http.rules.fallback,
                allowCorsPreflight = http.rules.allowCorsPreflight,
            )

            val strategy = http.authentication
            val guard = SecurityGuard(
                authenticator = strategy.resolvedAuthenticator(),
                asyncAuthenticator = strategy.resolvedAsyncAuthenticator(),
                authorizationManager = authorizationManager,
                pathNormalizer = pathNormalizer,
                unauthorizedHandler = strategy.resolvedUnauthorizedHandler(),
                forbiddenHandler = strategy.resolvedForbiddenHandler(),
            )

            state.routes.beforeMatched(guard::handle)
        }
    }

    /**
     * Mutable security configuration for [JavalinSecurityPlugin].
     *
     * The HTTP guard is installed only when [http] is called at least once; the WS guard only when
     * [ws] is called at least once. If neither is called, no guards are installed.
     */
    class Config internal constructor() {

        private var httpConfig: HttpSecurityConfig? = null
        private var wsConfig: WsSecurityConfig? = null

        internal val http: HttpSecurityConfig? get() = httpConfig
        internal val ws: WsSecurityConfig? get() = wsConfig

        /**
         * Configures the HTTP security block. Repeated calls reuse the same [HttpSecurityConfig]
         * (fields are last-write-wins; rule entries accumulate).
         */
        fun http(configure: Consumer<HttpSecurityConfig>) {
            val config = httpConfig ?: HttpSecurityConfig().also { httpConfig = it }
            configure.accept(config)
        }

        /**
         * Configures the WebSocket security block. Repeated calls reuse the same [WsSecurityConfig]
         * (fields are last-write-wins; rule entries accumulate).
         */
        fun ws(configure: Consumer<WsSecurityConfig>) {
            val config = wsConfig ?: WsSecurityConfig().also { wsConfig = it }
            configure.accept(config)
        }

    }

    companion object {

        /** Request attribute key for the resolved [io.github.mzlnk.javalin.security.authentication.Authentication]. */
        const val AUTHENTICATION_ATTRIBUTE: String = "io.github.mzlnk.javalin.security.Authentication"

    }

}

// ── AuthenticationStrategy resolution helpers ──────────────────────────────
//
// A block with no [AuthenticationStrategy] configured (`null`) treats every caller as anonymous —
// the pattern-based rule table alone decides access — while still applying the strategy-agnostic
// defaults for the unauthorized/forbidden handlers.

private fun AuthenticationStrategy?.resolvedAuthenticator(): Authenticator? =
    (this as? AuthenticationStrategy.Sync)?.authenticator()

private fun AuthenticationStrategy?.resolvedAsyncAuthenticator(): AsyncAuthenticator? =
    (this as? AuthenticationStrategy.Async)?.authenticator()

private fun AuthenticationStrategy?.resolvedUnauthorizedHandler(): UnauthorizedHandler =
    this?.unauthorizedHandler ?: UnauthorizedHandler.DEFAULT

private fun AuthenticationStrategy?.resolvedForbiddenHandler(): ForbiddenHandler =
    this?.forbiddenHandler ?: ForbiddenHandler.DEFAULT
