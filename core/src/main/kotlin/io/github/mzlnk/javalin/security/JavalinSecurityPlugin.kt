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
 * Register via `config.registerPlugin(JavalinSecurityPlugin { ... })` or [security]. Both guards
 * are installed on start. Configure authentication, fallback, and related options on [Config.http]
 * and [Config.ws]; declare pattern-based rules on [Config.rules]. Wiring runs in [onStart].
 * Resolved authentication is available via `ctx.with(JavalinSecurityPlugin::class)` and the
 * package extensions. HTTP uses `beforeMatched` at [PluginPriority.EARLY]; WebSocket uses
 * `wsBeforeUpgrade`.
 */
class JavalinSecurityPlugin(userConfig: Consumer<Config>) :
    ContextPlugin<JavalinSecurityPlugin.Config, SecurityContext>(userConfig, Config()) {

    /** Runs before other plugins' `beforeMatched` handlers so the guard executes early. */
    override fun priority(): PluginPriority = PluginPriority.EARLY

    /** Creates the per-request [SecurityContext] extension. */
    override fun createExtension(context: Context): SecurityContext = SecurityContext(context)

    /** Validates config and registers the HTTP and WebSocket guards. */
    override fun onStart(state: JavalinState) {
        val http = pluginConfig.http
        val ws = pluginConfig.ws
        val rules = pluginConfig.rules
        val router = state.router

        ws.validate()

        val pathNormalizer = PathNormalizer(contextPath = router.contextPath)

        // ── WebSocket guard ───────────────────────────────────────────────

        val wsAuthorizationManager = WsAuthorizationManager(
            entries = rules.wsEntries().map { entry ->
                WsAuthorizationManager.Entry(pattern = entry.pattern, rule = entry.rule, routerConfig = router)
            },
            fallback = ws.fallback,
        )

        val wsStrategy = ws.authentication
        val wsGuard = WsSecurityGuard(
            authenticator = wsStrategy.resolvedAuthenticator(),
            asyncAuthenticator = wsStrategy.resolvedAsyncAuthenticator(),
            authorizationManager = wsAuthorizationManager,
            pathNormalizer = pathNormalizer,
            unauthorizedHandler = wsStrategy.resolvedUnauthorizedHandler(),
            forbiddenHandler = wsStrategy.resolvedForbiddenHandler(),
            allowedOrigins = ws.allowedOrigins?.toSet(),
        )

        state.routes.wsBeforeUpgrade(wsGuard::handle)

        // ── HTTP guard ────────────────────────────────────────────────────

        val authorizationManager = AuthorizationManager(
            entries = rules.httpEntries().map { entry ->
                AuthorizationManager.Entry(
                    pattern = entry.pattern,
                    method = entry.method,
                    rule = entry.rule,
                    routerConfig = router,
                )
            },
            fallback = http.fallback,
            allowCorsPreflight = http.allowCorsPreflight,
        )

        val httpStrategy = http.authentication
        val guard = SecurityGuard(
            authenticator = httpStrategy.resolvedAuthenticator(),
            asyncAuthenticator = httpStrategy.resolvedAsyncAuthenticator(),
            authorizationManager = authorizationManager,
            pathNormalizer = pathNormalizer,
            unauthorizedHandler = httpStrategy.resolvedUnauthorizedHandler(),
            forbiddenHandler = httpStrategy.resolvedForbiddenHandler(),
        )

        state.routes.beforeMatched(guard::handle)
    }

    /**
     * Mutable security configuration for [JavalinSecurityPlugin].
     *
     * Pattern-based rules for both HTTP and WebSocket are declared on [rules]. Channel-specific
     * options live on [http] and [ws]. Both guards are always installed when the plugin starts;
     * with no further configuration, unmatched traffic is denied via each channel's default
     * [io.github.mzlnk.javalin.security.authorization.Rules.deny] fallback.
     */
    class Config internal constructor() {

        /** HTTP authentication, fallback rule, and CORS preflight policy. */
        @JvmField
        val http: HttpSecurityConfig = HttpSecurityConfig()

        /** WebSocket authentication, Origin protection, and fallback rule. */
        @JvmField
        val ws: WsSecurityConfig = WsSecurityConfig()

        /**
         * Unified pattern-based rule table for HTTP and WebSocket.
         * Verb methods (`get`, `post`, …, `ws`) and [SecurityRules.apiBuilder] accumulate entries.
         */
        @JvmField
        val rules: SecurityRules = SecurityRules()

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
