package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.http.authorization.AuthorizationManager
import io.github.mzlnk.javalin.security.PathNormalizer
import io.github.mzlnk.javalin.security.ws.WsAuthorizationManager
import io.github.mzlnk.javalin.security.ws.WsSecurityGuard
import io.javalin.config.JavalinState
import io.javalin.plugin.Plugin
import io.javalin.plugin.PluginPriority

/**
 * The Javalin plugin that installs the security framework.
 *
 * All wiring happens in [onStart], which Javalin invokes once the entire `Javalin.create { }` block
 * has been applied. This is deliberate: the authorization matcher and the [PathNormalizer] mirror
 * Javalin's own router settings (`caseInsensitiveRoutes`, `ignoreTrailingSlashes`,
 * `treatMultipleSlashesAsSingleSlash`), and reading them at startup - rather than at the moment
 * `security { }` is called - guarantees they reflect the final router configuration regardless of
 * the order in which the user declares things. A mismatch there would be an authorization bypass,
 * so this ordering-independence is a security property, not just ergonomics.
 *
 * **Guards ordering:** When both HTTP and WS security are configured, the WS guard is registered as
 * a `beforeMatched` handler *before* the HTTP guard. The WS guard checks whether the request path
 * falls under WS jurisdiction (matches at least one WS authorization rule). If it does, the WS guard
 * handles authentication and authorization, then calls [io.javalin.http.Context.skipRemainingHandlers]
 * — preventing the HTTP guard from re-processing the request. If the path is not a WS path, the WS
 * guard passes through and the HTTP guard handles it normally.
 *
 * The plugin runs at [PluginPriority.EARLY] so the security guard's `beforeMatched` handler is
 * registered before `beforeMatched` handlers added by other plugins (those with [PluginPriority.NORMAL]
 * or [PluginPriority.LATE]). However, handlers added directly via `cfg.routes.beforeMatched()` or
 * `cfg.routes.before()` inside `Javalin.create { }` are registered before any plugin's `onStart`,
 * so they run before the guard. To observe a resolved [authentication.Authentication], add user `beforeMatched`
 * handlers on the Javalin instance after creation (`app.beforeMatched { ... }`).
 *
 * The plugin is not [repeatable], so accidentally calling `security { }` twice fails fast.
 */
internal class JavalinSecurityPlugin(
    private val security: JavalinSecurity,
) : Plugin<Unit?>() {

    override fun priority(): PluginPriority = PluginPriority.EARLY

    override fun onStart(state: JavalinState) {
        val http = security.httpConfig
        val ws = security.wsConfig
        val router = state.router

        val pathNormalizer = PathNormalizer(
            ignoreTrailingSlashes = router.ignoreTrailingSlashes,
            treatMultipleSlashesAsSingleSlash = router.treatMultipleSlashesAsSingleSlash,
        )

        // ── WebSocket guard (runs first) ──────────────────────────────────

        if (ws != null) {
            val wsAuthorizationManager = WsAuthorizationManager(
                ws.authorizeConfig.entries.map { entry ->
                    WsAuthorizationManager.Entry(
                        pattern = entry.pattern,
                        rule = entry.rule,
                        caseInsensitive = router.caseInsensitiveRoutes,
                    )
                },
            )

            val wsGuard = WsSecurityGuard(
                authenticationManager = ws.authenticationManager,
                asyncAuthenticationManager = ws.asyncAuthenticationManager,
                authorizationManager = wsAuthorizationManager,
                pathNormalizer = pathNormalizer,
                unauthorizedHandler = ws.unauthorizedHandler,
                accessDeniedHandler = ws.accessDeniedHandler,
            )

            state.routes.beforeMatched(wsGuard::handle)
        }

        // ── HTTP guard (runs second) ─────────────────────────────────────

        val authorizationManager = AuthorizationManager(
            http.authorizeRequestsConfig.entries.map { entry ->
                AuthorizationManager.Entry(
                    pattern = entry.pattern,
                    method = entry.method,
                    rule = entry.rule,
                    caseInsensitive = router.caseInsensitiveRoutes,
                )
            },
        )

        val guard = SecurityGuard(
            authenticationManager = http.authenticationManager,
            asyncAuthenticationManager = http.asyncAuthenticationManager,
            authorizationManager = authorizationManager,
            pathNormalizer = pathNormalizer,
            unauthorizedHandler = http.unauthorizedHandler,
            accessDeniedHandler = http.accessDeniedHandler,
        )

        state.routes.beforeMatched(guard::handle)
    }

}
