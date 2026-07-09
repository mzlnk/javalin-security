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
 * **HTTP guard:** registered as a `beforeMatched` handler. The plugin runs at [PluginPriority.EARLY]
 * so the guard is registered before `beforeMatched` handlers added by other plugins (those with
 * [PluginPriority.NORMAL] or [PluginPriority.LATE]). However, handlers added directly via
 * `cfg.routes.beforeMatched()` inside `Javalin.create { }` are registered before any plugin's
 * `onStart`, so they run before the guard. To observe a resolved [authentication.Authentication],
 * add user `beforeMatched` handlers on the Javalin instance after creation (`app.beforeMatched { ... }`).
 *
 * **WS guard:** registered as a `wsBeforeUpgrade` handler, which runs on the HTTP upgrade request
 * before the WebSocket handshake completes. This is the correct lifecycle hook for WS security —
 * `beforeMatched` does not fire for WebSocket upgrade requests in Javalin 7. The WS guard and the
 * HTTP guard are independent; they share no ordering coupling.
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

            state.routes.wsBeforeUpgrade(wsGuard::handle)
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
