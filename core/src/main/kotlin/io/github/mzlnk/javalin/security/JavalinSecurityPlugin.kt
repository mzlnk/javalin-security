package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.http.authorization.AuthorizationManager
import io.github.mzlnk.javalin.security.ws.WsAuthorizationManager
import io.github.mzlnk.javalin.security.ws.WsSecurityGuard
import io.javalin.config.JavalinState
import io.javalin.http.Context
import io.javalin.plugin.ContextPlugin
import io.javalin.plugin.PluginPriority
import java.util.function.Consumer

/**
 * The Javalin plugin that installs the security framework.
 *
 * Public, `Consumer`-configured, and installed exactly like every other Javalin plugin:
 *
 * ```kotlin
 * config.registerPlugin(JavalinSecurityPlugin { security ->
 *     security.http { http -> ... }
 * })
 * ```
 *
 * ```java
 * config.registerPlugin(new JavalinSecurityPlugin(security -> {
 *     security.http(http -> ...);
 * }));
 * ```
 *
 * As a [io.javalin.plugin.ContextPlugin], it also exposes the resolved
 * [io.github.mzlnk.javalin.security.authentication.Authentication] via `ctx.with(JavalinSecurityPlugin.class)`
 * — the same language-neutral access path every Javalin `ContextPlugin` uses, with no Kotlin-only
 * extension-function indirection required.
 *
 * All wiring happens in [onStart], which Javalin invokes once the entire `Javalin.create { }` block
 * has been applied. This is deliberate: the authorization matcher and the [PathNormalizer] mirror
 * Javalin's own router settings (`caseInsensitiveRoutes`, `ignoreTrailingSlashes`,
 * `treatMultipleSlashesAsSingleSlash`), and reading them at startup - rather than at the moment the
 * plugin is configured - guarantees they reflect the final router configuration regardless of the
 * order in which the user declares things. A mismatch there would be an authorization bypass, so
 * this ordering-independence is a security property, not just ergonomics.
 *
 * **Both guards are opt-in.** A guard is registered only when the corresponding block is configured:
 * the HTTP guard requires [SecurityConfig.http] to have been called, and the WS guard requires
 * [SecurityConfig.ws]. Calling `registerPlugin(JavalinSecurityPlugin { })` with neither configured
 * installs no guards at all, leaving all routes unprotected. This keeps the two protocols symmetric
 * and prevents silent over-protection of routes when only one protocol is in use.
 *
 * **HTTP guard:** registered as a `beforeMatched` handler. The plugin runs at [PluginPriority.EARLY]
 * so the guard is registered before `beforeMatched` handlers added by other plugins (those with
 * [PluginPriority.NORMAL] or [PluginPriority.LATE]). However, handlers added directly via
 * `cfg.routes.beforeMatched()` inside `Javalin.create { }` are registered before any plugin's
 * `onStart`, so they run before the guard. To observe a resolved
 * [io.github.mzlnk.javalin.security.authentication.Authentication], add user `beforeMatched`
 * handlers on the Javalin instance after creation (`app.beforeMatched { ... }`).
 *
 * **WS guard:** registered as a `wsBeforeUpgrade` handler, which runs on the HTTP upgrade request
 * before the WebSocket handshake completes. This is the correct lifecycle hook for WS security —
 * `beforeMatched` does not fire for WebSocket upgrade requests in Javalin 7. The WS guard and the
 * HTTP guard are independent; they share no ordering coupling.
 *
 * The plugin is not repeatable (context-extending plugins never are), so accidentally registering
 * it twice fails fast.
 */
class JavalinSecurityPlugin(userConfig: Consumer<SecurityConfig>) :
    ContextPlugin<SecurityConfig, SecurityContext>(userConfig, SecurityConfig()) {

    override fun priority(): PluginPriority = PluginPriority.EARLY

    override fun createExtension(context: Context): SecurityContext = SecurityContext(context)

    override fun onStart(state: JavalinState) {
        val http = pluginConfig.http
        val ws = pluginConfig.ws
        val router = state.router

        http?.validate()
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

            val wsGuard = WsSecurityGuard(
                authenticator = ws.authenticator,
                asyncAuthenticator = ws.asyncAuthenticator,
                authorizationManager = wsAuthorizationManager,
                roleMapper = ws.roleMapper,
                pathNormalizer = pathNormalizer,
                unauthorizedHandler = ws.unauthorizedHandler,
                forbiddenHandler = ws.forbiddenHandler,
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

            val guard = SecurityGuard(
                authenticator = http.authenticator,
                asyncAuthenticator = http.asyncAuthenticator,
                authorizationManager = authorizationManager,
                roleMapper = http.roleMapper,
                pathNormalizer = pathNormalizer,
                unauthorizedHandler = http.unauthorizedHandler,
                forbiddenHandler = http.forbiddenHandler,
            )

            state.routes.beforeMatched(guard::handle)
        }
    }

    companion object {

        /** Request attribute key under which the resolved [io.github.mzlnk.javalin.security.authentication.Authentication] is stored on the [Context]. */
        const val AUTHENTICATION_ATTRIBUTE: String = "io.github.mzlnk.javalin.security.Authentication"

    }

}
