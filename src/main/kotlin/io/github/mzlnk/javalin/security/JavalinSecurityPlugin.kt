package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authorization.AuthorizationManager
import io.github.mzlnk.javalin.security.authorization.PathNormalizer
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
        val router = state.router

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

        val pathNormalizer = PathNormalizer(
            ignoreTrailingSlashes = router.ignoreTrailingSlashes,
            treatMultipleSlashesAsSingleSlash = router.treatMultipleSlashesAsSingleSlash,
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
