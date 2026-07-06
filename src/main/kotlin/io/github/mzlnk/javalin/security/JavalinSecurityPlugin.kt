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
 * [configureSecurity] is called - guarantees they reflect the final router configuration regardless
 * of the order in which the user declares things. A mismatch there would be an authorization bypass,
 * so this ordering-independence is a security property, not just ergonomics.
 *
 * The plugin is not [repeatable], so accidentally installing security twice fails fast.
 */
internal class JavalinSecurityPlugin(
    private val security: JavalinSecurity,
) : Plugin<Unit?>() {

    override fun priority(): PluginPriority = PluginPriority.NORMAL

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
            authorizationManager = authorizationManager,
            pathNormalizer = pathNormalizer,
            authenticationEntryPoint = http.authenticationEntryPoint,
            accessDeniedHandler = http.accessDeniedHandler,
        )

        state.routes.beforeMatched(guard::handle)
    }

}
