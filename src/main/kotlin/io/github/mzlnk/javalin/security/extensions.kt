package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authorization.AuthorizationManager
import io.github.mzlnk.javalin.security.authorization.PathNormalizer
import io.javalin.config.JavalinConfig
import io.javalin.http.Context

/** Request attribute key under which the resolved [Authentication] is stored on the [Context]. */
internal const val AUTHENTICATION_ATTRIBUTE = "io.github.mzlnk.javalin.security.authentication"

/**
 * Installs the security framework into a Javalin application.
 *
 * Call this inside `Javalin.create { }`:
 * ```
 * Javalin.create { config ->
 *     config.configureSecurity(SecurityConfig())
 *     config.routes.get("/api/v1/resource") { it.result("ok") }
 * }
 * ```
 *
 * It registers a `beforeMatched` guard that authenticates and authorizes every matched request.
 * Failures surface as Javalin's native `UnauthorizedResponse` (401) and `ForbiddenResponse` (403).
 */
fun JavalinConfig.configureSecurity(config: JavalinSecurityConfig) {
    val http = config.security.httpConfig

    val caseInsensitive = router.caseInsensitiveRoutes
    val authorizationManager = AuthorizationManager(
        http.authorizeRequestsConfig.entries.map { entry ->
            AuthorizationManager.Entry(
                pattern = entry.pattern,
                method = entry.method,
                rule = entry.rule,
                caseInsensitive = caseInsensitive,
            )
        },
    )

    val pathNormalizer = PathNormalizer(
        contextPath = router.contextPath,
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

    routes.beforeMatched(guard::handle)
}

/**
 * Returns the [Authentication] resolved for the current request.
 *
 * After the security guard has run this is always populated (an unauthenticated [Authentication]
 * when no credentials were provided). If security is not installed it falls back to unauthenticated.
 */
fun Context.authentication(): Authentication =
    attribute<Authentication>(AUTHENTICATION_ATTRIBUTE) ?: Authentication.unauthenticated()

/** Convenience accessor for the [Principal] of the current request's [authentication]. */
fun Context.principal(): Principal = authentication().principal
