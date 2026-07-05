package io.github.mzlnk.javalin.security

/**
 * Entry point implemented by applications to declare their security configuration.
 *
 * Typical usage:
 * ```
 * class SecurityConfig : JavalinSecurityConfig {
 *     override val security = javalinSecurity {
 *         http {
 *             authorizeRequests {
 *                 authorize("/api/v1/users", GET, permitAll)
 *             }
 *         }
 *     }
 * }
 * ```
 * and registered through [io.github.mzlnk.javalin.security.configureSecurity].
 */
interface JavalinSecurityConfig {

    val security: JavalinSecurity

}
