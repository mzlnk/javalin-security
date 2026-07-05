package io.github.mzlnk.javalin.security.authorization

/**
 * Built-in [AuthorizationRule] factories.
 *
 * These are exposed to end users as unqualified members of the `authorizeRequests { }` DSL, but are
 * also available directly for programmatic use and testing.
 */
object AuthorizationRules {

    internal const val ROLE_PREFIX = "ROLE_"

    /** Always grants access, even to unauthenticated callers. */
    val permitAll: AuthorizationRule = AuthorizationRule { _, _ -> true }

    /** Never grants access. */
    val denyAll: AuthorizationRule = AuthorizationRule { _, _ -> false }

    /** Grants access to any authenticated caller. */
    val authenticated: AuthorizationRule = AuthorizationRule { authentication, _ -> authentication.isAuthenticated }

    /** Grants access when the caller holds the given [authority]. */
    fun hasAuthority(authority: String): AuthorizationRule =
        AuthorizationRule { authentication, _ -> authentication.isAuthenticated && authority in authentication.authorities }

    /** Grants access when the caller holds at least one of the given [authorities]. */
    fun hasAnyAuthority(vararg authorities: String): AuthorizationRule =
        AuthorizationRule { authentication, _ ->
            authentication.isAuthenticated && authorities.any { it in authentication.authorities }
        }

    /** Grants access when the caller holds the role, i.e. the authority `ROLE_<role>`. */
    fun hasRole(role: String): AuthorizationRule = hasAuthority(ROLE_PREFIX + role)

    /** Grants access when the caller holds at least one of the given roles (`ROLE_<role>`). */
    fun hasAnyRole(vararg roles: String): AuthorizationRule =
        hasAnyAuthority(*roles.map { ROLE_PREFIX + it }.toTypedArray())

}
