package io.github.mzlnk.javalin.security.authorization

/**
 * The set of built-in authorization rule factories.
 *
 * Declared as an interface so the single implementation ([AuthorizationRules]) can be reused
 * unqualified inside the `authorizeRequests { }` DSL through Kotlin interface delegation, keeping one
 * source of truth for the rule logic.
 */
interface AuthorizationRuleFactory {

    /** Always grants access, even to unauthenticated callers. */
    val permitAll: AuthorizationRule

    /** Never grants access. */
    val denyAll: AuthorizationRule

    /** Grants access to any authenticated caller. */
    val authenticated: AuthorizationRule

    /** Grants access when the caller holds the given [authority]. */
    fun hasAuthority(authority: String): AuthorizationRule

    /** Grants access when the caller holds at least one of the given [authorities]. */
    fun hasAnyAuthority(vararg authorities: String): AuthorizationRule

    /** Grants access when the caller holds the role, i.e. the authority `ROLE_<role>`. */
    fun hasRole(role: String): AuthorizationRule

    /** Grants access when the caller holds at least one of the given roles (`ROLE_<role>`). */
    fun hasAnyRole(vararg roles: String): AuthorizationRule

}

/**
 * Built-in [AuthorizationRule] factories.
 *
 * These are exposed to end users as unqualified members of the `authorizeRequests { }` DSL, but are
 * also available directly for programmatic use and testing.
 */
object AuthorizationRules : AuthorizationRuleFactory {

    internal const val ROLE_PREFIX = "ROLE_"

    override val permitAll: AuthorizationRule = AuthorizationRule { _, _ -> true }

    override val denyAll: AuthorizationRule = AuthorizationRule { _, _ -> false }

    override val authenticated: AuthorizationRule = AuthorizationRule { authentication, _ -> authentication.isAuthenticated }

    override fun hasAuthority(authority: String): AuthorizationRule =
        AuthorizationRule { authentication, _ -> authentication.isAuthenticated && authority in authentication.authorities }

    override fun hasAnyAuthority(vararg authorities: String): AuthorizationRule =
        AuthorizationRule { authentication, _ ->
            authentication.isAuthenticated && authorities.any { it in authentication.authorities }
        }

    override fun hasRole(role: String): AuthorizationRule = hasAuthority(ROLE_PREFIX + role)

    override fun hasAnyRole(vararg roles: String): AuthorizationRule =
        hasAnyAuthority(*roles.map { ROLE_PREFIX + it }.toTypedArray())

}
