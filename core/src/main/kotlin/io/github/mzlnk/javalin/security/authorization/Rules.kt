package io.github.mzlnk.javalin.security.authorization

import io.javalin.security.RouteRole

/**
 * Built-in [Rule] factories.
 *
 * Call from Java as `Rules.allow()`, `Rules.hasRole(...)`, etc. From Kotlin, the same rules are
 * available as unqualified DSL members inside `rules { }` via [RuleFactory].
 */
object Rules {

    /** Always grants access, including to unauthenticated callers. */
    @JvmStatic
    fun allow(): Rule = Rule { _, _ -> true }

    /** Never grants access. */
    @JvmStatic
    fun deny(): Rule = Rule { _, _ -> false }

    /** Grants access to any authenticated caller. */
    @JvmStatic
    fun authenticated(): Rule = Rule { authentication, _ -> authentication.isAuthenticated }

    /**
     * Grants access when the caller holds [role].
     * Matching uses [RouteRole] equality via set membership on the caller's roles.
     */
    @JvmStatic
    fun hasRole(role: RouteRole): Rule =
        Rule { authentication, _ -> authentication.isAuthenticated && role in authentication.roles }

    /**
     * Grants access when the caller holds at least one of [roles].
     * Matching uses [RouteRole] equality (see [hasRole]).
     */
    @JvmStatic
    fun hasAnyRole(vararg roles: RouteRole): Rule =
        Rule { authentication, _ -> authentication.isAuthenticated && roles.any { it in authentication.roles } }

}
