package io.github.mzlnk.javalin.security.authorization

import io.javalin.security.RouteRole

/**
 * The single source of truth for built-in [Rule] logic.
 *
 * Java users call these `@JvmStatic` methods directly — e.g. `Rules.allow()`,
 * `Rules.hasRole(Role.ADMIN)` — with no extra indirection.
 *
 * Kotlin users access the same rules as unqualified DSL members inside a rule-declaration block
 * (e.g. `rules { }`) via [RuleFactory] delegation to [DefaultRules], which delegates here.
 */
object Rules {

    /** Always grants access, even to unauthenticated callers. */
    @JvmStatic
    fun allow(): Rule = Rule { _, _ -> true }

    /** Never grants access. */
    @JvmStatic
    fun deny(): Rule = Rule { _, _ -> false }

    /** Grants access to any authenticated caller. */
    @JvmStatic
    fun authenticated(): Rule = Rule { authentication, _ -> authentication.isAuthenticated }

    /**
     * Grants access when the caller holds the given [role].
     *
     * Matching is a plain `role in authentication.roles` set-membership check, so it relies on
     * [RouteRole] equality — enum constants and data classes compare correctly out of the box.
     */
    @JvmStatic
    fun hasRole(role: RouteRole): Rule =
        Rule { authentication, _ -> authentication.isAuthenticated && role in authentication.roles }

    /**
     * Grants access when the caller holds at least one of the given [roles].
     *
     * Matching is a plain set-membership check per [RouteRole] equality (see [hasRole]).
     */
    @JvmStatic
    fun hasAnyRole(vararg roles: RouteRole): Rule =
        Rule { authentication, _ -> authentication.isAuthenticated && roles.any { it in authentication.roles } }

}
