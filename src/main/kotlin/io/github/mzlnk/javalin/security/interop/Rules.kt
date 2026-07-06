package io.github.mzlnk.javalin.security.interop

import io.github.mzlnk.javalin.security.authorization.AuthorizationRule
import io.github.mzlnk.javalin.security.authorization.AuthorizationRules

/**
 * Java-friendly static factory for the built-in [AuthorizationRule]s.
 *
 * Kotlin users access the same rules as unqualified DSL members inside `authorizeRequests { }` via
 * [io.github.mzlnk.javalin.security.authorization.AuthorizationRuleFactory] delegation. Java users
 * call these `@JvmStatic` methods instead — e.g. `Rules.permitAll()`, `Rules.hasRole("ADMIN")`.
 *
 * Every method delegates to [AuthorizationRules], the single source of truth for rule logic.
 */
object Rules {

    /** Always grants access, even to unauthenticated callers. */
    @JvmStatic
    fun permitAll(): AuthorizationRule = AuthorizationRules.permitAll

    /** Never grants access. */
    @JvmStatic
    fun denyAll(): AuthorizationRule = AuthorizationRules.denyAll

    /** Grants access to any authenticated caller. */
    @JvmStatic
    fun authenticated(): AuthorizationRule = AuthorizationRules.authenticated

    /** Grants access when the caller holds the given [authority]. */
    @JvmStatic
    fun hasAuthority(authority: String): AuthorizationRule = AuthorizationRules.hasAuthority(authority)

    /** Grants access when the caller holds at least one of the given [authorities]. */
    @JvmStatic
    fun hasAnyAuthority(vararg authorities: String): AuthorizationRule =
        AuthorizationRules.hasAnyAuthority(*authorities)

    /** Grants access when the caller holds the role, i.e. the authority `ROLE_<role>`. */
    @JvmStatic
    fun hasRole(role: String): AuthorizationRule = AuthorizationRules.hasRole(role)

    /** Grants access when the caller holds at least one of the given roles (`ROLE_<role>`). */
    @JvmStatic
    fun hasAnyRole(vararg roles: String): AuthorizationRule = AuthorizationRules.hasAnyRole(*roles)
}
