package io.github.mzlnk.javalin.security.authorization

import io.javalin.security.RouteRole

/**
 * Built-in [Rule] factories exposed as unqualified members via Kotlin interface delegation.
 *
 * Logic lives in [Rules]; [DefaultRules] bridges this interface for delegation.
 * Prefer calling [Rules] directly (`Rules.allow()`, `Rules.hasRole(...)`, etc.).
 */
interface RuleFactory {

    /** Always grants access, including to unauthenticated callers. */
    val allow: Rule

    /** Never grants access. */
    val deny: Rule

    /** Grants access to any authenticated caller. */
    val authenticated: Rule

    /** Grants access when the caller holds [role]. */
    fun hasRole(role: RouteRole): Rule

    /** Grants access when the caller holds at least one of [roles]. */
    fun hasAnyRole(vararg roles: RouteRole): Rule

}

/** Exposes [Rules] as unqualified DSL members through [RuleFactory] delegation. */
internal object DefaultRules : RuleFactory {

    override val allow: Rule get() = Rules.allow()

    override val deny: Rule get() = Rules.deny()

    override val authenticated: Rule get() = Rules.authenticated()

    override fun hasRole(role: RouteRole): Rule = Rules.hasRole(role)

    override fun hasAnyRole(vararg roles: RouteRole): Rule = Rules.hasAnyRole(*roles)

}
