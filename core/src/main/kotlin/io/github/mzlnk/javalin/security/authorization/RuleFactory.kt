package io.github.mzlnk.javalin.security.authorization

import io.javalin.security.RouteRole

/**
 * The set of built-in [Rule] factories, exposed as unqualified members inside a rule-declaration
 * block (e.g. `rules { add("/x", GET, allow) }`) via Kotlin interface delegation.
 *
 * The actual rule logic lives in [Rules]; [DefaultRules] exists solely to bridge this interface
 * for delegation.
 */
interface RuleFactory {

    /** Always grants access, even to unauthenticated callers. */
    val allow: Rule

    /** Never grants access. */
    val deny: Rule

    /** Grants access to any authenticated caller. */
    val authenticated: Rule

    /** Grants access when the caller holds the given [role]. */
    fun hasRole(role: RouteRole): Rule

    /** Grants access when the caller holds at least one of the given [roles]. */
    fun hasAnyRole(vararg roles: RouteRole): Rule

}

/**
 * DSL adapter that exposes [Rules] as unqualified members of a rule-declaration block through
 * Kotlin interface delegation.
 */
internal object DefaultRules : RuleFactory {

    override val allow: Rule get() = Rules.allow()

    override val deny: Rule get() = Rules.deny()

    override val authenticated: Rule get() = Rules.authenticated()

    override fun hasRole(role: RouteRole): Rule = Rules.hasRole(role)

    override fun hasAnyRole(vararg roles: RouteRole): Rule = Rules.hasAnyRole(*roles)

}
