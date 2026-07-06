package io.github.mzlnk.javalin.security.authorization

/**
 * The set of built-in authorization rule factories.
 *
 * Declared as an interface so [AuthorizationRules] can be mixed into the `authorizeRequests { }`
 * DSL receiver via Kotlin interface delegation, making all rule names available unqualified inside
 * the block.
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
 * DSL adapter that exposes [Rules] as unqualified members of the `authorizeRequests { }` block
 * through Kotlin interface delegation.
 *
 * The actual rule logic lives in [Rules]; this object exists solely to bridge the [AuthorizationRuleFactory]
 * interface required for delegation.
 */
object AuthorizationRules : AuthorizationRuleFactory {

    override val permitAll: AuthorizationRule get() = Rules.permitAll()

    override val denyAll: AuthorizationRule get() = Rules.denyAll()

    override val authenticated: AuthorizationRule get() = Rules.authenticated()

    override fun hasAuthority(authority: String): AuthorizationRule = Rules.hasAuthority(authority)

    override fun hasAnyAuthority(vararg authorities: String): AuthorizationRule = Rules.hasAnyAuthority(*authorities)

    override fun hasRole(role: String): AuthorizationRule = Rules.hasRole(role)

    override fun hasAnyRole(vararg roles: String): AuthorizationRule = Rules.hasAnyRole(*roles)

}
