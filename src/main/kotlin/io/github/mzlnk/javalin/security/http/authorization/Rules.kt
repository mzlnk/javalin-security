package io.github.mzlnk.javalin.security.http.authorization

/**
 * The single source of truth for built-in [AuthorizationRule] logic.
 *
 * Java users call these `@JvmStatic` methods directly — e.g. `Rules.permitAll()`,
 * `Rules.hasRole("ADMIN")` — with no extra indirection.
 *
 * Kotlin users access the same rules as unqualified DSL members inside `authorizeRequests { }`
 * via [AuthorizationRuleFactory] delegation on [AuthorizationRules], which delegates here.
 */
object Rules {

    /** Always grants access, even to unauthenticated callers. */
    @JvmStatic
    fun permitAll(): AuthorizationRule = AuthorizationRule { _, _ -> true }

    /** Never grants access. */
    @JvmStatic
    fun denyAll(): AuthorizationRule = AuthorizationRule { _, _ -> false }

    /** Grants access to any authenticated caller. */
    @JvmStatic
    fun authenticated(): AuthorizationRule = AuthorizationRule { authentication, _ -> authentication.isAuthenticated }

    /** Grants access when the caller holds the given [authority]. */
    @JvmStatic
    fun hasAuthority(authority: String): AuthorizationRule =
        AuthorizationRule { authentication, _ -> authentication.isAuthenticated && authority in authentication.authorities }

    /** Grants access when the caller holds at least one of the given [authorities]. */
    @JvmStatic
    fun hasAnyAuthority(vararg authorities: String): AuthorizationRule =
        AuthorizationRule { authentication, _ ->
            authentication.isAuthenticated && authorities.any { it in authentication.authorities }
        }

}
