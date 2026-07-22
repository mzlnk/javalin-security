package io.github.mzlnk.javalin.security.authorization

/**
 * The single source of truth for built-in [Rule] logic.
 *
 * Java users call these `@JvmStatic` methods directly — e.g. `Rules.allow()`,
 * `Rules.hasAuthority("ADMIN")` — with no extra indirection.
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

    /** Grants access when the caller holds the given [authority]. */
    @JvmStatic
    fun hasAuthority(authority: String): Rule =
        Rule { authentication, _ -> authentication.isAuthenticated && authority in authentication.authorities }

    /** Grants access when the caller holds at least one of the given [authorities]. */
    @JvmStatic
    fun hasAnyAuthority(vararg authorities: String): Rule =
        Rule { authentication, _ ->
            authentication.isAuthenticated && authorities.any { it in authentication.authorities }
        }

}
