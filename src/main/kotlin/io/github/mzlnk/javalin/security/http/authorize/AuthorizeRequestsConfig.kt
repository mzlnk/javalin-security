package io.github.mzlnk.javalin.security.http.authorize

import io.github.mzlnk.javalin.security.authorization.AuthorizationManager
import io.github.mzlnk.javalin.security.authorization.AuthorizationRule
import io.github.mzlnk.javalin.security.authorization.AuthorizationRules
import io.javalin.http.HandlerType

/**
 * Holds the compiled authorization rules for the `authorizeRequests { }` block.
 */
class AuthorizeRequestsConfig internal constructor(
    internal val authorizationManager: AuthorizationManager,
) {

    class Dsl {

        private val entries = mutableListOf<AuthorizationManager.Entry>()

        /** Always grants access, even to unauthenticated callers. */
        val permitAll: AuthorizationRule get() = AuthorizationRules.permitAll

        /** Never grants access. */
        val denyAll: AuthorizationRule get() = AuthorizationRules.denyAll

        /** Grants access to any authenticated caller. */
        val authenticated: AuthorizationRule get() = AuthorizationRules.authenticated

        /** Grants access when the caller holds the role, i.e. the authority `ROLE_<role>`. */
        fun hasRole(role: String): AuthorizationRule = AuthorizationRules.hasRole(role)

        /** Grants access when the caller holds at least one of the given roles. */
        fun hasAnyRole(vararg roles: String): AuthorizationRule = AuthorizationRules.hasAnyRole(*roles)

        /** Grants access when the caller holds the given [authority]. */
        fun hasAuthority(authority: String): AuthorizationRule = AuthorizationRules.hasAuthority(authority)

        /** Grants access when the caller holds at least one of the given [authorities]. */
        fun hasAnyAuthority(vararg authorities: String): AuthorizationRule = AuthorizationRules.hasAnyAuthority(*authorities)

        /**
         * Registers a rule for requests matching [pattern] with the given HTTP [method].
         *
         * A custom rule may be supplied as a trailing lambda, e.g.
         * `authorize("/x", GET) { auth, ctx -> ... }`.
         */
        fun authorize(pattern: String, method: HandlerType, rule: AuthorizationRule) {
            entries += AuthorizationManager.Entry(pattern = pattern, method = method, rule = rule)
        }

        /**
         * Registers a rule for requests matching [pattern] for any HTTP method.
         *
         * A custom rule may be supplied as a trailing lambda.
         */
        fun authorize(pattern: String, rule: AuthorizationRule) {
            entries += AuthorizationManager.Entry(pattern = pattern, method = null, rule = rule)
        }

        fun build(): AuthorizeRequestsConfig =
            AuthorizeRequestsConfig(authorizationManager = AuthorizationManager(entries.toList()))

    }

}
