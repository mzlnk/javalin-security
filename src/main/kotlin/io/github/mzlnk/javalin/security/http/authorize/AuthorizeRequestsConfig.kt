package io.github.mzlnk.javalin.security.http.authorize

import io.github.mzlnk.javalin.security.authorization.AuthorizationRule
import io.github.mzlnk.javalin.security.authorization.AuthorizationRuleFactory
import io.github.mzlnk.javalin.security.authorization.AuthorizationRules
import io.javalin.http.HandlerType

/**
 * Holds the raw authorization rule declarations for the `authorizeRequests { }` block.
 *
 * The declarations are kept as plain [Entry] specs (not a compiled matcher) because the correct
 * path-normalization and case-sensitivity settings are only known once the security is installed
 * into a Javalin instance. They are compiled at that point by
 * [io.github.mzlnk.javalin.security.configureSecurity].
 */
class AuthorizeRequestsConfig internal constructor(
    internal val entries: List<Entry>,
) {

    class Entry internal constructor(
        internal val pattern: String,
        internal val method: HandlerType?,
        internal val rule: AuthorizationRule,
    )

    class Dsl : AuthorizationRuleFactory by AuthorizationRules {

        private val entries = mutableListOf<Entry>()

        /**
         * Registers a rule for requests matching [pattern] with the given HTTP [method].
         *
         * A custom rule may be supplied as a trailing lambda, e.g.
         * `authorize("/x", GET) { auth, ctx -> ... }`.
         */
        fun authorize(pattern: String, method: HandlerType, rule: AuthorizationRule) {
            entries += Entry(pattern = pattern, method = method, rule = rule)
        }

        /**
         * Registers a rule for requests matching [pattern] for any HTTP method.
         *
         * A custom rule may be supplied as a trailing lambda.
         */
        fun authorize(pattern: String, rule: AuthorizationRule) {
            entries += Entry(pattern = pattern, method = null, rule = rule)
        }

        /**
         * Registers a terminal catch-all rule applied to every request (any path, any method).
         *
         * Because matching is first-match-wins, this should be declared last; it mirrors Spring
         * Security's `anyRequest()` and reduces the risk of leaving routes uncovered.
         */
        fun anyRequest(rule: AuthorizationRule) {
            entries += Entry(pattern = "/**", method = null, rule = rule)
        }

        fun build(): AuthorizeRequestsConfig = AuthorizeRequestsConfig(entries = entries.toList())

    }

}
