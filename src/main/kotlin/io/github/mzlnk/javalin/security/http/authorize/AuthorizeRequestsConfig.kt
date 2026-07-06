package io.github.mzlnk.javalin.security.http.authorize

import io.github.mzlnk.javalin.security.authorization.AuthorizationRule
import io.javalin.http.HandlerType

/**
 * Holds the raw authorization rule declarations for the `authorizeRequests` block.
 *
 * The declarations are kept as plain [Entry] specs (not a compiled matcher) because the correct
 * path-normalization and case-sensitivity settings are only known once the security is installed
 * into a Javalin instance. They are compiled at that point by [JavalinSecurityPlugin][io.github.mzlnk.javalin.security.JavalinSecurityPlugin].
 */
class AuthorizeRequestsConfig internal constructor(
    internal val entries: List<Entry>,
) {

    class Entry internal constructor(
        internal val pattern: String,
        internal val method: HandlerType?,
        internal val rule: AuthorizationRule,
    )

    class Builder {

        private val entries = mutableListOf<Entry>()

        /**
         * Registers a rule for requests matching [pattern] with the given HTTP [method].
         *
         * A custom rule may be supplied as a lambda, e.g.
         * `authorize("/x", GET, (auth, ctx) -> ...)`.
         */
        fun authorize(pattern: String, method: HandlerType, rule: AuthorizationRule): Builder {
            entries += Entry(pattern = pattern, method = method, rule = rule)
            return this
        }

        /**
         * Registers a rule for requests matching [pattern] for any HTTP method.
         *
         * A custom rule may be supplied as a lambda.
         */
        fun authorize(pattern: String, rule: AuthorizationRule): Builder {
            entries += Entry(pattern = pattern, method = null, rule = rule)
            return this
        }

        /**
         * Registers a terminal catch-all rule applied to every request (any path, any method).
         *
         * Because matching is first-match-wins, this should be declared last; it mirrors Spring
         * Security's `anyRequest()` and reduces the risk of leaving routes uncovered.
         */
        fun anyRequest(rule: AuthorizationRule): Builder {
            entries += Entry(pattern = "/**", method = null, rule = rule)
            return this
        }

        /**
         * Permits CORS preflight `OPTIONS` requests identified by the presence of the
         * `Access-Control-Request-Method` request header.
         *
         * This is a narrowly-scoped opt-in helper. It does **not** blanket-exempt all `OPTIONS`
         * requests, preserving the deny-by-default guarantee for regular `OPTIONS` traffic while
         * allowing browsers to complete the preflight exchange.
         *
         * **Ordering:** Call this before `anyRequest(denyAll)` (first-match-wins). Javalin's CORS
         * plugin must be registered alongside security to add the required CORS response headers;
         * this helper only controls whether the security guard passes the preflight through.
         */
        fun permitCorsPreflight(): Builder {
            entries += Entry(
                pattern = "/**",
                method = HandlerType.OPTIONS,
                rule = AuthorizationRule { _, ctx -> ctx.header("Access-Control-Request-Method") != null },
            )
            return this
        }

        fun build(): AuthorizeRequestsConfig = AuthorizeRequestsConfig(entries = entries.toList())

    }

}
