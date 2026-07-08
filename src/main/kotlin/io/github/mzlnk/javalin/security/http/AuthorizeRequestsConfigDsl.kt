package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.http.authorization.AuthorizationRule
import io.github.mzlnk.javalin.security.http.authorization.AuthorizationRuleFactory
import io.github.mzlnk.javalin.security.http.authorization.AuthorizationRules
import io.javalin.http.HandlerType

/**
 * Kotlin DSL receiver for the `authorizeRequests { }` block.
 *
 * Implements [AuthorizationRuleFactory] via delegation so the built-in rules ([permitAll],
 * [denyAll], [authenticated], [hasAuthority], etc.) are available as unqualified names inside the
 * block, e.g. `authorize("/api/...", GET, permitAll)`.
 */
class AuthorizeRequestsConfigDsl internal constructor() : AuthorizationRuleFactory by AuthorizationRules {

    private val builder = AuthorizeRequestsConfig.Builder()

    /**
     * Registers a rule for requests matching [pattern] with the given HTTP [method].
     *
     * A custom rule may be supplied as a trailing lambda, e.g.
     * `authorize("/x", GET) { auth, ctx -> auth.isAuthenticated }`.
     */
    fun authorize(pattern: String, method: HandlerType, rule: AuthorizationRule) {
        builder.authorize(pattern, method, rule)
    }

    /**
     * Registers a rule for requests matching [pattern] for any HTTP method.
     *
     * A custom rule may be supplied as a trailing lambda.
     */
    fun authorize(pattern: String, rule: AuthorizationRule) {
        builder.authorize(pattern, rule)
    }

    /**
     * Registers a terminal catch-all rule applied to every request (any path, any method).
     *
     * Because matching is first-match-wins, this should be declared last; it mirrors Spring
     * Security's `anyRequest()` and reduces the risk of leaving routes uncovered.
     */
    var anyRequest: AuthorizationRule? = null
        set(rule) {
            field = rule
            rule?.let { builder.anyRequest(it) }
        }

    /**
     * Permits CORS preflight `OPTIONS` requests identified by the presence of the
     * `Access-Control-Request-Method` request header.
     *
     * This is a narrowly-scoped opt-in helper. It does **not** blanket-exempt all `OPTIONS`
     * requests, preserving the deny-by-default guarantee for regular `OPTIONS` traffic while
     * allowing browsers to complete the preflight exchange.
     *
     * **Ordering:** Assign `true` before `anyRequest = denyAll` (first-match-wins). Javalin's CORS
     * plugin must be registered alongside the security configuration to add the required CORS
     * response headers; this helper only controls whether the security guard passes the preflight.
     */
    var permitCorsPreflight: Boolean = false
        set(value) {
            field = value
            if (value) builder.permitCorsPreflight()
        }

    internal fun build(): AuthorizeRequestsConfig = builder.build()

}
