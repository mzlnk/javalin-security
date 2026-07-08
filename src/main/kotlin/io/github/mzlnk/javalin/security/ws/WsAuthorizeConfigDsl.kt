package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.authorization.AuthorizationRule
import io.github.mzlnk.javalin.security.authorization.AuthorizationRuleFactory
import io.github.mzlnk.javalin.security.authorization.AuthorizationRules

/**
 * Kotlin DSL receiver for the WebSocket `authorizeRequests { }` block.
 *
 * Implements [AuthorizationRuleFactory] via delegation so the built-in rules ([permitAll],
 * [denyAll], [authenticated], [hasAuthority], etc.) are available as unqualified names inside the
 * block.
 */
class WsAuthorizeConfigDsl internal constructor() : AuthorizationRuleFactory by AuthorizationRules {

    private val builder = WsAuthorizeConfig.Builder()

    /**
     * Registers an authorization rule for WebSocket upgrade requests matching [pattern].
     *
     * A custom rule may be supplied as a trailing lambda.
     */
    fun authorize(pattern: String, rule: AuthorizationRule) {
        builder.authorize(pattern, rule)
    }

    /**
     * Registers a terminal catch-all rule applied to every WebSocket upgrade request (any path).
     *
     * Because matching is first-match-wins, this should be declared last; it mirrors Spring
     * Security's `anyRequest()` and reduces the risk of leaving WS endpoints uncovered.
     */
    var anyRequest: AuthorizationRule? = null
        set(rule) {
            field = rule
            rule?.let { builder.anyRequest(it) }
        }

    internal fun build(): WsAuthorizeConfig = builder.build()

}
