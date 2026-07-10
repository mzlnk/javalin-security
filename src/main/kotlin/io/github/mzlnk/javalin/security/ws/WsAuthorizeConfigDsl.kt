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
     *
     * **Pattern matching note:** Unlike the HTTP block, which evaluates authorization against the
     * matched route template (e.g. `/users/{id}`), WS authorization matches the concrete request
     * path. Path-template placeholders such as `{id}` are treated as literal characters by the
     * underlying [io.github.mzlnk.javalin.security.authorization.AntPathMatcher] and will not
     * match real request paths. Use Ant-style wildcards in the pattern instead: `*` matches a
     * single path segment and `**` matches any number of path segments.
     * A mis-written pattern such as `/ws/room/{id}` simply fails to match, so the upgrade is
     * denied by the deny-by-default rule rather than inadvertently opened.
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
