package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authorization.Rule
import io.github.mzlnk.javalin.security.authorization.compilePattern
import io.javalin.config.RouterConfig
import io.javalin.http.Context
import io.javalin.router.matcher.PathParser

/**
 * Evaluates the configured WS pattern-based rule table against an upgrade request whose endpoint
 * declares no [io.javalin.security.RouteRole]s.
 *
 * Matching is first-match-wins in declaration order. Each pattern is compiled once, at plugin
 * startup, into a Javalin [PathParser] - the same primitive Javalin's own router uses to match the
 * WS endpoint itself - and evaluated against the concrete (already context-path-stripped) upgrade
 * request path.
 *
 * A request that matches no entry falls through to [fallback] (deny, by default) - this is the
 * deny-by-default guarantee.
 */
internal class WsAuthorizationManager(
    private val entries: List<Entry>,
    private val fallback: Rule?,
) {

    class Entry(
        pattern: String,
        val rule: Rule,
        routerConfig: RouterConfig,
    ) {
        private val parser = compilePattern(pattern, routerConfig)

        fun matches(path: String): Boolean = parser.matches(path)
    }

    /**
     * Evaluates the first matching rule for the given [path].
     *
     * Returns `true` when a matching rule grants access, or when no entry matches but [fallback]
     * grants access. Returns `false` (deny) otherwise - the deny-by-default guarantee.
     */
    fun isGranted(path: String, authentication: Authentication, context: Context): Boolean {
        val matched = entries.firstOrNull { it.matches(path) }
        if (matched != null) {
            return matched.rule.isGranted(authentication, context)
        }
        return fallback?.isGranted(authentication, context) ?: false
    }

}
