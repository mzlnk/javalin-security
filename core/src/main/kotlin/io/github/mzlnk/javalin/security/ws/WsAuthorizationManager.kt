package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authorization.Rule
import io.github.mzlnk.javalin.security.authorization.compilePattern
import io.javalin.config.RouterConfig
import io.javalin.http.Context

/**
 * Evaluates the WebSocket pattern-based rule table for upgrade requests with no route-declared roles.
 *
 * First match wins in declaration order. Patterns are compiled once at startup into a Javalin
 * [io.javalin.router.matcher.PathParser]. Unmatched requests fall through to [fallback] (deny when unset).
 */
internal class WsAuthorizationManager(
    private val entries: List<Entry>,
    private val fallback: Rule?,
) {

    /** Compiled rule entry for a WS path pattern. */
    class Entry(
        pattern: String,
        val rule: Rule,
        routerConfig: RouterConfig,
    ) {
        private val parser = compilePattern(pattern, routerConfig)

        /** Returns `true` when [path] matches this entry. */
        fun matches(path: String): Boolean = parser.matches(path)
    }

    /**
     * Returns whether access is granted for [path] given [authentication].
     * Uses [fallback] when no entry matches; denies when [fallback] is unset.
     */
    fun isGranted(path: String, authentication: Authentication, context: Context): Boolean {
        val matched = entries.firstOrNull { it.matches(path) }
        if (matched != null) {
            return matched.rule.isGranted(authentication, context)
        }
        return fallback?.isGranted(authentication, context) ?: false
    }

}
