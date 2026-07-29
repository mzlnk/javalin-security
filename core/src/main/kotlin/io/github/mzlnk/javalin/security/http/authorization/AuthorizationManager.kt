package io.github.mzlnk.javalin.security.http.authorization

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authorization.Rule
import io.github.mzlnk.javalin.security.authorization.compilePattern
import io.javalin.config.RouterConfig
import io.javalin.http.Context
import io.javalin.http.HandlerType

/**
 * Evaluates the HTTP pattern-based rule table for requests with no route-declared roles.
 *
 * First match wins in declaration order. Patterns are compiled once at startup into a Javalin
 * [io.javalin.router.matcher.PathParser] and matched against the context-path-stripped request path.
 * Unmatched requests fall through to [fallback]. Returns a boolean; the guard renders the response.
 */
internal class AuthorizationManager(
    private val entries: List<Entry>,
    private val fallback: Rule,
    private val allowCorsPreflight: Boolean,
) {

    /** Compiled rule entry for a path pattern and optional HTTP method. */
    class Entry(
        pattern: String,
        val method: HandlerType?,
        val rule: Rule,
        routerConfig: RouterConfig,
    ) {
        private val parser = compilePattern(pattern, routerConfig)

        /** Returns `true` when [method] and [path] match this entry. */
        fun matches(method: HandlerType, path: String): Boolean =
            methodMatches(method) && parser.matches(path)

        private fun methodMatches(requestMethod: HandlerType): Boolean = when {
            method == null -> true
            method == requestMethod -> true
            // Javalin serves HEAD requests through the matched GET handler, so a GET rule must
            // also govern the corresponding HEAD request.
            method == HandlerType.GET && requestMethod == HandlerType.HEAD -> true
            else -> false
        }
    }

    /** Returns whether access is granted for [method] and [path] given [authentication]. */
    fun isGranted(method: HandlerType, path: String, authentication: Authentication, context: Context): Boolean {
        // Narrowly-scoped CORS preflight bypass, checked ahead of the rule table so it is
        // unaffected by an otherwise deny-by-default fallback. Does not exempt regular OPTIONS
        // traffic - only requests carrying the preflight-identifying header.
        if (allowCorsPreflight && method == HandlerType.OPTIONS && context.header("Access-Control-Request-Method") != null) {
            return true
        }

        val matched = entries.firstOrNull { it.matches(method, path) }
        if (matched != null) {
            return matched.rule.isGranted(authentication, context)
        }

        return fallback.isGranted(authentication, context)
    }

}
