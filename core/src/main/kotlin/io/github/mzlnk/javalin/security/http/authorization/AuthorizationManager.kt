package io.github.mzlnk.javalin.security.http.authorization

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authorization.Rule
import io.github.mzlnk.javalin.security.authorization.compilePattern
import io.javalin.config.RouterConfig
import io.javalin.http.Context
import io.javalin.http.HandlerType
import io.javalin.router.matcher.PathParser

/**
 * Evaluates the configured pattern-based rule table against a request that has no route-declared
 * roles (see [io.github.mzlnk.javalin.security.SecurityGuard] for where the RouteRole check runs).
 *
 * Matching is first-match-wins in declaration order. Each pattern is compiled once, at plugin
 * startup, into a Javalin [PathParser] and evaluated directly against the concrete (already
 * context-path-stripped) request path — the exact same primitive Javalin's own router uses for
 * its routes, so a rule pattern can never drift from how the corresponding route would actually
 * be matched.
 *
 * A request that matches no entry falls through to [fallback] (deny, by default) — this is the
 * deny-by-default guarantee. This component performs no control flow via exceptions - it returns
 * whether access is [granted][isGranted] and leaves the response decision to the
 * [io.github.mzlnk.javalin.security.SecurityGuard].
 */
internal class AuthorizationManager(
    private val entries: List<Entry>,
    private val fallback: Rule?,
    private val allowCorsPreflight: Boolean,
) {

    class Entry(
        pattern: String,
        val method: HandlerType?,
        val rule: Rule,
        routerConfig: RouterConfig,
    ) {
        private val parser = compilePattern(pattern, routerConfig)

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

        return fallback?.isGranted(authentication, context) ?: false
    }

}
