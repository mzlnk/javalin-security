package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authorization.AntPathMatcher
import io.github.mzlnk.javalin.security.authorization.AuthorizationRule
import io.javalin.http.Context

/**
 * Evaluates the configured WS authorization rules against a WebSocket upgrade request.
 *
 * Matching is first-match-wins in declaration order and secure-by-default: a request that matches
 * no entry is denied. However, the guard only invokes this manager for paths that have at least
 * one matching rule (WS jurisdiction check via [hasRule]). Paths without any matching WS rule are
 * passed through to the HTTP security guard.
 *
 * Matching operates on the already-normalized request path (see
 * [io.github.mzlnk.javalin.security.PathNormalizer]) so it stays consistent
 * with Javalin's own route matching.
 */
internal class WsAuthorizationManager(
    private val entries: List<Entry>,
) {

    class Entry(
        pattern: String,
        val rule: AuthorizationRule,
        caseInsensitive: Boolean = false,
    ) {
        private val matcher = AntPathMatcher(pattern, caseInsensitive)

        fun matches(path: String): Boolean = matcher.matches(path)
    }

    /**
     * Returns `true` when at least one configured WS authorization rule matches the given [path].
     *
     * When no rule matches, the path is not under WS jurisdiction and the WS guard passes it
     * through to the HTTP security guard without any WS-side authentication or authorization.
     */
    fun hasRule(path: String): Boolean = entries.any { it.matches(path) }

    /**
     * Evaluates the first matching rule for the given [path].
     *
     * Returns `true` when a matching rule grants access. If no entry matches the path (should not
     * happen when [hasRule] returned `true`), it returns `false` (deny-by-default).
     */
    fun isGranted(path: String, authentication: Authentication, context: Context): Boolean {
        val matched = entries.firstOrNull { it.matches(path) } ?: return false
        return matched.rule.isGranted(authentication, context)
    }

}
