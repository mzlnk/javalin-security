package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authorization.AntPathMatcher
import io.github.mzlnk.javalin.security.authorization.AuthorizationRule
import io.javalin.http.Context

/**
 * Evaluates the configured WS authorization rules against a WebSocket upgrade request.
 *
 * Matching is first-match-wins in declaration order and **deny-by-default**: a request that matches
 * no entry is denied ([isGranted] returns `false`). This means every WS upgrade is evaluated here,
 * and any path without an explicit rule is rejected.
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
     * Evaluates the first matching rule for the given [path].
     *
     * Returns `true` when a matching rule grants access. Returns `false` (deny) when no entry
     * matches the path — the deny-by-default guarantee.
     */
    fun isGranted(path: String, authentication: Authentication, context: Context): Boolean {
        val matched = entries.firstOrNull { it.matches(path) } ?: return false
        return matched.rule.isGranted(authentication, context)
    }

}
