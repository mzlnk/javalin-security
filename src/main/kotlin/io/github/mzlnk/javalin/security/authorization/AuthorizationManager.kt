package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.http.Context
import io.javalin.http.HandlerType

/**
 * Evaluates the configured authorization rules against a request.
 *
 * Matching is first-match-wins in declaration order and secure-by-default: a request that matches
 * no entry is denied. This component performs no control flow via exceptions - it returns whether
 * access is [granted][isGranted] and leaves the response decision to the
 * [io.github.mzlnk.javalin.security.SecurityGuard].
 *
 * Matching operates on the already-normalized request path (see
 * [io.github.mzlnk.javalin.security.authorization.PathNormalizer]) so it stays consistent with
 * Javalin's own route matching.
 */
internal class AuthorizationManager(
    private val entries: List<Entry>,
) {

    class Entry(
        pattern: String,
        val method: HandlerType?,
        val rule: AuthorizationRule,
        caseInsensitive: Boolean = false,
    ) {
        private val matcher = AntPathMatcher(pattern, caseInsensitive)

        fun matches(method: HandlerType, path: String): Boolean =
            methodMatches(method) && matcher.matches(path)

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
        val matched = entries.firstOrNull { it.matches(method, path) } ?: return false
        return matched.rule.isGranted(authentication, context)
    }

}
