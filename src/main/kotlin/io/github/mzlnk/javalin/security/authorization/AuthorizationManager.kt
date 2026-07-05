package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.Authentication
import io.javalin.http.Context
import io.javalin.http.HandlerType

/**
 * Evaluates the configured authorization rules against a request.
 *
 * Matching is first-match-wins in declaration order and secure-by-default: a request that matches
 * no entry is denied. This component performs no control flow via exceptions - it returns whether
 * access is [granted][isGranted] and leaves the response decision to the
 * [io.github.mzlnk.javalin.security.SecurityGuard].
 */
internal class AuthorizationManager(
    private val entries: List<Entry>,
) {

    class Entry(
        pattern: String,
        val method: HandlerType?,
        val rule: AuthorizationRule,
    ) {
        private val matcher = AntPathMatcher(pattern)

        fun matches(context: Context): Boolean =
            (method == null || method == context.method()) && matcher.matches(context.path())
    }

    fun isGranted(context: Context, authentication: Authentication): Boolean {
        val matched = entries.firstOrNull { it.matches(context) } ?: return false
        return matched.rule.isGranted(authentication, context)
    }

}
