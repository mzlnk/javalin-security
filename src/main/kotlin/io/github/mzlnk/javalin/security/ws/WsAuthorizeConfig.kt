package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authorization.AuthorizationRule

/**
 * Holds the raw WebSocket authorization rule declarations for the `authorizeRequests` block.
 *
 * The declarations are kept as plain [Entry] specs (not a compiled matcher) because the correct
 * path-normalization and case-sensitivity settings are only known once the security is installed
 * into a Javalin instance. They are compiled at that point by
 * [io.github.mzlnk.javalin.security.JavalinSecurityPlugin].
 *
 * Unlike the HTTP variant, WS authorization rules match on path only (no HTTP method), since
 * WebSocket upgrade requests are evaluated once before the upgrade and individual WS events
 * (connect, message, close, error) are not subject to separate authorization.
 */
class WsAuthorizeConfig internal constructor(
    internal val entries: List<Entry>,
) {

    class Entry internal constructor(
        internal val pattern: String,
        internal val rule: AuthorizationRule,
    )

    class Builder {

        private val entries = mutableListOf<Entry>()
        private var anyRequestSet = false

        /**
         * Registers an authorization rule for WebSocket upgrade requests matching [pattern].
         *
         * A custom rule may be supplied as a lambda.
         *
         * **Pattern matching note:** Unlike the HTTP block, which evaluates authorization against
         * the matched route template (e.g. `/users/{id}`), WS authorization matches the concrete
         * request path. Path-template placeholders such as `{id}` are treated as literal characters
         * by the underlying [io.github.mzlnk.javalin.security.authorization.AntPathMatcher] and
         * will not match real request paths. Use Ant-style wildcards in the pattern instead:
         * `*` matches a single path segment and `**` matches any number of path segments.
         * A mis-written pattern such as `/ws/room/{id}` simply fails to match, so the upgrade is
         * denied by the deny-by-default rule rather than inadvertently opened.
         */
        fun authorize(pattern: String, rule: AuthorizationRule): Builder {
            entries += Entry(pattern = pattern, rule = rule)
            return this
        }

        /**
         * Registers a terminal catch-all rule applied to every WebSocket upgrade request
         * (any path).
         *
         * Because matching is first-match-wins, this should be declared last; it mirrors Spring
         * Security's `anyRequest()` and reduces the risk of leaving WS endpoints uncovered.
         *
         * May only be called once; a second call throws [SecurityConfigurationException].
         */
        fun anyRequest(rule: AuthorizationRule): Builder {
            if (anyRequestSet) {
                throw SecurityConfigurationException(
                    "anyRequest was already configured; it may only be set once.",
                )
            }
            anyRequestSet = true
            entries += Entry(pattern = "/**", rule = rule)
            return this
        }

        fun build(): WsAuthorizeConfig = WsAuthorizeConfig(entries = entries.toList())

    }

}
