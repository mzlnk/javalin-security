package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.authorization.DefaultRules
import io.github.mzlnk.javalin.security.authorization.Rule
import io.github.mzlnk.javalin.security.authorization.RuleFactory
import io.javalin.http.HandlerType

/**
 * The HTTP pattern-based rule table, configured via `http.rules { }`.
 *
 * Implements [RuleFactory] via delegation so the built-in rules ([allow], [deny], [authenticated],
 * [hasRole], etc.) are available as unqualified names inside the block, e.g.
 * `add("/api/...", GET, allow)`.
 *
 * This table is the fallback mechanism for authorization: a request whose matched route declares
 * [io.javalin.security.RouteRole]s is checked against those roles first (see
 * [io.github.mzlnk.javalin.security.SecurityGuard]); only requests with no declared roles fall
 * through to this pattern table, and requests matching no entry here fall through to [fallback].
 */
class SecurityRules internal constructor() : RuleFactory by DefaultRules {

    internal val entries: MutableList<Entry> = mutableListOf()

    internal class Entry(
        val pattern: String,
        val method: HandlerType?,
        val rule: Rule,
    )

    /**
     * Registers a rule for requests matching [pattern] with the given HTTP [method].
     *
     * [pattern] uses Javalin's own route syntax: `*` (wildcard, crosses path segments), `{param}`
     * (no-slash path parameter) and `<param>` (slash-accepting path parameter). A custom rule may
     * be supplied as a lambda, e.g. `add("/x", GET) { auth, ctx -> auth.isAuthenticated }`.
     */
    fun add(pattern: String, method: HandlerType, rule: Rule) {
        entries += Entry(pattern, method, rule)
    }

    /**
     * Registers a rule for requests matching [pattern] for any HTTP method.
     *
     * A custom rule may be supplied as a trailing lambda.
     */
    fun add(pattern: String, rule: Rule) {
        entries += Entry(pattern, null, rule)
    }

    /**
     * The rule applied when no entry above matches the request path and method.
     *
     * Last write wins. Unset (`null`, the default) denies unmatched requests — the deny-by-default
     * guarantee. Set to `allow` to open every otherwise-uncovered path, or `authenticated` to
     * require login by default.
     */
    @JvmField
    var fallback: Rule? = null

    /**
     * When `true`, permits CORS preflight `OPTIONS` requests identified by the presence of the
     * `Access-Control-Request-Method` request header.
     *
     * This is a narrowly-scoped opt-in helper. It does **not** blanket-exempt all `OPTIONS`
     * requests, preserving the deny-by-default guarantee for regular `OPTIONS` traffic while
     * allowing browsers to complete the preflight exchange. Checked before the rule table and
     * [fallback], so its effect does not depend on entry ordering.
     *
     * Javalin's CORS plugin must be registered alongside security to add the required CORS
     * response headers; this flag only controls whether the security guard passes the preflight
     * request through.
     */
    @JvmField
    var allowCorsPreflight: Boolean = false

}
