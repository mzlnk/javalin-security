package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.authorization.DefaultRules
import io.github.mzlnk.javalin.security.authorization.Rule
import io.github.mzlnk.javalin.security.authorization.RuleFactory
import io.javalin.http.HandlerType

/**
 * HTTP pattern-based rule table, configured via `http.rules { }`.
 *
 * Exposes built-in rules ([allow], [deny], [authenticated], [hasRole], etc.) as unqualified names
 * via [RuleFactory]. Used when the matched route declares no [io.javalin.security.RouteRole]s;
 * unmatched requests fall through to [fallback].
 */
class SecurityRules internal constructor() : RuleFactory by DefaultRules {

    internal val entries: MutableList<Entry> = mutableListOf()

    internal class Entry(
        val pattern: String,
        val method: HandlerType?,
        val rule: Rule,
    )

    /**
     * Registers a rule for requests matching [pattern] with HTTP [method].
     * [pattern] uses Javalin route syntax: `*`, `{param}`, `<param>`.
     */
    fun add(pattern: String, method: HandlerType, rule: Rule) {
        entries += Entry(pattern, method, rule)
    }

    /** Registers a rule for requests matching [pattern] for any HTTP method. */
    fun add(pattern: String, rule: Rule) {
        entries += Entry(pattern, null, rule)
    }

    /**
     * Rule applied when no entry matches. Last write wins.
     * When `null` (default), unmatched requests are denied.
     */
    @JvmField
    var fallback: Rule? = null

    /**
     * When `true`, permits CORS preflight `OPTIONS` requests that carry
     * `Access-Control-Request-Method`. Does not exempt other `OPTIONS` traffic. Checked before
     * the rule table and [fallback]. CORS response headers still require Javalin's CORS plugin.
     */
    @JvmField
    var allowCorsPreflight: Boolean = false

}
