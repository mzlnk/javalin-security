package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.authorization.DefaultRules
import io.github.mzlnk.javalin.security.authorization.Rule
import io.github.mzlnk.javalin.security.authorization.RuleFactory

/**
 * WebSocket pattern-based rule table, configured via `ws.rules { }`.
 *
 * Exposes built-in rules as unqualified names via [RuleFactory]. Matches on path only (no HTTP
 * method). Used when the WS endpoint declares no [io.javalin.security.RouteRole]s; unmatched
 * upgrades fall through to [fallback].
 */
class WsSecurityRules internal constructor() : RuleFactory by DefaultRules {

    internal val entries: MutableList<Entry> = mutableListOf()

    internal class Entry(
        val pattern: String,
        val rule: Rule,
    )

    /**
     * Registers a rule for upgrade requests matching [pattern].
     * [pattern] uses Javalin route syntax: `*`, `{param}`, `<param>`.
     */
    fun add(pattern: String, rule: Rule) {
        entries += Entry(pattern, rule)
    }

    /**
     * Rule applied when no entry matches. Last write wins.
     * When `null` (default), unmatched requests are denied.
     */
    @JvmField
    var fallback: Rule? = null

}
