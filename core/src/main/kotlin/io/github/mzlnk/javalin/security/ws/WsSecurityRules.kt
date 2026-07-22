package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.authorization.DefaultRules
import io.github.mzlnk.javalin.security.authorization.Rule
import io.github.mzlnk.javalin.security.authorization.RuleFactory

/**
 * The WebSocket pattern-based rule table, configured via `ws.rules { }`.
 *
 * Implements [RuleFactory] via delegation so the built-in rules ([allow], [deny], [authenticated],
 * etc.) are available as unqualified names inside the block.
 *
 * Unlike the HTTP variant, WS rules match on path only (no HTTP method), since WebSocket upgrade
 * requests are evaluated once before the upgrade and individual WS events (connect, message,
 * close, error) are not subject to separate authorization.
 *
 * Like the HTTP table, this is the fallback for upgrade requests whose WS endpoint declares no
 * [io.javalin.security.RouteRole]s (see [io.github.mzlnk.javalin.security.ws.WsSecurityGuard]).
 */
class WsSecurityRules internal constructor() : RuleFactory by DefaultRules {

    internal val entries: MutableList<Entry> = mutableListOf()

    internal class Entry(
        val pattern: String,
        val rule: Rule,
    )

    /**
     * Registers a rule for WebSocket upgrade requests matching [pattern].
     *
     * [pattern] uses Javalin's own route syntax: `*` (wildcard, crosses path segments), `{param}`
     * (no-slash path parameter) and `<param>` (slash-accepting path parameter) — the same syntax
     * used to declare the WS endpoint itself, so e.g. `/ws/room/{id}` now matches real request
     * paths (unlike the legacy Ant-style matcher, where path-parameter placeholders were literal).
     * A custom rule may be supplied as a trailing lambda.
     */
    fun add(pattern: String, rule: Rule) {
        entries += Entry(pattern, rule)
    }

    /**
     * The rule applied when no entry above matches the request path.
     *
     * Last write wins. Unset (`null`, the default) denies unmatched requests — the deny-by-default
     * guarantee.
     */
    @JvmField
    var fallback: Rule? = null

}
