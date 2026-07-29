package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder
import io.github.mzlnk.javalin.security.apibuilder.SecurityRuleGroup
import io.github.mzlnk.javalin.security.apibuilder.SecurityRulesScope
import io.github.mzlnk.javalin.security.authorization.Rule
import io.javalin.http.HandlerType

/**
 * Unified pattern-based rule table for HTTP and WebSocket endpoints.
 *
 * Declared on [JavalinSecurityPlugin.Config.rules]. Verb methods mirror Javalin's route API
 * (`get`, `post`, …, `ws`) but take a [Rule] instead of a handler. Use [apiBuilder] to group
 * rules under path prefixes, analogous to [io.javalin.config.RoutesConfig.apiBuilder].
 *
 * HTTP entries match path + optional method (a GET rule also governs HEAD). WebSocket entries
 * match on path only. First match wins per protocol; unmatched requests fall through to the
 * fallback on [io.github.mzlnk.javalin.security.http.HttpSecurityConfig] /
 * [io.github.mzlnk.javalin.security.ws.WsSecurityConfig].
 */
class SecurityRules internal constructor() {

    internal sealed class Entry {
        class Http(val pattern: String, val method: HandlerType?, val rule: Rule) : Entry()
        class Ws(val pattern: String, val rule: Rule) : Entry()
    }

    internal val entries: MutableList<Entry> = mutableListOf()

    internal fun httpEntries(): List<Entry.Http> = entries.filterIsInstance<Entry.Http>()

    internal fun wsEntries(): List<Entry.Ws> = entries.filterIsInstance<Entry.Ws>()

    /** Registers an HTTP rule for [pattern] with the given [method] (`null` = any method). */
    internal fun addHttp(pattern: String, method: HandlerType?, rule: Rule) {
        entries += Entry.Http(pattern, method, rule)
    }

    /** Registers a WebSocket upgrade rule for [pattern]. */
    internal fun addWs(pattern: String, rule: Rule) {
        entries += Entry.Ws(pattern, rule)
    }

    /** Registers a GET rule for [pattern]. */
    fun get(pattern: String, rule: Rule) {
        addHttp(pattern, HandlerType.GET, rule)
    }

    /** Registers a POST rule for [pattern]. */
    fun post(pattern: String, rule: Rule) {
        addHttp(pattern, HandlerType.POST, rule)
    }

    /** Registers a PUT rule for [pattern]. */
    fun put(pattern: String, rule: Rule) {
        addHttp(pattern, HandlerType.PUT, rule)
    }

    /** Registers a PATCH rule for [pattern]. */
    fun patch(pattern: String, rule: Rule) {
        addHttp(pattern, HandlerType.PATCH, rule)
    }

    /** Registers a DELETE rule for [pattern]. */
    fun delete(pattern: String, rule: Rule) {
        addHttp(pattern, HandlerType.DELETE, rule)
    }

    /** Registers a HEAD rule for [pattern]. */
    fun head(pattern: String, rule: Rule) {
        addHttp(pattern, HandlerType.HEAD, rule)
    }

    /** Registers an OPTIONS rule for [pattern]. */
    fun options(pattern: String, rule: Rule) {
        addHttp(pattern, HandlerType.OPTIONS, rule)
    }

    /** Registers a rule for [pattern] matching any HTTP method. */
    fun any(pattern: String, rule: Rule) {
        addHttp(pattern, null, rule)
    }

    /** Registers a WebSocket upgrade rule for [pattern]. */
    fun ws(pattern: String, rule: Rule) {
        addWs(pattern, rule)
    }

    /**
     * Declares rules using the static [SecurityApiBuilder] DSL.
     * Supports nested [SecurityApiBuilder.path] groups. Repeated calls accumulate entries.
     */
    fun apiBuilder(group: SecurityRuleGroup) {
        try {
            SecurityApiBuilder.setStaticScope(SecurityRulesScope(this))
            group.addRules()
        } finally {
            SecurityApiBuilder.clearStaticScope()
        }
    }

}
