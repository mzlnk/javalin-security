package io.github.mzlnk.javalin.security.apibuilder

import io.github.mzlnk.javalin.security.authorization.Rule
import io.javalin.http.HandlerType

/**
 * Static methods for declaring security rules inside [io.github.mzlnk.javalin.security.SecurityRules.apiBuilder].
 *
 * Mirrors Javalin's [io.javalin.apibuilder.ApiBuilder]: verb methods take a [Rule] instead of a handler.
 * Import with `import static io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.*` (Java)
 * or `import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.*` (Kotlin).
 */
object SecurityApiBuilder {

    private val staticScope = ThreadLocal<SecurityRulesScope>()

    /** Sets the thread-local scope used by the static verb methods. */
    @JvmStatic
    internal fun setStaticScope(scope: SecurityRulesScope) {
        staticScope.set(scope)
    }

    /** Clears the thread-local scope. */
    @JvmStatic
    internal fun clearStaticScope() {
        staticScope.remove()
    }

    private fun scope(): SecurityRulesScope =
        staticScope.get()
            ?: throw IllegalStateException("The static security API can only be used within a rules.apiBuilder() call.")

    /**
     * Prefixes all rules defined in [group] with [path].
     * Paths are normalized so both `path("/api")` and `path("api")` work.
     */
    @JvmStatic
    fun path(path: String, group: SecurityRuleGroup) {
        val normalized = if (path.startsWith("/")) path else "/$path"
        val current = scope()
        current.pushPath(normalized)
        try {
            group.addRules()
        } finally {
            current.popPath()
        }
    }

    /** Registers a GET rule for [path]. */
    @JvmStatic
    fun get(path: String, rule: Rule) {
        scope().addHttp(path, HandlerType.GET, rule)
    }

    /** Registers a POST rule for [path]. */
    @JvmStatic
    fun post(path: String, rule: Rule) {
        scope().addHttp(path, HandlerType.POST, rule)
    }

    /** Registers a PUT rule for [path]. */
    @JvmStatic
    fun put(path: String, rule: Rule) {
        scope().addHttp(path, HandlerType.PUT, rule)
    }

    /** Registers a PATCH rule for [path]. */
    @JvmStatic
    fun patch(path: String, rule: Rule) {
        scope().addHttp(path, HandlerType.PATCH, rule)
    }

    /** Registers a DELETE rule for [path]. */
    @JvmStatic
    fun delete(path: String, rule: Rule) {
        scope().addHttp(path, HandlerType.DELETE, rule)
    }

    /** Registers a HEAD rule for [path]. */
    @JvmStatic
    fun head(path: String, rule: Rule) {
        scope().addHttp(path, HandlerType.HEAD, rule)
    }

    /** Registers an OPTIONS rule for [path]. */
    @JvmStatic
    fun options(path: String, rule: Rule) {
        scope().addHttp(path, HandlerType.OPTIONS, rule)
    }

    /** Registers a rule for [path] matching any HTTP method. */
    @JvmStatic
    fun any(path: String, rule: Rule) {
        scope().addHttp(path, null, rule)
    }

    /** Registers a WebSocket upgrade rule for [path]. */
    @JvmStatic
    fun ws(path: String, rule: Rule) {
        scope().addWs(path, rule)
    }

}
