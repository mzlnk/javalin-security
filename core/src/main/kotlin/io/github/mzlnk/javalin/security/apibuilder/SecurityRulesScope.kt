package io.github.mzlnk.javalin.security.apibuilder

import io.github.mzlnk.javalin.security.SecurityRules
import io.github.mzlnk.javalin.security.authorization.Rule
import io.javalin.http.HandlerType
import java.util.ArrayDeque

/**
 * Thread-local path-prefix stack and rule-table target for [SecurityApiBuilder].
 *
 * Path normalization mirrors Javalin's [io.javalin.apibuilder.ApiBuilderScope].
 */
internal class SecurityRulesScope(private val rules: SecurityRules) {

    private val pathDeque = ArrayDeque<String>()

    fun pushPath(path: String) {
        pathDeque.addLast(path)
    }

    fun popPath() {
        pathDeque.removeLast()
    }

    fun prefixPath(path: String): String {
        val normalized = when {
            path == "*" -> path
            path.startsWith("/") || path.isEmpty() -> path
            else -> "/$path"
        }
        return pathDeque.joinToString("") + normalized
    }

    fun addHttp(pattern: String, method: HandlerType?, rule: Rule) {
        rules.addHttp(prefixPath(pattern), method, rule)
    }

    fun addWs(pattern: String, rule: Rule) {
        rules.addWs(prefixPath(pattern), rule)
    }

}
