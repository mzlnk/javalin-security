package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.javalin.config.RouterConfig
import io.javalin.router.matcher.PathParser

/**
 * Compiles [pattern] into a Javalin [PathParser] using the same route syntax as Javalin's router
 * (`*`, `{param}`, `<param>`), with [routerConfig] applied at plugin startup.
 *
 * Rejects Ant-style tokens (`**`, `?`) with a [SecurityConfigurationException].
 */
internal fun compilePattern(pattern: String, routerConfig: RouterConfig): PathParser {
    if ("**" in pattern) {
        throw SecurityConfigurationException(
            "Pattern '$pattern' uses Ant-style '**', which Javalin's route syntax does not support. " +
                "Javalin's own '*' wildcard already matches across path segments, so replace '/**' " +
                "with '/*', or use a slash-accepting parameter such as '/<path>'.",
        )
    }
    if ("?" in pattern) {
        throw SecurityConfigurationException(
            "Pattern '$pattern' contains '?', an Ant-style single-character wildcard that Javalin's " +
                "route syntax does not support. Declare an explicit path parameter instead, e.g. '{id}'.",
        )
    }
    return try {
        PathParser(pattern, routerConfig)
    } catch (ex: Exception) {
        throw SecurityConfigurationException("Pattern '$pattern' is not a valid Javalin route pattern: ${ex.message}")
    }
}
