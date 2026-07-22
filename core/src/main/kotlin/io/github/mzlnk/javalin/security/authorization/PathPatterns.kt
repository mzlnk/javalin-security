package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.javalin.config.RouterConfig
import io.javalin.router.matcher.PathParser

/**
 * Compiles [pattern] into a Javalin [PathParser] using exactly the same syntax and matching rules
 * Javalin's own router uses for route paths (`*`, `{param}`, `<param>`) — so a security rule
 * pattern can never drift from how Javalin itself would match the same path. [routerConfig] is
 * read at plugin startup, mirroring `ignoreTrailingSlashes`, `treatMultipleSlashesAsSingleSlash`
 * and `caseInsensitiveRoutes`.
 *
 * Rejects the Ant-style tokens (`**`, `?`) supported by the legacy matcher this library used to
 * ship, so a pattern copied from an older config fails fast at startup with migration guidance
 * instead of silently matching differently.
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
