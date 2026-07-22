package io.github.mzlnk.javalin.security

/**
 * Strips the router's configured context path from an incoming request path so that rule
 * patterns - compiled with Javalin's own [io.javalin.router.matcher.PathParser] - are matched
 * against the same path Javalin's router itself would match against.
 *
 * Trailing-slash handling, duplicate-slash handling and case-insensitivity all live inside
 * [io.javalin.router.matcher.PathParser] itself (driven by the same
 * [io.javalin.config.RouterConfig] flags Javalin's router reads), so this class does only the one
 * thing a compiled pattern cannot do on its own: remove the context path.
 */
internal class PathNormalizer(private val contextPath: String) {

    fun normalize(rawPath: String): String {
        var path = rawPath.removePrefix(contextPath)
        if (path.isEmpty()) {
            path = "/"
        }
        if (!path.startsWith("/")) {
            path = "/$path"
        }
        return path
    }

}
