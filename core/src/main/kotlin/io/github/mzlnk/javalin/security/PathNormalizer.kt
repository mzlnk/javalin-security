package io.github.mzlnk.javalin.security

/**
 * Strips the router's context path from an incoming request path before rule matching.
 *
 * Trailing-slash, duplicate-slash, and case-insensitivity handling remain in [io.javalin.router.matcher.PathParser] via [io.javalin.config.RouterConfig].
 */
internal class PathNormalizer(private val contextPath: String) {

    /** Returns [rawPath] with the configured context path removed, defaulting empty results to `/` and ensuring a leading slash. */
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
