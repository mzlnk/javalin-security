package io.github.mzlnk.javalin.security.http.authorization

/**
 * Normalizes an incoming request path so that authorization matching stays consistent with how
 * Javalin's router matches routes.
 *
 * Without this, quirks such as a trailing slash (`/admin/`), duplicate slashes (`/admin//x`) or a
 * configured context path could let a request reach a protected handler while slipping past its
 * authorization rule - an authorization bypass. The flags here mirror Javalin's
 * `io.javalin.config.RouterConfig` so the two layers agree.
 *
 * Case sensitivity is intentionally handled by [AntPathMatcher] (via a case-insensitive regex)
 * rather than here, so patterns and paths keep their original casing for logging.
 *
 * The context path is supplied per call (from `context.contextPath()`) and stripped with a plain
 * `removePrefix`, mirroring Javalin's own `ctx.path().removePrefix(ctx.contextPath())` so the two
 * layers operate on the exact same request path and cannot diverge.
 */
internal class PathNormalizer(
    private val ignoreTrailingSlashes: Boolean,
    private val treatMultipleSlashesAsSingleSlash: Boolean,
) {

    fun normalize(rawPath: String, contextPath: String): String {
        var path = rawPath.removePrefix(contextPath)

        if (path.isEmpty()) {
            path = "/"
        }
        if (!path.startsWith("/")) {
            path = "/$path"
        }
        if (treatMultipleSlashesAsSingleSlash) {
            path = MULTIPLE_SLASHES.replace(path, "/")
        }
        if (ignoreTrailingSlashes && path.length > 1 && path.endsWith("/")) {
            path = path.trimEnd('/').ifEmpty { "/" }
        }
        return path
    }

    private companion object {
        val MULTIPLE_SLASHES = Regex("/{2,}")
    }

}
