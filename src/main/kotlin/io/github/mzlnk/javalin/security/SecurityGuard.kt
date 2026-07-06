package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticationEntryPoint
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler
import io.github.mzlnk.javalin.security.authorization.AuthorizationManager
import io.github.mzlnk.javalin.security.authorization.PathNormalizer
import io.javalin.http.Context
import org.slf4j.LoggerFactory

/**
 * The request-time pipeline and the sole bridge between the framework and Javalin.
 *
 * It authenticates, publishes the [Authentication] on the [Context], then authorizes. Failures are
 * delegated to the configured [AuthenticationEntryPoint] (401) and [AccessDeniedHandler] (403); the
 * guard itself contains no interception, reflection or thread-locals.
 */
internal class SecurityGuard(
    private val authenticationManager: AuthenticationManager,
    private val authorizationManager: AuthorizationManager,
    private val pathNormalizer: PathNormalizer,
    private val authenticationEntryPoint: AuthenticationEntryPoint,
    private val accessDeniedHandler: AccessDeniedHandler,
) {

    fun handle(context: Context) {
        val method = context.method()
        val path = authorizationPath(context)

        val authentication = when (val result = authenticationManager.authenticate(context)) {
            is AuthenticationResult.Success -> result.authentication
            is AuthenticationResult.NotAuthenticated -> Authentication.unauthenticated()
            is AuthenticationResult.Failure -> {
                // The failure message/cause is logged but never forwarded to the client, to avoid
                // leaking why authentication failed.
                log.warn("Authentication failed for {} {}: {}", method, sanitize(path), sanitize(result.message ?: "no detail"), result.cause)
                authenticationEntryPoint.commence(context, result)
                context.skipRemainingHandlers()
                return
            }
        }

        context.attribute(AUTHENTICATION_ATTRIBUTE, authentication)

        if (authorizationManager.isGranted(method, path, authentication, context)) {
            if (log.isDebugEnabled) {
                log.debug("Access granted to {} for {} {}", principalName(authentication), method, sanitize(path))
            }
            return
        }

        if (authentication.isAuthenticated) {
            log.warn("Access denied to {} for {} {}", principalName(authentication), method, sanitize(path))
            accessDeniedHandler.handle(context, authentication)
            context.skipRemainingHandlers()
        } else {
            log.warn("Access denied to anonymous caller for {} {}", method, sanitize(path))
            authenticationEntryPoint.commence(context, null)
            context.skipRemainingHandlers()
        }
    }

    /**
     * Resolves the path that authorization rules are evaluated against.
     *
     * For a matched dynamic route this is Javalin's own matched route template (e.g. `/users/{id}`),
     * which is bypass-proof because it is exactly what the router dispatched to. For requests with no
     * matched HTTP endpoint (static files, single-page-app fallback, HEAD served by a GET resource)
     * it falls back to the request path sourced from `context.path()` with the runtime context path
     * removed - the same input Javalin routes on - normalized for trailing/duplicate slashes.
     */
    private fun authorizationPath(context: Context): String =
        context.endpoints().matchedHttpEndpoint()?.path
            ?: pathNormalizer.normalize(context.path(), context.contextPath())

    private fun principalName(authentication: Authentication): String =
        sanitize((authentication.principal as? AuthenticatedPrincipal)?.name ?: "anonymous")

    private companion object {
        val log = LoggerFactory.getLogger(SecurityGuard::class.java)

        /** Matches ASCII control characters (including CR, LF and TAB). */
        val CONTROL_CHARS = Regex("\\p{Cntrl}")

        /** Upper bound on the length of any single value written to the log. */
        const val MAX_LOGGED_LENGTH = 256

        /**
         * Sanitizes an attacker-influenced value (request path, principal name, provider message)
         * before it is written to the log. Control characters are replaced so a crafted value
         * cannot inject newlines to forge additional log lines (CRLF log injection), and overly
         * long values are truncated to keep log lines bounded.
         */
        fun sanitize(value: String): String {
            val cleaned = CONTROL_CHARS.replace(value, "_")
            return if (cleaned.length > MAX_LOGGED_LENGTH) {
                cleaned.substring(0, MAX_LOGGED_LENGTH) + "..."
            } else {
                cleaned
            }
        }
    }

}
