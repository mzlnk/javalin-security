package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticationManager
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler
import io.github.mzlnk.javalin.security.authorization.AuthorizationManager
import io.github.mzlnk.javalin.security.authorization.PathNormalizer
import io.javalin.http.Context
import org.slf4j.LoggerFactory
import java.util.concurrent.CompletableFuture

/**
 * The request-time pipeline and the sole bridge between the framework and Javalin.
 *
 * It authenticates, publishes the [authentication.Authentication] on the [Context], then authorizes. Failures are
 * delegated to the configured [UnauthorizedHandler] (401) and [AccessDeniedHandler] (403); the
 * guard itself contains no interception, reflection or thread-locals.
 *
 * **Sync path (default, zero overhead):** When [authenticationManager] is present (or neither
 * manager is set, treating all requests as anonymous), the pipeline is entirely synchronous.
 *
 * **Async path (opt-in):** When [asyncAuthenticationManager] is present, authentication resolves
 * via [Context.future] so the request thread is released while the [CompletableFuture] is in
 * flight. Authorization and all fail-closed semantics run inside the completion stage, so the same
 * security guarantees apply across the async boundary.
 */
internal class SecurityGuard(
    private val authenticationManager: AuthenticationManager?,
    private val asyncAuthenticationManager: AsyncAuthenticationManager?,
    private val authorizationManager: AuthorizationManager,
    private val pathNormalizer: PathNormalizer,
    private val unauthorizedHandler: UnauthorizedHandler,
    private val accessDeniedHandler: AccessDeniedHandler,
) {

    fun handle(context: Context) {
        val method = context.method()
        val path = authorizationPath(context)

        if (asyncAuthenticationManager != null) {
            handleAsync(context, method, path)
        } else {
            handleSync(context, method, path)
        }
    }

    // ── synchronous path ─────────────────────────────────────────────────────

    private fun handleSync(context: Context, method: io.javalin.http.HandlerType, path: String) {
        val result = authenticationManager?.authenticate(context)
            ?: AuthenticationResult.NotAuthenticated

        val authentication = when (result) {
            is AuthenticationResult.Success -> result.authentication
            is AuthenticationResult.NotAuthenticated -> Authentication.unauthenticated()
            is AuthenticationResult.Failure -> {
                logAuthFailure(method, path, result)
                unauthorizedHandler.handle(context, result)
                context.skipRemainingHandlers()
                return
            }
        }

        context.attribute(AUTHENTICATION_ATTRIBUTE, authentication)
        enforceAuthorization(context, method, path, authentication)
    }

    // ── asynchronous path ─────────────────────────────────────────────────────

    private fun handleAsync(context: Context, method: io.javalin.http.HandlerType, path: String) {
        context.future {
            asyncAuthenticationManager!!.authenticate(context)
                .thenApply { result ->
                    when (result) {
                        is AuthenticationResult.Success -> result.authentication
                        is AuthenticationResult.NotAuthenticated -> Authentication.unauthenticated()
                        is AuthenticationResult.Failure -> {
                            logAuthFailure(method, path, result)
                            unauthorizedHandler.handle(context, result)
                            context.skipRemainingHandlers()
                            null
                        }
                    }
                }
                .thenAccept { authentication ->
                    if (authentication != null) {
                        context.attribute(AUTHENTICATION_ATTRIBUTE, authentication)
                        enforceAuthorization(context, method, path, authentication)
                    }
                }
        }
    }

    // ── shared pipeline steps ─────────────────────────────────────────────────

    private fun enforceAuthorization(
        context: Context,
        method: io.javalin.http.HandlerType,
        path: String,
        authentication: Authentication,
    ) {
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
            unauthorizedHandler.handle(context, null)
            context.skipRemainingHandlers()
        }
    }

    private fun logAuthFailure(
        method: io.javalin.http.HandlerType,
        path: String,
        result: AuthenticationResult.Failure,
    ) {
        log.warn(
            "Authentication failed for {} {}: {}",
            method,
            sanitize(path),
            sanitize(result.message ?: "no detail"),
            result.cause,
        )
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
        sanitize(authentication.principal?.name ?: "anonymous")

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
