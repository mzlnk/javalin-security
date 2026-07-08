package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.AUTHENTICATION_ATTRIBUTE
import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticationManager
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler
import io.github.mzlnk.javalin.security.PathNormalizer
import io.javalin.http.Context
import org.slf4j.LoggerFactory
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException

/**
 * The WebSocket upgrade-time security pipeline.
 *
 * Registered as a [beforeMatched][io.javalin.config.RouterConfig.beforeMatched] handler that runs
 * *before* the HTTP security guard. The two-phase logic is:
 *
 * 1. **Jurisdiction check** — if the resolved request path does not match any WS authorization
 *    rule, the guard returns immediately (pass-through to the HTTP guard).
 * 2. **Authenticate + authorize** — when the path is under WS jurisdiction, the guard
 *    authenticates the upgrade request, then evaluates the matching WS authorization rule. On
 *    grant, it calls [Context.skipRemainingHandlers] so the HTTP guard does not re-process the
 *    request. On deny, the configured [UnauthorizedHandler] (401) or [AccessDeniedHandler] (403)
 *    is invoked.
 *
 * **Sync path (default, zero overhead):** When [authenticationManager] is present (or neither
 * manager is set, treating all requests as anonymous), the pipeline is entirely synchronous.
 *
 * **Async path (opt-in):** When [asyncAuthenticationManager] is present, authentication resolves
 * via [Context.future] so the request thread is released while the [CompletableFuture] is in
 * flight. Authorization and all fail-closed semantics run inside the completion stage.
 */
internal class WsSecurityGuard(
    private val authenticationManager: AuthenticationManager?,
    private val asyncAuthenticationManager: AsyncAuthenticationManager?,
    private val authorizationManager: WsAuthorizationManager,
    private val pathNormalizer: PathNormalizer,
    private val unauthorizedHandler: UnauthorizedHandler,
    private val accessDeniedHandler: AccessDeniedHandler,
) {

    fun handle(context: Context) {
        val path = authorizationPath(context)

        if (!authorizationManager.hasRule(path)) {
            return
        }

        if (asyncAuthenticationManager != null) {
            handleAsync(context, path)
        } else {
            handleSync(context, path)
        }
    }

    // ── synchronous path ─────────────────────────────────────────────────────

    private fun handleSync(context: Context, path: String) {
        val result = authenticationManager?.authenticate(context)
            ?: AuthenticationResult.NotAuthenticated

        val authentication = when (result) {
            is AuthenticationResult.Success -> result.authentication
            is AuthenticationResult.NotAuthenticated -> Authentication.unauthenticated()
            is AuthenticationResult.Failure -> {
                logAuthFailure(path, result)
                unauthorizedHandler.handle(context, result)
                context.skipRemainingHandlers()
                return
            }
        }

        context.attribute(AUTHENTICATION_ATTRIBUTE, authentication)
        enforceAuthorization(context, path, authentication)
    }

    // ── asynchronous path ─────────────────────────────────────────────────────

    private fun handleAsync(context: Context, path: String) {
        context.future {
            val authFuture = try {
                asyncAuthenticationManager!!.authenticate(context)
            } catch (t: Throwable) {
                CompletableFuture.failedFuture(t)
            }
            authFuture
                .exceptionally { throwable ->
                    val cause = (throwable as? CompletionException)?.cause ?: throwable
                    AuthenticationResult.Failure(message = "async WS authentication error", cause = cause)
                }
                .thenApply { result ->
                    when (result) {
                        is AuthenticationResult.Success -> result.authentication
                        is AuthenticationResult.NotAuthenticated -> Authentication.unauthenticated()
                        is AuthenticationResult.Failure -> {
                            logAuthFailure(path, result)
                            unauthorizedHandler.handle(context, result)
                            context.skipRemainingHandlers()
                            null
                        }
                    }
                }
                .thenAccept { authentication ->
                    if (authentication != null) {
                        context.attribute(AUTHENTICATION_ATTRIBUTE, authentication)
                        enforceAuthorization(context, path, authentication)
                    }
                }
        }
    }

    // ── shared pipeline steps ─────────────────────────────────────────────────

    private fun enforceAuthorization(
        context: Context,
        path: String,
        authentication: Authentication,
    ) {
        if (authorizationManager.isGranted(path, authentication, context)) {
            if (log.isDebugEnabled) {
                log.debug("WS access granted to {} for {}", principalName(authentication), sanitize(path))
            }
            context.skipRemainingHandlers()
            return
        }

        if (authentication.isAuthenticated) {
            log.warn("WS access denied to {} for {}", principalName(authentication), sanitize(path))
            accessDeniedHandler.handle(context, authentication)
            context.skipRemainingHandlers()
        } else {
            log.warn("WS access denied to anonymous caller for {}", sanitize(path))
            unauthorizedHandler.handle(context, null)
            context.skipRemainingHandlers()
        }
    }

    private fun logAuthFailure(
        path: String,
        result: AuthenticationResult.Failure,
    ) {
        log.warn(
            "WS authentication failed for {}: {}",
            sanitize(path),
            sanitize(result.message ?: "no detail"),
            result.cause,
        )
    }

    /**
     * Resolves the path that WS authorization rules are evaluated against.
     *
     * For a matched dynamic route this is Javalin's own matched route template (e.g.
     * `/ws/chat/{room}`), which is bypass-proof because it is exactly what the router dispatched
     * to. For requests with no matched HTTP endpoint it falls back to the request path sourced
     * from `context.path()` with the runtime context path removed — the same input Javalin
     * routes on — normalized for trailing/duplicate slashes.
     */
    private fun authorizationPath(context: Context): String =
        context.endpoints().matchedHttpEndpoint()?.path
            ?: pathNormalizer.normalize(context.path(), context.contextPath())

    private fun principalName(authentication: Authentication): String =
        sanitize(authentication.principal?.name ?: "anonymous")

    private companion object {
        val log = LoggerFactory.getLogger(WsSecurityGuard::class.java)

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
