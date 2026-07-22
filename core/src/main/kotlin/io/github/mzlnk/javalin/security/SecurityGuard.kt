package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import io.github.mzlnk.javalin.security.http.authorization.AuthorizationManager
import io.javalin.http.Context
import io.javalin.security.RouteRole
import org.slf4j.LoggerFactory
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException

/**
 * The request-time pipeline and the sole bridge between the framework and Javalin.
 *
 * It authenticates, publishes the [Authentication] on the [Context], then authorizes. Failures are
 * delegated to the configured [UnauthorizedHandler] (401) and [ForbiddenHandler] (403); the
 * guard itself contains no interception, reflection or thread-locals.
 *
 * **Authorization has two paths**, checked in order:
 * 1. If the matched route declares [RouteRole]s (`ctx.routeRoles()` is non-empty), access is
 *    granted when those roles include [Anyone], or when they intersect the resolved
 *    [Authentication]'s own [Authentication.roles]. Matching is a plain set-membership check,
 *    relying on [RouteRole] equality.
 * 2. Otherwise, [authorizationManager] evaluates the pattern-based rule table.
 *
 * **Sync path (default, zero overhead):** When [authenticator] is present (or no
 * [io.github.mzlnk.javalin.security.authentication.AuthenticationScheme] is configured, treating
 * all requests as anonymous), the pipeline is entirely synchronous.
 *
 * **Async path (opt-in):** When [asyncAuthenticator] is present, authentication resolves via
 * [Context.future] so the request thread is released while the [CompletableFuture] is in flight.
 * Authorization and all fail-closed semantics run inside the completion stage, so the same
 * security guarantees apply across the async boundary.
 *
 * [authenticator] and [asyncAuthenticator] are resolved by [io.github.mzlnk.javalin.security.JavalinSecurityPlugin]
 * from the single [io.github.mzlnk.javalin.security.authentication.AuthenticationScheme] assigned
 * to `http.authentication`; the two are mutually exclusive by construction (a scheme is either
 * [io.github.mzlnk.javalin.security.authentication.AuthenticationScheme.Sync] or
 * [io.github.mzlnk.javalin.security.authentication.AuthenticationScheme.Async], never both).
 */
internal class SecurityGuard(
    private val authenticator: Authenticator?,
    private val asyncAuthenticator: AsyncAuthenticator?,
    private val authorizationManager: AuthorizationManager,
    private val pathNormalizer: PathNormalizer,
    private val unauthorizedHandler: UnauthorizedHandler,
    private val forbiddenHandler: ForbiddenHandler,
) {

    fun handle(context: Context) {
        val method = context.method()
        val path = pathNormalizer.normalize(context.path())

        if (asyncAuthenticator != null) {
            handleAsync(context, method, path)
        } else {
            handleSync(context, method, path)
        }
    }

    // ── synchronous path ─────────────────────────────────────────────────────

    private fun handleSync(context: Context, method: io.javalin.http.HandlerType, path: String) {
        val result = authenticator?.authenticate(context)
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

        context.attribute(JavalinSecurityPlugin.AUTHENTICATION_ATTRIBUTE, authentication)
        enforceAuthorization(context, method, path, authentication)
    }

    // ── asynchronous path ─────────────────────────────────────────────────────

    private fun handleAsync(context: Context, method: io.javalin.http.HandlerType, path: String) {
        context.future {
            val authFuture = try {
                asyncAuthenticator!!.authenticate(context)
            } catch (t: Throwable) {
                CompletableFuture.failedFuture(t)
            }
            authFuture
                .exceptionally { throwable ->
                    val cause = (throwable as? CompletionException)?.cause ?: throwable
                    AuthenticationResult.Failure(message = "async authentication error", cause = cause)
                }
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
                        context.attribute(JavalinSecurityPlugin.AUTHENTICATION_ATTRIBUTE, authentication)
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
        val routeRoles = context.routeRoles()

        val granted = if (routeRoles.isNotEmpty()) {
            grantedByRole(routeRoles, authentication)
        } else {
            authorizationManager.isGranted(method, path, authentication, context)
        }

        if (granted) {
            if (log.isDebugEnabled) {
                log.debug("Access granted to {} for {} {}", principalName(authentication), method, LogSanitizer.sanitize(path))
            }
            return
        }

        if (authentication.isAuthenticated) {
            log.warn("Access denied to {} for {} {}", principalName(authentication), method, LogSanitizer.sanitize(path))
            forbiddenHandler.handle(context, authentication)
            context.skipRemainingHandlers()
        } else {
            log.warn("Access denied to anonymous caller for {} {}", method, LogSanitizer.sanitize(path))
            unauthorizedHandler.handle(context, null)
            context.skipRemainingHandlers()
        }
    }

    /**
     * Grants access when the matched route's declared [RouteRole]s include [Anyone], or when
     * they intersect the caller's own [Authentication.roles]. A plain set-membership check,
     * relying on [RouteRole] equality.
     */
    private fun grantedByRole(routeRoles: Set<RouteRole>, authentication: Authentication): Boolean =
        Anyone in routeRoles || routeRoles.any { it in authentication.roles }

    private fun logAuthFailure(
        method: io.javalin.http.HandlerType,
        path: String,
        result: AuthenticationResult.Failure,
    ) {
        log.warn(
            "Authentication failed for {} {}: {}",
            method,
            LogSanitizer.sanitize(path),
            LogSanitizer.sanitize(result.message ?: "no detail"),
            result.cause,
        )
    }

    private fun principalName(authentication: Authentication): String =
        LogSanitizer.sanitize(authentication.principal?.name ?: "anonymous")

    private companion object {
        val log = LoggerFactory.getLogger(SecurityGuard::class.java)
    }
}
