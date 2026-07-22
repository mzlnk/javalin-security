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
 *    granted when those roles include [Anyone], or when [roleMapper] maps the resolved
 *    [Authentication] to a role set that intersects the declared ones. If no [roleMapper] is
 *    configured, a route with declared roles is denied (logged) rather than silently falling
 *    through to the rule table.
 * 2. Otherwise, [authorizationManager] evaluates the pattern-based rule table.
 *
 * **Sync path (default, zero overhead):** When [authenticator] is present (or neither manager is
 * set, treating all requests as anonymous), the pipeline is entirely synchronous.
 *
 * **Async path (opt-in):** When [asyncAuthenticator] is present, authentication resolves via
 * [Context.future] so the request thread is released while the [CompletableFuture] is in flight.
 * Authorization and all fail-closed semantics run inside the completion stage, so the same
 * security guarantees apply across the async boundary.
 */
internal class SecurityGuard(
    private val authenticator: Authenticator?,
    private val asyncAuthenticator: AsyncAuthenticator?,
    private val authorizationManager: AuthorizationManager,
    private val roleMapper: RoleMapper?,
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
            grantedByRole(routeRoles, authentication, context)
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
     * [roleMapper] resolves the caller to at least one of the declared roles. A route with
     * declared roles and no configured [roleMapper] is denied (logged) rather than silently
     * falling through to the pattern rule table - declaring roles is an explicit signal that
     * role-based access control is expected here.
     */
    private fun grantedByRole(routeRoles: Set<RouteRole>, authentication: Authentication, context: Context): Boolean {
        if (Anyone in routeRoles) return true

        val mapper = roleMapper
        if (mapper == null) {
            log.warn(
                "Route declares roles {} but no roleMapper is configured on the HTTP security " +
                    "block; denying. Set 'http.roleMapper = { authentication, ctx -> ... }'.",
                routeRoles,
            )
            return false
        }

        val callerRoles = mapper.map(authentication, context)
        return routeRoles.any { it in callerRoles }
    }

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
