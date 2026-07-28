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
 * HTTP request-time security pipeline: authenticate, publish [Authentication] on the [Context],
 * then authorize.
 *
 * Failures go to [unauthorizedHandler] (401) or [forbiddenHandler] (403). When the matched route
 * declares [RouteRole]s, access is granted if they include [Anyone] or intersect
 * [Authentication.roles]; otherwise [authorizationManager] evaluates the pattern table.
 * Uses [authenticator] synchronously, or [asyncAuthenticator] via [Context.future] when present
 * (the two are mutually exclusive).
 */
internal class SecurityGuard(
    private val authenticator: Authenticator?,
    private val asyncAuthenticator: AsyncAuthenticator?,
    private val authorizationManager: AuthorizationManager,
    private val pathNormalizer: PathNormalizer,
    private val unauthorizedHandler: UnauthorizedHandler,
    private val forbiddenHandler: ForbiddenHandler,
) {

    /** Runs the security pipeline for [context]. */
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
                log.debug("Access granted to {} for {} {}", identityName(authentication), method, LogSanitizer.sanitize(path))
            }
            return
        }

        if (authentication.isAuthenticated) {
            log.warn("Access denied to {} for {} {}", identityName(authentication), method, LogSanitizer.sanitize(path))
            forbiddenHandler.handle(context, authentication)
            context.skipRemainingHandlers()
        } else {
            log.warn("Access denied to anonymous caller for {} {}", method, LogSanitizer.sanitize(path))
            unauthorizedHandler.handle(context, null)
            context.skipRemainingHandlers()
        }
    }

    /** Returns `true` when [routeRoles] include [Anyone] or intersect [Authentication.roles]. */
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

    private fun identityName(authentication: Authentication): String =
        LogSanitizer.sanitize(authentication.identity?.name ?: "anonymous")

    private companion object {
        val log = LoggerFactory.getLogger(SecurityGuard::class.java)
    }
}
