package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.Anyone
import io.github.mzlnk.javalin.security.JavalinSecurityPlugin
import io.github.mzlnk.javalin.security.LogSanitizer
import io.github.mzlnk.javalin.security.PathNormalizer
import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import io.javalin.http.Context
import io.javalin.security.RouteRole
import org.slf4j.LoggerFactory
import java.util.concurrent.CompletionException

/**
 * WebSocket upgrade-time security pipeline, registered as a `wsBeforeUpgrade` handler.
 *
 * When [allowedOrigins] is set, validates `Origin` first and rejects missing/unlisted values via
 * [forbiddenHandler]. Then authenticates (sync, or async resolved by blocking `join()`), publishes
 * [Authentication] on the [Context], and authorizes via route roles or [authorizationManager].
 * Unmatched paths are denied (anonymous → 401, authenticated → 403). [authenticator] and
 * [asyncAuthenticator] are mutually exclusive.
 */
internal class WsSecurityGuard(
    private val authenticator: Authenticator?,
    private val asyncAuthenticator: AsyncAuthenticator?,
    private val authorizationManager: WsAuthorizationManager,
    private val pathNormalizer: PathNormalizer,
    private val unauthorizedHandler: UnauthorizedHandler,
    private val forbiddenHandler: ForbiddenHandler,
    private val allowedOrigins: Set<String>?,
) {

    /** Runs the upgrade security pipeline for [context]. */
    fun handle(context: Context) {
        val path = pathNormalizer.normalize(context.path())

        if (allowedOrigins != null) {
            val origin = context.header("Origin")
            if (origin == null || origin !in allowedOrigins) {
                log.warn(
                    "WS upgrade rejected: Origin {} not allowed for {}",
                    LogSanitizer.sanitize(origin ?: "<none>"),
                    LogSanitizer.sanitize(path),
                )
                forbiddenHandler.handle(context, Authentication.unauthenticated())
                context.skipRemainingHandlers()
                return
            }
        }

        val result = resolveAuthentication(context)

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

        context.attribute(JavalinSecurityPlugin.AUTHENTICATION_ATTRIBUTE, authentication)
        enforceAuthorization(context, path, authentication)
    }

    // ── authentication resolution ─────────────────────────────────────────────

    private fun resolveAuthentication(context: Context): AuthenticationResult {
        if (asyncAuthenticator != null) {
            return try {
                asyncAuthenticator.authenticate(context).join()
            } catch (e: CompletionException) {
                AuthenticationResult.Failure(
                    message = "async WS authentication error",
                    cause = e.cause ?: e,
                )
            } catch (t: Throwable) {
                AuthenticationResult.Failure(
                    message = "async WS authentication error",
                    cause = t,
                )
            }
        }
        return authenticator?.authenticate(context) ?: AuthenticationResult.NotAuthenticated
    }

    // ── authorization ─────────────────────────────────────────────────────────

    private fun enforceAuthorization(
        context: Context,
        path: String,
        authentication: Authentication,
    ) {
        val routeRoles = context.routeRoles()

        val granted = if (routeRoles.isNotEmpty()) {
            grantedByRole(routeRoles, authentication)
        } else {
            authorizationManager.isGranted(path, authentication, context)
        }

        if (granted) {
            if (log.isDebugEnabled) {
                log.debug("WS access granted to {} for {}", principalName(authentication), LogSanitizer.sanitize(path))
            }
            return
        }

        if (authentication.isAuthenticated) {
            log.warn("WS access denied to {} for {}", principalName(authentication), LogSanitizer.sanitize(path))
            forbiddenHandler.handle(context, authentication)
            context.skipRemainingHandlers()
        } else {
            log.warn("WS access denied to anonymous caller for {}", LogSanitizer.sanitize(path))
            unauthorizedHandler.handle(context, null)
            context.skipRemainingHandlers()
        }
    }

    /** Returns `true` when [routeRoles] include [Anyone] or intersect [Authentication.roles]. */
    private fun grantedByRole(routeRoles: Set<RouteRole>, authentication: Authentication): Boolean =
        Anyone in routeRoles || routeRoles.any { it in authentication.roles }

    // ── helpers ───────────────────────────────────────────────────────────────

    private fun logAuthFailure(path: String, result: AuthenticationResult.Failure) {
        log.warn(
            "WS authentication failed for {}: {}",
            LogSanitizer.sanitize(path),
            LogSanitizer.sanitize(result.message ?: "no detail"),
            result.cause,
        )
    }

    private fun principalName(authentication: Authentication): String =
        LogSanitizer.sanitize(authentication.identity?.name ?: "anonymous")

    private companion object {
        val log = LoggerFactory.getLogger(WsSecurityGuard::class.java)
    }

}
