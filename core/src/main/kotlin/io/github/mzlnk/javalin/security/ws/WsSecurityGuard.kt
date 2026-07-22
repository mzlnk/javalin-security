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
 * The WebSocket upgrade-time security pipeline.
 *
 * Registered as a [wsBeforeUpgrade][io.javalin.config.RouterConfig.wsBeforeUpgrade] handler, which
 * runs on the HTTP upgrade request before the WebSocket handshake completes. The pipeline:
 *
 * 1. **Origin check (CSWSH)** — when [allowedOrigins] is configured, the `Origin` header is
 *    validated first. A missing or unlisted origin invokes the configured [ForbiddenHandler]
 *    (403 by default) and halts the upgrade before authentication runs.
 * 2. **Authenticate** — authenticate the upgrade request (sync, or async resolved by a blocking
 *    join, see below).
 * 3. **Authorize** — if the matched WS endpoint declares [RouteRole]s, grant access when they
 *    include [Anyone] or intersect the caller's own [Authentication.roles]; otherwise evaluate
 *    the configured WS rule table. On grant, the guard returns and the upgrade proceeds to
 *    [onConnect][io.javalin.websocket.WsConnectContext]. On deny, the configured
 *    [UnauthorizedHandler] (401) or [ForbiddenHandler] (403) is invoked and the upgrade is halted
 *    via [Context.skipRemainingHandlers].
 *
 * **Deny-by-default:** a path that matches no configured WS rule (and declares no granted role) is
 * denied outright (anonymous caller → 401, authenticated caller → 403).
 *
 * **Sync path (default, zero overhead):** when [authenticator] is present, or neither manager is
 * set (anonymous), the pipeline is fully synchronous.
 *
 * **Async (blocking) path (opt-in):** when [asyncAuthenticator] is present, the returned
 * [java.util.concurrent.CompletableFuture] is joined on the upgrade thread. `ctx.future` is not
 * used because the WebSocket handshake is synchronous — deferring the upgrade via `ctx.future` is
 * not a supported Javalin pattern. With `config.concurrency.useVirtualThreads = true` the blocking
 * join is cheap; for heavy I/O, virtual threads or a pre-fetched token cache are recommended.
 *
 * If the async future completes exceptionally, or [asyncAuthenticator] throws synchronously, the
 * error is caught and converted to [AuthenticationResult.Failure] so the pipeline remains
 * fail-closed and no internal detail is leaked to the caller.
 *
 * [authenticator] and [asyncAuthenticator] are resolved by [io.github.mzlnk.javalin.security.JavalinSecurityPlugin]
 * from the single [io.github.mzlnk.javalin.security.authentication.AuthenticationScheme] assigned
 * to `ws.authentication`; the two are mutually exclusive by construction (a scheme is either
 * [io.github.mzlnk.javalin.security.authentication.AuthenticationScheme.Sync] or
 * [io.github.mzlnk.javalin.security.authentication.AuthenticationScheme.Async], never both).
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

    /**
     * Grants access when the matched WS endpoint's declared [RouteRole]s include [Anyone], or
     * when they intersect the caller's own [Authentication.roles]. A plain set-membership check,
     * relying on [RouteRole] equality.
     */
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
        LogSanitizer.sanitize(authentication.principal?.name ?: "anonymous")

    private companion object {
        val log = LoggerFactory.getLogger(WsSecurityGuard::class.java)
    }

}
