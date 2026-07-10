package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.AUTHENTICATION_ATTRIBUTE
import io.github.mzlnk.javalin.security.LogSanitizer
import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticationManager
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler
import io.github.mzlnk.javalin.security.PathNormalizer
import io.javalin.http.Context
import org.slf4j.LoggerFactory
import java.util.concurrent.CompletionException

/**
 * The WebSocket upgrade-time security pipeline.
 *
 * Registered as a [wsBeforeUpgrade][io.javalin.config.RouterConfig.wsBeforeUpgrade] handler, which
 * runs on the HTTP upgrade request before the WebSocket handshake completes. The pipeline:
 *
 * 1. **Origin check (CSWSH)** — when [allowedOrigins] is configured, the `Origin` header is
 *    validated first. A missing or unlisted origin invokes the configured [AccessDeniedHandler]
 *    (403 by default) and halts the upgrade before authentication runs.
 * 2. **Authenticate** — authenticate the upgrade request (sync, or async resolved by a blocking
 *    join, see below).
 * 3. **Authorize** — evaluate the configured WS authorization rules against the resolved identity.
 *    On grant, the guard returns and the upgrade proceeds to [onConnect][io.javalin.websocket.WsConnectContext].
 *    On deny, the configured [UnauthorizedHandler] (401) or [AccessDeniedHandler] (403) is invoked
 *    and the upgrade is halted via [Context.skipRemainingHandlers].
 *
 * **Deny-by-default:** a path that matches no configured WS rule is denied outright
 * (anonymous caller → 401, authenticated caller → 403).
 *
 * **Sync path (default, zero overhead):** when [authenticationManager] is present, or neither
 * manager is set (anonymous), the pipeline is fully synchronous.
 *
 * **Async (blocking) path (opt-in):** when [asyncAuthenticationManager] is present, the returned
 * [java.util.concurrent.CompletableFuture] is joined on the upgrade thread. `ctx.future` is not
 * used because the WebSocket handshake is synchronous — deferring the upgrade via `ctx.future` is
 * not a supported Javalin pattern. With `config.useVirtualThreads = true` the blocking join is
 * cheap; for heavy I/O, virtual threads or a pre-fetched token cache are recommended.
 *
 * If the async future completes exceptionally, or [asyncAuthenticationManager] throws
 * synchronously, the error is caught and converted to [AuthenticationResult.Failure] so the
 * pipeline remains fail-closed and no internal detail is leaked to the caller.
 */
internal class WsSecurityGuard(
    private val authenticationManager: AuthenticationManager?,
    private val asyncAuthenticationManager: AsyncAuthenticationManager?,
    private val authorizationManager: WsAuthorizationManager,
    private val pathNormalizer: PathNormalizer,
    private val unauthorizedHandler: UnauthorizedHandler,
    private val accessDeniedHandler: AccessDeniedHandler,
    private val allowedOrigins: Set<String>?,
) {

    fun handle(context: Context) {
        val path = authorizationPath(context)

        if (allowedOrigins != null) {
            val origin = context.header("Origin")
            if (origin == null || origin !in allowedOrigins) {
                log.warn(
                    "WS upgrade rejected: Origin {} not allowed for {}",
                    LogSanitizer.sanitize(origin ?: "<none>"),
                    LogSanitizer.sanitize(path),
                )
                accessDeniedHandler.handle(context, Authentication.unauthenticated())
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

        context.attribute(AUTHENTICATION_ATTRIBUTE, authentication)
        enforceAuthorization(context, path, authentication)
    }

    // ── authentication resolution ─────────────────────────────────────────────

    private fun resolveAuthentication(context: Context): AuthenticationResult {
        if (asyncAuthenticationManager != null) {
            return try {
                asyncAuthenticationManager.authenticate(context).join()
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
        return authenticationManager?.authenticate(context) ?: AuthenticationResult.NotAuthenticated
    }

    // ── authorization ─────────────────────────────────────────────────────────

    private fun enforceAuthorization(
        context: Context,
        path: String,
        authentication: Authentication,
    ) {
        if (authorizationManager.isGranted(path, authentication, context)) {
            if (log.isDebugEnabled) {
                log.debug("WS access granted to {} for {}", principalName(authentication), LogSanitizer.sanitize(path))
            }
            return
        }

        if (authentication.isAuthenticated) {
            log.warn("WS access denied to {} for {}", principalName(authentication), LogSanitizer.sanitize(path))
            accessDeniedHandler.handle(context, authentication)
            context.skipRemainingHandlers()
        } else {
            log.warn("WS access denied to anonymous caller for {}", LogSanitizer.sanitize(path))
            unauthorizedHandler.handle(context, null)
            context.skipRemainingHandlers()
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private fun logAuthFailure(path: String, result: AuthenticationResult.Failure) {
        log.warn(
            "WS authentication failed for {}: {}",
            LogSanitizer.sanitize(path),
            LogSanitizer.sanitize(result.message ?: "no detail"),
            result.cause,
        )
    }

    /**
     * Resolves the path used for WS authorization rule matching.
     *
     * WebSocket upgrade requests are matched by Javalin's WS router, not the HTTP router, so
     * [io.javalin.http.Context.endpoints] does not return a matched HTTP endpoint for upgrades.
     * The actual request path (with context path removed and trailing/duplicate slashes normalized)
     * is used directly, which is the same input Javalin's WS router dispatches on.
     */
    private fun authorizationPath(context: Context): String =
        pathNormalizer.normalize(context.path(), context.contextPath())

    private fun principalName(authentication: Authentication): String =
        LogSanitizer.sanitize(authentication.principal?.name ?: "anonymous")

    private companion object {
        val log = LoggerFactory.getLogger(WsSecurityGuard::class.java)
    }

}
