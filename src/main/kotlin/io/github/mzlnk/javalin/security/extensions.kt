package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticatedPrincipal
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.config.JavalinConfig
import io.javalin.http.Context
import io.javalin.websocket.WsContext

/**
 * Installs and configures the security framework into a Javalin application using an inline DSL.
 *
 * Call this inside `Javalin.create { }` and configure authorization rules, providers, and failure
 * handlers directly inline — no separate config class required. The call order relative to route
 * declarations does not matter because the guard is wired in `onStart`, after the entire
 * `Javalin.create { }` block has been applied.
 *
 * **Both guards are opt-in.** An HTTP guard is registered only when an `http { }` block is
 * configured; a WS guard is registered only when a `ws { }` block is configured. Calling
 * `config.security { }` with neither block installs no guards and leaves all routes unprotected.
 *
 * When the HTTP guard is active, failures surface as Javalin's native `UnauthorizedResponse`
 * (401) and `ForbiddenResponse` (403) by default, customizable via `unauthorizedHandler` and
 * `accessDeniedHandler`.
 *
 * Ordering-independence is a security property: the authorization matcher and the path normalizer
 * mirror the final router configuration at startup, so they cannot diverge from the actual routing
 * regardless of declaration order.
 */
fun JavalinConfig.security(init: JavalinSecurityDsl.() -> Unit) {
    registerPlugin(JavalinSecurityPlugin(JavalinSecurityDsl().apply(init).build()))
}

/**
 * Returns the [authentication.Authentication] resolved for the current request.
 *
 * After the security guard has run this is always populated (an unauthenticated [authentication.Authentication]
 * when no credentials were provided). If security is not installed it falls back to unauthenticated.
 */
fun Context.authentication(): Authentication =
    attribute<Authentication>(AUTHENTICATION_ATTRIBUTE) ?: Authentication.unauthenticated()

/** Convenience accessor for the principal of the current request. `null` when the request is unauthenticated. */
@Suppress("UNCHECKED_CAST")
fun <T : AuthenticatedPrincipal> Context.principal(): T = (authentication().principal ?: error("no principal")) as T

/**
 * Returns the [Authentication] resolved for the current WebSocket session.
 *
 * The [Authentication] is set on the HTTP upgrade [Context] during `wsBeforeUpgrade`. Because
 * Javalin's [WsContext] shares the same underlying request attribute map as the upgrade context,
 * attributes set during the upgrade are accessible here in [onConnect][io.javalin.websocket.WsConnectHandler],
 * [onMessage][io.javalin.websocket.WsMessageHandler], and other WS event handlers.
 *
 * Falls back to an unauthenticated [Authentication] if the WS security block is not installed or
 * the path was not covered by a WS authorization rule.
 *
 * **Authorization scope:** the security guard enforces authorization once, at upgrade time. A
 * long-lived connection is **not** re-checked if a token later expires mid-session. To
 * re-validate credentials on individual messages, read `ctx.authentication()` inside your
 * `onMessage` handler and close the session if the principal is no longer valid:
 *
 * ```kotlin
 * ws.onMessage { ctx ->
 *     if (!ctx.authentication().isAuthenticated) {
 *         ctx.closeSession(4001, "session expired")
 *         return@onMessage
 *     }
 *     // … handle message …
 * }
 * ```
 */
fun WsContext.authentication(): Authentication =
    attribute<Authentication>(AUTHENTICATION_ATTRIBUTE) ?: Authentication.unauthenticated()

/** Convenience accessor for the principal of the current WebSocket session. Throws when the session is unauthenticated. */
@Suppress("UNCHECKED_CAST")
fun <T : AuthenticatedPrincipal> WsContext.principal(): T = (authentication().principal ?: error("no principal")) as T
