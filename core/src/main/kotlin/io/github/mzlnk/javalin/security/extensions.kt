@file:JvmName("SecurityExtensions")

package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.config.JavalinConfig
import io.javalin.http.Context
import io.javalin.websocket.WsContext
import java.util.function.Consumer

/**
 * Installs and configures the security framework into a Javalin application.
 *
 * Discoverable sugar for `config.registerPlugin(JavalinSecurityPlugin(configure))` — the
 * canonical, language-neutral installation path used from Java. Call this inside
 * `Javalin.create { }` and configure authentication, RouteRole mapping, and rule tables directly
 * inline:
 *
 * ```kotlin
 * config.security { security ->
 *     security.http { http -> ... }
 * }
 * ```
 *
 * The call order relative to route declarations does not matter because the guard is wired in
 * `onStart`, after the entire `Javalin.create { }` block has been applied.
 *
 * See [JavalinSecurityPlugin] for the full opt-in/ordering/lifecycle contract.
 */
fun JavalinConfig.security(configure: Consumer<JavalinSecurityPlugin.Config>) {
    registerPlugin(JavalinSecurityPlugin(configure))
}

/**
 * Returns the [Authentication] resolved for the current request.
 *
 * Kotlin sugar for `ctx.with(JavalinSecurityPlugin::class).authentication()`.
 */
fun Context.authentication(): Authentication = with(JavalinSecurityPlugin::class).authentication()

/**
 * Convenience accessor for the principal of the current request. `null` when the request is
 * unauthenticated.
 *
 * Kotlin sugar for `ctx.with(JavalinSecurityPlugin::class).principal()`. Java has no reified
 * generics, so this overload is not usable from Java without an explicit type witness; use the
 * [Class]-taking overload below instead.
 */
fun <T : Identity> Context.principal(): T? = with(JavalinSecurityPlugin::class).principal()

/**
 * Java-friendly accessor for the principal of the current request, cast to [type]. `null` when
 * the request is unauthenticated.
 *
 * Kotlin sugar for `ctx.with(JavalinSecurityPlugin::class).principal(type)`. Prefer this overload
 * from Java, where the type-parameterless [principal] extension above requires an awkward
 * explicit type witness. Passing [type] gives a natural call site (via a static import) and an
 * immediate, descriptive `ClassCastException` if the principal is of a different type:
 *
 * ```java
 * import static io.github.mzlnk.javalin.security.SecurityExtensions.principal;
 * // …
 * MyPrincipal principal = principal(ctx, MyPrincipal.class);
 * ```
 *
 * Equivalent, without the static import: `ctx.with(JavalinSecurityPlugin.class).principal(type)`.
 */
fun <T : Identity> Context.principal(type: Class<T>): T? = with(JavalinSecurityPlugin::class).principal(type)

/**
 * Returns the [Authentication] resolved for the current WebSocket session.
 *
 * The [Authentication] is set on the HTTP upgrade [Context] during `wsBeforeUpgrade`. Because
 * Javalin's [WsContext] shares the same underlying request attribute map as the upgrade context,
 * attributes set during the upgrade are accessible here in [onConnect][io.javalin.websocket.WsConnectHandler],
 * [onMessage][io.javalin.websocket.WsMessageHandler], and other WS event handlers.
 *
 * [WsContext] is not a Javalin [Context], so the `ctx.with(...)` extension-plugin lookup used by
 * [Context.authentication] does not apply here; this reads the same request attribute directly
 * (see [JavalinSecurityPlugin.AUTHENTICATION_ATTRIBUTE]).
 *
 * Falls back to an unauthenticated [Authentication] if the WS security block is not installed or
 * the endpoint declared no rule/role that granted access.
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
    attribute<Authentication>(JavalinSecurityPlugin.AUTHENTICATION_ATTRIBUTE) ?: Authentication.unauthenticated()

/**
 * Convenience accessor for the principal of the current WebSocket session. `null` when the
 * session is unauthenticated.
 *
 * Java has no reified generics, so this overload is not usable from Java without an explicit
 * type witness; use the [Class]-taking overload below instead.
 */
@Suppress("UNCHECKED_CAST")
fun <T : Identity> WsContext.principal(): T? = authentication().identity as T?

/**
 * Java-friendly accessor for the principal of the current WebSocket session, cast to [type].
 * `null` when the session is unauthenticated.
 *
 * Prefer this overload from Java, where the type-parameterless [principal] extension above
 * requires an awkward explicit type witness. Passing [type] gives a natural call site (via a
 * static import) and an immediate, descriptive `ClassCastException` if the principal is of a
 * different type:
 *
 * ```java
 * import static io.github.mzlnk.javalin.security.SecurityExtensions.principal;
 * // …
 * MyPrincipal principal = principal(wsCtx, MyPrincipal.class);
 * ```
 */
fun <T : Identity> WsContext.principal(type: Class<T>): T? = type.cast(authentication().identity)
