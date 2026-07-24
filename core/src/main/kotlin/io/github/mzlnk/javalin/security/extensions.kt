@file:JvmName("SecurityExtensions")

package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.config.JavalinConfig
import io.javalin.http.Context
import io.javalin.websocket.WsContext
import java.util.function.Consumer

/**
 * Installs and configures the security plugin on this [JavalinConfig].
 *
 * Equivalent to `config.registerPlugin(JavalinSecurityPlugin(configure))`. See [JavalinSecurityPlugin]
 * for lifecycle and opt-in guard behavior.
 */
fun JavalinConfig.security(configure: Consumer<JavalinSecurityPlugin.Config>) {
    registerPlugin(JavalinSecurityPlugin(configure))
}

/** Returns the [Authentication] resolved for the current request. */
fun Context.authentication(): Authentication = with(JavalinSecurityPlugin::class).authentication()

/**
 * Returns the principal of the current request, or `null` when unauthenticated.
 * Prefer the [Class]-taking overload from Java.
 */
fun <T : Identity> Context.principal(): T? = with(JavalinSecurityPlugin::class).principal()

/**
 * Returns the principal of the current request cast to [type], or `null` when unauthenticated.
 * Throws [ClassCastException] if the principal is not an instance of [type].
 */
fun <T : Identity> Context.principal(type: Class<T>): T? = with(JavalinSecurityPlugin::class).principal(type)

/**
 * Returns the [Authentication] resolved for the current WebSocket session.
 *
 * Set during `wsBeforeUpgrade` on the upgrade [Context] and readable from [WsContext] handlers via
 * the shared request attribute map. Falls back to unauthenticated if WS security is not installed.
 * Authorization is enforced once at upgrade time and is not re-checked on later messages.
 */
fun WsContext.authentication(): Authentication =
    attribute<Authentication>(JavalinSecurityPlugin.AUTHENTICATION_ATTRIBUTE) ?: Authentication.unauthenticated()

/**
 * Returns the principal of the current WebSocket session, or `null` when unauthenticated.
 * Prefer the [Class]-taking overload from Java.
 */
@Suppress("UNCHECKED_CAST")
fun <T : Identity> WsContext.principal(): T? = authentication().identity as T?

/**
 * Returns the principal of the current WebSocket session cast to [type], or `null` when unauthenticated.
 * Throws [ClassCastException] if the principal is not an instance of [type].
 */
fun <T : Identity> WsContext.principal(type: Class<T>): T? = type.cast(authentication().identity)
