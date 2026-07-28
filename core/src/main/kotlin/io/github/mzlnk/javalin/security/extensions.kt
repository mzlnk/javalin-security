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
 * Returns the identity of the current request, or `null` when unauthenticated.
 * Prefer the [Class]-taking overload from Java.
 */
fun <T : Identity> Context.identity(): T? = with(JavalinSecurityPlugin::class).identity()

/**
 * Returns the identity of the current request cast to [type], or `null` when unauthenticated.
 * Throws [ClassCastException] if the identity is not an instance of [type].
 */
fun <T : Identity> Context.identity(type: Class<T>): T? = with(JavalinSecurityPlugin::class).identity(type)

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
 * Returns the identity of the current WebSocket session, or `null` when unauthenticated.
 * Prefer the [Class]-taking overload from Java.
 */
@Suppress("UNCHECKED_CAST")
fun <T : Identity> WsContext.identity(): T? = authentication().identity as T?

/**
 * Returns the identity of the current WebSocket session cast to [type], or `null` when unauthenticated.
 * Throws [ClassCastException] if the identity is not an instance of [type].
 */
fun <T : Identity> WsContext.identity(type: Class<T>): T? = type.cast(authentication().identity)
