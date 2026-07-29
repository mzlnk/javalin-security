@file:JvmName("SecurityExtensions")
package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Identity
import io.javalin.config.JavalinConfig
import io.javalin.http.Context
import io.javalin.websocket.WsContext
import java.util.function.Consumer

/**
 * Installs and configures the security plugin on this [JavalinConfig].
 *
 * Equivalent to `config.registerPlugin(JavalinSecurityPlugin(configure))`. See [JavalinSecurityPlugin]
 * for lifecycle and guard behavior.
 */
fun JavalinConfig.security(configure: Consumer<JavalinSecurityPlugin.Config>) {
    registerPlugin(JavalinSecurityPlugin(configure))
}

/** Returns the [Authentication] resolved for the current request. */
fun Context.authentication(): Authentication = with(JavalinSecurityPlugin::class).authentication()

/**
 * Returns the identity of the current request.
 *
 * Throws [IllegalStateException] when the caller is unauthenticated. Prefer [identityOrNull]
 * when the route may be hit anonymously. Prefer the [Class]-taking overload from Java.
 */
fun <T : Identity> Context.identity(): T = with(JavalinSecurityPlugin::class).identity()

/**
 * Returns the identity of the current request cast to [type].
 *
 * Throws [IllegalStateException] when unauthenticated, or [ClassCastException] if the identity
 * is not an instance of [type]. Prefer [identityOrNull] when the caller may be anonymous.
 */
fun <T : Identity> Context.identity(type: Class<T>): T = with(JavalinSecurityPlugin::class).identity(type)

/**
 * Returns the identity of the current request, or `null` when unauthenticated.
 * Prefer the [Class]-taking overload from Java.
 */
fun <T : Identity> Context.identityOrNull(): T? = with(JavalinSecurityPlugin::class).identityOrNull()

/**
 * Returns the identity of the current request cast to [type], or `null` when unauthenticated.
 * Throws [ClassCastException] if the identity is not an instance of [type].
 */
fun <T : Identity> Context.identityOrNull(type: Class<T>): T? =
    with(JavalinSecurityPlugin::class).identityOrNull(type)

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
 * Returns the identity of the current WebSocket session.
 *
 * Throws [IllegalStateException] when the caller is unauthenticated. Prefer [identityOrNull]
 * when the upgrade may be anonymous. Prefer the [Class]-taking overload from Java.
 */
@Suppress("UNCHECKED_CAST")
fun <T : Identity> WsContext.identity(): T =
    authentication().identity as T? ?: throw missingIdentity()

/**
 * Returns the identity of the current WebSocket session cast to [type].
 *
 * Throws [IllegalStateException] when unauthenticated, or [ClassCastException] if the identity
 * is not an instance of [type]. Prefer [identityOrNull] when the caller may be anonymous.
 */
fun <T : Identity> WsContext.identity(type: Class<T>): T =
    identityOrNull(type) ?: throw missingIdentity()

/**
 * Returns the identity of the current WebSocket session, or `null` when unauthenticated.
 * Prefer the [Class]-taking overload from Java.
 */
@Suppress("UNCHECKED_CAST")
fun <T : Identity> WsContext.identityOrNull(): T? = authentication().identity as T?

/**
 * Returns the identity of the current WebSocket session cast to [type], or `null` when unauthenticated.
 * Throws [ClassCastException] if the identity is not an instance of [type].
 */
fun <T : Identity> WsContext.identityOrNull(type: Class<T>): T? {
    val identity = authentication().identity ?: return null
    return type.cast(identity)
}

private fun missingIdentity(): IllegalStateException =
    IllegalStateException("No authenticated identity on the current request. Use identityOrNull() when the caller may be anonymous.")
