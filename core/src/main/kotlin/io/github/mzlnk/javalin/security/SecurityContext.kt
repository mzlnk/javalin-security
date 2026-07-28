package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.http.Context

/**
 * Per-request security extension exposed by [JavalinSecurityPlugin].
 *
 * Obtain via `ctx.with(JavalinSecurityPlugin::class)` (Kotlin) or `ctx.with(JavalinSecurityPlugin.class)` (Java). The `Context.authentication()` / `Context.identity()` extensions in this package delegate here.
 */
class SecurityContext internal constructor(private val context: Context) {

    /**
     * Returns the [Authentication] resolved for the current request.
     *
     * After the security guard has run this is always populated (unauthenticated when no credentials were provided). If security is not installed or the request never passed through the guard, returns unauthenticated.
     */
    fun authentication(): Authentication =
        context.attribute<Authentication>(JavalinSecurityPlugin.AUTHENTICATION_ATTRIBUTE) ?: Authentication.unauthenticated()

    /** Returns the identity of the current request, or `null` when unauthenticated. */
    @Suppress("UNCHECKED_CAST")
    fun <T : Identity> identity(): T? = authentication().identity as T?

    /**
     * Returns the identity of the current request cast to [type], or `null` when unauthenticated.
     *
     * Prefer this overload from Java; a wrong type yields an immediate `ClassCastException`.
     */
    fun <T : Identity> identity(type: Class<T>): T? = type.cast(authentication().identity)

}
