package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticatedPrincipal
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.http.Context

/**
 * The per-request extension exposed by [JavalinSecurityPlugin], obtained via
 * `ctx.with(JavalinSecurityPlugin.class)` (Java) or `ctx.with(JavalinSecurityPlugin::class)`
 * (Kotlin) — Javalin's own language-neutral pattern for plugin-provided context data (compare
 * `ctx.with(RateLimitPlugin.class)`).
 *
 * The `Context.authentication()` / `Context.principal()` Kotlin extension functions in
 * `extensions.kt` are thin sugar over this same class, kept for Kotlin call-site convenience.
 */
class SecurityContext internal constructor(private val context: Context) {

    /**
     * Returns the [Authentication] resolved for the current request.
     *
     * After the security guard has run this is always populated (an unauthenticated
     * [Authentication] when no credentials were provided). If security is not installed, or this
     * request was never passed through the guard, falls back to unauthenticated.
     */
    fun authentication(): Authentication =
        context.attribute<Authentication>(JavalinSecurityPlugin.AUTHENTICATION_ATTRIBUTE) ?: Authentication.unauthenticated()

    /** Convenience accessor for the principal of the current request. `null` when the request is unauthenticated. */
    @Suppress("UNCHECKED_CAST")
    fun <T : AuthenticatedPrincipal> principal(): T? = authentication().principal as T?

}
