package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticatedPrincipal
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.config.JavalinConfig
import io.javalin.http.Context

/**
 * Installs and configures the security framework into a Javalin application using an inline DSL.
 *
 * Call this inside `Javalin.create { }` and configure authorization rules, providers, and failure
 * handlers directly inline — no separate config class required. The call order relative to route
 * declarations does not matter because the guard is wired in `onStart`, after the entire
 * `Javalin.create { }` block has been applied.
 *
 * It registers a `beforeMatched` guard that authenticates and authorizes every matched request.
 * Failures surface as Javalin's native `UnauthorizedResponse` (401) and `ForbiddenResponse` (403).
 *
 * This ordering-independence is a security property: the authorization matcher and the path
 * normalizer mirror the final router configuration at startup, so they cannot diverge from the
 * actual routing regardless of declaration order.
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
