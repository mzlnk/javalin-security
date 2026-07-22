package io.github.mzlnk.javalin.security

import io.javalin.security.RouteRole

/**
 * A built-in [RouteRole] that marks a route as publicly accessible, even to unauthenticated
 * callers, when declared alongside this library's guard:
 *
 * ```kotlin
 * config.routes.get("/public", handler, Anyone)
 * ```
 *
 * This is the RouteRole-based equivalent of the pattern-table's `allow` rule, for routes that
 * declare their roles directly rather than relying on a pattern match.
 */
object Anyone : RouteRole
