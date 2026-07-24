package io.github.mzlnk.javalin.security

import io.javalin.security.RouteRole

/**
 * Built-in [RouteRole] that grants public access to a route, including unauthenticated callers.
 *
 * Equivalent to the pattern-table `allow` rule when roles are declared on the route itself
 * (e.g. `config.routes.get("/public", handler, Anyone)`).
 */
object Anyone : RouteRole
