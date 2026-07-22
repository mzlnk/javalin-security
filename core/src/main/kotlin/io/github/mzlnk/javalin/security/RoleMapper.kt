package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.http.Context
import io.javalin.security.RouteRole

/**
 * Maps a resolved [Authentication] to the set of Javalin [RouteRole]s the caller holds.
 *
 * This is the bridge between the framework-agnostic [Authentication] (authorities as strings) and
 * Javalin's own route-declaration mechanism (`config.routes.get(path, handler, Role.ADMIN)`,
 * `ctx.routeRoles()`). When a route declares roles, the guard grants access if the mapped roles
 * intersect the declared ones (or if the declared roles include [Anyone]); when a route declares
 * no roles, the pattern-based rule table (see `rules { }`) decides instead.
 *
 * Register via `http.roleMapper = { authentication, ctx -> ... }`.
 */
fun interface RoleMapper {

    fun map(authentication: Authentication, context: Context): Set<RouteRole>

}
