package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.Identity
import io.javalin.security.RouteRole

/**
 * The [Identity] produced by JWT authentication.
 *
 * Wraps the verified [token] so handlers and authorization rules can read claims without
 * re-parsing. [name] is the `sub` claim; when `sub` is absent, [name] is an empty string.
 * [roles], resolved via [JwtRolesMapper] from the decoded token, land on
 * [io.github.mzlnk.javalin.security.authentication.Authentication.roles].
 */
class Jwt @JvmOverloads constructor(
    val token: DecodedJwt,
    override val roles: Set<RouteRole> = emptySet(),
) : Identity {

    override val name: String get() = token.subject

}
