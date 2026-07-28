package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.Identity

/**
 * The [Identity] produced by JWT authentication.
 *
 * Wraps the verified [token] so handlers and authorization rules can read claims without
 * re-parsing. [name] is the `sub` claim; when `sub` is absent, [name] is an empty string.
 */
class JwtIdentity(val token: DecodedJwt) : Identity {

    override val name: String get() = token.subject

}
