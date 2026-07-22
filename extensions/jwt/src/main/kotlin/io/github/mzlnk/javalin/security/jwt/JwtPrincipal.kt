package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.AuthenticatedPrincipal

/**
 * The [AuthenticatedPrincipal] produced by JWT authentication.
 *
 * Wraps the fully verified and decoded [token] so that route handlers and authorization rules can
 * read any claim without re-parsing the token:
 *
 * ```kotlin
 * val principal: JwtPrincipal? = ctx.principal()
 * val roles: List<String>? = principal?.token?.claim("roles")
 * ```
 *
 * [name] is the `sub` (subject) claim; it is used for logging and as the human-readable identity.
 * When no `sub` claim was present in the token, [name] is an empty string — callers that require a
 * non-empty subject should validate it in their [JwtAuthoritiesMapper] or a custom authorization rule.
 */
class JwtPrincipal(val token: DecodedJwt) : AuthenticatedPrincipal {

    override val name: String get() = token.subject

}
