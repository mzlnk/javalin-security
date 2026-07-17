package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.AuthenticatedPrincipal

/**
 * The [AuthenticatedPrincipal] produced by HTTP Basic authentication.
 *
 * [name] is the username supplied in the request's `Basic` credentials, as resolved by
 * [BasicCredentialsResolver] and validated against a [UserLookup]:
 *
 * ```kotlin
 * val principal: BasicAuthPrincipal = ctx.principal()
 * val username: String = principal.name
 * ```
 */
class BasicAuthPrincipal(override val name: String) : AuthenticatedPrincipal
