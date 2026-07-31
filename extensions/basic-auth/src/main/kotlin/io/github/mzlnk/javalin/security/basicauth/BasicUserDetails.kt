package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.Identity
import io.javalin.security.RouteRole

/**
 * Lookup result for HTTP Basic authentication: the caller's [identity], the [encodedPassword]
 * used to verify it, and the [roles] granted on success.
 *
 * Separates the caller's [identity] from the [encodedPassword] used to verify it, so the encoded
 * password never has to live on the [Identity] itself and is not reachable from handlers via
 * `ctx.identity<I>()`. [encodedPassword] is compared against the caller-supplied raw password by
 * [PasswordEncoder]. [roles] land on
 * [io.github.mzlnk.javalin.security.authentication.Authentication.roles].
 */
data class BasicUserDetails @JvmOverloads constructor(
    val identity: Identity,
    val encodedPassword: String,
    val roles: Set<RouteRole> = emptySet(),
)
