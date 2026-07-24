package io.github.mzlnk.javalin.security.basicauth

import io.javalin.security.RouteRole

/**
 * The record returned by a [UserLookup] for a known username.
 *
 * [password] is the encoded password as understood by the configured [PasswordEncoder], not the
 * plaintext sent on the wire. [roles] are the [RouteRole]s granted to this user and land on
 * [io.github.mzlnk.javalin.security.authentication.Authentication.roles].
 */
data class BasicUser(
    val username: String,
    val password: String,
    val roles: Set<RouteRole> = emptySet(),
)
