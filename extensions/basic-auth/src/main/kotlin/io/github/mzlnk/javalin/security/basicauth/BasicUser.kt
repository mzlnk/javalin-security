package io.github.mzlnk.javalin.security.basicauth

import io.javalin.security.RouteRole

/**
 * The record returned by a [UserLookup] for a known username.
 *
 * [password] is the *encoded* password as understood by the configured [PasswordEncoder] — never
 * the plaintext password a caller sends on the wire. What "encoded" means depends entirely on the
 * [PasswordEncoder] in use: for [PasswordEncoder.noOp] it is a plain string compared as-is; for a
 * hashing-based encoder it would be the hash (and, typically, embedded salt/parameters).
 *
 * [roles] are the [RouteRole]s granted to this user, supplied directly by the application (e.g.
 * from a database column) — they land as-is on [io.github.mzlnk.javalin.security.authentication.Authentication.roles].
 */
data class BasicUser(
    val username: String,
    val password: String,
    val roles: Set<RouteRole> = emptySet(),
)
