package io.github.mzlnk.javalin.security.apikey

import io.github.mzlnk.javalin.security.authentication.Identity
import io.javalin.security.RouteRole

/**
 * Lookup result for opaque API-key authentication: the caller's [identity] and the [roles]
 * granted on success.
 *
 * [roles] land on [io.github.mzlnk.javalin.security.authentication.Authentication.roles].
 */
data class ApiKeyDetails @JvmOverloads constructor(
    val identity: Identity,
    val roles: Set<RouteRole> = emptySet(),
)
