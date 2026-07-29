package io.github.mzlnk.javalin.security.apikey

import io.javalin.security.RouteRole

/**
 * The record returned by an [ApiKeyLookup] for a known API key.
 *
 * [name] is a human-readable identifier for the caller (service name, key label, or similar).
 * [roles] are the [RouteRole]s granted to this key and land on
 * [io.github.mzlnk.javalin.security.authentication.Authentication.roles].
 */
data class ApiKeyPrincipal @JvmOverloads constructor(
    val name: String,
    val roles: Set<RouteRole> = emptySet(),
)
