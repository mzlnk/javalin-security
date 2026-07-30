package io.github.mzlnk.javalin.security.opaquetoken

import io.javalin.security.RouteRole
import java.time.Instant

/**
 * The record returned by an [OpaqueTokenLookup] for a known opaque token.
 *
 * [subject] is a human-readable identifier for the caller (user id, service name, or similar).
 * [roles] are the [RouteRole]s granted to this token and land on
 * [io.github.mzlnk.javalin.security.authentication.Authentication.roles].
 * [expiresAt], when non-null, is validated by [OpaqueTokenAuthenticator] against its clock;
 * tokens at-or-before "now" are rejected as expired.
 */
data class OpaqueTokenDetails @JvmOverloads constructor(
    val subject: String,
    val roles: Set<RouteRole> = emptySet(),
    val expiresAt: Instant? = null,
)
