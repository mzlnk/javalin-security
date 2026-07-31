package io.github.mzlnk.javalin.security.opaquetoken

import io.github.mzlnk.javalin.security.authentication.Identity
import io.javalin.security.RouteRole
import java.time.Instant

/**
 * The stored record behind an opaque token: the caller's own [identity], optional [expiresAt]
 * the extension checks before authenticating, and the [roles] granted on success.
 *
 * [expiresAt] is compared against [OpaqueTokenAuthenticator]'s clock; `null` means the token
 * never expires. Revoke a token by having [OpaqueTokenLookup] return `null` for it, rather than
 * returning an [OpaqueTokenDetails] with a past [expiresAt]. [roles] land on
 * [io.github.mzlnk.javalin.security.authentication.Authentication.roles].
 */
data class OpaqueTokenDetails @JvmOverloads constructor(
    val identity: Identity,
    val expiresAt: Instant? = null,
    val roles: Set<RouteRole> = emptySet(),
)
