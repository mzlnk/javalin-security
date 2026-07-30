package io.github.mzlnk.javalin.security.opaquetoken

import io.github.mzlnk.javalin.security.authentication.Identity
import java.time.Instant

/**
 * The stored record behind an opaque token: the caller's own [identity], plus an optional
 * [expiresAt] the extension checks before authenticating.
 *
 * [expiresAt] is compared against [OpaqueTokenAuthenticator]'s clock; `null` means the token
 * never expires. Revoke a token by having [OpaqueTokenLookup] return `null` for it, rather than
 * returning a [TokenRecord] with a past [expiresAt].
 */
data class TokenRecord @JvmOverloads constructor(
    val identity: Identity,
    val expiresAt: Instant? = null,
)
