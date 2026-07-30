package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.Identity

/**
 * Maps a verified [DecodedJwt] to a caller-defined [Identity].
 *
 * Configure via `jwt { it.identityMapper = ... }` when handlers should see your own domain
 * identity instead of the default [Jwt] wrapper — e.g. looking up a local user record by the
 * token's `sub` claim. Mutually exclusive with [JwtRolesMapper]: since the mapped identity is
 * yours, roles come from its own `roles` property instead of a separate mapper.
 *
 * Returning `null` fails authentication with
 * [io.github.mzlnk.javalin.security.authentication.AuthenticationResult.Failure] — use this when
 * the token is cryptographically valid but no longer maps to a real caller (e.g. a deleted user).
 */
fun interface JwtIdentityMapper {

    /** Maps a verified [token] to an [Identity], or `null` to fail authentication. */
    fun map(token: DecodedJwt): Identity?

}
