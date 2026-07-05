package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context
import io.javalin.http.UnauthorizedResponse

/**
 * Invoked when a request cannot proceed because the caller is not authenticated.
 *
 * This is triggered in two situations:
 * - a provider reported an [AuthenticationResult.Failure] (bad/expired credentials), or
 * - an anonymous caller hit a rule that requires authentication.
 *
 * Companion libraries override this to emit protocol-specific challenges, for example a
 * `WWW-Authenticate: Bearer` header for JWT or `WWW-Authenticate: Basic` for basic auth.
 *
 * The default implementation responds with a generic 401 and never echoes the provider's failure
 * message back to the client, to avoid leaking why authentication failed.
 */
fun interface AuthenticationEntryPoint {

    fun commence(context: Context, failure: AuthenticationResult.Failure?)

    companion object {

        /** The default entry point: a bare `401 Unauthorized` with no credential details leaked. */
        val DEFAULT: AuthenticationEntryPoint = AuthenticationEntryPoint { _, _ -> throw UnauthorizedResponse() }

    }

}
