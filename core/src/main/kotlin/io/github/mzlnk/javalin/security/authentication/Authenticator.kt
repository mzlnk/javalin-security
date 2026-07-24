package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context

/**
 * Blocking authentication hook for a request.
 *
 * Returns [AuthenticationResult.Success], [AuthenticationResult.Failure], or
 * [AuthenticationResult.NotAuthenticated]. Must not throw when no credentials are present.
 * Register via [AuthenticationStrategy.Sync.authenticator] or a companion factory such as `jwt { }`.
 */
fun interface Authenticator {

    /** Authenticates [context] and returns the result. */
    fun authenticate(context: Context): AuthenticationResult

}
