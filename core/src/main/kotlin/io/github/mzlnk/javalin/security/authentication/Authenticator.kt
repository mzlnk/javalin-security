package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context

/**
 * The single pluggable hook for authentication.
 *
 * Implementations inspect the incoming request and return a decisive [AuthenticationResult]:
 * [AuthenticationResult.Success] when valid credentials are present, [AuthenticationResult.Failure]
 * when credentials are present but invalid, or [AuthenticationResult.NotAuthenticated] when no
 * credentials are present at all (the request proceeds as anonymous and the authorization rules
 * decide whether access is allowed).
 *
 * Implementations must not throw for the "no credentials present" case.
 *
 * Register via `http.authenticator = { ctx -> ... }`, or the fluent Java assignment
 * `http.authenticator = ctx -> ...`.
 */
fun interface Authenticator {

    fun authenticate(context: Context): AuthenticationResult

}
