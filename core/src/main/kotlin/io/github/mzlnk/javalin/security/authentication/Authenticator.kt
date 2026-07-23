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
 * Register by implementing [AuthenticationStrategy.Sync] and returning this from
 * [AuthenticationStrategy.Sync.authenticator] — either directly, or via a companion library's
 * strategy factory (e.g. `http.authentication = jwt { }`).
 */
fun interface Authenticator {

    fun authenticate(context: Context): AuthenticationResult

}
