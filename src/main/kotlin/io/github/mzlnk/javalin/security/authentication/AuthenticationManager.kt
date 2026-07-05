package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context

/**
 * Drives the single configured [AuthenticationProvider].
 *
 * It performs no control-flow branching of its own and never throws: it simply returns the
 * provider's [AuthenticationResult] and lets the [io.github.mzlnk.javalin.security.SecurityGuard]
 * decide how to react.
 */
internal class AuthenticationManager(
    private val provider: AuthenticationProvider,
) {

    fun authenticate(context: Context): AuthenticationResult = provider.resolve(context)

}
