package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authorization.AuthorizationManager
import io.javalin.http.Context
import io.javalin.http.ForbiddenResponse
import io.javalin.http.UnauthorizedResponse

/**
 * The request-time pipeline and the sole bridge between the framework and Javalin.
 *
 * It authenticates, publishes the [Authentication] on the [Context], then authorizes. This is the
 * only component allowed to signal failures, which it does exclusively through Javalin's native
 * [UnauthorizedResponse] (401) and [ForbiddenResponse] (403). No custom exceptions, interception,
 * reflection or thread-locals are involved.
 */
internal class SecurityGuard(
    private val authenticationManager: AuthenticationManager,
    private val authorizationManager: AuthorizationManager,
) {

    fun handle(context: Context) {
        val authentication = when (val result = authenticationManager.authenticate(context)) {
            is AuthenticationResult.Success -> result.authentication
            is AuthenticationResult.NotAuthenticated -> Authentication.unauthenticated()
            is AuthenticationResult.Failure -> throw UnauthorizedResponse(result.message ?: "Unauthorized")
        }

        context.attribute(AUTHENTICATION_ATTRIBUTE, authentication)

        if (!authorizationManager.isGranted(context, authentication)) {
            if (authentication.isAuthenticated) {
                throw ForbiddenResponse()
            } else {
                throw UnauthorizedResponse()
            }
        }
    }

}
