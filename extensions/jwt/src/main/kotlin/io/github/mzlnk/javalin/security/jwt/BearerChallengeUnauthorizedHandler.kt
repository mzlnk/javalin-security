package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.javalin.http.Context

/**
 * An [UnauthorizedHandler] that includes a `WWW-Authenticate: Bearer` challenge on 401 responses.
 *
 * Enable by setting `bearerChallenge = true` in the `jwt { }` block (optional `realm`, default
 * `"API"`). The response body is empty; only the challenge header is sent. When [failure] is an
 * [AuthenticationResult.Failure], the header includes `error="invalid_token"`; when the caller was
 * simply unauthenticated, [failure] is `null` and no `error` attribute is included.
 */
class BearerChallengeUnauthorizedHandler(private val realm: String = "API") : UnauthorizedHandler {

    override fun handle(context: Context, failure: AuthenticationResult.Failure?) {
        val challenge = buildString {
            append("""Bearer realm="$realm"""")
            if (failure != null) {
                append(""", error="invalid_token"""")
            }
        }
        context.header("WWW-Authenticate", challenge)
        context.status(401)
    }

    companion object {

        /** Creates a [BearerChallengeUnauthorizedHandler] with the given [realm] (defaults to `"API"`). */
        @JvmStatic
        @JvmOverloads
        fun withRealm(realm: String = "API"): BearerChallengeUnauthorizedHandler =
            BearerChallengeUnauthorizedHandler(realm)

    }

}
