package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.javalin.http.Context

/**
 * An [UnauthorizedHandler] that includes a `WWW-Authenticate: Bearer` challenge in the 401 response.
 *
 * This is opt-in behavior. To activate it, set `bearerChallenge = true` inside the `jwt { }`
 * block, or assign an instance directly to `http.unauthorizedHandler` / `ws.unauthorizedHandler`:
 *
 * ```kotlin
 * http { http ->
 *     http.jwt { jwt ->
 *         jwt.decoder = myDecoder
 *         jwt.bearerChallenge = true    // emits WWW-Authenticate header
 *         jwt.realm = "My API"          // optional, defaults to "API"
 *     }
 * }
 * ```
 *
 * The response body is intentionally empty — the only information sent to the caller is the
 * `WWW-Authenticate` header. No internal failure detail is ever exposed.
 *
 * When [failure] carries an [AuthenticationResult.Failure] (bad/expired token), the response
 * includes `error="invalid_token"`. When the caller was simply unauthenticated (no token sent),
 * [failure] is `null` and no `error` attribute is included.
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
