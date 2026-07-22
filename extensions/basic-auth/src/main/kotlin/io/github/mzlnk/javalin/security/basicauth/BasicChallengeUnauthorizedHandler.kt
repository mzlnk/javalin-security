package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.javalin.http.Context

/**
 * An [UnauthorizedHandler] that includes a `WWW-Authenticate: Basic` challenge (RFC 7617) in the
 * 401 response.
 *
 * This is opt-in behavior. To activate it, set `basicChallenge = true` inside the `basicAuth { }`
 * block:
 *
 * ```kotlin
 * http { http ->
 *     http.authentication = basicAuth { basic ->
 *         basic.userLookup = myUserLookup
 *         basic.basicChallenge = true   // emits WWW-Authenticate header
 *         basic.realm = "My API"        // optional, defaults to "API"
 *     }
 * }
 * ```
 *
 * The response body is intentionally empty — the only information sent to the caller is the
 * `WWW-Authenticate` header. No internal failure detail (e.g. which of "unknown user" or "wrong
 * password" occurred) is ever exposed, regardless of whether [failure] is present.
 */
class BasicChallengeUnauthorizedHandler(private val realm: String = "API") : UnauthorizedHandler {

    override fun handle(context: Context, failure: AuthenticationResult.Failure?) {
        context.header("WWW-Authenticate", """Basic realm="$realm", charset="UTF-8"""")
        context.status(401)
    }

    companion object {

        /** Creates a [BasicChallengeUnauthorizedHandler] with the given [realm] (defaults to `"API"`). */
        @JvmStatic
        @JvmOverloads
        fun withRealm(realm: String = "API"): BasicChallengeUnauthorizedHandler =
            BasicChallengeUnauthorizedHandler(realm)

    }

}
