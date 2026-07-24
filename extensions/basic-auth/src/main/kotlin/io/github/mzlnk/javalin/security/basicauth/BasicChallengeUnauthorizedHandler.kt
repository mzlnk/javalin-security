package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.javalin.http.Context

/**
 * An [UnauthorizedHandler] that includes a `WWW-Authenticate: Basic` challenge (RFC 7617) on 401
 * responses.
 *
 * Enable by setting `basicChallenge = true` in the `basicAuth { }` block (optional `realm`,
 * default `"API"`). The response body is empty; only the challenge header is sent. Failure detail
 * is never exposed, regardless of whether [failure] is present.
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
