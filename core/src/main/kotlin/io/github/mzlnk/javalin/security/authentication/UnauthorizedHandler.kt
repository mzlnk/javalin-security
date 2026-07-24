package io.github.mzlnk.javalin.security.authentication

import io.javalin.http.Context
import io.javalin.http.UnauthorizedResponse

/**
 * Handles requests that cannot proceed because the caller is not authenticated.
 *
 * Invoked on [AuthenticationResult.Failure] or when an anonymous caller hits a rule that requires
 * authentication. The default responds with a generic 401 and does not echo failure details.
 * Implementations only need to render the response; the guard skips remaining handlers afterward.
 */
fun interface UnauthorizedHandler {

    /**
     * Renders the unauthorized response for [context].
     * [failure] is non-null when authentication failed; `null` when the caller is anonymous.
     */
    fun handle(context: Context, failure: AuthenticationResult.Failure?)

    companion object {

        /** Default handler: bare `401 Unauthorized` via [UnauthorizedResponse]. */
        @JvmStatic
        val DEFAULT: UnauthorizedHandler = UnauthorizedHandler { _, _ -> throw UnauthorizedResponse() }

    }

}
