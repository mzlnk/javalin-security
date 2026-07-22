package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.http.Context
import io.javalin.http.ForbiddenResponse

/**
 * Invoked when an authenticated caller is denied access by the authorization rules.
 *
 * Applications override this to customise the 403 response (body, headers, problem+json, etc.).
 * The default implementation responds with a bare `403 Forbidden`, mirroring Javalin's own
 * [ForbiddenResponse].
 *
 * Implementations do not need to throw to stop the request: the guard skips all remaining handlers
 * after invoking this callback, so the matched handler is never reached. Simply rendering the desired
 * response (status, headers, body) is sufficient.
 */
fun interface ForbiddenHandler {

    fun handle(context: Context, authentication: Authentication)

    companion object {

        /** The default handler: a bare `403 Forbidden`. */
        val DEFAULT: ForbiddenHandler = ForbiddenHandler { _, _ -> throw ForbiddenResponse() }

    }

}
