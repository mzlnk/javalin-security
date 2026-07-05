package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.Authentication
import io.javalin.http.Context
import io.javalin.http.ForbiddenResponse

/**
 * Invoked when an authenticated caller is denied access by the authorization rules.
 *
 * Applications override this to customise the 403 response (body, headers, problem+json, etc.).
 * The default implementation responds with a bare `403 Forbidden`.
 */
fun interface AccessDeniedHandler {

    fun handle(context: Context, authentication: Authentication)

    companion object {

        /** The default handler: a bare `403 Forbidden`. */
        val DEFAULT: AccessDeniedHandler = AccessDeniedHandler { _, _ -> throw ForbiddenResponse() }

    }

}
