package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.http.Context
import io.javalin.http.ForbiddenResponse

/**
 * Handles access denied for an authenticated caller.
 *
 * Defaults to a bare `403 Forbidden` via [ForbiddenResponse]. Implementations only need to render
 * the response; the guard skips remaining handlers afterward.
 */
fun interface ForbiddenHandler {

    /** Renders the forbidden response for [context] given the caller's [authentication]. */
    fun handle(context: Context, authentication: Authentication)

    companion object {

        /** Default handler: bare `403 Forbidden`. */
        @JvmStatic
        val DEFAULT: ForbiddenHandler = ForbiddenHandler { _, _ -> throw ForbiddenResponse() }

    }

}
