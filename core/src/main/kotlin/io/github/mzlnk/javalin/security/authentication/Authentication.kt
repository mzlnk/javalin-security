package io.github.mzlnk.javalin.security.authentication

import io.javalin.security.RouteRole

/**
 * Security token stored on the Javalin [io.javalin.http.Context] for the duration of a request.
 *
 * Exposes [identity], granted [roles], and [isAuthenticated]. Create instances only through
 * [authenticated] / [unauthenticated]. Roles are owned here — not on [Identity].
 */
class Authentication private constructor(

    /** Caller's identity, or `null` when unauthenticated. */
    val identity: Identity?,

    /** [RouteRole]s granted to the caller. Empty when unauthenticated. */
    val roles: Set<RouteRole>,

) {

    /** `true` when the caller has been successfully authenticated. */
    val isAuthenticated: Boolean get() = (identity != null)

    companion object {

        /**
         * Builds an authenticated [Authentication] for [identity] with the given [roles].
         *
         * [roles] defaults to empty when the scheme grants no roles.
         */
        @JvmStatic
        @JvmOverloads
        fun authenticated(
            identity: Identity,
            roles: Set<RouteRole> = emptySet(),
        ): Authentication = Authentication(identity = identity, roles = roles)

        /** Returns the shared unauthenticated [Authentication]. */
        @JvmStatic
        fun unauthenticated(): Authentication = UNAUTHENTICATED

        private val UNAUTHENTICATED = Authentication(identity = null, roles = emptySet())

    }

}
