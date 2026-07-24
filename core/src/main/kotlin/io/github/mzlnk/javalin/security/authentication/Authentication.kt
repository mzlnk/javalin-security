package io.github.mzlnk.javalin.security.authentication

import io.javalin.security.RouteRole

/**
 * Security token stored on the Javalin [io.javalin.http.Context] for the duration of a request.
 *
 * Exposes [identity], granted [roles], and [isAuthenticated]. Create instances only through
 * [authenticated] / [unauthenticated].
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

        /** Builds an authenticated [Authentication] for [identity] and [roles]. */
        @JvmStatic
        @JvmOverloads
        fun authenticated(identity: Identity, roles: Set<RouteRole> = emptySet()): Authentication =
            Authentication(identity = identity, roles = roles)

        /** Builds an authenticated [Authentication] for [identity] and [roles]. */
        @JvmStatic
        fun authenticated(identity: Identity, vararg roles: RouteRole): Authentication =
            Authentication(identity = identity, roles = roles.toSet())

        /** Returns the shared unauthenticated [Authentication]. */
        @JvmStatic
        fun unauthenticated(): Authentication = UNAUTHENTICATED

        private val UNAUTHENTICATED = Authentication(identity = null, roles = emptySet())

    }

}
