package io.github.mzlnk.javalin.security.authentication

import io.javalin.security.RouteRole

/**
 * The core security token stored on the Javalin [io.javalin.http.Context] for the duration of a request.
 *
 * It exposes the resolved [identity], the [RouteRole]s granted to the caller as [roles], and
 * whether the current request is [isAuthenticated]. Authorization rules are evaluated against
 * this object.
 *
 * Instances are created only through the [authenticated] / [unauthenticated] factories; the
 * constructor is private so these factories remain the single source of valid [Authentication]
 * values.
 */
class Authentication private constructor(

    /** The identity of the caller. `null` when the request is unauthenticated. */
    val identity: Identity?,

    /** The [RouteRole]s granted to the caller. Empty when unauthenticated. */
    val roles: Set<RouteRole>,

) {

    /** `true` when the caller has been successfully authenticated. */
    val isAuthenticated: Boolean get() = (identity != null)

    companion object {

        /** Builds an authenticated [Authentication] for the given [identity] and [roles]. */
        @JvmStatic
        @JvmOverloads
        fun authenticated(identity: Identity, roles: Set<RouteRole> = emptySet()): Authentication =
            Authentication(identity = identity, roles = roles)

        /** Builds an authenticated [Authentication] for the given [identity] and [roles]. */
        @JvmStatic
        fun authenticated(identity: Identity, vararg roles: RouteRole): Authentication =
            Authentication(identity = identity, roles = roles.toSet())

        /** Returns the shared unauthenticated (anonymous) [Authentication]. */
        @JvmStatic
        fun unauthenticated(): Authentication = UNAUTHENTICATED

        private val UNAUTHENTICATED = Authentication(identity = null, roles = emptySet())

    }

}
