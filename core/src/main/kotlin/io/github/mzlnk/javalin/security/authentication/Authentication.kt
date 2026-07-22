package io.github.mzlnk.javalin.security.authentication

import io.javalin.security.RouteRole

/**
 * The core security token stored on the Javalin [io.javalin.http.Context] for the duration of a request.
 *
 * It exposes the resolved [principal], the [RouteRole]s granted to the caller as [roles], and
 * whether the current request is [isAuthenticated]. Authorization rules are evaluated against
 * this object.
 */
interface Authentication {

    /** The identity of the caller. `null` when the request is unauthenticated. */
    val principal: AuthenticatedPrincipal?

    /** The [RouteRole]s granted to the caller. Empty when unauthenticated. */
    val roles: Set<RouteRole>

    /** `true` when the caller has been successfully authenticated. */
    val isAuthenticated: Boolean

    companion object {

        /** Builds an authenticated [Authentication] for the given [principal] and [roles]. */
        @JvmStatic
        @JvmOverloads
        fun authenticated(principal: AuthenticatedPrincipal, roles: Set<RouteRole> = emptySet()): Authentication =
            AuthenticatedAuthentication(principal = principal, roles = roles)

        /** Builds an authenticated [Authentication] for the given [principal] and [roles]. */
        @JvmStatic
        fun authenticated(principal: AuthenticatedPrincipal, vararg roles: RouteRole): Authentication =
            AuthenticatedAuthentication(principal = principal, roles = roles.toSet())

        /** Returns the shared unauthenticated (anonymous) [Authentication]. */
        @JvmStatic
        fun unauthenticated(): Authentication = UnauthenticatedAuthentication

    }

}

internal data class AuthenticatedAuthentication(
    override val principal: AuthenticatedPrincipal,
    override val roles: Set<RouteRole>,
) : Authentication {

    override val isAuthenticated: Boolean = true

}

internal data object UnauthenticatedAuthentication : Authentication {

    override val principal: AuthenticatedPrincipal? = null
    override val roles: Set<RouteRole> = emptySet()
    override val isAuthenticated: Boolean = false

}
