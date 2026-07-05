package io.github.mzlnk.javalin.security

/**
 * The core security token stored on the Javalin [io.javalin.http.Context] for the duration of a request.
 *
 * It exposes the resolved [principal], the granted [authorities] and whether the current request
 * is [isAuthenticated]. Authorization rules are evaluated against this object.
 */
interface Authentication {

    /** The identity of the caller. Either an [AuthenticatedPrincipal] or [UnauthenticatedPrincipal]. */
    val principal: Principal

    /** The authorities (roles/permissions) granted to the caller. Empty when unauthenticated. */
    val authorities: Set<String>

    /** `true` when the caller has been successfully authenticated. */
    val isAuthenticated: Boolean

    companion object {

        /** Builds an authenticated [Authentication] for the given [principal] and [authorities]. */
        @JvmStatic
        @JvmOverloads
        fun authenticated(principal: AuthenticatedPrincipal, authorities: Set<String> = emptySet()): Authentication =
            AuthenticatedAuthentication(principal = principal, authorities = authorities)

        /** Builds an authenticated [Authentication] for the given [principal] and [authorities]. */
        @JvmStatic
        fun authenticated(principal: AuthenticatedPrincipal, vararg authorities: String): Authentication =
            AuthenticatedAuthentication(principal = principal, authorities = authorities.toSet())

        /** Returns the shared unauthenticated (anonymous) [Authentication]. */
        @JvmStatic
        fun unauthenticated(): Authentication = UnauthenticatedAuthentication

    }

}

internal data class AuthenticatedAuthentication(
    override val principal: AuthenticatedPrincipal,
    override val authorities: Set<String>,
) : Authentication {

    override val isAuthenticated: Boolean = true

}

internal data object UnauthenticatedAuthentication : Authentication {

    override val principal: Principal = UnauthenticatedPrincipal
    override val authorities: Set<String> = emptySet()
    override val isAuthenticated: Boolean = false

}
