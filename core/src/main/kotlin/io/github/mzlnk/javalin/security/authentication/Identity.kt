package io.github.mzlnk.javalin.security.authentication

import io.javalin.security.RouteRole

/**
 * Identity of a successfully authenticated caller.
 *
 * Companion libraries supply concrete types that carry scheme-specific data such as subject or
 * claims, and that fully own the [RouteRole]s granted to the caller. Stored on
 * [Authentication.identity] for the duration of the request; [Authentication.authenticated]
 * derives [Authentication.roles] from [roles].
 */
interface Identity {

    /** Human-readable identifier for the caller (username, subject, or similar). */
    val name: String

    /** [RouteRole]s granted to this identity. Defaults to empty when a scheme grants no roles. */
    val roles: Set<RouteRole> get() = emptySet()

}
