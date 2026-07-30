package io.github.mzlnk.javalin.security.session

import io.javalin.security.RouteRole
import java.io.Serializable

/**
 * The record stored in the HTTP session for a logged-in caller.
 *
 * [subject] is a human-readable identifier (username, user id, or similar).
 * [roles] are the [RouteRole]s granted to this principal and land on
 * [io.github.mzlnk.javalin.security.authentication.Authentication.roles] after authentication.
 *
 * Must be [Serializable] so it can travel with the session when the container uses a
 * distributed session store. Prefer enum [RouteRole]s (enums are serializable) when
 * sessions may be replicated.
 */
data class SessionPrincipal @JvmOverloads constructor(
    val subject: String,
    val roles: Set<RouteRole> = emptySet(),
) : Serializable {
    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
