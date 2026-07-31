package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.authentication.Identity
import io.javalin.security.RouteRole
import java.io.Serializable

/**
 * Session payload: the caller's [identity] and the [roles] granted for the session.
 *
 * Stored by [SessionManager] implementations (including [HttpSessionManager]). [roles] land on
 * [io.github.mzlnk.javalin.security.authentication.Authentication.roles] when the session is
 * validated. When using [HttpSessionManager], [identity] must itself be [Serializable].
 */
data class SessionDetails @JvmOverloads constructor(
    val identity: Identity,
    val roles: Set<RouteRole> = emptySet(),
) : Serializable
