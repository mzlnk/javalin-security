@file:JvmName("SessionSecurity")

package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import java.util.function.Consumer

/**
 * Configuration for the [session] strategy factory.
 *
 * Builds an [AuthenticationStrategy.Sync] backed by a [SessionAuthenticator] and the caller's
 * [sessionManager]. [sessionManager] is the extension's single storage abstraction —
 * lifecycle (login, validate, logout) is driven by calling the manager directly from your
 * handlers. See [HttpSessionManager] for the servlet-backed default implementation.
 */
class SessionConfig internal constructor() {

    /**
     * The [SessionManager] backing the built [SessionAuthenticator]. Required; throws
     * [SecurityConfigurationException] if unset when the strategy is built.
     *
     * Set to an instance of [HttpSessionManager] for standard servlet-session storage, or
     * bring your own implementation (Redis, in-memory, signed cookie, …).
     */
    @JvmField
    var sessionManager: SessionManager? = null

    /** Renders 403 responses for authenticated callers denied by authorization. Defaults to a bare 403. */
    @JvmField
    var forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT

    /**
     * Renders 401 responses for failed or absent authentication.
     * Defaults to [UnauthorizedHandler.DEFAULT] (bare HTTP 401).
     */
    @JvmField
    var unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT

    internal fun buildAuthenticator(): SessionAuthenticator {
        val manager = sessionManager ?: throw SecurityConfigurationException(
            "session.sessionManager is required but was not configured. " +
                "Set 'sessionManager = ...' inside the 'session { }' block " +
                "(e.g. 'sessionManager = HttpSessionManager.of()').",
        )
        return SessionAuthenticator.of(manager)
    }

}

/**
 * Builds an [AuthenticationStrategy.Sync] for session-based authentication.
 *
 * Assign the result to `http.authentication`. [SessionConfig.sessionManager] is required —
 * hold the same [SessionManager] reference in your login / logout handlers and call
 * [SessionManager.create] / [SessionManager.invalidate] directly.
 *
 * To use [SessionAuthenticator] directly (without the DSL), call [SessionAuthenticator.of]
 * with your [SessionManager] and wrap it in a custom [AuthenticationStrategy.Sync].
 */
fun session(configure: Consumer<SessionConfig>): AuthenticationStrategy.Sync {
    val config = SessionConfig().also(configure::accept)
    val authenticator = config.buildAuthenticator()
    val unauthorizedHandlerValue = config.unauthorizedHandler
    val forbiddenHandlerValue = config.forbiddenHandler
    return object : AuthenticationStrategy.Sync {
        override val unauthorizedHandler: UnauthorizedHandler get() = unauthorizedHandlerValue
        override val forbiddenHandler: ForbiddenHandler get() = forbiddenHandlerValue
        override fun authenticator() = authenticator
    }
}
