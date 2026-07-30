@file:JvmMultifileClass
@file:JvmName("SessionSecurity")

package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import java.util.function.Consumer

/**
 * Configuration for the [session] strategy factory.
 *
 * Builds an [AuthenticationStrategy.Sync] backed by a [SessionAuthenticator] and
 * [sessionManager]. The identity type your session stores is your own — bring your own type;
 * roles come from its `roles` property. When using the default [HttpSessionManager], the
 * identity must be `java.io.Serializable` (rejected at create time). Session create/invalidate
 * is the caller's responsibility — keep a reference to [sessionManager] and call it from your
 * login/logout handlers.
 */
class SessionConfig internal constructor() {

    /**
     * The [SessionManager] backing the built [SessionAuthenticator].
     *
     * Defaults to [HttpSessionManager.of] (servlet-session storage). Bring your own
     * implementation (Redis, in-memory, signed cookie, …) to change how sessions are stored.
     * Hold onto this reference (or your own instance) to create and invalidate sessions from
     * application handlers.
     */
    @JvmField
    var sessionManager: SessionManager = HttpSessionManager.of()

    /** Renders 403 responses for authenticated callers denied by authorization. Defaults to a bare 403. */
    @JvmField
    var forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT

    /**
     * Renders 401 responses for failed or absent authentication.
     * Defaults to [UnauthorizedHandler.DEFAULT] (bare HTTP 401).
     */
    @JvmField
    var unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT

}

/**
 * Builds an [AuthenticationStrategy.Sync] for session-based authentication.
 *
 * Assign the result to `http.authentication`. Nothing is required — [SessionConfig.sessionManager]
 * defaults to [HttpSessionManager.of]. Keep a reference to your [SessionManager] and call
 * [SessionManager.create] / [SessionManager.invalidate] from login/logout handlers; the strategy
 * only validates sessions on each request. To use [SessionAuthenticator] directly, call
 * [SessionAuthenticator.builder] and wrap it in a custom [AuthenticationStrategy.Sync] (or
 * [AuthenticationStrategy.sync]).
 */
fun session(configure: Consumer<SessionConfig>): AuthenticationStrategy.Sync {
    val config = SessionConfig().also(configure::accept)
    return AuthenticationStrategy.sync(
        authenticator = SessionAuthenticator.of(config.sessionManager),
        unauthorizedHandler = config.unauthorizedHandler,
        forbiddenHandler = config.forbiddenHandler,
    )
}
