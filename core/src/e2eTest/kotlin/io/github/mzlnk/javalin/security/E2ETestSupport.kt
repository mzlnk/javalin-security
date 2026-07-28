package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler

/** Minimal [Identity] for e2e tests. */
data class TestIdentity(override val name: String) : Identity

/**
 * Builds an [AuthenticationStrategy.Sync] for e2e tests.
 * [authenticator] defaults to always returning [AuthenticationResult.NotAuthenticated].
 */
fun authenticationStrategy(
    authenticator: Authenticator = Authenticator { AuthenticationResult.NotAuthenticated },
    unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT,
    forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT,
): AuthenticationStrategy.Sync = object : AuthenticationStrategy.Sync {
    override val unauthorizedHandler: UnauthorizedHandler = unauthorizedHandler
    override val forbiddenHandler: ForbiddenHandler = forbiddenHandler
    override fun authenticator(): Authenticator = authenticator
}

/** Builds an [AuthenticationStrategy.Async] for e2e tests. */
fun asyncAuthenticationStrategy(
    asyncAuthenticator: AsyncAuthenticator,
    unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT,
    forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT,
): AuthenticationStrategy.Async = object : AuthenticationStrategy.Async {
    override val unauthorizedHandler: UnauthorizedHandler = unauthorizedHandler
    override val forbiddenHandler: ForbiddenHandler = forbiddenHandler
    override fun authenticator(): AsyncAuthenticator = asyncAuthenticator
}
