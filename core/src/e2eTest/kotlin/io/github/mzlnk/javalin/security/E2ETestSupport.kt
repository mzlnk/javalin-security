package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler

/**
 * A minimal [Identity] used to identify the caller across e2e tests, standing in for a real
 * application principal (e.g. a JPA `User` entity or a decoded token subject).
 */
data class TestPrincipal(override val name: String) : Identity

/**
 * Builds an [AuthenticationStrategy.Sync] directly, without going through a companion library's
 * `jwt { }` / `basicAuth { }` factory — the way a fully custom authentication mechanism is wired
 * up (see [AuthenticationStrategy]).
 *
 * [authenticator] defaults to a no-op authenticator that always reports
 * [AuthenticationResult.NotAuthenticated] (anonymous), so a strategy can be built purely to carry
 * an [unauthorizedHandler] or [forbiddenHandler] override.
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

/** Builds an [AuthenticationStrategy.Async] directly. See [authenticationStrategy] for the optional overrides. */
fun asyncAuthenticationStrategy(
    asyncAuthenticator: AsyncAuthenticator,
    unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT,
    forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT,
): AuthenticationStrategy.Async = object : AuthenticationStrategy.Async {
    override val unauthorizedHandler: UnauthorizedHandler = unauthorizedHandler
    override val forbiddenHandler: ForbiddenHandler = forbiddenHandler
    override fun authenticator(): AsyncAuthenticator = asyncAuthenticator
}
