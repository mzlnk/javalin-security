package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator
import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import io.javalin.http.Context
import io.javalin.http.HandlerType
import io.mockk.every
import io.mockk.mockk

/** Minimal [Identity] for unit tests. */
data class TestIdentity(override val name: String) : Identity

/** Creates a [Context] mock with [Context.method], [Context.path], and [Context.header] stubbed. */
fun mockContext(
    method: HandlerType = HandlerType.GET,
    path: String = "/",
    headers: Map<String, String> = emptyMap(),
): Context =
    mockk {
        every { method() } returns method
        every { path() } returns path
        every { header(any()) } answers { headers[firstArg()] }
    }

/**
 * Builds an [AuthenticationStrategy.Sync] for tests.
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

/** Builds an [AuthenticationStrategy.Async] for tests. */
fun asyncAuthenticationStrategy(
    asyncAuthenticator: AsyncAuthenticator,
    unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT,
    forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT,
): AuthenticationStrategy.Async = object : AuthenticationStrategy.Async {
    override val unauthorizedHandler: UnauthorizedHandler = unauthorizedHandler
    override val forbiddenHandler: ForbiddenHandler = forbiddenHandler
    override fun authenticator(): AsyncAuthenticator = asyncAuthenticator
}
