package io.github.mzlnk.javalin.security.authentication

import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler

/**
 * Authentication mechanism assigned to `http.authentication` / `ws.authentication`.
 *
 * Carries how to authenticate, which [io.javalin.security.RouteRole]s land on
 * [Authentication.roles], and how to render auth failures. Reassignment replaces the previous
 * strategy (last write wins). A strategy is either [Sync] or [Async], never both. Companion
 * libraries provide factories such as `jwt { }` and `basicAuth { }`; custom mechanisms implement
 * [Sync] or [Async] directly.
 */
sealed interface AuthenticationStrategy {

    /** Renders failed or absent authentication. Defaults to a bare HTTP 401. */
    val unauthorizedHandler: UnauthorizedHandler get() = UnauthorizedHandler.DEFAULT

    /** Renders access denied for an authenticated caller. Defaults to a bare HTTP 403. */
    val forbiddenHandler: ForbiddenHandler get() = ForbiddenHandler.DEFAULT

    /**
     * Strategy backed by a blocking [Authenticator].
     *
     * Prefer [Async] when authentication performs remote I/O and the request thread should be
     * released while that work is in flight.
     */
    interface Sync : AuthenticationStrategy {

        /** Blocking authenticator that resolves the caller's identity. */
        fun authenticator(): Authenticator

    }

    /**
     * Strategy backed by a non-blocking [AsyncAuthenticator].
     *
     * On HTTP, the guard uses [io.javalin.http.Context.future]. On WebSocket upgrade, the future is
     * resolved with a blocking `join()`.
     */
    interface Async : AuthenticationStrategy {

        /** Non-blocking authenticator that resolves the caller's identity. */
        fun authenticator(): AsyncAuthenticator

    }

    companion object {

        /**
         * Builds a [Sync] strategy backed by [authenticator].
         *
         * Convenience for extension authors and custom schemes that would otherwise repeat an
         * anonymous `object : Sync { ... }` around a single [Authenticator].
         */
        @JvmStatic
        @JvmOverloads
        fun sync(
            authenticator: Authenticator,
            unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT,
            forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT,
        ): Sync {
            val authenticatorValue = authenticator
            val unauthorizedHandlerValue = unauthorizedHandler
            val forbiddenHandlerValue = forbiddenHandler
            return object : Sync {
                override val unauthorizedHandler: UnauthorizedHandler get() = unauthorizedHandlerValue
                override val forbiddenHandler: ForbiddenHandler get() = forbiddenHandlerValue
                override fun authenticator(): Authenticator = authenticatorValue
            }
        }

        /**
         * Builds an [Async] strategy backed by [authenticator].
         *
         * Convenience for extension authors and custom schemes that would otherwise repeat an
         * anonymous `object : Async { ... }` around a single [AsyncAuthenticator].
         */
        @JvmStatic
        @JvmOverloads
        fun async(
            authenticator: AsyncAuthenticator,
            unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT,
            forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT,
        ): Async {
            val authenticatorValue = authenticator
            val unauthorizedHandlerValue = unauthorizedHandler
            val forbiddenHandlerValue = forbiddenHandler
            return object : Async {
                override val unauthorizedHandler: UnauthorizedHandler get() = unauthorizedHandlerValue
                override val forbiddenHandler: ForbiddenHandler get() = forbiddenHandlerValue
                override fun authenticator(): AsyncAuthenticator = authenticatorValue
            }
        }

    }

}
