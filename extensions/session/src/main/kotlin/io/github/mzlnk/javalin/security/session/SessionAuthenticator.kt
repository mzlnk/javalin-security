package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.http.Context

/**
 * Implements session-based authentication by delegating to a [SessionManager].
 *
 * On each request, calls [SessionManager.validate] to resolve the current identity:
 * - `null` → [AuthenticationResult.NotAuthenticated] (the request continues as anonymous)
 * - non-null → [AuthenticationResult.Success] with the identity
 *
 * [sessionManager] is a required composition dependency: it fully owns how sessions are
 * created, validated, and destroyed. The authenticator itself is storage-agnostic.
 *
 * Construct via `session { }`, [Builder], or [of].
 */
class SessionAuthenticator private constructor(
    /** The [SessionManager] this authenticator delegates to. Required. */
    val sessionManager: SessionManager,
) : Authenticator {

    override fun authenticate(context: Context): AuthenticationResult {
        val identity = sessionManager.validate(context)
            ?: return AuthenticationResult.NotAuthenticated

        return AuthenticationResult.Success(Authentication.authenticated(identity))
    }

    /** Fluent builder for constructing a [SessionAuthenticator]. */
    class Builder(private val sessionManager: SessionManager) {

        /** Builds a [SessionAuthenticator] backed by the supplied [SessionManager]. */
        fun build(): SessionAuthenticator = SessionAuthenticator(sessionManager = sessionManager)

    }

    companion object {

        /**
         * Creates a [Builder] pre-loaded with the required [sessionManager].
         *
         * [sessionManager] is the only required argument.
         */
        @JvmStatic
        fun builder(sessionManager: SessionManager): Builder = Builder(sessionManager)

        /** Creates a [SessionAuthenticator] backed by [sessionManager]. */
        @JvmStatic
        fun of(sessionManager: SessionManager): SessionAuthenticator =
            Builder(sessionManager).build()

    }

}
