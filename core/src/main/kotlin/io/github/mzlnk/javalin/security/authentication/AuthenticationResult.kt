package io.github.mzlnk.javalin.security.authentication

/** Outcome of an [Authenticator.authenticate] call. */
sealed interface AuthenticationResult {

    /** Successful authentication as [authentication]. */
    data class Success(val authentication: Authentication) : AuthenticationResult

    /**
     * Credentials were present but invalid (expired, malformed, etc.).
     *
     * Short-circuits to [UnauthorizedHandler] (HTTP 401 by default). [message] and [cause] are
     * for logging only and are not returned to the client.
     */
    data class Failure(
        val message: String? = null,
        val cause: Throwable? = null,
    ) : AuthenticationResult

    /**
     * No credentials were present. The request continues as anonymous and authorization decides
     * whether access is allowed.
     */
    data object NotAuthenticated : AuthenticationResult

}
