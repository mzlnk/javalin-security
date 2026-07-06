package io.github.mzlnk.javalin.security.authentication

/**
 * The outcome of an [AuthenticationProvider.resolve] call.
 *
 * Modelled as a sealed hierarchy to make all cases explicit and avoid nullable handling.
 */
sealed interface AuthenticationResult {

    /** The request was successfully authenticated as [authentication]. */
    data class Success(val authentication: Authentication) : AuthenticationResult

    /**
     * Credentials were present but invalid (e.g. an expired or malformed token).
     *
     * This short-circuits the request to the configured
     * [io.github.mzlnk.javalin.security.authentication.AuthenticationEntryPoint] (HTTP 401 by
     * default). The [message] and [cause] are for logging only and are not returned to the client.
     */
    data class Failure(
        val message: String? = null,
        val cause: Throwable? = null,
    ) : AuthenticationResult

    /**
     * No credentials were present. The request continues as unauthenticated (anonymous) and the
     * authorization rules decide whether access is allowed.
     */
    data object NotAuthenticated : AuthenticationResult

}
