package io.github.mzlnk.javalin.security.session

import io.javalin.http.Context

/**
 * Owns the lifecycle of a caller's session and its stored [SessionPrincipal].
 *
 * The default implementation ([HttpSessionManager]) is backed by the servlet HTTP session
 * (`ctx.sessionAttribute(...)`). Plug in a custom [SessionManager] to back sessions with
 * something else (Redis, an in-memory store, a signed cookie payload, etc.) — the rest of the
 * extension is agnostic to the storage strategy.
 *
 * The three operations are:
 * - [create] — establishes a session for [SessionPrincipal] (called on login).
 * - [validate] — returns the [SessionPrincipal] for the current request, or `null` when the
 *   request has no valid session.
 * - [invalidate] — destroys the current session (called on logout). Must be safe to call when
 *   there is no active session.
 *
 * Implementations should not throw when no session exists: return `null` from [validate] and
 * no-op from [invalidate].
 */
interface SessionManager {

    /**
     * Establishes a session for [principal] on the current request.
     *
     * Called by [SessionStrategy.login] after your credential check. May rotate/replace any
     * pre-existing session id to mitigate session fixation, depending on the implementation.
     */
    fun create(context: Context, principal: SessionPrincipal)

    /**
     * Returns the [SessionPrincipal] associated with the current request, or `null` when no
     * valid session exists.
     *
     * Called by [SessionAuthenticator] on every request. Must not throw when credentials are
     * absent.
     */
    fun validate(context: Context): SessionPrincipal?

    /**
     * Destroys the current session, if any.
     *
     * Called by [SessionStrategy.logout]. Must be safe to call when no session exists.
     */
    fun invalidate(context: Context)

}
