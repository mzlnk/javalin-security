package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.authentication.Identity
import io.javalin.http.Context

/**
 * Owns the lifecycle of a caller's session and its stored identity.
 *
 * The default implementation ([HttpSessionManager]) is backed by the servlet HTTP session
 * (`ctx.sessionAttribute(...)`). Plug in a custom [SessionManager] to back sessions with
 * something else (Redis, an in-memory store, a signed cookie payload, etc.) — the rest of the
 * extension is agnostic to the storage strategy.
 *
 * The three operations are:
 * - [create] — establishes a session for an identity (call from your login handler after
 *   verifying credentials).
 * - [validate] — returns the [Identity] for the current request, or `null` when the request has
 *   no valid session. Invoked by [SessionAuthenticator] on every request.
 * - [invalidate] — destroys the current session (call from your logout handler). Must be safe to
 *   call when there is no active session.
 *
 * Implementations should not throw when no session exists: return `null` from [validate] and
 * no-op from [invalidate].
 */
interface SessionManager {

    /**
     * Establishes a session for [identity] on the current request.
     *
     * Call from your login handler after verifying credentials. May rotate/replace any
     * pre-existing session id to mitigate session fixation, depending on the implementation.
     */
    fun create(context: Context, identity: Identity)

    /**
     * Returns the [Identity] associated with the current request, or `null` when no valid
     * session exists.
     *
     * Called by [SessionAuthenticator] on every request. Must not throw when credentials are
     * absent.
     */
    fun validate(context: Context): Identity?

    /**
     * Destroys the current session, if any.
     *
     * Call from your logout handler. Must be safe to call when no session exists.
     */
    fun invalidate(context: Context)

}
