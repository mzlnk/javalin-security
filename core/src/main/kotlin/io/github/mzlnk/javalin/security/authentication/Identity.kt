package io.github.mzlnk.javalin.security.authentication

/**
 * Identity of a successfully authenticated caller.
 *
 * Companion libraries supply concrete types that carry scheme-specific data such as subject or
 * claims. Roles are **not** part of [Identity] — they are supplied to
 * [Authentication.authenticated] by whichever extension attaches the identity (via scheme-specific
 * `*Details` records or a roles mapper). Stored on [Authentication.identity] for the duration of
 * the request.
 */
interface Identity {

    /** Human-readable identifier for the caller (username, subject, or similar). */
    val name: String

}
