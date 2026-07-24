package io.github.mzlnk.javalin.security.authentication

/**
 * Identity of a successfully authenticated caller.
 *
 * Companion libraries supply concrete types that carry scheme-specific data such as subject or
 * claims. Stored on [Authentication.identity] for the duration of the request.
 */
interface Identity {

    /** Human-readable identifier for the principal (username, subject, or similar). */
    val name: String

}
