package io.github.mzlnk.javalin.security.authentication

/**
 * Represents the identity of a successfully authenticated caller.
 *
 * Companion libraries (e.g. a JWT integration) provide concrete implementations that carry
 * whatever identity data they resolve from the request (subject, claims, etc.).
 */
interface AuthenticatedPrincipal : Principal {

    /** A human-readable identifier for the principal (e.g. username or subject). */
    val name: String

}