package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.PasswordCredentials

/**
 * Resolves a username to [PasswordCredentials] carrying the caller's own identity.
 *
 * Returns the stored [PasswordCredentials] (encoded password and the identity to attach on
 * success), or `null` when the username is unknown. Must return `null` for unknown users rather
 * than throw. [BasicAuthenticator] compares [PasswordCredentials.encodedPassword] against the
 * caller's raw password via [PasswordEncoder], then attaches [PasswordCredentials.identity] as
 * the request's identity — the encoded password itself never reaches the request. Register via
 * the `basicAuth { }` block (`userLookup`).
 */
fun interface UserLookup {

    /** Returns the [PasswordCredentials] for [username], or `null` when no such user exists. */
    fun lookup(username: String): PasswordCredentials?

}
