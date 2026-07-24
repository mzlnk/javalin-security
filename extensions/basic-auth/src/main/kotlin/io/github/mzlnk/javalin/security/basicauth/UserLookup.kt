package io.github.mzlnk.javalin.security.basicauth

/**
 * Resolves a [BasicUser] record by username.
 *
 * Returns the stored [BasicUser] (encoded password and granted roles), or `null` when the username
 * is unknown. Must return `null` for unknown users rather than throw. [BasicAuthenticator]
 * compares [BasicUser.password] against the caller's raw password via [PasswordEncoder]. Register
 * via the `basicAuth { }` block (`userLookup`).
 */
fun interface UserLookup {

    /** Returns the [BasicUser] for [username], or `null` when no such user exists. */
    fun lookup(username: String): BasicUser?

}
