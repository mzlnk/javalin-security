package io.github.mzlnk.javalin.security.basicauth

/**
 * Resolves a username to [BasicUserDetails] carrying the caller's own identity.
 *
 * Returns the stored [BasicUserDetails] (encoded password, identity, and roles to attach on
 * success), or `null` when the username is unknown. Must return `null` for unknown users rather
 * than throw. [BasicAuthenticator] compares [BasicUserDetails.encodedPassword] against the
 * caller's raw password via [PasswordEncoder], then attaches [BasicUserDetails.identity] and
 * [BasicUserDetails.roles] on the request — the encoded password itself never reaches the
 * request. Register via the `basicAuth { }` block (`userLookup`).
 */
fun interface UserLookup {

    /** Returns the [BasicUserDetails] for [username], or `null` when no such user exists. */
    fun lookup(username: String): BasicUserDetails?

}
