package io.github.mzlnk.javalin.security.basicauth

/**
 * The single pluggable hook for resolving a [BasicUser] record by username.
 *
 * Implementations decide *where* users come from — an in-memory map, a database, an external
 * identity store, etc. — and return the stored [BasicUser] (with its *encoded* password and
 * granted authorities), or `null` when the username is unknown.
 *
 * This is deliberately separate from password comparison: [BasicAuthAuthenticationManager] takes
 * the [BasicUser.password] returned here and compares it against the caller-supplied raw password
 * via the configured [PasswordEncoder]. A [UserLookup] implementation must never throw for the
 * "user not found" case — it should return `null` instead — so that an unknown username is
 * indistinguishable, from the manager's perspective, from a known username with a wrong password.
 *
 * Register via `basicAuth { userLookup = ... }` or supply a lambda:
 *
 * ```kotlin
 * basicAuth {
 *     userLookup = UserLookup { username -> repository.findByUsername(username) }
 * }
 * ```
 */
fun interface UserLookup {

    /** Returns the [BasicUser] record for [username], or `null` when no such user exists. */
    fun lookup(username: String): BasicUser?

}
