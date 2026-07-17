package io.github.mzlnk.javalin.security.basicauth

/**
 * The record returned by a [UserLookup] for a known username.
 *
 * [password] is the *encoded* password as understood by the configured [PasswordEncoder] — never
 * the plaintext password a caller sends on the wire. What "encoded" means depends entirely on the
 * [PasswordEncoder] in use: for [PasswordEncoder.noOp] it is a plain string compared as-is; for a
 * hashing-based encoder it would be the hash (and, typically, embedded salt/parameters).
 */
data class BasicUser(
    val username: String,
    val password: String,
    val authorities: Set<String> = emptySet(),
)
