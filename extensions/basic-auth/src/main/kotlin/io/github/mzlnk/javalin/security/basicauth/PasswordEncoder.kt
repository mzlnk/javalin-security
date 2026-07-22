package io.github.mzlnk.javalin.security.basicauth

import java.security.MessageDigest

/**
 * Compares a raw password supplied by the caller against the encoded password returned by a
 * [UserLookup].
 *
 * This is deliberately a single, narrow hook: the framework only ever needs to know whether a raw
 * password *matches* a stored one, never how to produce the stored encoding in the first place —
 * that responsibility belongs to whatever provisions [BasicUser] records (a migration script, an
 * admin tool, an identity provider, etc.), not to the request-time authentication pipeline.
 *
 * Register via the `basicAuth { }` block (`passwordEncoder` field). Defaults to [noOp], which compares the raw
 * password directly against the stored value in constant time. Real deployments should supply an
 * encoder backed by a proper password-hashing algorithm (BCrypt, Argon2, PBKDF2, ...) so that
 * plaintext passwords are never persisted.
 */
fun interface PasswordEncoder {

    /** Returns `true` when [rawPassword] matches [encodedPassword]. */
    fun matches(rawPassword: String, encodedPassword: String): Boolean

    companion object {

        /**
         * Returns a [PasswordEncoder] that compares [rawPassword] against [encodedPassword] as
         * plain strings, in constant time with respect to the compared content (via
         * [MessageDigest.isEqual]) to reduce the risk of timing side-channels.
         *
         * This performs **no hashing**. It is intended for local development, tests, and
         * deployments that already store passwords hashed at rest and pass a matching hasher's
         * output through as both sides of the comparison. Production deployments storing
         * plaintext-derived credentials should supply a proper hashing-based encoder instead.
         */
        @JvmStatic
        fun noOp(): PasswordEncoder = PasswordEncoder { rawPassword, encodedPassword ->
            MessageDigest.isEqual(
                rawPassword.toByteArray(Charsets.UTF_8),
                encodedPassword.toByteArray(Charsets.UTF_8),
            )
        }

    }

}
