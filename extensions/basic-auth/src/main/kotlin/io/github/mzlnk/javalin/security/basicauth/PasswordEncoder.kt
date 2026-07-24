package io.github.mzlnk.javalin.security.basicauth

import java.security.MessageDigest

/**
 * Compares a raw password from the caller against the encoded password from a [UserLookup].
 *
 * Register via `basicAuth { passwordEncoder = ... }`. Defaults to [noOp]. Production deployments
 * should supply a hashing-based encoder (BCrypt, Argon2, PBKDF2, etc.).
 */
fun interface PasswordEncoder {

    /** Returns `true` when [rawPassword] matches [encodedPassword]. */
    fun matches(rawPassword: String, encodedPassword: String): Boolean

    companion object {

        /**
         * Returns a [PasswordEncoder] that compares passwords as plain strings in constant time
         * via [MessageDigest.isEqual]. Performs no hashing.
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
