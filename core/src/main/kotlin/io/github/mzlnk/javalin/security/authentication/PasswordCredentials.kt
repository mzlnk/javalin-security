package io.github.mzlnk.javalin.security.authentication

/**
 * Credentials returned by a username-based lookup for password-verified authentication schemes.
 *
 * Separates the caller's [identity] from the [encodedPassword] used to verify it, so the encoded
 * password never has to live on the [Identity] itself and is not reachable from handlers via
 * `ctx.identity<I>()`. [encodedPassword] is compared against the caller-supplied raw password by
 * whichever password comparator the consuming extension defines (see
 * `io.github.mzlnk.javalin.security.basicauth.PasswordEncoder`).
 */
data class PasswordCredentials(
    val identity: Identity,
    val encodedPassword: String,
)
