package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.authentication.Identity

/**
 * [Identity] produced by session authentication.
 *
 * [name] is the [SessionPrincipal.subject] stored in the HTTP session after a successful
 * [SessionStrategy.login].
 */
class SessionIdentity(override val name: String) : Identity
