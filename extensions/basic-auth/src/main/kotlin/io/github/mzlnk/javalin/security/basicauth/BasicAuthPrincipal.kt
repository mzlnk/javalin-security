package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.Identity

/**
 * [Identity] produced by HTTP Basic authentication.
 *
 * [name] is the username from the request's Basic credentials after lookup and password validation.
 */
class BasicAuthPrincipal(override val name: String) : Identity
