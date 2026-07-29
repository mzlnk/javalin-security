package io.github.mzlnk.javalin.security.apikey

import io.github.mzlnk.javalin.security.authentication.Identity

/**
 * [Identity] produced by API-key authentication.
 *
 * [name] is the [ApiKeyPrincipal.name] returned by [ApiKeyLookup] after a successful lookup.
 */
class ApiKeyIdentity(override val name: String) : Identity
