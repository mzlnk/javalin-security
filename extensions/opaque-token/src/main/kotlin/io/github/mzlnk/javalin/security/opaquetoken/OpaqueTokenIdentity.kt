package io.github.mzlnk.javalin.security.opaquetoken

import io.github.mzlnk.javalin.security.authentication.Identity

/**
 * [Identity] produced by opaque-token authentication.
 *
 * [name] is the [OpaqueTokenDetails.subject] returned by [OpaqueTokenLookup] after a successful
 * lookup.
 */
class OpaqueTokenIdentity(override val name: String) : Identity
