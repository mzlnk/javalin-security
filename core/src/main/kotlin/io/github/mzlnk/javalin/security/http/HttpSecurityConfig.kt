package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.authentication.AuthenticationScheme
import java.util.function.Consumer

/**
 * The HTTP security configuration: the authentication scheme and the pattern-based rule table.
 *
 * A single mutable, field-assignment config — the same shape as Javalin's own subconfigs
 * (`config.http`, `config.router`, ...): plain `var` assignment, last write wins, no builder.
 *
 * **One field decides authentication.** [authentication] holds the single
 * [AuthenticationScheme] used by this block — how the caller is authenticated, how failures are
 * rendered, and (via [io.github.mzlnk.javalin.security.authentication.Authentication.roles]) which
 * [io.javalin.security.RouteRole]s the caller holds, all in one place. Companion libraries
 * contribute ready-made schemes via their own factory functions, e.g. `http.authentication = jwt { }`.
 * Assigning [authentication] again simply replaces the previous scheme (last write wins) — there
 * is no separate authenticator/handler state to drift out of sync with it.
 *
 * **Two ways to grant access**, checked in this order by the guard:
 * 1. If the matched route declares [io.javalin.security.RouteRole]s, the guard grants access when
 *    they intersect the resolved [io.github.mzlnk.javalin.security.authentication.Authentication.roles]
 *    (a plain set-membership check relying on [io.javalin.security.RouteRole] equality), or when the
 *    route declares [io.github.mzlnk.javalin.security.Anyone].
 * 2. Otherwise, the [rules] pattern table decides.
 */
class HttpSecurityConfig internal constructor() {

    /**
     * The single [AuthenticationScheme] used to authenticate requests on this block.
     *
     * Unset (`null`, the default) means every request is treated as anonymous and the [rules]
     * pattern table alone decides access. Assign a scheme built by a companion library
     * (`http.authentication = jwt { }`, `http.authentication = basicAuth { }`) or implement
     * [AuthenticationScheme.Sync] / [AuthenticationScheme.Async] directly for a custom mechanism.
     */
    @JvmField
    var authentication: AuthenticationScheme? = null

    /** The pattern-based rule table, used for routes with no declared [io.javalin.security.RouteRole]s. */
    internal val rules: SecurityRules = SecurityRules()

    /** Configures the pattern-based rule table. May be called more than once; entries accumulate in call order. */
    fun rules(configure: Consumer<SecurityRules>) {
        configure.accept(rules)
    }

}
