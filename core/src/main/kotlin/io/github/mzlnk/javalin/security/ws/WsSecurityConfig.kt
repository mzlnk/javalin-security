package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AuthenticationScheme
import java.util.function.Consumer

/**
 * The WebSocket security configuration: the authentication scheme, the pattern-based rule table,
 * and CSWSH origin protection.
 *
 * A single mutable, field-assignment config, same shape as [io.github.mzlnk.javalin.security.http.HttpSecurityConfig].
 *
 * Security is enforced once — during the HTTP upgrade request, before the WebSocket handshake
 * completes — via Javalin's `wsBeforeUpgrade` hook. Once the connection is established, individual
 * WS events (connect, message, close, error) are not subject to further authorization by this
 * library (though handlers may read the [io.github.mzlnk.javalin.security.authentication.Authentication]
 * from `ctx.authentication()` to make per-message decisions if desired).
 *
 * **One field decides authentication.** [authentication] holds the single
 * [AuthenticationScheme] used by this block, mirroring the HTTP block exactly. Companion
 * libraries contribute ready-made schemes via their own factory functions, e.g.
 * `ws.authentication = jwt { }`.
 *
 * **Two ways to grant access**, checked in this order by the guard, mirroring the HTTP block:
 * 1. If the matched WS endpoint declares [io.javalin.security.RouteRole]s
 *    (`config.routes.ws(path, handler, Role.ADMIN)`), the guard grants access when they intersect
 *    the resolved [io.github.mzlnk.javalin.security.authentication.Authentication.roles] (a plain
 *    set-membership check relying on [io.javalin.security.RouteRole] equality), or when the
 *    endpoint declares [io.github.mzlnk.javalin.security.Anyone].
 * 2. Otherwise, the [rules] pattern table decides.
 *
 * **Deny-by-default:** upgrade requests resolved by neither mechanism are denied (anonymous → 401,
 * authenticated → 403).
 *
 * **CSWSH protection:** WebSocket handshakes are not subject to the browser same-origin policy
 * or CORS. If you authenticate via cookies, configure [allowedOrigins] to restrict which origins
 * may upgrade. When set, upgrades with a missing or unlisted `Origin` header are rejected via the
 * configured scheme's `forbiddenHandler` (403 by default) before authentication runs.
 *
 * The authentication scheme configured here is independent from the HTTP security block. If
 * unset, all callers are treated as anonymous and authorization decides access.
 */
class WsSecurityConfig internal constructor() {

    /**
     * The single [AuthenticationScheme] used to authenticate WebSocket upgrade requests on this block.
     *
     * Unset (`null`, the default) means every upgrade is treated as anonymous and the [rules]
     * pattern table alone decides access. Assign a scheme built by a companion library
     * (`ws.authentication = jwt { }`) or implement [AuthenticationScheme.Sync] /
     * [AuthenticationScheme.Async] directly for a custom mechanism.
     */
    @JvmField
    var authentication: AuthenticationScheme? = null

    /**
     * Restricts WebSocket upgrades to requests whose `Origin` header matches one of the given
     * origins exactly (e.g. `"https://app.example.com"`).
     *
     * Each entry must be a non-blank full origin string. An empty or all-blank collection is
     * rejected when the plugin starts, to avoid silently denying all upgrades. When unset (the
     * default), no Origin check is performed.
     */
    @JvmField
    var allowedOrigins: Collection<String>? = null

    /** The pattern-based rule table, used for WS endpoints with no declared [io.javalin.security.RouteRole]s. */
    internal val rules: WsSecurityRules = WsSecurityRules()

    /** Configures the pattern-based rule table. May be called more than once; entries accumulate in call order. */
    fun rules(configure: Consumer<WsSecurityRules>) {
        configure.accept(rules)
    }

    /** Validates cross-field invariants. Called once, when the plugin starts. */
    internal fun validate() {
        val origins = allowedOrigins
        if (origins != null) {
            if (origins.isEmpty()) {
                throw SecurityConfigurationException(
                    "allowedOrigins must not be empty; providing an empty collection would deny " +
                        "all WebSocket upgrades. Leave allowedOrigins unset to disable the Origin check.",
                )
            }
            if (origins.any { it.isBlank() }) {
                throw SecurityConfigurationException(
                    "allowedOrigins contains blank entries; each entry must be a non-blank full " +
                        "origin string (e.g. \"https://app.example.com\").",
                )
            }
        }
    }

}
