package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.RoleMapper
import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import java.util.function.Consumer

/**
 * The WebSocket security configuration: upgrade-time authentication orchestration, RouteRole
 * mapping, the pattern-based rule table, and how authentication/authorization failures are
 * rendered.
 *
 * A single mutable, field-assignment config, same shape as [io.github.mzlnk.javalin.security.http.HttpSecurityConfig].
 *
 * Security is enforced once — during the HTTP upgrade request, before the WebSocket handshake
 * completes — via Javalin's `wsBeforeUpgrade` hook. Once the connection is established, individual
 * WS events (connect, message, close, error) are not subject to further authorization by this
 * library (though handlers may read the [io.github.mzlnk.javalin.security.authentication.Authentication]
 * from `ctx.authentication()` to make per-message decisions if desired).
 *
 * **Two ways to grant access**, checked in this order by the guard, mirroring the HTTP block:
 * 1. If the matched WS endpoint declares [io.javalin.security.RouteRole]s
 *    (`config.routes.ws(path, handler, Role.ADMIN)`), [roleMapper] resolves the caller's roles and
 *    the guard grants access when they intersect (or when the endpoint declares
 *    [io.github.mzlnk.javalin.security.Anyone]).
 * 2. Otherwise, the [rules] pattern table decides.
 *
 * **Deny-by-default:** upgrade requests resolved by neither mechanism are denied (anonymous → 401,
 * authenticated → 403).
 *
 * **CSWSH protection:** WebSocket handshakes are not subject to the browser same-origin policy
 * or CORS. If you authenticate via cookies, configure [allowedOrigins] to restrict which origins
 * may upgrade. When set, upgrades with a missing or unlisted `Origin` header are rejected via the
 * configured [forbiddenHandler] (403 by default) before authentication runs.
 *
 * The authentication managers configured here are independent from the HTTP security block.
 * If no manager is set, all callers are treated as anonymous and authorization decides access.
 */
class WsSecurityConfig internal constructor() {

    /** Registers a blocking [Authenticator] for WebSocket upgrade authentication. Mutually exclusive with [asyncAuthenticator]. */
    var authenticator: Authenticator? = null

    /**
     * Registers an opt-in async [AsyncAuthenticator] for I/O-bound WebSocket authentication.
     *
     * **Blocking trade-off:** Unlike the HTTP async path (which releases the request thread via
     * `ctx.future`), the WebSocket handshake is synchronous — `ctx.future` deferral is not a
     * supported Javalin pattern for WS upgrades. The returned [java.util.concurrent.CompletableFuture]
     * is therefore resolved via a blocking `join()` on the upgrade thread. This is safe and correct,
     * but it pins an upgrade thread for the duration of the I/O call.
     *
     * Recommendations to avoid Jetty thread-pool pressure under load:
     * - Enable `config.concurrency.useVirtualThreads = true`, or
     * - Use a pre-fetched token cache so lookups are in-memory rather than remote.
     *
     * Mutually exclusive with [authenticator] — validated when the plugin starts.
     */
    var asyncAuthenticator: AsyncAuthenticator? = null

    /**
     * Maps the resolved authentication to the [io.javalin.security.RouteRole]s the caller holds,
     * for WS endpoints that declare roles directly. Unset means endpoints with declared roles
     * always fall through to the [rules] pattern table instead.
     */
    var roleMapper: RoleMapper? = null

    /** Overrides how failed/absent WebSocket authentication is rendered (HTTP 401 by default). */
    var unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT

    /** Overrides how WebSocket access-denied for an authenticated caller is rendered (HTTP 403 by default). */
    var forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT

    /**
     * Restricts WebSocket upgrades to requests whose `Origin` header matches one of the given
     * origins exactly (e.g. `"https://app.example.com"`).
     *
     * Each entry must be a non-blank full origin string. An empty or all-blank collection is
     * rejected when the plugin starts, to avoid silently denying all upgrades. When unset (the
     * default), no Origin check is performed.
     */
    var allowedOrigins: Collection<String>? = null

    /** The pattern-based rule table, used for WS endpoints with no declared [io.javalin.security.RouteRole]s. */
    internal val rules: WsSecurityRules = WsSecurityRules()

    /** Configures the pattern-based rule table. May be called more than once; entries accumulate in call order. */
    fun rules(configure: Consumer<WsSecurityRules>) {
        configure.accept(rules)
    }

    /** Validates cross-field invariants. Called once, when the plugin starts. */
    internal fun validate() {
        if (authenticator != null && asyncAuthenticator != null) {
            throw SecurityConfigurationException(
                "Both a blocking authenticator and an asyncAuthenticator were configured for the WS " +
                    "block, but they are mutually exclusive: choose one authentication path (blocking " +
                    "or async) per security configuration.",
            )
        }
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
