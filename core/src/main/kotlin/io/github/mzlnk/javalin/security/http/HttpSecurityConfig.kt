package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.RoleMapper
import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import java.util.function.Consumer

/**
 * The HTTP security configuration: authentication orchestration, RouteRole mapping, the
 * pattern-based rule table, and how authentication/authorization failures are rendered.
 *
 * A single mutable, field-assignment config — the same shape as Javalin's own subconfigs
 * (`config.http`, `config.router`, ...): plain `var` assignment, last write wins, no builder.
 * Companion libraries contribute their authentication strategy by assigning [authenticator] or
 * [asyncAuthenticator] from their own extension functions on this receiver (e.g. `http.jwt { }`).
 *
 * **Sync vs async authentication.** The default, zero-overhead path uses a blocking [Authenticator].
 * For authentication that performs remote I/O (JWKS endpoint, database), the opt-in
 * [asyncAuthenticator] path releases the request thread while authentication is in flight. With
 * `config.concurrency.useVirtualThreads = true`, the blocking manager is usually sufficient; async
 * is an advanced option.
 *
 * **Two ways to grant access**, checked in this order by the guard:
 * 1. If the matched route declares [io.javalin.security.RouteRole]s, [roleMapper] resolves the
 *    caller's roles and the guard grants access when they intersect (or when the route declares
 *    [io.github.mzlnk.javalin.security.Anyone]).
 * 2. Otherwise, the [rules] pattern table decides.
 */
class HttpSecurityConfig internal constructor() {

    /**
     * Registers a blocking [Authenticator].
     *
     * This is the hook that companion libraries assign from their own configuration extension
     * functions. Mutually exclusive with [asyncAuthenticator] — validated when the plugin starts.
     */
    var authenticator: Authenticator? = null

    /**
     * Registers an opt-in async [AsyncAuthenticator] for I/O-bound authentication.
     *
     * The security guard integrates with Javalin's async machinery ([io.javalin.http.Context.future])
     * to release the request thread while authentication is in flight. All fail-closed semantics
     * and no-message-leak behaviour are preserved across the async boundary.
     *
     * Mutually exclusive with [authenticator] — validated when the plugin starts. For
     * `config.concurrency.useVirtualThreads = true` applications, the blocking path is typically
     * preferred — virtual threads make blocking I/O cheap.
     */
    var asyncAuthenticator: AsyncAuthenticator? = null

    /**
     * Maps the resolved [io.github.mzlnk.javalin.security.authentication.Authentication] to the
     * [io.javalin.security.RouteRole]s the caller holds, for routes that declare roles directly
     * (`config.routes.get(path, handler, Role.ADMIN)`). Unset means routes with declared roles
     * always fall through to the [rules] pattern table instead.
     */
    var roleMapper: RoleMapper? = null

    /** Overrides how failed/absent authentication is rendered (HTTP 401 by default). */
    var unauthorizedHandler: UnauthorizedHandler = UnauthorizedHandler.DEFAULT

    /** Overrides how access-denied for an authenticated caller is rendered (HTTP 403 by default). */
    var forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT

    /** The pattern-based rule table, used for routes with no declared [io.javalin.security.RouteRole]s. */
    internal val rules: SecurityRules = SecurityRules()

    /** Configures the pattern-based rule table. May be called more than once; entries accumulate in call order. */
    fun rules(configure: Consumer<SecurityRules>) {
        configure.accept(rules)
    }

    /** Validates cross-field invariants. Called once, when the plugin starts. */
    internal fun validate() {
        if (authenticator != null && asyncAuthenticator != null) {
            throw SecurityConfigurationException(
                "Both a blocking authenticator and an asyncAuthenticator were configured, but they " +
                    "are mutually exclusive: choose one authentication path (blocking or async) per " +
                    "security configuration.",
            )
        }
    }

}
