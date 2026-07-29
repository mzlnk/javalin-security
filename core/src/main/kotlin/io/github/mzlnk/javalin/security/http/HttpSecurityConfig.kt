package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authorization.Rule
import io.github.mzlnk.javalin.security.authorization.Rules

/**
 * HTTP security configuration: authentication strategy, fallback rule, and CORS preflight policy.
 *
 * Mutable field-assignment config (last write wins). Pattern-based rules are declared on
 * [io.github.mzlnk.javalin.security.JavalinSecurityPlugin.Config.rules]. Route-declared
 * [io.javalin.security.RouteRole]s are checked first (including [io.github.mzlnk.javalin.security.Anyone]);
 * otherwise the shared rule table decides. Assign strategies such as `jwt { }` or `basicAuth { }`
 * to [authentication].
 */
class HttpSecurityConfig internal constructor() {

    /**
     * [AuthenticationStrategy] for this channel.
     * When `null` (default), every request is anonymous and the rule table alone decides access.
     */
    @JvmField
    var authentication: AuthenticationStrategy? = null

    /**
     * Rule applied when no HTTP entry matches. Last write wins.
     * Defaults to [Rules.deny], so unmatched requests are denied.
     */
    @JvmField
    var fallback: Rule = Rules.deny()

    /**
     * When `true`, permits CORS preflight `OPTIONS` requests that carry
     * `Access-Control-Request-Method`. Does not exempt other `OPTIONS` traffic. Checked before
     * the rule table and [fallback]. CORS response headers still require Javalin's CORS plugin.
     */
    @JvmField
    var allowCorsPreflight: Boolean = false

}
