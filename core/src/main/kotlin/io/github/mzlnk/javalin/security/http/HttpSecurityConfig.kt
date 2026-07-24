package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import java.util.function.Consumer

/**
 * HTTP security configuration: authentication strategy and pattern-based rule table.
 *
 * Mutable field-assignment config (last write wins). Route-declared [io.javalin.security.RouteRole]s
 * are checked first (including [io.github.mzlnk.javalin.security.Anyone]); otherwise [rules]
 * decides. Assign strategies such as `jwt { }` or `basicAuth { }` to [authentication].
 */
class HttpSecurityConfig internal constructor() {

    /**
     * [AuthenticationStrategy] for this block.
     * When `null` (default), every request is anonymous and [rules] alone decides access.
     */
    @JvmField
    var authentication: AuthenticationStrategy? = null

    /** Pattern-based rule table for routes with no declared [io.javalin.security.RouteRole]s. */
    internal val rules: SecurityRules = SecurityRules()

    /** Configures the pattern-based rule table. Repeated calls accumulate entries in order. */
    fun rules(configure: Consumer<SecurityRules>) {
        configure.accept(rules)
    }

}
