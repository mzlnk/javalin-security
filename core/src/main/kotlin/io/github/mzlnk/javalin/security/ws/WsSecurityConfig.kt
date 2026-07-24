package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import java.util.function.Consumer

/**
 * WebSocket security configuration: authentication, pattern rules, and Origin protection.
 *
 * Enforced once on the HTTP upgrade via `wsBeforeUpgrade`. Route-declared roles are checked first;
 * otherwise [rules] decides. Unmatched upgrades are denied. When [allowedOrigins] is set, missing
 * or unlisted `Origin` values are rejected before authentication. Independent from the HTTP block.
 */
class WsSecurityConfig internal constructor() {

    /**
     * [AuthenticationStrategy] for WebSocket upgrades on this block.
     * When `null` (default), every upgrade is anonymous and [rules] alone decides access.
     */
    @JvmField
    var authentication: AuthenticationStrategy? = null

    /**
     * Exact `Origin` values allowed to upgrade (e.g. `"https://app.example.com"`).
     * Empty or blank collections are rejected at plugin start. When unset, no Origin check runs.
     */
    @JvmField
    var allowedOrigins: Collection<String>? = null

    /** Pattern-based rule table for endpoints with no declared [io.javalin.security.RouteRole]s. */
    internal val rules: WsSecurityRules = WsSecurityRules()

    /** Configures the pattern-based rule table. Repeated calls accumulate entries in order. */
    fun rules(configure: Consumer<WsSecurityRules>) {
        configure.accept(rules)
    }

    /** Validates cross-field invariants. Called once when the plugin starts. */
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
