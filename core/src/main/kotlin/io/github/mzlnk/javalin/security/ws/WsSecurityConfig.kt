package io.github.mzlnk.javalin.security.ws

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authorization.Rule
import io.github.mzlnk.javalin.security.authorization.Rules

/**
 * WebSocket security configuration: authentication, Origin protection, and fallback rule.
 *
 * Enforced once on the HTTP upgrade via `wsBeforeUpgrade`. Pattern-based rules are declared on
 * [io.github.mzlnk.javalin.security.JavalinSecurityPlugin.Config.rules]. Route-declared roles are
 * checked first; otherwise the shared rule table decides. Unmatched upgrades are denied by the
 * default [fallback]. When [allowedOrigins] is set, missing or unlisted `Origin` values are
 * rejected before authentication. Independent from the HTTP channel.
 */
class WsSecurityConfig internal constructor() {

    /**
     * [AuthenticationStrategy] for WebSocket upgrades on this channel.
     * When `null` (default), every upgrade is anonymous and the rule table alone decides access.
     */
    @JvmField
    var authentication: AuthenticationStrategy? = null

    /**
     * Exact `Origin` values allowed to upgrade (e.g. `"https://app.example.com"`).
     * Empty or blank collections are rejected at plugin start. When unset (`null`), no Origin
     * check runs.
     */
    @JvmField
    var allowedOrigins: Collection<String>? = null

    /**
     * Rule applied when no WebSocket entry matches. Last write wins.
     * Defaults to [Rules.deny], so unmatched upgrades are denied.
     */
    @JvmField
    var fallback: Rule = Rules.deny()

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
