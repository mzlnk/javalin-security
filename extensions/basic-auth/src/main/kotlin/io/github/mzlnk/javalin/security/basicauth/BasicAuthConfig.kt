@file:JvmName("BasicAuthSecurity")

package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AuthenticationScheme
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import java.util.function.Consumer

/**
 * Configuration object for the [basicAuth] scheme factory.
 *
 * Configures HTTP Basic authentication (RFC 7617). [userLookup] is the only required field; all
 * other settings have defaults.
 *
 * The addon (this config) owns the decision of *how users are looked up* — [userLookup] — and *how
 * a raw password is compared against the stored one* — [passwordEncoder] — as well as *where the
 * raw credentials are located in the request* — [credentialsResolver]. The [io.javalin.security.RouteRole]s
 * granted to a caller come directly from [BasicUser.roles], supplied by [userLookup] — there is no
 * separate role-mapping step.
 *
 * What [basicAuth] builds from this config:
 * - A [BasicAuthenticator] from [userLookup], [passwordEncoder] and [credentialsResolver] — the
 *   [AuthenticationScheme.Sync.authenticator] of the returned scheme.
 * - The scheme's [AuthenticationScheme.forbiddenHandler] directly from [forbiddenHandler].
 * - The scheme's [AuthenticationScheme.unauthorizedHandler]: a [BasicChallengeUnauthorizedHandler]
 *   when [basicChallenge] is `true`, otherwise [UnauthorizedHandler.DEFAULT].
 *
 * This config does not configure the rule table — use `http.rules { }` alongside
 * `http.authentication = basicAuth { }`. HTTP Basic authentication is HTTP-only; there is no WS
 * variant of this scheme.
 */
class BasicAuthConfig internal constructor() {

    /**
     * The [UserLookup] used to resolve a username to its stored [BasicUser] record. **Required.**
     *
     * Throws [SecurityConfigurationException] if `null` when the scheme is built.
     */
    @JvmField
    var userLookup: UserLookup? = null

    /**
     * Compares the raw password supplied by the caller against the stored (encoded) password.
     *
     * Defaults to [PasswordEncoder.noOp], a plain constant-time string comparison with no hashing.
     * Real deployments should supply an encoder backed by a proper password-hashing algorithm.
     */
    @JvmField
    var passwordEncoder: PasswordEncoder = PasswordEncoder.noOp()

    /**
     * Locates the raw credentials within the incoming request.
     *
     * Defaults to [BasicCredentialsResolver.DEFAULT], i.e. the `Authorization: Basic ...` header.
     */
    @JvmField
    var credentialsResolver: BasicCredentialsResolver = BasicCredentialsResolver.DEFAULT

    /**
     * The scheme's [AuthenticationScheme.forbiddenHandler].
     *
     * Overrides how access-denied for an authenticated caller is rendered. Defaults to a bare
     * HTTP 403.
     */
    @JvmField
    var forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT

    /**
     * When `true`, failed or absent authentication responds with a
     * `WWW-Authenticate: Basic ...` header alongside the 401.
     *
     * Defaults to `false`. Enable when clients (e.g. browsers) need the challenge to prompt the
     * user for credentials.
     */
    @JvmField
    var basicChallenge: Boolean = false

    /**
     * The `realm` attribute included in the `WWW-Authenticate` header when [basicChallenge] is `true`.
     *
     * Defaults to `"API"`.
     */
    @JvmField
    var realm: String = "API"

    internal fun buildAuthenticator(): BasicAuthenticator {
        val lookup = userLookup ?: throw SecurityConfigurationException(
            "basicAuth.userLookup is required but was not configured. " +
                "Set 'userLookup = ...' inside the 'basicAuth { }' block.",
        )
        return BasicAuthenticator.builder(lookup)
            .passwordEncoder(passwordEncoder)
            .credentialsResolver(credentialsResolver)
            .build()
    }

    internal fun buildUnauthorizedHandler(): UnauthorizedHandler =
        if (basicChallenge) BasicChallengeUnauthorizedHandler(realm) else UnauthorizedHandler.DEFAULT

}

/**
 * Builds an [AuthenticationScheme.Sync] configured for HTTP Basic authentication (RFC 7617).
 *
 * The same one-stop configuration works from both languages — the [BasicAuthConfig] arrives as an
 * explicit `Consumer` parameter, just like every other configuration block in this library, and
 * the returned scheme is assigned directly to `http.authentication`:
 *
 * ```kotlin
 * http.authentication = basicAuth { basic ->
 *     basic.userLookup = myUserLookup
 * }
 * ```
 *
 * ```java
 * http.authentication = BasicAuthSecurity.basicAuth(basic -> {
 *     basic.userLookup = myUserLookup;
 * });
 * ```
 *
 * Users who want the [BasicAuthenticator] object itself can build one via
 * [BasicAuthenticator.builder] and wrap it in a custom [AuthenticationScheme.Sync] implementation.
 *
 * The [BasicAuthConfig.userLookup] field is the only required setting.
 */
fun basicAuth(configure: Consumer<BasicAuthConfig>): AuthenticationScheme.Sync {
    val config = BasicAuthConfig().also(configure::accept)
    val authenticator = config.buildAuthenticator()
    val unauthorizedHandlerValue = config.buildUnauthorizedHandler()
    val forbiddenHandlerValue = config.forbiddenHandler
    return object : AuthenticationScheme.Sync {
        override val unauthorizedHandler: UnauthorizedHandler get() = unauthorizedHandlerValue
        override val forbiddenHandler: ForbiddenHandler get() = forbiddenHandlerValue
        override fun authenticator() = authenticator
    }
}
