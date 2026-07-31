@file:JvmName("BasicAuthSecurity")

package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import java.util.function.Consumer

/**
 * Configuration for the [basicAuth] strategy factory (HTTP Basic, RFC 7617).
 *
 * [userLookup] is required. The identity type your [UserLookup] returns is your own — bring your
 * own type; roles come from [BasicUserDetails.roles]. Builds a [BasicAuthenticator] and, when
 * [basicChallenge] is `true`, a [BasicChallengeUnauthorizedHandler]; otherwise uses
 * [UnauthorizedHandler.DEFAULT]. HTTP-only — there is no WebSocket variant.
 */
class BasicAuthConfig internal constructor() {

    /**
     * Resolves a username to its stored [BasicUserDetails].
     * Required; throws [SecurityConfigurationException] if unset when the strategy is built.
     */
    @JvmField
    var userLookup: UserLookup? = null

    /**
     * Compares the caller's raw password against the stored encoded password.
     * Defaults to [PasswordEncoder.noOp].
     */
    @JvmField
    var passwordEncoder: PasswordEncoder = PasswordEncoder.noOp()

    /**
     * Locates raw credentials in the request.
     * Defaults to [BasicCredentialsResolver.DEFAULT] (`Authorization: Basic ...`).
     */
    @JvmField
    var credentialsResolver: BasicCredentialsResolver = BasicCredentialsResolver.DEFAULT

    /** Renders 403 responses for authenticated callers denied by authorization. Defaults to a bare 403. */
    @JvmField
    var forbiddenHandler: ForbiddenHandler = ForbiddenHandler.DEFAULT

    /**
     * When `true`, failed or absent authentication includes a `WWW-Authenticate: Basic ...` header.
     * Defaults to `false`.
     */
    @JvmField
    var basicChallenge: Boolean = false

    /** Realm attribute for the Basic challenge when [basicChallenge] is `true`. Defaults to `"API"`. */
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
 * Builds an [AuthenticationStrategy.Sync] for HTTP Basic authentication.
 *
 * Assign the result to `http.authentication`. Only [BasicAuthConfig.userLookup] is required.
 * The identity type flowing through the extension is entirely yours — the extension attaches
 * whichever identity and roles your [UserLookup] returns via [BasicUserDetails]. To use
 * [BasicAuthenticator] directly, call [BasicAuthenticator.builder] and wrap it in a custom
 * [AuthenticationStrategy.Sync].
 */
fun basicAuth(configure: Consumer<BasicAuthConfig>): AuthenticationStrategy.Sync {
    val config = BasicAuthConfig().also(configure::accept)
    val authenticator = config.buildAuthenticator()
    return AuthenticationStrategy.sync(
        authenticator = authenticator,
        unauthorizedHandler = config.buildUnauthorizedHandler(),
        forbiddenHandler = config.forbiddenHandler,
    )
}
