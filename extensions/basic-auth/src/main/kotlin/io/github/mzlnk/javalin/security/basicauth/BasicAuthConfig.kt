@file:JvmName("BasicAuthSecurity")

package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.http.HttpSecurityConfig
import java.util.function.Consumer

/**
 * Configuration object for the `basicAuth { }` block inside `http { }`.
 *
 * Configures HTTP Basic authentication (RFC 7617) and wires it into the HTTP security pipeline.
 * [userLookup] is the only required field; all other settings have defaults.
 *
 * The addon (this config) owns the decision of *how users are looked up* — [userLookup] — and *how
 * a raw password is compared against the stored one* — [passwordEncoder] — as well as *where the
 * raw credentials are located in the request* — [credentialsResolver].
 *
 * What this block does explicitly:
 * - Sets `http.authenticator` to a [BasicAuthenticator] built from [userLookup], [passwordEncoder]
 *   and [credentialsResolver].
 * - When [basicChallenge] is `true`, also sets `http.unauthorizedHandler` to a
 *   [BasicChallengeUnauthorizedHandler]. This is the only additional side-effect and is opt-in.
 *
 * What this block does NOT do:
 * - It does not configure the rule table — use `http.rules { }` alongside `basicAuth { }`.
 * - It does not override `http.forbiddenHandler` — configure it separately if needed.
 */
class BasicAuthConfig internal constructor() {

    /**
     * The [UserLookup] used to resolve a username to its stored [BasicUser] record. **Required.**
     *
     * Throws [SecurityConfigurationException] if `null` when the authenticator is built.
     */
    var userLookup: UserLookup? = null

    /**
     * Compares the raw password supplied by the caller against the stored (encoded) password.
     *
     * Defaults to [PasswordEncoder.noOp], a plain constant-time string comparison with no hashing.
     * Real deployments should supply an encoder backed by a proper password-hashing algorithm.
     */
    var passwordEncoder: PasswordEncoder = PasswordEncoder.noOp()

    /**
     * Locates the raw credentials within the incoming request.
     *
     * Defaults to [BasicCredentialsResolver.DEFAULT], i.e. the `Authorization: Basic ...` header.
     */
    var credentialsResolver: BasicCredentialsResolver = BasicCredentialsResolver.DEFAULT

    /**
     * When `true`, failed or absent authentication responds with a
     * `WWW-Authenticate: Basic ...` header alongside the 401.
     *
     * Defaults to `false`. Enable when clients (e.g. browsers) need the challenge to prompt the
     * user for credentials.
     */
    var basicChallenge: Boolean = false

    /**
     * The `realm` attribute included in the `WWW-Authenticate` header when [basicChallenge] is `true`.
     *
     * Defaults to `"API"`.
     */
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

    internal fun buildChallenge(): BasicChallengeUnauthorizedHandler =
        BasicChallengeUnauthorizedHandler(realm)

}

/**
 * Configures HTTP Basic authentication inside an `http { }` block.
 *
 * The same one-stop configuration works from both languages — the [BasicAuthConfig] arrives as an
 * explicit `Consumer` parameter, just like every other configuration block in this library:
 *
 * ```kotlin
 * http.basicAuth { basic ->
 *     basic.userLookup = myUserLookup
 * }
 * ```
 *
 * ```java
 * BasicAuthSecurity.basicAuth(http, basic -> {
 *     basic.setUserLookup(myUserLookup);
 * });
 * ```
 *
 * Users who want the authenticator object itself can build one via [BasicAuthenticator.builder]
 * and assign it to `http.authenticator` directly.
 *
 * The [BasicAuthConfig.userLookup] field is the only required setting.
 */
fun HttpSecurityConfig.basicAuth(configure: Consumer<BasicAuthConfig>) {
    val config = BasicAuthConfig().also(configure::accept)
    authenticator = config.buildAuthenticator()
    if (config.basicChallenge) {
        unauthorizedHandler = config.buildChallenge()
    }
}
