package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.http.HttpConfigDsl

/**
 * Kotlin DSL receiver for the `basicAuth { }` block inside `http { }`.
 *
 * Configures HTTP Basic authentication (RFC 7617) and wires it into the HTTP security pipeline.
 * [userLookup] is the only required field; all other settings have defaults.
 *
 * The addon (this DSL) owns the decision of *how users are looked up* — [userLookup] — and *how a
 * raw password is compared against the stored one* — [passwordEncoder] — as well as *where the
 * raw credentials are located in the request* — [credentialsResolver].
 *
 * What this block does explicitly:
 * - Sets [HttpConfigDsl.authenticationManager] to a [BasicAuthAuthenticationManager] built from
 *   [userLookup], [passwordEncoder] and [credentialsResolver].
 * - When [basicChallenge] is `true`, also sets [HttpConfigDsl.unauthorizedHandler] to a
 *   [BasicChallengeUnauthorizedHandler]. This is the only additional side-effect and is opt-in.
 *
 * What this block does NOT do:
 * - It does not configure authorization rules — use `authorizeRequests { }` alongside `basicAuth { }`.
 * - It does not override [HttpConfigDsl.accessDeniedHandler] — configure it separately if needed.
 */
class BasicAuthDsl internal constructor() {

    /**
     * The [UserLookup] used to resolve a username to its stored [BasicUser] record. **Required.**
     *
     * Throws [SecurityConfigurationException] if `null` when the manager is built.
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

    internal fun buildManager(): BasicAuthAuthenticationManager {
        val lookup = userLookup ?: throw SecurityConfigurationException(
            "basicAuth.userLookup is required but was not configured. " +
                "Set 'userLookup = ...' inside the 'basicAuth { }' block.",
        )
        return BasicAuthAuthenticationManager.builder(lookup)
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
 * This is a Kotlin convenience extension on [HttpConfigDsl]; Java users construct a
 * [BasicAuthAuthenticationManager] directly via [BasicAuthAuthenticationManager.builder] and pass
 * it to `http.authenticationManager(...)`.
 *
 * The [BasicAuthDsl.userLookup] field is the only required setting.
 */
fun HttpConfigDsl.basicAuth(init: BasicAuthDsl.() -> Unit) {
    val dsl = BasicAuthDsl().apply(init)
    authenticationManager = dsl.buildManager()
    if (dsl.basicChallenge) {
        unauthorizedHandler = dsl.buildChallenge()
    }
}
