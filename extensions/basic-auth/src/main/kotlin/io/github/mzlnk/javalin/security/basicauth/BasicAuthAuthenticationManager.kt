package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.http.Context
import org.slf4j.LoggerFactory

/**
 * Implements HTTP Basic authentication (RFC 7617).
 *
 * The pipeline is explicit and has no hidden side-effects:
 * 1. Extract [BasicCredentials] from the request via [BasicCredentialsResolver].
 *    No credentials -> [AuthenticationResult.NotAuthenticated] (anonymous; authorization rules
 *    decide access). Malformed credentials (bad Base64, missing `:` separator) ->
 *    [AuthenticationResult.Failure].
 * 2. Look up the username via [UserLookup]. Unknown username -> [AuthenticationResult.Failure].
 *    The configured [PasswordEncoder] is still invoked against a dummy encoded value in this case
 *    so that responding to an unknown username takes a similar code path/time as a known username
 *    with a wrong password.
 * 3. Compare the supplied raw password against the stored [BasicUser.password] via
 *    [PasswordEncoder]. A mismatch -> [AuthenticationResult.Failure].
 * 4. Return [AuthenticationResult.Success] with a [BasicAuthPrincipal] and the user's authorities.
 *
 * Construct via the Kotlin DSL (`basicAuth { userLookup = ... }` inside `http { }`) or use
 * [Builder] from Java.
 */
class BasicAuthAuthenticationManager private constructor(
    private val userLookup: UserLookup,
    private val passwordEncoder: PasswordEncoder,
    private val credentialsResolver: BasicCredentialsResolver,
) : AuthenticationManager {

    override fun authenticate(context: Context): AuthenticationResult {
        val credentials = try {
            credentialsResolver.resolve(context) ?: return AuthenticationResult.NotAuthenticated
        } catch (ex: IllegalArgumentException) {
            log.debug("Basic credentials could not be parsed: {}", ex.message, ex)
            return AuthenticationResult.Failure(message = ex.message, cause = ex)
        }

        val user = userLookup.lookup(credentials.username)
        if (user == null) {
            // Still run the password comparison against a dummy value so that an unknown username
            // takes a similar path to a known username with a wrong password.
            passwordEncoder.matches(credentials.password, DUMMY_ENCODED_PASSWORD)
            log.debug("Basic authentication failed: unknown username")
            return AuthenticationResult.Failure(message = "invalid username or password")
        }

        if (!passwordEncoder.matches(credentials.password, user.password)) {
            log.debug("Basic authentication failed: password mismatch")
            return AuthenticationResult.Failure(message = "invalid username or password")
        }

        val principal = BasicAuthPrincipal(user.username)
        return AuthenticationResult.Success(Authentication.authenticated(principal, user.authorities))
    }

    /**
     * Fluent builder for Java interop.
     *
     * Usage from Java:
     *
     * ```java
     * BasicAuthAuthenticationManager manager = BasicAuthAuthenticationManager.builder(userLookup)
     *     .passwordEncoder(PasswordEncoder.noOp())
     *     .build();
     * ```
     */
    class Builder(private val userLookup: UserLookup) {

        private var passwordEncoder: PasswordEncoder = PasswordEncoder.noOp()
        private var credentialsResolver: BasicCredentialsResolver = BasicCredentialsResolver.DEFAULT

        fun passwordEncoder(encoder: PasswordEncoder): Builder {
            this.passwordEncoder = encoder
            return this
        }

        /**
         * Overrides how the raw credentials are located in the request (defaults to
         * [BasicCredentialsResolver.DEFAULT], i.e. the `Authorization: Basic ...` header).
         */
        fun credentialsResolver(resolver: BasicCredentialsResolver): Builder {
            this.credentialsResolver = resolver
            return this
        }

        fun build(): BasicAuthAuthenticationManager = BasicAuthAuthenticationManager(
            userLookup = userLookup,
            passwordEncoder = passwordEncoder,
            credentialsResolver = credentialsResolver,
        )

    }

    companion object {

        private val log = LoggerFactory.getLogger(BasicAuthAuthenticationManager::class.java)

        // Never matches a real password; only used to keep the comparison path uniform for
        // unknown usernames.
        private const val DUMMY_ENCODED_PASSWORD = "\u0000dummy-password-for-timing-uniformity\u0000"

        /**
         * Creates a [Builder] pre-loaded with the required [userLookup].
         *
         * This is the only required argument; all other settings have sensible defaults.
         */
        @JvmStatic
        fun builder(userLookup: UserLookup): Builder = Builder(userLookup)

        /** Creates a [BasicAuthAuthenticationManager] with the given [userLookup] and default settings. */
        @JvmStatic
        fun of(userLookup: UserLookup): BasicAuthAuthenticationManager = Builder(userLookup).build()

    }

}
