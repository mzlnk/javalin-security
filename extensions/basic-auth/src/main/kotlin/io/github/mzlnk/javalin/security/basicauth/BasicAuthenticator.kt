package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.http.Context
import org.slf4j.LoggerFactory

/**
 * Implements HTTP Basic authentication (RFC 7617).
 *
 * Extracts [BasicCredentials] via [BasicCredentialsResolver]: missing credentials yield
 * [AuthenticationResult.NotAuthenticated]; malformed credentials yield [AuthenticationResult.Failure].
 * Looks up the username via [UserLookup] and compares the raw password with [PasswordEncoder]; an
 * unknown username or password mismatch yields [AuthenticationResult.Failure]. On success, returns
 * [AuthenticationResult.Success] with a [BasicAuthPrincipal] and the user's roles. Construct via
 * `basicAuth { }` or [Builder].
 */
class BasicAuthenticator private constructor(
    private val userLookup: UserLookup,
    private val passwordEncoder: PasswordEncoder,
    private val credentialsResolver: BasicCredentialsResolver,
) : Authenticator {

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
        return AuthenticationResult.Success(Authentication.authenticated(principal, user.roles))
    }

    /** Fluent builder for constructing a [BasicAuthenticator]. */
    class Builder(private val userLookup: UserLookup) {

        private var passwordEncoder: PasswordEncoder = PasswordEncoder.noOp()
        private var credentialsResolver: BasicCredentialsResolver = BasicCredentialsResolver.DEFAULT

        /** Sets the [PasswordEncoder] used to compare passwords. Defaults to [PasswordEncoder.noOp]. */
        fun passwordEncoder(encoder: PasswordEncoder): Builder {
            this.passwordEncoder = encoder
            return this
        }

        /**
         * Overrides how credentials are located in the request.
         *
         * Defaults to [BasicCredentialsResolver.DEFAULT] (`Authorization: Basic ...`).
         */
        fun credentialsResolver(resolver: BasicCredentialsResolver): Builder {
            this.credentialsResolver = resolver
            return this
        }

        /** Builds a [BasicAuthenticator] with the configured settings. */
        fun build(): BasicAuthenticator = BasicAuthenticator(
            userLookup = userLookup,
            passwordEncoder = passwordEncoder,
            credentialsResolver = credentialsResolver,
        )

    }

    companion object {

        private val log = LoggerFactory.getLogger(BasicAuthenticator::class.java)

        // Never matches a real password; only used to keep the comparison path uniform for
        // unknown usernames.
        private const val DUMMY_ENCODED_PASSWORD = "\u0000dummy-password-for-timing-uniformity\u0000"

        /**
         * Creates a [Builder] pre-loaded with the required [userLookup].
         *
         * [userLookup] is the only required argument; other settings use defaults.
         */
        @JvmStatic
        fun builder(userLookup: UserLookup): Builder = Builder(userLookup)

        /** Creates a [BasicAuthenticator] with the given [userLookup] and default settings. */
        @JvmStatic
        fun of(userLookup: UserLookup): BasicAuthenticator = Builder(userLookup).build()

    }

}
