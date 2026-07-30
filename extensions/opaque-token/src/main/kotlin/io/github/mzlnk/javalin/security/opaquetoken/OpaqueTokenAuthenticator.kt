package io.github.mzlnk.javalin.security.opaquetoken

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.javalin.http.Context
import org.slf4j.LoggerFactory
import java.time.Clock

/**
 * Implements opaque bearer-token authentication.
 *
 * Extracts a raw token via [TokenResolver]: missing credentials yield
 * [AuthenticationResult.NotAuthenticated]. Looks up the token via [OpaqueTokenLookup]; an unknown
 * token yields [AuthenticationResult.Failure]. When [TokenRecord.expiresAt] is set and is
 * at-or-before [clock]'s instant, yields [AuthenticationResult.Failure] with message
 * `"token expired"`. On success, returns [AuthenticationResult.Success] with the looked-up
 * identity as the identity. Construct via `opaqueToken { }` or [Builder].
 */
class OpaqueTokenAuthenticator private constructor(
    private val tokenLookup: OpaqueTokenLookup,
    private val resolver: TokenResolver,
    private val clock: Clock,
) : Authenticator {

    override fun authenticate(context: Context): AuthenticationResult {
        val rawToken = resolver.resolve(context) ?: return AuthenticationResult.NotAuthenticated

        val record = tokenLookup.lookup(rawToken)
        if (record == null) {
            log.debug("Opaque token authentication failed: unknown token")
            return AuthenticationResult.Failure(message = "invalid token")
        }

        val expiresAt = record.expiresAt
        if (expiresAt != null && !expiresAt.isAfter(clock.instant())) {
            log.debug("Opaque token authentication failed: token expired")
            return AuthenticationResult.Failure(message = "token expired")
        }

        return AuthenticationResult.Success(Authentication.authenticated(record.identity))
    }

    /** Fluent builder for constructing an [OpaqueTokenAuthenticator]. */
    class Builder(private val tokenLookup: OpaqueTokenLookup) {

        private var resolver: TokenResolver = TokenResolver.DEFAULT
        private var clock: Clock = Clock.systemUTC()

        /**
         * Overrides how the raw token is located in the request.
         *
         * Defaults to [TokenResolver.DEFAULT] (`Authorization: Bearer ...`).
         */
        fun resolver(resolver: TokenResolver): Builder {
            this.resolver = resolver
            return this
        }

        /**
         * Overrides the clock used for [TokenRecord.expiresAt] validation.
         *
         * Defaults to [Clock.systemUTC]. Inject a fixed clock in tests.
         */
        fun clock(clock: Clock): Builder {
            this.clock = clock
            return this
        }

        /** Builds an [OpaqueTokenAuthenticator] with the configured settings. */
        fun build(): OpaqueTokenAuthenticator = OpaqueTokenAuthenticator(
            tokenLookup = tokenLookup,
            resolver = resolver,
            clock = clock,
        )

    }

    companion object {

        private val log = LoggerFactory.getLogger(OpaqueTokenAuthenticator::class.java)

        /**
         * Creates a [Builder] pre-loaded with the required [tokenLookup].
         *
         * [tokenLookup] is the only required argument; other settings use defaults.
         */
        @JvmStatic
        fun builder(tokenLookup: OpaqueTokenLookup): Builder = Builder(tokenLookup)

        /** Creates an [OpaqueTokenAuthenticator] with the given [tokenLookup] and default settings. */
        @JvmStatic
        fun of(tokenLookup: OpaqueTokenLookup): OpaqueTokenAuthenticator = Builder(tokenLookup).build()

    }

}
