package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.javalin.http.Context
import org.slf4j.LoggerFactory

/**
 * Implements JWT bearer-token authentication.
 *
 * Extracts the raw token via [TokenResolver]: missing token yields
 * [AuthenticationResult.NotAuthenticated]. Calls [JwtDecoder.decode] with the configured
 * [JwtVerification]; any thrown exception yields [AuthenticationResult.Failure]. On success, maps
 * the [DecodedJwt] to a [JwtPrincipal], resolves roles via [JwtRolesMapper], and returns
 * [AuthenticationResult.Success]. Construct via `jwt { }` or [Builder].
 */
class JwtAuthenticator private constructor(
    private val decoder: JwtDecoder,
    private val verification: JwtVerification,
    private val rolesMapper: JwtRolesMapper,
    private val tokenResolver: TokenResolver,
) : Authenticator {

    override fun authenticate(context: Context): AuthenticationResult {
        val rawToken = tokenResolver.resolve(context)
            ?: return AuthenticationResult.NotAuthenticated

        val decoded = try {
            decoder.decode(rawToken, verification)
        } catch (ex: Exception) {
            log.debug("JWT verification failed: {}", ex.message, ex)
            return AuthenticationResult.Failure(message = ex.message, cause = ex)
        }

        val principal = JwtPrincipal(decoded)
        val roles = rolesMapper.map(decoded)
        return AuthenticationResult.Success(Authentication.authenticated(principal, roles))
    }

    /** Fluent builder for constructing a [JwtAuthenticator]. */
    class Builder(
        private val decoder: JwtDecoder,
        private val verification: JwtVerification,
    ) {

        private var rolesMapper: JwtRolesMapper = JwtRolesMapper.noRoles()
        private var tokenResolver: TokenResolver = TokenResolver.DEFAULT

        /** Sets the [JwtRolesMapper] used to resolve roles from a verified token. Defaults to [JwtRolesMapper.noRoles]. */
        fun rolesMapper(mapper: JwtRolesMapper): Builder {
            this.rolesMapper = mapper
            return this
        }

        /**
         * Overrides how the raw token is located in the request.
         *
         * Defaults to [TokenResolver.DEFAULT] (`Authorization: Bearer ...`).
         */
        fun tokenResolver(resolver: TokenResolver): Builder {
            this.tokenResolver = resolver
            return this
        }

        /** Builds a [JwtAuthenticator] with the configured settings. */
        fun build(): JwtAuthenticator = JwtAuthenticator(
            decoder = decoder,
            verification = verification,
            rolesMapper = rolesMapper,
            tokenResolver = tokenResolver,
        )

    }

    companion object {

        private val log = LoggerFactory.getLogger(JwtAuthenticator::class.java)

        /**
         * Creates a [Builder] pre-loaded with the required [decoder] and [verification].
         *
         * These are the only required arguments; other settings use defaults.
         */
        @JvmStatic
        fun builder(decoder: JwtDecoder, verification: JwtVerification): Builder = Builder(decoder, verification)

        /** Creates a [JwtAuthenticator] with the given [decoder], [verification], and default settings. */
        @JvmStatic
        fun of(decoder: JwtDecoder, verification: JwtVerification): JwtAuthenticator =
            Builder(decoder, verification).build()

    }

}
