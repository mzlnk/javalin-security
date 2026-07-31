package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.javalin.http.Context
import org.slf4j.LoggerFactory

/**
 * Implements JWT bearer-token authentication.
 *
 * Extracts the raw token via [TokenResolver]: missing token yields
 * [AuthenticationResult.NotAuthenticated]. Calls [JwtDecoder.decode] with the configured
 * [JwtVerification]; any thrown exception yields [AuthenticationResult.Failure]. On success,
 * resolves the identity:
 * - when [identityMapper] is set, maps the [DecodedJwt] to it (`null` yields
 *   [AuthenticationResult.Failure]);
 * - otherwise falls back to the default [Jwt] identity.
 * Roles always come from [rolesMapper], independent of which identity is attached.
 *
 * Construct via `jwt { }` or [Builder].
 */
class JwtAuthenticator private constructor(
    private val decoder: JwtDecoder,
    private val verification: JwtVerification,
    private val rolesMapper: JwtRolesMapper,
    private val identityMapper: JwtIdentityMapper?,
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

        val mapper = identityMapper
        val identity: Identity? = if (mapper != null) {
            mapper.map(decoded)
        } else {
            Jwt(decoded)
        }

        if (identity == null) {
            return AuthenticationResult.Failure(message = "jwt.identityMapper returned null for a verified token")
        }

        return AuthenticationResult.Success(
            Authentication.authenticated(identity, rolesMapper.map(decoded)),
        )
    }

    /** Fluent builder for constructing a [JwtAuthenticator]. */
    class Builder(
        private val decoder: JwtDecoder,
        private val verification: JwtVerification,
    ) {

        private var rolesMapper: JwtRolesMapper = JwtRolesMapper.noRoles()
        private var identityMapper: JwtIdentityMapper? = null
        private var tokenResolver: TokenResolver = TokenResolver.DEFAULT

        /**
         * Sets the [JwtRolesMapper] used to resolve roles from a verified token.
         * Defaults to [JwtRolesMapper.noRoles].
         */
        fun rolesMapper(mapper: JwtRolesMapper): Builder {
            this.rolesMapper = mapper
            return this
        }

        /**
         * Sets the [JwtIdentityMapper] used to resolve the [Identity] from a verified token.
         * Defaults to `null` (falls back to the built-in [Jwt] identity).
         */
        fun identityMapper(mapper: JwtIdentityMapper?): Builder {
            this.identityMapper = mapper
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
            identityMapper = identityMapper,
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
