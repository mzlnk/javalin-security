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
 * The pipeline is explicit and has no hidden side-effects:
 * 1. Extract the raw token from the request via [TokenResolver].
 *    No token -> [AuthenticationResult.NotAuthenticated] (anonymous; authorization rules decide access).
 * 2. Call [JwtDecoder.decode] with the configured [JwtVerification]. Any thrown exception ->
 *    [AuthenticationResult.Failure] (logged; 401).
 * 3. Map the [DecodedJwt] to a [JwtPrincipal] and resolve authorities via [JwtAuthoritiesMapper].
 * 4. Return [AuthenticationResult.Success] with the populated [Authentication].
 *
 * Construct via the `jwt { }` block (which assigns it to `http.authenticator` or
 * `ws.authenticator`) or use [Builder] to obtain an instance directly.
 */
class JwtAuthenticator private constructor(
    private val decoder: JwtDecoder,
    private val verification: JwtVerification,
    private val authoritiesMapper: JwtAuthoritiesMapper,
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
        val authorities = authoritiesMapper.map(decoded)
        return AuthenticationResult.Success(Authentication.authenticated(principal, authorities))
    }

    /**
     * Fluent builder for Java interop.
     *
     * Usage from Java:
     *
     * ```java
     * JwtVerification verification = JwtVerification.builder(JwtKeySource.publicKey(rsaKey)).build();
     * JwtAuthenticator authenticator = JwtAuthenticator.builder(NimbusJwtDecoder.INSTANCE, verification)
     *     .authoritiesMapper(JwtAuthoritiesMapper.fromClaim("roles"))
     *     .build();
     * ```
     */
    class Builder(
        private val decoder: JwtDecoder,
        private val verification: JwtVerification,
    ) {

        private var authoritiesMapper: JwtAuthoritiesMapper = JwtAuthoritiesMapper.noAuthorities()
        private var tokenResolver: TokenResolver = TokenResolver.DEFAULT

        fun authoritiesMapper(mapper: JwtAuthoritiesMapper): Builder {
            this.authoritiesMapper = mapper
            return this
        }

        /**
         * Overrides how the raw token is located in the request (defaults to [TokenResolver.DEFAULT],
         * i.e. the `Authorization: Bearer ...` header).
         */
        fun tokenResolver(resolver: TokenResolver): Builder {
            this.tokenResolver = resolver
            return this
        }

        fun build(): JwtAuthenticator = JwtAuthenticator(
            decoder = decoder,
            verification = verification,
            authoritiesMapper = authoritiesMapper,
            tokenResolver = tokenResolver,
        )

    }

    companion object {

        private val log = LoggerFactory.getLogger(JwtAuthenticator::class.java)

        /**
         * Creates a [Builder] pre-loaded with the required [decoder] and [verification].
         *
         * These are the only required arguments; all other settings have sensible defaults.
         */
        @JvmStatic
        fun builder(decoder: JwtDecoder, verification: JwtVerification): Builder = Builder(decoder, verification)

        /** Creates a [JwtAuthenticator] with the given [decoder], [verification] and default settings. */
        @JvmStatic
        fun of(decoder: JwtDecoder, verification: JwtVerification): JwtAuthenticator =
            Builder(decoder, verification).build()

    }

}
