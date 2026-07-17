package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.http.Context
import org.slf4j.LoggerFactory

/**
 * Implements JWT bearer-token authentication.
 *
 * The pipeline is explicit and has no hidden side-effects:
 * 1. Extract the raw token from the request via [JwtTokenResolver].
 *    No token -> [AuthenticationResult.NotAuthenticated] (anonymous; authorization rules decide access).
 * 2. Call [JwtDecoder.decode] with the configured [JwtVerification]. Any thrown exception ->
 *    [AuthenticationResult.Failure] (logged; 401).
 * 3. Map the [DecodedJwt] to a [JwtPrincipal] and resolve authorities via [JwtAuthoritiesMapper].
 * 4. Return [AuthenticationResult.Success] with the populated [Authentication].
 *
 * Construct via the Kotlin DSL (`jwt { decoder = ...; keySource = ... }` inside `http { }`) or use
 * [Builder] from Java.
 */
class JwtAuthenticationManager private constructor(
    private val decoder: JwtDecoder,
    private val verification: JwtVerification,
    private val authoritiesMapper: JwtAuthoritiesMapper,
    private val tokenResolver: JwtTokenResolver,
) : AuthenticationManager {

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
     * JwtAuthenticationManager manager = JwtAuthenticationManager.builder(NimbusJwtDecoder.INSTANCE, verification)
     *     .authoritiesMapper(JwtAuthoritiesMapper.fromClaim("roles"))
     *     .build();
     * ```
     */
    class Builder(
        private val decoder: JwtDecoder,
        private val verification: JwtVerification,
    ) {

        private var authoritiesMapper: JwtAuthoritiesMapper = JwtAuthoritiesMapper.noAuthorities()
        private var tokenResolver: JwtTokenResolver = JwtTokenResolver.DEFAULT

        fun authoritiesMapper(mapper: JwtAuthoritiesMapper): Builder {
            this.authoritiesMapper = mapper
            return this
        }

        /**
         * Overrides how the raw token is located in the request (defaults to [JwtTokenResolver.DEFAULT],
         * i.e. the `Authorization: Bearer ...` header).
         */
        fun tokenResolver(resolver: JwtTokenResolver): Builder {
            this.tokenResolver = resolver
            return this
        }

        fun build(): JwtAuthenticationManager = JwtAuthenticationManager(
            decoder = decoder,
            verification = verification,
            authoritiesMapper = authoritiesMapper,
            tokenResolver = tokenResolver,
        )

    }

    companion object {

        private val log = LoggerFactory.getLogger(JwtAuthenticationManager::class.java)

        /**
         * Creates a [Builder] pre-loaded with the required [decoder] and [verification].
         *
         * These are the only required arguments; all other settings have sensible defaults.
         */
        @JvmStatic
        fun builder(decoder: JwtDecoder, verification: JwtVerification): Builder = Builder(decoder, verification)

        /** Creates a [JwtAuthenticationManager] with the given [decoder], [verification] and default settings. */
        @JvmStatic
        fun of(decoder: JwtDecoder, verification: JwtVerification): JwtAuthenticationManager =
            Builder(decoder, verification).build()

    }

}
