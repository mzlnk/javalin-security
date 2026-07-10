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
 * 1. Extract the raw bearer token from the `Authorization` header via [BearerTokenResolver].
 *    No header -> [AuthenticationResult.NotAuthenticated] (anonymous; authorization rules decide access).
 * 2. Call [JwtDecoder.decode]. Any thrown exception -> [AuthenticationResult.Failure] (logged; 401).
 * 3. Map the [DecodedJwt] to a [JwtPrincipal] and resolve authorities via [JwtAuthoritiesMapper].
 * 4. Return [AuthenticationResult.Success] with the populated [Authentication].
 *
 * Construct via the Kotlin DSL (`jwt { decoder = ... }` inside `http { }`) or use [Builder] from Java.
 */
class JwtAuthenticationManager private constructor(
    private val decoder: JwtDecoder,
    private val authoritiesMapper: JwtAuthoritiesMapper,
) : AuthenticationManager {

    override fun authenticate(context: Context): AuthenticationResult {
        val rawToken = BearerTokenResolver.resolve(context)
            ?: return AuthenticationResult.NotAuthenticated

        val decoded = try {
            decoder.decode(rawToken)
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
     * JwtAuthenticationManager manager = JwtAuthenticationManager.builder(myDecoder)
     *     .authoritiesMapper(JwtAuthoritiesMapper.fromClaim("roles"))
     *     .build();
     * ```
     */
    class Builder(private val decoder: JwtDecoder) {

        private var authoritiesMapper: JwtAuthoritiesMapper = JwtAuthoritiesMapper.noAuthorities()

        fun authoritiesMapper(mapper: JwtAuthoritiesMapper): Builder {
            this.authoritiesMapper = mapper
            return this
        }

        fun build(): JwtAuthenticationManager = JwtAuthenticationManager(
            decoder = decoder,
            authoritiesMapper = authoritiesMapper,
        )

    }

    companion object {

        private val log = LoggerFactory.getLogger(JwtAuthenticationManager::class.java)

        /**
         * Creates a [Builder] pre-loaded with the required [decoder].
         *
         * The [JwtDecoder] is the only required argument; all other settings have sensible defaults.
         */
        @JvmStatic
        fun builder(decoder: JwtDecoder): Builder = Builder(decoder)

        /** Creates a [JwtAuthenticationManager] with the given [decoder] and default settings. */
        @JvmStatic
        fun of(decoder: JwtDecoder): JwtAuthenticationManager = Builder(decoder).build()

    }

}
