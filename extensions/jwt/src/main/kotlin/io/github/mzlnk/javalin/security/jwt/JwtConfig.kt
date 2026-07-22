@file:JvmName("JwtSecurity")

package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.github.mzlnk.javalin.security.http.HttpSecurityConfig
import io.github.mzlnk.javalin.security.ws.WsSecurityConfig
import java.util.function.Consumer

/**
 * Configuration object for the `jwt { }` block inside `http { }` / `ws { }`.
 *
 * Configures JWT bearer-token authentication and wires it into the security pipeline.
 * [decoder] and [keySource] are the only required fields; all other settings have defaults.
 *
 * The addon (this config) owns the decision of *where the verification key comes from* and *which
 * claims are checked* — [keySource], [issuer], [audiences], [clockSkewSeconds] — as well as
 * *where the raw token is located in the request* — [tokenResolver]. The [decoder] is a thin,
 * stateless adapter (e.g. `NimbusJwtDecoder`) that only performs the actual signature
 * verification and claim checks for the [JwtVerification] built from these fields.
 *
 * What this block does explicitly:
 * - Builds a [JwtVerification] from [keySource], [issuer], [audiences] and [clockSkewSeconds].
 * - Sets `authenticator` on the receiving [HttpSecurityConfig]/[WsSecurityConfig] to a
 *   [JwtAuthenticator] built from [decoder], that [JwtVerification], and [authoritiesMapper].
 * - When [bearerChallenge] is `true`, also sets `unauthorizedHandler` to a
 *   [BearerChallengeUnauthorizedHandler]. This is the only additional side-effect and is opt-in.
 *
 * What this block does NOT do:
 * - It does not configure the rule table — use `http.rules { }` / `ws.rules { }` alongside `jwt { }`.
 * - It does not override `forbiddenHandler` — configure it separately if needed.
 */
class JwtConfig internal constructor() {

    /**
     * The [JwtDecoder] adapter used to verify and decode incoming bearer tokens. **Required.**
     *
     * Expected to be a stateless implementation (e.g. the `NimbusJwtDecoder` object) that performs
     * verification purely from the [JwtVerification] built from this block's other fields.
     *
     * Throws [SecurityConfigurationException] if `null` when the authenticator is built.
     */
    var decoder: JwtDecoder? = null

    /**
     * Describes where the key(s) used to verify the token's signature come from — a local public
     * key, a PEM-encoded key, an HMAC secret, or a remote JWKS endpoint. **Required.**
     *
     * See [JwtKeySource]'s factory methods (`publicKey`, `pem`, `pemFile`, `secret`, `jwks`, ...).
     *
     * Throws [SecurityConfigurationException] if `null` when the authenticator is built.
     */
    var keySource: JwtKeySource? = null

    /**
     * Validates that the token's `iss` claim matches this value.
     *
     * Defaults to `null` (issuer not checked). Tokens with a different or absent issuer are
     * rejected when set.
     */
    var issuer: String? = null

    /**
     * Validates that the token's `aud` claim contains at least one of these values.
     *
     * Defaults to an empty set (audience not checked).
     */
    var audiences: Set<String> = emptySet()

    /**
     * The maximum acceptable clock skew, in seconds, for `exp` and `nbf` validation.
     *
     * Defaults to `60` seconds. Set to `0` to disable clock skew tolerance.
     */
    var clockSkewSeconds: Int = 60

    /**
     * Maps a verified [DecodedJwt] to the caller's granted authorities.
     *
     * Defaults to [JwtAuthoritiesMapper.noAuthorities] (empty set). Authorization rules that rely
     * on specific authorities (e.g. `hasAuthority("ADMIN")`) require a non-default mapper.
     */
    var authoritiesMapper: JwtAuthoritiesMapper = JwtAuthoritiesMapper.noAuthorities()

    /**
     * When `true`, failed or absent authentication responds with a
     * `WWW-Authenticate: Bearer ...` header alongside the 401.
     *
     * Defaults to `false`. Enable when clients need the challenge to discover the authentication
     * scheme (e.g. OAuth 2.0 resource servers per RFC 6750).
     */
    var bearerChallenge: Boolean = false

    /**
     * The `realm` attribute included in the `WWW-Authenticate` header when [bearerChallenge] is `true`.
     *
     * Defaults to `"API"`.
     */
    var realm: String = "API"

    /**
     * Locates the raw token within the incoming request.
     *
     * Defaults to [TokenResolver.DEFAULT], i.e. the `Authorization: Bearer ...` header. Swap
     * in [TokenResolver.cookie] for browser/SPA flows that store the JWT in a cookie instead:
     *
     * ```kotlin
     * http.jwt { jwt ->
     *     jwt.decoder = myDecoder
     *     jwt.tokenResolver = TokenResolver.cookie("access_token")
     * }
     * ```
     */
    var tokenResolver: TokenResolver = TokenResolver.DEFAULT

    internal fun buildAuthenticator(): JwtAuthenticator {
        val d = decoder ?: throw SecurityConfigurationException(
            "jwt.decoder is required but was not configured. " +
                "Set 'decoder = NimbusJwtDecoder' (or another JwtDecoder adapter) inside the 'jwt { }' block.",
        )
        val ks = keySource ?: throw SecurityConfigurationException(
            "jwt.keySource is required but was not configured. " +
                "Set 'keySource = JwtKeySource.publicKey(...)' (or another JwtKeySource factory) " +
                "inside the 'jwt { }' block.",
        )
        val verification = JwtVerification.builder(ks)
            .apply { issuer?.let { issuer(it) } }
            .apply { if (audiences.isNotEmpty()) audience(*audiences.toTypedArray()) }
            .clockSkew(clockSkewSeconds)
            .build()
        return JwtAuthenticator.builder(d, verification)
            .authoritiesMapper(authoritiesMapper)
            .tokenResolver(tokenResolver)
            .build()
    }

    internal fun buildChallenge(): BearerChallengeUnauthorizedHandler =
        BearerChallengeUnauthorizedHandler(realm)

}

/**
 * Configures JWT bearer-token authentication inside an `http { }` block.
 *
 * The same one-stop configuration works from both languages — the [JwtConfig] arrives as an
 * explicit `Consumer` parameter, just like every other configuration block in this library:
 *
 * ```kotlin
 * http.jwt { jwt ->
 *     jwt.decoder = NimbusJwtDecoder
 *     jwt.keySource = JwtKeySource.pemFile(path)
 * }
 * ```
 *
 * ```java
 * JwtSecurity.jwt(http, jwt -> {
 *     jwt.setDecoder(NimbusJwtDecoder.INSTANCE);
 *     jwt.setKeySource(JwtKeySource.pemFile(path));
 * });
 * ```
 *
 * Users who want the authenticator object itself (e.g. to share it between blocks) can build one
 * via [JwtAuthenticator.builder] and assign it to `http.authenticator` directly.
 *
 * The [JwtConfig.decoder] and [JwtConfig.keySource] fields are the only required settings.
 */
fun HttpSecurityConfig.jwt(configure: Consumer<JwtConfig>) {
    val config = JwtConfig().also(configure::accept)
    authenticator = config.buildAuthenticator()
    if (config.bearerChallenge) {
        unauthorizedHandler = config.buildChallenge()
    }
}

/**
 * Configures JWT bearer-token authentication inside a `ws { }` block.
 *
 * Mirrors the `http { }` extension exactly — it builds the same [JwtAuthenticator] from
 * [JwtConfig.decoder]/[JwtConfig.keySource]/[JwtConfig.authoritiesMapper] and assigns it to
 * `ws.authenticator`. When [JwtConfig.bearerChallenge] is `true`, it also sets
 * `ws.unauthorizedHandler` to a [BearerChallengeUnauthorizedHandler].
 *
 * **Browser clients cannot set an `Authorization` header on a WebSocket handshake.** For
 * browser/SPA flows, set `tokenResolver = TokenResolver.cookie("...")` and pair it with
 * `ws.allowedOrigins` on the surrounding `ws { }` block — WebSocket handshakes are not
 * protected by the browser same-origin policy or CORS, so an explicit origin allowlist is the
 * CSWSH defense when authenticating via a cookie:
 *
 * ```kotlin
 * ws { ws ->
 *     ws.jwt { jwt ->
 *         jwt.decoder = NimbusJwtDecoder
 *         jwt.keySource = JwtKeySource.publicKey(rsaPublicKey)
 *         jwt.tokenResolver = TokenResolver.cookie("access_token")
 *     }
 *     ws.allowedOrigins = listOf("https://app.example.com")
 *     ws.rules { r -> r.add("/ws/chat", r.authenticated) }
 * }
 * ```
 *
 * The [JwtConfig.decoder] and [JwtConfig.keySource] fields are the only required settings.
 */
fun WsSecurityConfig.jwt(configure: Consumer<JwtConfig>) {
    val config = JwtConfig().also(configure::accept)
    authenticator = config.buildAuthenticator()
    if (config.bearerChallenge) {
        unauthorizedHandler = config.buildChallenge()
    }
}
