package io.github.mzlnk.javalin.security.jwt.auth0

import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import io.github.mzlnk.javalin.security.jwt.DecodedJwt
import io.github.mzlnk.javalin.security.jwt.JwtDecoder
import io.github.mzlnk.javalin.security.jwt.JwtKeySource
import io.github.mzlnk.javalin.security.jwt.JwtVerification
import io.github.mzlnk.javalin.security.jwt.SimpleDecodedJwt
import java.net.URL
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.ConcurrentHashMap

/**
 * A [JwtDecoder] implementation backed by the [auth0 java-jwt](https://github.com/auth0/java-jwt)
 * library (v4.x), with JWKS support provided by [jwks-rsa](https://github.com/auth0/jwks-rsa-java).
 *
 * **Dependency:** `com.auth0:java-jwt` and `com.auth0:jwks-rsa` are `compileOnly` dependencies of
 * this module, not bundled transitively — add them yourself (matching the versions this module
 * was built against) if you use this decoder. This keeps consumers who pick a different
 * [JwtDecoder] adapter (e.g. `NimbusJwtDecoder`) free of these libraries on their classpath.
 *
 * This adapter is stateless: it holds no configuration of its own (other than an internal cache
 * for remote JWKS providers) and performs signature verification + claim checks purely from the
 * [JwtVerification] passed to [decode]. All key-source and claim-validation configuration lives
 * in the `jwt { }` DSL (or [JwtVerification.builder] for Java), not here — analogous to how
 * Javalin's `JavalinJackson` implements `JsonMapper` without owning any Jackson configuration
 * itself.
 *
 * Register it as the decoder:
 *
 * ```kotlin
 * jwt {
 *     decoder = Auth0JwtDecoder
 *     keySource = JwtKeySource.publicKey(rsaPublicKey)
 * }
 * ```
 *
 * **PEM format:** only the X.509/PKCS#8 public key format is supported
 * (`-----BEGIN PUBLIC KEY-----`). PKCS#1 RSA keys (`-----BEGIN RSA PUBLIC KEY-----`)
 * must be converted first with `openssl rsa -pubin -in key.pem -RSAPublicKey_out | openssl rsa -RSAPublicKey_in -pubout`.
 *
 * **Algorithm selection:** unlike Nimbus's key selector (which is handed the token and returns
 * candidate keys), auth0's `JWTVerifier` is built for one concrete [Algorithm] instance up front.
 * This adapter first decodes the token *without* verifying it to read the `alg`/`kid` header
 * fields (auth0's own documented pattern for JWKS use cases), picks a concrete algorithm
 * consistent with the configured key's type, and only then builds and runs the verifier:
 * - RSA local keys: when no explicit algorithms are configured, all RSA/PSS JWS algorithms are
 *   accepted (RS256/384/512, PS256/384/512). The token's `alg` header selects the specific one.
 *   The `kid` header is ignored for local keys. RSASSA-PSS (`PS*`) verification requires a JCE
 *   provider that implements it; the JDK's built-in providers only do so from Java 11 onwards.
 * - EC local keys: when no explicit algorithms are configured, ES256/384/512 are accepted based on
 *   the token's `alg` header. The `kid` header is ignored for local keys.
 * - HMAC: the algorithm is explicit (e.g. `"HS256"`), taken from the key source, not the token.
 * - JWKS: the key is resolved by matching the token's `kid` against the remote JWK set; the
 *   algorithm is then picked based on the resolved key's type (RSA or EC) and the token's `alg`.
 */
object Auth0JwtDecoder : JwtDecoder {

    private val RSA_ALGORITHMS: Set<String> = setOf(
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512",
    )
    private val EC_ALGORITHMS: Set<String> = setOf("ES256", "ES384", "ES512")

    /** Cache of remote JWKS providers, keyed by URL, so fetch/cache state survives across [decode] calls. */
    private val jwksProviders = ConcurrentHashMap<URL, JwkProvider>()

    override fun decode(token: String, verification: JwtVerification): DecodedJwt {
        val header = JWT.decode(token)
        val algorithm = algorithmFor(header, verification.keySource)

        val verifierBuilder = JWT.require(algorithm)
        verification.issuer?.let { verifierBuilder.withIssuer(it) }
        if (verification.audiences.isNotEmpty()) {
            verifierBuilder.withAudience(*verification.audiences.toTypedArray())
        }
        verifierBuilder.acceptLeeway(verification.clockSkewSeconds.toLong())

        val decoded = verifierBuilder.build().verify(token)
        return SimpleDecodedJwt(
            subject = decoded.subject ?: "",
            claims = decoded.claims.mapValues { (_, claim) -> claim.`as`(Any::class.java) },
        )
    }

    private fun algorithmFor(header: DecodedJWT, keySource: JwtKeySource): Algorithm =
        when (keySource) {
            is JwtKeySource.PublicKeySource -> publicKeyAlgorithm(header, keySource)
            is JwtKeySource.SecretSource -> secretAlgorithm(keySource)
            is JwtKeySource.JwksSource -> jwksAlgorithm(header, keySource)
        }

    private fun publicKeyAlgorithm(header: DecodedJWT, keySource: JwtKeySource.PublicKeySource): Algorithm {
        val publicKey = keySource.publicKey
        val accepted = acceptedAlgorithmNames(keySource.algorithms, publicKey)
        return buildAlgorithm(requireAccepted(header.algorithm, accepted), publicKey)
    }

    private fun secretAlgorithm(keySource: JwtKeySource.SecretSource): Algorithm =
        when (keySource.algorithm) {
            "HS256" -> Algorithm.HMAC256(keySource.secret)
            "HS384" -> Algorithm.HMAC384(keySource.secret)
            "HS512" -> Algorithm.HMAC512(keySource.secret)
            else -> throw IllegalArgumentException(
                "Unsupported HMAC algorithm '${keySource.algorithm}'; only HS256/HS384/HS512 are supported.",
            )
        }

    private fun jwksAlgorithm(header: DecodedJWT, keySource: JwtKeySource.JwksSource): Algorithm {
        val kid = header.keyId
            ?: throw JWTVerificationException("JWT header is missing 'kid'; required for JWKS key resolution.")
        val provider = jwksProviders.computeIfAbsent(keySource.url) { JwkProviderBuilder(it).build() }
        val publicKey = provider.get(kid).publicKey
        val accepted = acceptedAlgorithmNames(emptySet(), publicKey)
        return buildAlgorithm(requireAccepted(header.algorithm, accepted), publicKey)
    }

    private fun acceptedAlgorithmNames(configured: Set<String>, publicKey: PublicKey): Set<String> = when {
        configured.isNotEmpty() -> configured
        publicKey is RSAPublicKey -> RSA_ALGORITHMS
        publicKey is ECPublicKey -> EC_ALGORITHMS
        else -> throw IllegalArgumentException(
            "Unsupported public key type '${publicKey.algorithm}'; only RSA and EC are supported.",
        )
    }

    private fun requireAccepted(algorithm: String, accepted: Set<String>): String {
        if (algorithm !in accepted) {
            throw JWTVerificationException(
                "Unexpected JWT algorithm '$algorithm'; expected one of $accepted.",
            )
        }
        return algorithm
    }

    private fun buildAlgorithm(name: String, key: PublicKey): Algorithm = when {
        key is RSAPublicKey && name in RSA_ALGORITHMS -> rsaAlgorithm(name, key)
        key is ECPublicKey && name in EC_ALGORITHMS -> ecAlgorithm(name, key)
        else -> throw IllegalArgumentException(
            "Unsupported algorithm '$name' for key type '${key.algorithm}'.",
        )
    }

    private fun rsaAlgorithm(name: String, key: RSAPublicKey): Algorithm = when (name) {
        "RS256" -> Algorithm.RSA256(key, null)
        "RS384" -> Algorithm.RSA384(key, null)
        "RS512" -> Algorithm.RSA512(key, null)
        "PS256" -> Algorithm.RSA256PSS(key, null)
        "PS384" -> Algorithm.RSA384PSS(key, null)
        "PS512" -> Algorithm.RSA512PSS(key, null)
        else -> throw IllegalArgumentException(
            "Unsupported RSA algorithm '$name'; only RS256/384/512 and PS256/384/512 are supported.",
        )
    }

    private fun ecAlgorithm(name: String, key: ECPublicKey): Algorithm = when (name) {
        "ES256" -> Algorithm.ECDSA256(key, null)
        "ES384" -> Algorithm.ECDSA384(key, null)
        "ES512" -> Algorithm.ECDSA512(key, null)
        else -> throw IllegalArgumentException("Unsupported EC algorithm '$name'; only ES256/ES384/ES512 are supported.")
    }

}
