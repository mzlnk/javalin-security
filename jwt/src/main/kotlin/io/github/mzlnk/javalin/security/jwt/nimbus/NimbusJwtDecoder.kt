package io.github.mzlnk.javalin.security.jwt.nimbus

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import io.github.mzlnk.javalin.security.jwt.DecodedJwt
import io.github.mzlnk.javalin.security.jwt.JwtDecoder
import io.github.mzlnk.javalin.security.jwt.SimpleDecodedJwt
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.security.spec.InvalidKeySpecException
import java.security.Key
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.spec.SecretKeySpec

/**
 * A [JwtDecoder] implementation backed by the [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt)
 * library (v10.x).
 *
 * Construct via the companion factory methods — each covers a different key source:
 *
 * ```kotlin
 * // Local RSA public key
 * val decoder = NimbusJwtDecoder.withPublicKey(rsaPublicKey).build()
 *
 * // Local EC public key
 * val decoder = NimbusJwtDecoder.withPublicKey(ecPublicKey).build()
 *
 * // Public key from PEM string or file (RSA or EC, X.509/PKCS#8 format)
 * val decoder = NimbusJwtDecoder.withPemString(pemString).issuer("https://auth.example.com").build()
 * val decoder = NimbusJwtDecoder.withPemFile(Paths.get("/keys/public.pem")).build()
 *
 * // HMAC shared secret
 * val decoder = NimbusJwtDecoder.withSecret("my-secret").build()
 *
 * // Remote JWKS with auto-caching and kid-based key selection
 * val decoder = NimbusJwtDecoder.withJwksUrl("https://auth.example.com/.well-known/jwks.json")
 *     .issuer("https://auth.example.com")
 *     .audience("my-api")
 *     .build()
 * ```
 *
 * **PEM format:** only the X.509/PKCS#8 public key format is supported
 * (`-----BEGIN PUBLIC KEY-----`). PKCS#1 RSA keys (`-----BEGIN RSA PUBLIC KEY-----`)
 * must be converted first with `openssl rsa -pubin -in key.pem -RSAPublicKey_out | openssl rsa -RSAPublicKey_in -pubout`.
 *
 * **Algorithm selection:**
 * - RSA local keys: all RSA/PSS JWS algorithms are accepted (RS256/384/512, PS256/384/512). The token's `alg` header selects the specific one. The `kid` header is ignored for local keys.
 * - EC local keys: ES256/384/512 are accepted based on the token's `alg` header. The `kid` header is ignored for local keys.
 * - HMAC: the algorithm is explicit (defaults to HS256).
 * - JWKS: algorithms and key selection are resolved by matching the token's `kid` against the remote JWK set.
 */
class NimbusJwtDecoder private constructor(
    private val processor: ConfigurableJWTProcessor<SecurityContext>,
) : JwtDecoder {

    override fun decode(token: String): DecodedJwt {
        val claimsSet = processor.process(token, null)
        return SimpleDecodedJwt(
            subject = claimsSet.subject ?: "",
            claims = claimsSet.claims,
        )
    }

    /**
     * Builder for [NimbusJwtDecoder]. Obtain via the companion factory methods.
     *
     * Optional claim validation settings (issuer, audience, clock skew) can be added before calling [build].
     */
    class Builder internal constructor(
        private val keySelectorFactory: () -> JWSKeySelector<SecurityContext>,
    ) {

        private var expectedIssuer: String? = null
        private var expectedAudience: Set<String> = emptySet()
        private var clockSkewSeconds: Int = 60

        /**
         * Validates that the token's `iss` claim matches [issuer].
         * Tokens with a different or absent issuer are rejected.
         */
        fun issuer(issuer: String): Builder = apply { this.expectedIssuer = issuer }

        /**
         * Validates that the token's `aud` claim contains the given [audiences].
         *
         * Pass a single value for the typical resource-server case:
         * ```kotlin
         * .audience("https://api.example.com")
         * ```
         */
        fun audience(vararg audiences: String): Builder = apply {
            this.expectedAudience = audiences.toSet()
        }

        /**
         * Sets the maximum acceptable clock skew for `exp` and `nbf` validation.
         *
         * Defaults to `60` seconds. Set to `0` to disable clock skew tolerance.
         */
        fun clockSkew(seconds: Int): Builder = apply { this.clockSkewSeconds = seconds }

        fun build(): NimbusJwtDecoder {
            val processor = DefaultJWTProcessor<SecurityContext>()
            processor.jwsKeySelector = keySelectorFactory()
            processor.jwtClaimsSetVerifier = buildClaimsVerifier()
            return NimbusJwtDecoder(processor)
        }

        private fun buildClaimsVerifier(): DefaultJWTClaimsVerifier<SecurityContext> {
            val exactMatch: JWTClaimsSet? = buildExactMatchClaims()
            val verifier = DefaultJWTClaimsVerifier<SecurityContext>(exactMatch, emptySet())
            verifier.maxClockSkew = clockSkewSeconds
            return verifier
        }

        private fun buildExactMatchClaims(): JWTClaimsSet? {
            if (expectedIssuer == null && expectedAudience.isEmpty()) return null
            return JWTClaimsSet.Builder().apply {
                expectedIssuer?.let { issuer(it) }
                if (expectedAudience.isNotEmpty()) audience(expectedAudience.toList())
            }.build()
        }

    }

    companion object {

        private val RSA_ALGORITHMS: Set<JWSAlgorithm> = setOf(
            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
            JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
        )

        private val EC_ALGORITHMS: Set<JWSAlgorithm> = setOf(
            JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
        )

        /**
         * Verifies tokens using the given RSA [publicKey].
         *
         * RS256/RS384/RS512/PS256/PS384/PS512 algorithms are all accepted; the token's `alg` header
         * selects the specific one. The `kid` header is ignored — the provided key is always used.
         */
        @JvmStatic
        fun withPublicKey(publicKey: RSAPublicKey): Builder = Builder {
            JWSKeySelector { header, _ ->
                if (header.algorithm in RSA_ALGORITHMS) listOf<Key>(publicKey) else emptyList()
            }
        }

        /**
         * Verifies tokens using the given EC [publicKey].
         *
         * ES256/ES384/ES512 algorithms are accepted; the token's `alg` header selects the specific one.
         * The `kid` header is ignored — the provided key is always used.
         */
        @JvmStatic
        fun withPublicKey(publicKey: ECPublicKey): Builder = Builder {
            JWSKeySelector { header, _ ->
                if (header.algorithm in EC_ALGORITHMS) listOf<Key>(publicKey) else emptyList()
            }
        }

        /**
         * Verifies tokens using a public key parsed from a PEM [string].
         *
         * Supports `-----BEGIN PUBLIC KEY-----` (X.509/PKCS#8 format) for both RSA and EC keys.
         * The key type (RSA or EC) is detected automatically.
         *
         * @throws IllegalArgumentException if the PEM string cannot be parsed or the key type is unsupported.
         */
        @JvmStatic
        fun withPemString(pem: String): Builder {
            return when (val key = parsePemPublicKey(pem)) {
                is RSAPublicKey -> withPublicKey(key)
                is ECPublicKey -> withPublicKey(key)
                else -> throw IllegalArgumentException(
                    "Unsupported public key type '${key.algorithm}'; only RSA and EC are supported.",
                )
            }
        }

        /**
         * Verifies tokens using a public key loaded from a PEM [file].
         *
         * The file must contain an X.509/PKCS#8 public key in PEM format
         * (`-----BEGIN PUBLIC KEY-----`). Both RSA and EC keys are supported.
         *
         * @throws IllegalArgumentException if the file cannot be parsed or the key type is unsupported.
         */
        @JvmStatic
        fun withPemFile(path: Path): Builder = withPemString(Files.readString(path))

        /**
         * Verifies tokens using an HMAC [secret] string.
         *
         * The [algorithm] defaults to HS256. Pass `JWSAlgorithm.HS384` or `JWSAlgorithm.HS512`
         * explicitly when using longer secrets.
         *
         * The secret is encoded as UTF-8 bytes. For binary secrets, use [withSecretBytes].
         */
        @JvmStatic
        @JvmOverloads
        fun withSecret(
            secret: String,
            algorithm: JWSAlgorithm = JWSAlgorithm.HS256,
        ): Builder = withSecretBytes(secret.toByteArray(Charsets.UTF_8), algorithm)

        /**
         * Verifies tokens using raw HMAC secret [bytes].
         *
         * Useful when the secret was originally stored as bytes (e.g. Base64-decoded).
         */
        @JvmStatic
        @JvmOverloads
        fun withSecretBytes(
            secretBytes: ByteArray,
            algorithm: JWSAlgorithm = JWSAlgorithm.HS256,
        ): Builder {
            val secretKey: Key = SecretKeySpec(secretBytes, "HMAC")
            return Builder {
                JWSKeySelector { header, _ ->
                    if (header.algorithm == algorithm) listOf(secretKey) else emptyList()
                }
            }
        }

        /**
         * Verifies tokens using a remote JWKS endpoint at [url].
         *
         * The JWK set is fetched and cached automatically (Nimbus built-in cache with refresh-ahead).
         * Key selection is `kid`-based: the token header's `kid` is matched against the remote JWK set.
         * Both RSA and EC keys are supported.
         *
         * @param url the JWKS endpoint URL string (e.g. `https://auth.example.com/.well-known/jwks.json`)
         */
        @JvmStatic
        fun withJwksUrl(url: String): Builder = withJwksUrl(URL(url))

        /**
         * Verifies tokens using a remote JWKS endpoint at [url].
         */
        @JvmStatic
        fun withJwksUrl(url: URL): Builder = Builder {
            val jwkSource: JWKSource<SecurityContext> = JWKSourceBuilder.create<SecurityContext>(url).build()
            JWSKeySelector { header, secCtx ->
                val keyType = KeyType.forAlgorithm(header.algorithm) ?: return@JWSKeySelector emptyList()
                val matcher = JWKMatcher.Builder()
                    .keyType(keyType)
                    .apply { header.keyID?.let { keyID(it) } }
                    .build()
                jwkSource.get(JWKSelector(matcher), secCtx).flatMap { jwk ->
                    @Suppress("UNCHECKED_CAST")
                    when (jwk) {
                        is RSAKey -> listOf(jwk.toRSAPublicKey())
                        is ECKey -> listOf(jwk.toECPublicKey())
                        is OctetSequenceKey -> listOf(jwk.toSecretKey())
                        else -> emptyList()
                    } as List<Key>
                }
            }
        }

        private fun parsePemPublicKey(pem: String): PublicKey {
            val base64 = pem.lines()
                .filterNot { it.startsWith("-----") }
                .joinToString("")
                .replace("\\s".toRegex(), "")
            val der = Base64.getDecoder().decode(base64)
            val spec = X509EncodedKeySpec(der)
            return try {
                KeyFactory.getInstance("RSA").generatePublic(spec)
            } catch (_: InvalidKeySpecException) {
                try {
                    KeyFactory.getInstance("EC").generatePublic(spec)
                } catch (e: InvalidKeySpecException) {
                    throw IllegalArgumentException(
                        "Cannot parse PEM as RSA or EC public key. " +
                            "Only X.509/PKCS#8 format (-----BEGIN PUBLIC KEY-----) is supported.",
                        e,
                    )
                }
            }
        }

    }

}
