package io.github.mzlnk.javalin.security.jwt.nimbus

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import io.github.mzlnk.javalin.security.jwt.DecodedJwt
import io.github.mzlnk.javalin.security.jwt.JwtDecoder
import io.github.mzlnk.javalin.security.jwt.JwtKeySource
import io.github.mzlnk.javalin.security.jwt.JwtVerification
import io.github.mzlnk.javalin.security.jwt.SimpleDecodedJwt
import java.security.Key
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.spec.SecretKeySpec

/**
 * A [JwtDecoder] backed by [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt) (v10.x).
 *
 * `com.nimbusds:nimbus-jose-jwt` is a `compileOnly` dependency of this module; add it yourself
 * (matching the version this module was built against) when using this decoder. Signature
 * verification and claim checks use the [JwtVerification] passed to [decode]. Local PEM keys must
 * be X.509/PKCS#8 (`-----BEGIN PUBLIC KEY-----`); PKCS#1 RSA PEMs are not accepted.
 */
object NimbusJwtDecoder : JwtDecoder {

    private val RSA_ALGORITHMS: Set<JWSAlgorithm> = setOf(
        JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
        JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
    )

    private val EC_ALGORITHMS: Set<JWSAlgorithm> = setOf(
        JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
    )

    /** Cache of remote JWKS sources, keyed by URL string, so fetch/cache state survives across [decode] calls. */
    private val jwksSources = ConcurrentHashMap<String, JWKSource<SecurityContext>>()

    override fun decode(token: String, verification: JwtVerification): DecodedJwt {
        val processor = DefaultJWTProcessor<SecurityContext>()
        processor.jwsKeySelector = keySelectorFor(verification.keySource)
        processor.jwtClaimsSetVerifier = claimsVerifierFor(verification)

        val claimsSet = processor.process(token, null)
        return SimpleDecodedJwt(
            subject = claimsSet.subject ?: "",
            claims = claimsSet.claims,
        )
    }

    private fun keySelectorFor(keySource: JwtKeySource): JWSKeySelector<SecurityContext> =
        when (keySource) {
            is JwtKeySource.PublicKeySource -> publicKeySelector(keySource)
            is JwtKeySource.SecretSource -> secretKeySelector(keySource)
            is JwtKeySource.JwksSource -> jwksKeySelector(keySource)
        }

    private fun publicKeySelector(keySource: JwtKeySource.PublicKeySource): JWSKeySelector<SecurityContext> {
        val publicKey = keySource.publicKey
        val accepted: Set<JWSAlgorithm> = when {
            keySource.algorithms.isNotEmpty() -> keySource.algorithms.map { JWSAlgorithm.parse(it) }.toSet()
            publicKey is RSAPublicKey -> RSA_ALGORITHMS
            publicKey is ECPublicKey -> EC_ALGORITHMS
            else -> throw IllegalArgumentException(
                "Unsupported public key type '${publicKey.algorithm}'; only RSA and EC are supported.",
            )
        }
        return JWSKeySelector { header, _ ->
            if (header.algorithm in accepted) listOf<Key>(publicKey) else emptyList()
        }
    }

    private fun secretKeySelector(keySource: JwtKeySource.SecretSource): JWSKeySelector<SecurityContext> {
        val algorithm = JWSAlgorithm.parse(keySource.algorithm)
        val secretKey: Key = SecretKeySpec(keySource.secret, "HMAC")
        return JWSKeySelector { header, _ ->
            if (header.algorithm == algorithm) listOf(secretKey) else emptyList()
        }
    }

    private fun jwksKeySelector(keySource: JwtKeySource.JwksSource): JWSKeySelector<SecurityContext> {
        val jwkSource = jwksSources.computeIfAbsent(keySource.url.toString()) {
            JWKSourceBuilder.create<SecurityContext>(keySource.url).build()
        }
        return JWSKeySelector { header, secCtx ->
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

    private fun claimsVerifierFor(verification: JwtVerification): DefaultJWTClaimsVerifier<SecurityContext> {
        val exactMatch: JWTClaimsSet? = buildExactMatchClaims(verification)
        val verifier = DefaultJWTClaimsVerifier<SecurityContext>(exactMatch, emptySet())
        verifier.maxClockSkew = verification.clockSkewSeconds
        return verifier
    }

    private fun buildExactMatchClaims(verification: JwtVerification): JWTClaimsSet? {
        if (verification.issuer == null && verification.audiences.isEmpty()) return null
        return JWTClaimsSet.Builder().apply {
            verification.issuer?.let { issuer(it) }
            if (verification.audiences.isNotEmpty()) audience(verification.audiences.toList())
        }.build()
    }

}
