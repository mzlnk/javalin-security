package io.github.mzlnk.javalin.security.jwt.nimbus

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.mzlnk.javalin.security.jwt.DecodedJwt
import io.javalin.Javalin
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.Date
import java.util.UUID

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NimbusJwtDecoderTest {

    // ── RSA key pair used across RSA + JWKS tests ─────────────────────────────

    private lateinit var rsaJwk: RSAKey
    private lateinit var ecJwk: ECKey

    private var jwksServer: Javalin? = null
    private var jwksPort: Int = 0

    @BeforeAll
    fun setUp() {
        rsaJwk = RSAKeyGenerator(2048)
            .keyID("rsa-test-key")
            .generate()

        ecJwk = ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
            .keyID("ec-test-key")
            .generate()

        val publicJwkSet = JWKSet(listOf(rsaJwk.toPublicJWK(), ecJwk.toPublicJWK()))
        val jwksJson = publicJwkSet.toString()

        jwksServer = Javalin.create { cfg ->
            cfg.routes.get("/.well-known/jwks.json") { ctx ->
                ctx.contentType("application/json")
                ctx.result(jwksJson)
            }
        }.start(0)
        jwksPort = jwksServer!!.port()
    }

    @AfterAll
    fun tearDown() {
        jwksServer?.stop()
    }

    // ── Helper token builders ─────────────────────────────────────────────────

    private fun rsaToken(
        subject: String = "alice",
        issuer: String? = null,
        audience: List<String>? = null,
        expiresAt: Date = Date(System.currentTimeMillis() + 60_000),
        keyId: String = "rsa-test-key",
    ): String {
        val claims = JWTClaimsSet.Builder()
            .subject(subject)
            .apply { issuer?.let { issuer(it) } }
            .apply { audience?.let { audience(it) } }
            .expirationTime(expiresAt)
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build()
        return SignedJWT(header, claims).also { it.sign(RSASSASigner(rsaJwk)) }.serialize()
    }

    private fun ecToken(
        subject: String = "alice",
        expiresAt: Date = Date(System.currentTimeMillis() + 60_000),
    ): String {
        val claims = JWTClaimsSet.Builder()
            .subject(subject)
            .expirationTime(expiresAt)
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).keyID("ec-test-key").build()
        return SignedJWT(header, claims).also { it.sign(ECDSASigner(ecJwk)) }.serialize()
    }

    private fun hmacToken(
        subject: String = "alice",
        secret: String = "super-secret-key-with-enough-length",
        algorithm: JWSAlgorithm = JWSAlgorithm.HS256,
    ): String {
        val claims = JWTClaimsSet.Builder()
            .subject(subject)
            .expirationTime(Date(System.currentTimeMillis() + 60_000))
            .build()
        val header = JWSHeader(algorithm)
        val signer = MACSigner(secret.toByteArray(Charsets.UTF_8))
        return SignedJWT(header, claims).also { it.sign(signer) }.serialize()
    }

    // ── withPublicKey (RSA) ───────────────────────────────────────────────────

    @Test
    fun `withPublicKey(RSA) decodes a valid RS256 token`() {
        val decoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build()
        val decoded = decoder.decode(rsaToken(subject = "alice"))
        assertThat(decoded.subject).isEqualTo("alice")
    }

    @Test
    fun `withPublicKey(RSA) rejects an expired token`() {
        val decoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey())
            .clockSkew(0)
            .build()
        val expiredToken = rsaToken(expiresAt = Date(System.currentTimeMillis() - 5_000))
        assertThatThrownBy { decoder.decode(expiredToken) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `withPublicKey(RSA) rejects a token signed with a different key`() {
        val otherKey = RSAKeyGenerator(2048).generate()
        val decoder = NimbusJwtDecoder.withPublicKey(otherKey.toRSAPublicKey()).build()
        assertThatThrownBy { decoder.decode(rsaToken()) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `withPublicKey(RSA) rejects a tampered token`() {
        val decoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build()
        val tampered = rsaToken() + "tampered"
        assertThatThrownBy { decoder.decode(tampered) }.isInstanceOf(Exception::class.java)
    }

    // ── withPublicKey (RSA) + issuer/audience validation ─────────────────────

    @Test
    fun `withPublicKey(RSA) validates issuer when configured`() {
        val decoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey())
            .issuer("https://auth.example.com")
            .build()

        val validToken = rsaToken(issuer = "https://auth.example.com")
        assertThat(decoder.decode(validToken).subject).isEqualTo("alice")

        val wrongIssuerToken = rsaToken(issuer = "https://other.example.com")
        assertThatThrownBy { decoder.decode(wrongIssuerToken) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `withPublicKey(RSA) validates audience when configured`() {
        val decoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey())
            .audience("my-api")
            .build()

        val validToken = rsaToken(audience = listOf("my-api"))
        assertThat(decoder.decode(validToken).subject).isEqualTo("alice")

        val wrongAudienceToken = rsaToken(audience = listOf("other-api"))
        assertThatThrownBy { decoder.decode(wrongAudienceToken) }.isInstanceOf(Exception::class.java)
    }

    // ── withPublicKey (EC) ────────────────────────────────────────────────────

    @Test
    fun `withPublicKey(EC) decodes a valid ES256 token`() {
        val decoder = NimbusJwtDecoder.withPublicKey(ecJwk.toECPublicKey()).build()
        val decoded = decoder.decode(ecToken(subject = "carol"))
        assertThat(decoded.subject).isEqualTo("carol")
    }

    @Test
    fun `withPublicKey(EC) rejects a token signed with RSA key`() {
        val decoder = NimbusJwtDecoder.withPublicKey(ecJwk.toECPublicKey()).build()
        assertThatThrownBy { decoder.decode(rsaToken()) }.isInstanceOf(Exception::class.java)
    }

    // ── withPemString ─────────────────────────────────────────────────────────

    @Test
    fun `withPemString decodes valid RSA token from PEM public key`() {
        val pem = buildString {
            appendLine("-----BEGIN PUBLIC KEY-----")
            val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(
                rsaJwk.toRSAPublicKey().encoded,
            )
            appendLine(encoded)
            append("-----END PUBLIC KEY-----")
        }
        val decoder = NimbusJwtDecoder.withPemString(pem).build()
        val decoded = decoder.decode(rsaToken(subject = "alice"))
        assertThat(decoded.subject).isEqualTo("alice")
    }

    @Test
    fun `withPemString decodes valid EC token from PEM public key`() {
        val pem = buildString {
            appendLine("-----BEGIN PUBLIC KEY-----")
            val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(
                ecJwk.toECPublicKey().encoded,
            )
            appendLine(encoded)
            append("-----END PUBLIC KEY-----")
        }
        val decoder = NimbusJwtDecoder.withPemString(pem).build()
        val decoded = decoder.decode(ecToken(subject = "dave"))
        assertThat(decoded.subject).isEqualTo("dave")
    }

    @Test
    fun `withPemString throws for invalid PEM`() {
        assertThatThrownBy {
            NimbusJwtDecoder.withPemString("not-valid-pem").build()
        }.isInstanceOf(Exception::class.java)
    }

    // ── withSecret (HMAC) ─────────────────────────────────────────────────────

    @Test
    fun `withSecret decodes a valid HS256 token`() {
        val secret = "super-secret-key-with-enough-length"
        val decoder = NimbusJwtDecoder.withSecret(secret).build()
        val decoded = decoder.decode(hmacToken(subject = "eve", secret = secret))
        assertThat(decoded.subject).isEqualTo("eve")
    }

    @Test
    fun `withSecret rejects a token signed with a different secret`() {
        val decoder = NimbusJwtDecoder.withSecret("correct-secret-key-123456789012345").build()
        val token = hmacToken(secret = "wrong-secret-key-1234567890123456")
        assertThatThrownBy { decoder.decode(token) }.isInstanceOf(Exception::class.java)
    }

    // ── withJwksUrl ───────────────────────────────────────────────────────────

    @Test
    fun `withJwksUrl decodes a valid RSA token via remote JWKS`() {
        val decoder = NimbusJwtDecoder.withJwksUrl("http://localhost:$jwksPort/.well-known/jwks.json").build()
        val decoded = decoder.decode(rsaToken(subject = "frank"))
        assertThat(decoded.subject).isEqualTo("frank")
    }

    @Test
    fun `withJwksUrl decodes a valid EC token via remote JWKS`() {
        val decoder = NimbusJwtDecoder.withJwksUrl("http://localhost:$jwksPort/.well-known/jwks.json").build()
        val decoded = decoder.decode(ecToken(subject = "grace"))
        assertThat(decoded.subject).isEqualTo("grace")
    }

    @Test
    fun `withJwksUrl rejects a token signed with a key not in the JWKS`() {
        val decoder = NimbusJwtDecoder.withJwksUrl("http://localhost:$jwksPort/.well-known/jwks.json").build()
        val unknownKey = RSAKeyGenerator(2048).keyID("unknown-key").generate()
        val unknownKeyToken = run {
            val claims = JWTClaimsSet.Builder().subject("hank")
                .expirationTime(Date(System.currentTimeMillis() + 60_000)).build()
            val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID("unknown-key").build()
            SignedJWT(header, claims).also { it.sign(RSASSASigner(unknownKey)) }.serialize()
        }
        assertThatThrownBy { decoder.decode(unknownKeyToken) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `withJwksUrl validates issuer and audience`() {
        val decoder = NimbusJwtDecoder.withJwksUrl("http://localhost:$jwksPort/.well-known/jwks.json")
            .issuer("https://auth.example.com")
            .audience("my-api")
            .build()

        val validToken = rsaToken(issuer = "https://auth.example.com", audience = listOf("my-api"))
        assertThat(decoder.decode(validToken).subject).isEqualTo("alice")

        val noIssuerToken = rsaToken()
        assertThatThrownBy { decoder.decode(noIssuerToken) }.isInstanceOf(Exception::class.java)
    }

    // ── DecodedJwt claim access ───────────────────────────────────────────────

    @Test
    fun `decoded token exposes all claims in the claims map`() {
        val claims = JWTClaimsSet.Builder()
            .subject("alice")
            .claim("roles", listOf("ADMIN", "USER"))
            .claim("customClaim", "customValue")
            .expirationTime(Date(System.currentTimeMillis() + 60_000))
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID("rsa-test-key").build()
        val token = SignedJWT(header, claims).also { it.sign(RSASSASigner(rsaJwk)) }.serialize()

        val decoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build()
        val decoded = decoder.decode(token)

        assertThat(decoded.subject).isEqualTo("alice")
        assertThat(decoded.claim<List<String>>("roles")).containsExactlyInAnyOrder("ADMIN", "USER")
        assertThat(decoded.claim<String>("customClaim")).isEqualTo("customValue")
    }

    @Test
    fun `subject is blank string when token has no sub claim`() {
        val claims = JWTClaimsSet.Builder()
            .expirationTime(Date(System.currentTimeMillis() + 60_000))
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID("rsa-test-key").build()
        val token = SignedJWT(header, claims).also { it.sign(RSASSASigner(rsaJwk)) }.serialize()

        val decoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build()
        val decoded = decoder.decode(token)

        assertThat(decoded.subject).isBlank()
    }

}
