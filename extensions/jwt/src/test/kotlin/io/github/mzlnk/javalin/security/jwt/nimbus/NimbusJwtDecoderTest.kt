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
import io.github.mzlnk.javalin.security.jwt.JwtKeySource
import io.github.mzlnk.javalin.security.jwt.JwtVerification
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

    @Test
    fun `publicKey(RSA) decodes a valid RS256 token`() {
        val verification = JwtVerification.of(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
        val decoded = NimbusJwtDecoder.decode(rsaToken(subject = "alice"), verification)
        assertThat(decoded.subject).isEqualTo("alice")
    }

    @Test
    fun `publicKey(RSA) rejects an expired token`() {
        val verification = JwtVerification.builder(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
            .clockSkew(0)
            .build()
        val expiredToken = rsaToken(expiresAt = Date(System.currentTimeMillis() - 5_000))
        assertThatThrownBy { NimbusJwtDecoder.decode(expiredToken, verification) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `publicKey(RSA) rejects a token signed with a different key`() {
        val otherKey = RSAKeyGenerator(2048).generate()
        val verification = JwtVerification.of(JwtKeySource.publicKey(otherKey.toRSAPublicKey()))
        assertThatThrownBy { NimbusJwtDecoder.decode(rsaToken(), verification) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `publicKey(RSA) rejects a tampered token`() {
        val verification = JwtVerification.of(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
        val tampered = rsaToken() + "tampered"
        assertThatThrownBy { NimbusJwtDecoder.decode(tampered, verification) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `publicKey(RSA) validates issuer when configured`() {
        val verification = JwtVerification.builder(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
            .issuer("https://auth.example.com")
            .build()

        val validToken = rsaToken(issuer = "https://auth.example.com")
        assertThat(NimbusJwtDecoder.decode(validToken, verification).subject).isEqualTo("alice")

        val wrongIssuerToken = rsaToken(issuer = "https://other.example.com")
        assertThatThrownBy { NimbusJwtDecoder.decode(wrongIssuerToken, verification) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `publicKey(RSA) validates audience when configured`() {
        val verification = JwtVerification.builder(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
            .audience("my-api")
            .build()

        val validToken = rsaToken(audience = listOf("my-api"))
        assertThat(NimbusJwtDecoder.decode(validToken, verification).subject).isEqualTo("alice")

        val wrongAudienceToken = rsaToken(audience = listOf("other-api"))
        assertThatThrownBy {
            NimbusJwtDecoder.decode(wrongAudienceToken, verification)
        }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `publicKey(EC) decodes a valid ES256 token`() {
        val verification = JwtVerification.of(JwtKeySource.publicKey(ecJwk.toECPublicKey()))
        val decoded = NimbusJwtDecoder.decode(ecToken(subject = "carol"), verification)
        assertThat(decoded.subject).isEqualTo("carol")
    }

    @Test
    fun `publicKey(EC) rejects a token signed with RSA key`() {
        val verification = JwtVerification.of(JwtKeySource.publicKey(ecJwk.toECPublicKey()))
        assertThatThrownBy { NimbusJwtDecoder.decode(rsaToken(), verification) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `pem decodes valid RSA token from PEM public key`() {
        val pem = buildString {
            appendLine("-----BEGIN PUBLIC KEY-----")
            val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(
                rsaJwk.toRSAPublicKey().encoded,
            )
            appendLine(encoded)
            append("-----END PUBLIC KEY-----")
        }
        val verification = JwtVerification.of(JwtKeySource.pem(pem))
        val decoded = NimbusJwtDecoder.decode(rsaToken(subject = "alice"), verification)
        assertThat(decoded.subject).isEqualTo("alice")
    }

    @Test
    fun `pem decodes valid EC token from PEM public key`() {
        val pem = buildString {
            appendLine("-----BEGIN PUBLIC KEY-----")
            val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(
                ecJwk.toECPublicKey().encoded,
            )
            appendLine(encoded)
            append("-----END PUBLIC KEY-----")
        }
        val verification = JwtVerification.of(JwtKeySource.pem(pem))
        val decoded = NimbusJwtDecoder.decode(ecToken(subject = "dave"), verification)
        assertThat(decoded.subject).isEqualTo("dave")
    }

    @Test
    fun `pem throws for invalid PEM`() {
        assertThatThrownBy {
            JwtKeySource.pem("not-valid-pem")
        }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `secret decodes a valid HS256 token`() {
        val secret = "super-secret-key-with-enough-length"
        val verification = JwtVerification.of(JwtKeySource.secret(secret))
        val decoded = NimbusJwtDecoder.decode(hmacToken(subject = "eve", secret = secret), verification)
        assertThat(decoded.subject).isEqualTo("eve")
    }

    @Test
    fun `secret rejects a token signed with a different secret`() {
        val verification = JwtVerification.of(JwtKeySource.secret("correct-secret-key-123456789012345"))
        val token = hmacToken(secret = "wrong-secret-key-1234567890123456")
        assertThatThrownBy { NimbusJwtDecoder.decode(token, verification) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `jwks decodes a valid RSA token via remote JWKS`() {
        val verification = JwtVerification.of(JwtKeySource.jwks("http://localhost:$jwksPort/.well-known/jwks.json"))
        val decoded = NimbusJwtDecoder.decode(rsaToken(subject = "frank"), verification)
        assertThat(decoded.subject).isEqualTo("frank")
    }

    @Test
    fun `jwks decodes a valid EC token via remote JWKS`() {
        val verification = JwtVerification.of(JwtKeySource.jwks("http://localhost:$jwksPort/.well-known/jwks.json"))
        val decoded = NimbusJwtDecoder.decode(ecToken(subject = "grace"), verification)
        assertThat(decoded.subject).isEqualTo("grace")
    }

    @Test
    fun `jwks rejects a token signed with a key not in the JWKS`() {
        val verification = JwtVerification.of(JwtKeySource.jwks("http://localhost:$jwksPort/.well-known/jwks.json"))
        val unknownKey = RSAKeyGenerator(2048).keyID("unknown-key").generate()
        val unknownKeyToken = run {
            val claims = JWTClaimsSet.Builder().subject("hank")
                .expirationTime(Date(System.currentTimeMillis() + 60_000)).build()
            val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID("unknown-key").build()
            SignedJWT(header, claims).also { it.sign(RSASSASigner(unknownKey)) }.serialize()
        }
        assertThatThrownBy {
            NimbusJwtDecoder.decode(unknownKeyToken, verification)
        }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `jwks validates issuer and audience`() {
        val verification = JwtVerification.builder(
            JwtKeySource.jwks("http://localhost:$jwksPort/.well-known/jwks.json"),
        )
            .issuer("https://auth.example.com")
            .audience("my-api")
            .build()

        val validToken = rsaToken(issuer = "https://auth.example.com", audience = listOf("my-api"))
        assertThat(NimbusJwtDecoder.decode(validToken, verification).subject).isEqualTo("alice")

        val noIssuerToken = rsaToken()
        assertThatThrownBy { NimbusJwtDecoder.decode(noIssuerToken, verification) }.isInstanceOf(Exception::class.java)
    }

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

        val verification = JwtVerification.of(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
        val decoded = NimbusJwtDecoder.decode(token, verification)

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

        val verification = JwtVerification.of(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
        val decoded = NimbusJwtDecoder.decode(token, verification)

        assertThat(decoded.subject).isBlank()
    }

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
}
