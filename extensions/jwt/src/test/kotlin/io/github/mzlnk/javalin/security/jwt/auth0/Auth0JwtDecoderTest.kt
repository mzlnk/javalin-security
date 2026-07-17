package io.github.mzlnk.javalin.security.jwt.auth0

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.github.mzlnk.javalin.security.jwt.JwtKeySource
import io.github.mzlnk.javalin.security.jwt.JwtVerification
import io.javalin.Javalin
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.Date

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class Auth0JwtDecoderTest {

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
        keyId: String? = "rsa-test-key",
        privateKey: RSAPrivateKey = rsaJwk.toRSAPrivateKey(),
        publicKey: RSAPublicKey = rsaJwk.toRSAPublicKey(),
    ): String {
        val builder = JWT.create()
            .withSubject(subject)
            .apply { issuer?.let { withIssuer(it) } }
            .apply { audience?.let { withAudience(*it.toTypedArray()) } }
            .withExpiresAt(expiresAt)
            .apply { keyId?.let { withKeyId(it) } }
        return builder.sign(Algorithm.RSA256(publicKey, privateKey))
    }

    private fun ecToken(
        subject: String = "alice",
        expiresAt: Date = Date(System.currentTimeMillis() + 60_000),
    ): String =
        JWT.create()
            .withSubject(subject)
            .withExpiresAt(expiresAt)
            .withKeyId("ec-test-key")
            .sign(Algorithm.ECDSA256(ecJwk.toECPublicKey(), ecJwk.toECPrivateKey()))

    private fun hmacToken(
        subject: String = "alice",
        secret: String = "super-secret-key-with-enough-length",
    ): String =
        JWT.create()
            .withSubject(subject)
            .withExpiresAt(Date(System.currentTimeMillis() + 60_000))
            .sign(Algorithm.HMAC256(secret))

    // ── publicKey (RSA) ───────────────────────────────────────────────────────

    @Test
    fun `publicKey(RSA) decodes a valid RS256 token`() {
        val verification = JwtVerification.of(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
        val decoded = Auth0JwtDecoder.decode(rsaToken(subject = "alice"), verification)
        assertThat(decoded.subject).isEqualTo("alice")
    }

    @Test
    fun `publicKey(RSA) rejects an expired token`() {
        val verification = JwtVerification.builder(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
            .clockSkew(0)
            .build()
        val expiredToken = rsaToken(expiresAt = Date(System.currentTimeMillis() - 5_000))
        assertThatThrownBy { Auth0JwtDecoder.decode(expiredToken, verification) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `publicKey(RSA) rejects a token signed with a different key`() {
        val otherKey = RSAKeyGenerator(2048).generate()
        val token = rsaToken(privateKey = otherKey.toRSAPrivateKey(), publicKey = otherKey.toRSAPublicKey())
        val verification = JwtVerification.of(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
        assertThatThrownBy {
            Auth0JwtDecoder.decode(token, verification)
        }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `publicKey(RSA) rejects a tampered token`() {
        val verification = JwtVerification.of(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
        val tampered = rsaToken() + "tampered"
        assertThatThrownBy { Auth0JwtDecoder.decode(tampered, verification) }.isInstanceOf(Exception::class.java)
    }

    // ── publicKey (RSA) + issuer/audience validation ─────────────────────────

    @Test
    fun `publicKey(RSA) validates issuer when configured`() {
        val verification = JwtVerification.builder(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
            .issuer("https://auth.example.com")
            .build()

        val validToken = rsaToken(issuer = "https://auth.example.com")
        assertThat(Auth0JwtDecoder.decode(validToken, verification).subject).isEqualTo("alice")

        val wrongIssuerToken = rsaToken(issuer = "https://other.example.com")
        assertThatThrownBy { Auth0JwtDecoder.decode(wrongIssuerToken, verification) }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `publicKey(RSA) validates audience when configured`() {
        val verification = JwtVerification.builder(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
            .audience("my-api")
            .build()

        val validToken = rsaToken(audience = listOf("my-api"))
        assertThat(Auth0JwtDecoder.decode(validToken, verification).subject).isEqualTo("alice")

        val wrongAudienceToken = rsaToken(audience = listOf("other-api"))
        assertThatThrownBy {
            Auth0JwtDecoder.decode(wrongAudienceToken, verification)
        }.isInstanceOf(Exception::class.java)
    }

    // ── publicKey (EC) ────────────────────────────────────────────────────────

    @Test
    fun `publicKey(EC) decodes a valid ES256 token`() {
        val verification = JwtVerification.of(JwtKeySource.publicKey(ecJwk.toECPublicKey()))
        val decoded = Auth0JwtDecoder.decode(ecToken(subject = "carol"), verification)
        assertThat(decoded.subject).isEqualTo("carol")
    }

    @Test
    fun `publicKey(EC) rejects a token signed with RSA key`() {
        val verification = JwtVerification.of(JwtKeySource.publicKey(ecJwk.toECPublicKey()))
        assertThatThrownBy { Auth0JwtDecoder.decode(rsaToken(), verification) }.isInstanceOf(Exception::class.java)
    }

    // ── pem ────────────────────────────────────────────────────────────────────

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
        val decoded = Auth0JwtDecoder.decode(rsaToken(subject = "alice"), verification)
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
        val decoded = Auth0JwtDecoder.decode(ecToken(subject = "dave"), verification)
        assertThat(decoded.subject).isEqualTo("dave")
    }

    @Test
    fun `pem throws for invalid PEM`() {
        assertThatThrownBy {
            JwtKeySource.pem("not-valid-pem")
        }.isInstanceOf(Exception::class.java)
    }

    // ── secret (HMAC) ──────────────────────────────────────────────────────────

    @Test
    fun `secret decodes a valid HS256 token`() {
        val secret = "super-secret-key-with-enough-length"
        val verification = JwtVerification.of(JwtKeySource.secret(secret))
        val decoded = Auth0JwtDecoder.decode(hmacToken(subject = "eve", secret = secret), verification)
        assertThat(decoded.subject).isEqualTo("eve")
    }

    @Test
    fun `secret rejects a token signed with a different secret`() {
        val verification = JwtVerification.of(JwtKeySource.secret("correct-secret-key-123456789012345"))
        val token = hmacToken(secret = "wrong-secret-key-1234567890123456")
        assertThatThrownBy { Auth0JwtDecoder.decode(token, verification) }.isInstanceOf(Exception::class.java)
    }

    // ── jwks ───────────────────────────────────────────────────────────────────

    @Test
    fun `jwks decodes a valid RSA token via remote JWKS`() {
        val verification = JwtVerification.of(JwtKeySource.jwks("http://localhost:$jwksPort/.well-known/jwks.json"))
        val decoded = Auth0JwtDecoder.decode(rsaToken(subject = "frank"), verification)
        assertThat(decoded.subject).isEqualTo("frank")
    }

    @Test
    fun `jwks decodes a valid EC token via remote JWKS`() {
        val verification = JwtVerification.of(JwtKeySource.jwks("http://localhost:$jwksPort/.well-known/jwks.json"))
        val decoded = Auth0JwtDecoder.decode(ecToken(subject = "grace"), verification)
        assertThat(decoded.subject).isEqualTo("grace")
    }

    @Test
    fun `jwks rejects a token signed with a key not in the JWKS`() {
        val verification = JwtVerification.of(JwtKeySource.jwks("http://localhost:$jwksPort/.well-known/jwks.json"))
        val unknownKey = RSAKeyGenerator(2048).keyID("unknown-key").generate()
        val unknownKeyToken = JWT.create()
            .withSubject("hank")
            .withExpiresAt(Date(System.currentTimeMillis() + 60_000))
            .withKeyId("unknown-key")
            .sign(Algorithm.RSA256(unknownKey.toRSAPublicKey(), unknownKey.toRSAPrivateKey()))
        assertThatThrownBy {
            Auth0JwtDecoder.decode(unknownKeyToken, verification)
        }.isInstanceOf(Exception::class.java)
    }

    @Test
    fun `jwks rejects a token with no kid header`() {
        val verification = JwtVerification.of(JwtKeySource.jwks("http://localhost:$jwksPort/.well-known/jwks.json"))
        val noKidToken = rsaToken(keyId = null)
        assertThatThrownBy {
            Auth0JwtDecoder.decode(noKidToken, verification)
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
        assertThat(Auth0JwtDecoder.decode(validToken, verification).subject).isEqualTo("alice")

        val noIssuerToken = rsaToken()
        assertThatThrownBy { Auth0JwtDecoder.decode(noIssuerToken, verification) }.isInstanceOf(Exception::class.java)
    }

    // ── publicKey (RSA) + RSASSA-PSS ──────────────────────────────────────────

    @Test
    fun `publicKey(RSA) decodes a valid PS256 token`() {
        val verification = JwtVerification.of(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
        val psToken = JWT.create()
            .withSubject("alice")
            .withExpiresAt(Date(System.currentTimeMillis() + 60_000))
            .sign(Algorithm.RSA256PSS(rsaJwk.toRSAPublicKey(), rsaJwk.toRSAPrivateKey()))
        val decoded = Auth0JwtDecoder.decode(psToken, verification)
        assertThat(decoded.subject).isEqualTo("alice")
    }

    // ── DecodedJwt claim access ───────────────────────────────────────────────

    @Test
    fun `decoded token exposes all claims in the claims map`() {
        val token = JWT.create()
            .withSubject("alice")
            .withClaim("roles", listOf("ADMIN", "USER"))
            .withClaim("customClaim", "customValue")
            .withExpiresAt(Date(System.currentTimeMillis() + 60_000))
            .withKeyId("rsa-test-key")
            .sign(Algorithm.RSA256(rsaJwk.toRSAPublicKey(), rsaJwk.toRSAPrivateKey()))

        val verification = JwtVerification.of(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
        val decoded = Auth0JwtDecoder.decode(token, verification)

        assertThat(decoded.subject).isEqualTo("alice")
        assertThat(decoded.claim<List<String>>("roles")).containsExactlyInAnyOrder("ADMIN", "USER")
        assertThat(decoded.claim<String>("customClaim")).isEqualTo("customValue")
    }

    @Test
    fun `subject is blank string when token has no sub claim`() {
        val token = JWT.create()
            .withExpiresAt(Date(System.currentTimeMillis() + 60_000))
            .withKeyId("rsa-test-key")
            .sign(Algorithm.RSA256(rsaJwk.toRSAPublicKey(), rsaJwk.toRSAPrivateKey()))

        val verification = JwtVerification.of(JwtKeySource.publicKey(rsaJwk.toRSAPublicKey()))
        val decoded = Auth0JwtDecoder.decode(token, verification)

        assertThat(decoded.subject).isBlank()
    }

}
