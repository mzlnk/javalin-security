package io.github.mzlnk.javalin.security.jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.http.WebSocket
import java.net.http.WebSocketHandshakeException
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.net.http.HttpClient as JdkHttpClient

/**
 * Integration tests for the `jwt { }` scheme factory assigned via `ws.authentication = jwt { }`.
 *
 * Mirrors [JwtSecurityIT] (HTTP) and reuses the WS upgrade-attempt harness pattern from
 * `JavalinSecurityWsIT` in `javalin-security-core` — the decoder here is the real
 * [NimbusJwtDecoder], with tokens signed in-test against a locally generated RSA key pair.
 */
class JwtWsSecurityIT {

    private enum class Role : RouteRole { ADMIN, USER }

    private val roleOf: (String) -> RouteRole? = { name -> Role.entries.find { it.name == name } }

    private val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.genKeyPair()

    private fun token(subject: String, roles: List<String> = emptyList()): String {
        val claims = JWTClaimsSet.Builder()
            .subject(subject)
            .claim("roles", roles)
            .issueTime(Date())
            .expirationTime(Date(System.currentTimeMillis() + 60_000))
            .build()
        val jwt = SignedJWT(JWSHeader(JWSAlgorithm.RS256), claims)
        jwt.sign(RSASSASigner(keyPair.private as RSAPrivateKey))
        return jwt.serialize()
    }

    private fun bearerApp(): Javalin = Javalin.create { cfg ->
        cfg.security { security ->
            security.ws { ws ->
                ws.authentication = jwt { jwt ->
                    jwt.decoder = NimbusJwtDecoder
                    jwt.keySource = JwtKeySource.publicKey(keyPair.public)
                    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", roleOf)
                }
                ws.rules { r ->
                    r.add("/ws/chat", r.authenticated)
                    r.add("/ws/admin", r.hasRole(Role.ADMIN))
                }
            }
        }
        cfg.routes.ws("/ws/chat") { }
        cfg.routes.ws("/ws/admin") { }
    }

    private fun cookieApp(): Javalin = Javalin.create { cfg ->
        cfg.security { security ->
            security.ws { ws ->
                ws.authentication = jwt { jwt ->
                    jwt.decoder = NimbusJwtDecoder
                    jwt.keySource = JwtKeySource.publicKey(keyPair.public)
                    jwt.tokenResolver = TokenResolver.cookie("access_token")
                }
                ws.rules { r -> r.add("/ws/chat", r.authenticated) }
            }
        }
        cfg.routes.ws("/ws/chat") { }
    }

    /** Attempts a WebSocket upgrade and returns (connected, statusCodeOnFailure). */
    private fun tryConnect(
        origin: String,
        path: String,
        vararg headers: Pair<String, String>,
        timeoutMs: Long = 3_000,
    ): Pair<Boolean, Int?> {
        val latch = CountDownLatch(1)
        val connected = AtomicBoolean(false)
        val statusCode = AtomicReference<Int?>(null)

        val wsUri = URI.create(origin.replace("http://", "ws://") + path)
        val builder = JdkHttpClient.newHttpClient().newWebSocketBuilder()
        headers.forEach { (k, v) -> builder.header(k, v) }

        builder.buildAsync(wsUri, object : WebSocket.Listener {
            override fun onOpen(ws: WebSocket) {
                connected.set(true)
                ws.sendClose(WebSocket.NORMAL_CLOSURE, "").thenRun { latch.countDown() }
            }
        }).exceptionally { t ->
            val cause = if (t is java.util.concurrent.CompletionException) t.cause ?: t else t
            if (cause is WebSocketHandshakeException) {
                statusCode.set(cause.response.statusCode())
            }
            latch.countDown()
            null
        }

        latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        return connected.get() to statusCode.get()
    }

    // ── bearer header transport ─────────────────────────────────────────────

    @Test
    fun `should reject anonymous upgrade to an authenticated WS route`() = JavalinTest.test(bearerApp()) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/chat")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(401)
    }

    @Test
    fun `should allow upgrade with a valid bearer token`() = JavalinTest.test(bearerApp()) { _, client ->
        val (connected, _) = tryConnect(client.origin, "/ws/chat", "Authorization" to "Bearer ${token("alice")}")

        assertThat(connected).isTrue()
    }

    @Test
    fun `should allow upgrade when caller holds the required role`() = JavalinTest.test(bearerApp()) { _, client ->
        val (connected, _) = tryConnect(
            client.origin,
            "/ws/admin",
            "Authorization" to "Bearer ${token("admin", roles = listOf("ADMIN"))}",
        )

        assertThat(connected).isTrue()
    }

    @Test
    fun `should reject upgrade with 403 when authenticated caller lacks required role`() =
        JavalinTest.test(bearerApp()) { _, client ->
            val (connected, code) = tryConnect(
                client.origin,
                "/ws/admin",
                "Authorization" to "Bearer ${token("bob", roles = listOf("USER"))}",
            )

            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(403)
        }

    @Test
    fun `should reject upgrade with 401 when the bearer token is malformed`() = JavalinTest.test(bearerApp()) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/chat", "Authorization" to "Bearer not-a-jwt")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(401)
    }

    // ── cookie transport (browser/SPA flows) ────────────────────────────────

    @Test
    fun `should allow upgrade with a valid token carried in a cookie`() = JavalinTest.test(cookieApp()) { _, client ->
        val (connected, _) = tryConnect(client.origin, "/ws/chat", "Cookie" to "access_token=${token("alice")}")

        assertThat(connected).isTrue()
    }

    @Test
    fun `should reject upgrade with 401 when the cookie is absent`() = JavalinTest.test(cookieApp()) { _, client ->
        // An Authorization header is present, but the cookie-based resolver only looks at the cookie.
        val (connected, code) = tryConnect(client.origin, "/ws/chat", "Authorization" to "Bearer ${token("alice")}")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(401)
    }

}
