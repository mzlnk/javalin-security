package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.http.WebSocket
import java.net.http.WebSocketHandshakeException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.net.http.HttpClient as JdkHttpClient

class JwtWsSecurityTest {
    private enum class Role : RouteRole { ADMIN, USER }

    private val roleOf: (String) -> RouteRole? = { name -> Role.entries.find { it.name == name } }

    private val testDecoder = JwtDecoder { token, _ ->
        if (!token.startsWith("valid|")) throw IllegalArgumentException("bad token")
        val parts = token.split("|", limit = 3)
        val subject = parts.getOrElse(1) { "" }
        val roles = parts.getOrElse(2) { "" }.split(",").filter { it.isNotEmpty() }
        SimpleDecodedJwt(
            subject = subject,
            claims = mapOf("sub" to subject, "roles" to roles),
        )
    }

    @Test
    fun `should reject an anonymous upgrade when the WS route requires authentication`() {
        // given
        val app = bearerApp()

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should allow the upgrade when a valid bearer token is provided`() {
        // given
        val app = bearerApp()

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, _) = tryConnect(client.origin, "/ws/chat", "Authorization" to "Bearer ${token("alice")}")

            // then
            assertThat(connected).isTrue()
        }
    }

    @Test
    fun `should allow the upgrade when the caller holds the required role`() {
        // given
        val app = bearerApp()

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, _) = tryConnect(
                client.origin,
                "/ws/admin",
                "Authorization" to "Bearer ${token("admin", roles = listOf("ADMIN"))}",
            )

            // then
            assertThat(connected).isTrue()
        }
    }

    @Test
    fun `should reject the upgrade with 403 when the authenticated caller lacks the required role`() {
        // given
        val app = bearerApp()

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(
                client.origin,
                "/ws/admin",
                "Authorization" to "Bearer ${token("bob", roles = listOf("USER"))}",
            )

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(403)
        }
    }

    @Test
    fun `should reject the upgrade with 401 when the bearer token is malformed`() {
        // given
        val app = bearerApp()

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat", "Authorization" to "Bearer not-a-jwt")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should allow the upgrade when a valid token is carried in a cookie`() {
        // given
        val app = cookieApp()

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, _) = tryConnect(client.origin, "/ws/chat", "Cookie" to "access_token=${token("alice")}")

            // then
            assertThat(connected).isTrue()
        }
    }

    @Test
    fun `should reject the upgrade with 401 when the cookie is absent`() {
        // given
        val app = cookieApp()

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat", "Authorization" to "Bearer ${token("alice")}")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(401)
        }
    }

    private fun token(subject: String, roles: List<String> = emptyList()): String =
        "valid|$subject|${roles.joinToString(",")}"

    private fun bearerApp(): Javalin = Javalin.create { cfg ->
        cfg.security { security ->
            security.ws { ws ->
                ws.authentication = jwt { jwt ->
                    jwt.decoder = testDecoder
                    jwt.keySource = JwtKeySource.secret("test-secret")
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
                    jwt.decoder = testDecoder
                    jwt.keySource = JwtKeySource.secret("test-secret")
                    jwt.tokenResolver = TokenResolver.cookie("access_token")
                }
                ws.rules { r -> r.add("/ws/chat", r.authenticated) }
            }
        }
        cfg.routes.ws("/ws/chat") { }
    }

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
}
