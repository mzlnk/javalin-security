package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.javalin.Javalin
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.Socket
import java.net.URI
import java.net.http.WebSocket
import java.net.http.WebSocketHandshakeException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.net.http.HttpClient as JdkHttpClient

class JavalinSecurityWsAllowedOriginsKtTest {
    private val headerAuthenticator = Authenticator { ctx ->
        when (val user = ctx.header("X-User")) {
            null -> AuthenticationResult.NotAuthenticated
            else -> AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user)))
        }
    }

    @Test
    fun `should reject the upgrade with 403 when the Origin is not in the allowedOrigins list`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.fallback = r.allow }
                    ws.allowedOrigins = listOf("https://allowed.example.com")
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { server, _ ->
            // when
            val code = rawUpgradeStatusCode(
                "localhost", server.port(), "/ws/chat",
                mapOf("Origin" to "https://evil.example.com"),
            )

            // then
            assertThat(code).isEqualTo(403)
        }
    }

    @Test
    fun `should reject the upgrade with 403 when the Origin header is absent and allowedOrigins is set`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.fallback = r.allow }
                    ws.allowedOrigins = listOf("https://allowed.example.com")
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { server, _ ->
            // when
            val code = rawUpgradeStatusCode("localhost", server.port(), "/ws/chat")

            // then
            assertThat(code).isEqualTo(403)
        }
    }

    @Test
    fun `should accept the upgrade when the Origin is in the allowedOrigins list`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.fallback = r.allow }
                    ws.allowedOrigins = listOf("https://allowed.example.com")
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { server, _ ->
            // when
            val code = rawUpgradeStatusCode(
                "localhost", server.port(), "/ws/chat",
                mapOf("Origin" to "https://allowed.example.com"),
            )

            // then
            assertThat(code).isEqualTo(101)
        }
    }

    @Test
    fun `should accept any Origin when allowedOrigins is not configured`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.fallback = r.allow }
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, _) = tryConnect(client.origin, "/ws/chat")

            // then
            assertThat(connected).isTrue()
        }
    }

    @Test
    fun `should reject a disallowed Origin before authentication is even attempted`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.fallback = r.authenticated }
                    ws.allowedOrigins = listOf("https://allowed.example.com")
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { server, _ ->
            // when
            val code = rawUpgradeStatusCode(
                "localhost", server.port(), "/ws/chat",
                mapOf("Origin" to "https://evil.example.com", "X-User" to "alice"),
            )

            // then
            assertThat(code).isEqualTo(403)
        }
    }

    @Test
    fun `should invoke a custom forbiddenHandler when the Origin is disallowed`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.fallback = r.allow }
                    ws.allowedOrigins = listOf("https://allowed.example.com")
                    ws.authentication = authenticationStrategy(
                        forbiddenHandler = { ctx, _ ->
                            ctx.status(403).result("custom-origin-denied")
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { server, _ ->
            // when
            val code = rawUpgradeStatusCode(
                "localhost", server.port(), "/ws/chat",
                mapOf("Origin" to "https://evil.example.com"),
            )

            // then
            assertThat(code).isEqualTo(403)
        }
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

    private fun rawUpgradeStatusCode(
        host: String,
        port: Int,
        path: String,
        extraHeaders: Map<String, String> = emptyMap(),
    ): Int {
        Socket(host, port).use { socket ->
            socket.soTimeout = 5_000
            val out = socket.getOutputStream().bufferedWriter(Charsets.ISO_8859_1)
            val inp = socket.getInputStream().bufferedReader(Charsets.ISO_8859_1)

            out.write("GET $path HTTP/1.1\r\n")
            out.write("Host: $host:$port\r\n")
            out.write("Upgrade: websocket\r\n")
            out.write("Connection: Upgrade\r\n")
            out.write("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
            out.write("Sec-WebSocket-Version: 13\r\n")
            for ((k, v) in extraHeaders) {
                out.write("$k: $v\r\n")
            }
            out.write("\r\n")
            out.flush()

            // Read and parse the HTTP status line; e.g. "HTTP/1.1 403 Forbidden"
            val statusLine = inp.readLine() ?: return -1
            return statusLine.substringAfter(" ").substringBefore(" ").toIntOrNull() ?: -1
        }
    }
}
