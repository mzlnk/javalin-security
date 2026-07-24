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

class JavalinSecurityWsPathNormalizationKtTest {
    private val headerAuthenticator = Authenticator { ctx ->
        when (val user = ctx.header("X-User")) {
            null -> AuthenticationResult.NotAuthenticated
            else -> AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user)))
        }
    }

    @Test
    fun `should keep denying an upgrade when a trailing slash is added to the path`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws -> ws.rules { r -> r.add("/ws/admin", r.deny) } }
            }
            cfg.routes.ws("/ws/admin") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (_, code) = tryConnect(client.origin, "/ws/admin/")

            // then
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should keep denying an upgrade when the path contains duplicate slashes`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.router.treatMultipleSlashesAsSingleSlash = true
            cfg.security { security ->
                security.ws { ws -> ws.rules { r -> r.add("/ws/admin", r.deny) } }
            }
            cfg.routes.ws("/ws/admin") { }
        }

        JavalinTest.test(app) { server, _ ->
            // when
            val code = rawUpgradeStatusCode("localhost", server.port(), "/ws//admin")

            // then
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should match the authorization rule after the context path is stripped`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.router.contextPath = "/ctx"
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.authenticated) }
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when / then
            val (_, anonCode) = tryConnect(client.origin, "/ctx/ws/chat")
            assertThat(anonCode).isEqualTo(401)

            // when / then
            val (connected, _) = tryConnect(client.origin, "/ctx/ws/chat", "X-User" to "alice")
            assertThat(connected).isTrue()
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
