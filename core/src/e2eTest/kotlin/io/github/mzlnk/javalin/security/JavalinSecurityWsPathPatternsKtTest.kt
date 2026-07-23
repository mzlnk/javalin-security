package io.github.mzlnk.javalin.security

import io.javalin.Javalin
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

class JavalinSecurityWsPathPatternsKtTest {
    @Test
    fun `should match a concrete request path when the rule pattern declares a path parameter`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/room/{id}", r.allow) }
                }
            }
            cfg.routes.ws("/ws/room/{id}") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, _) = tryConnect(client.origin, "/ws/room/5")

            // then
            assertThat(connected).isTrue()
        }
    }

    @Test
    fun `should match a concrete request path when the rule pattern declares a wildcard`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws -> ws.rules { r -> r.add("/ws/room/*", r.allow) } }
            }
            cfg.routes.ws("/ws/room/{id}") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, _) = tryConnect(client.origin, "/ws/room/5")

            // then
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
}
