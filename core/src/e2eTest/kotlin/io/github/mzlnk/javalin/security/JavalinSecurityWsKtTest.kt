package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.javalin.Javalin
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.http.WebSocket
import java.net.http.WebSocketHandshakeException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.net.http.HttpClient as JdkHttpClient

class JavalinSecurityWsKtTest {
    private enum class Role : RouteRole { ADMIN }

    private val headerAuthenticator = Authenticator { ctx ->
        when (val user = ctx.header("X-User")) {
            null -> AuthenticationResult.NotAuthenticated
            "invalid" -> AuthenticationResult.Failure(message = "super secret internal reason")
            else -> {
                val roles = ctx.header("X-Roles")
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.filter { it.isNotEmpty() }
                    ?.mapNotNull { name -> Role.entries.find { it.name == name } }
                    ?.toSet()
                    ?: emptySet()
                AuthenticationResult.Success(Authentication.authenticated(TestIdentity(user), roles))
            }
        }
    }

    @Test
    fun `should reject anonymous upgrade when the route requires authentication`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.authenticated) }
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should deny an anonymous upgrade by default when no rule matches the path`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should deny an authenticated upgrade by default when no rule matches the path`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/other/*", r.authenticated) }
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat", "X-User" to "alice")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(403)
        }
    }

    @Test
    fun `should permit an anonymous upgrade when rule is allow`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws -> ws.rules { r -> r.add("/ws/*", r.allow) } }
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
    fun `should allow the upgrade when authenticated rule is hit with credentials`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.authenticated) }
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, _) = tryConnect(client.origin, "/ws/chat", "X-User" to "alice")

            // then
            assertThat(connected).isTrue()
        }
    }

    @Test
    fun `should allow the upgrade when the authenticated caller holds the required role`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.hasRole(Role.ADMIN)) }
                    ws.authentication = authenticationStrategy(
                        Authenticator {
                            AuthenticationResult.Success(
                                Authentication.authenticated(TestIdentity("alice"), Role.ADMIN),
                            )
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/admin") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, _) = tryConnect(client.origin, "/ws/admin")

            // then
            assertThat(connected).isTrue()
        }
    }

    @Test
    fun `should reject the upgrade with 403 when the authenticated caller lacks the required role`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.hasRole(Role.ADMIN)) }
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/admin") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/admin", "X-User" to "bob")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(403)
        }
    }

    @Test
    fun `should not run onConnect when the upgrade is denied`() {
        // given
        val onConnectRan = AtomicBoolean(false)
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws -> ws.rules { r -> r.add("/ws/*", r.deny) } }
            }
            cfg.routes.ws("/ws/chat") { ws ->
                ws.onConnect { onConnectRan.set(true) }
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, _) = tryConnect(client.origin, "/ws/chat")

            // then
            assertThat(connected).isFalse()
            Thread.sleep(200) // give the server time to potentially invoke onConnect (it must not)
            assertThat(onConnectRan.get()).isFalse()
        }
    }

    @Test
    fun `should reject the upgrade with 401 when credentials are invalid`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat", "X-User" to "invalid")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should not leak the internal authenticator message when authentication fails`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val body = upgradeRejectionBody(client.origin, "/ws/chat", "X-User" to "invalid")

            // then
            assertThat(body).doesNotContain("super secret internal reason")
        }
    }

    @Test
    fun `should invoke a custom unauthorizedHandler when the upgrade is anonymously denied`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.authenticated) }
                    ws.authentication = authenticationStrategy(
                        unauthorizedHandler = { ctx, _ ->
                            ctx.status(401).result("custom-ws-401")
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should invoke a custom forbiddenHandler when the upgrade is forbidden`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.hasRole(Role.ADMIN)) }
                    ws.authentication = authenticationStrategy(
                        authenticator = headerAuthenticator,
                        forbiddenHandler = { ctx, _ ->
                            ctx.status(403).result("custom-ws-403")
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/admin") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/admin", "X-User" to "bob")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(403)
        }
    }

    @Test
    fun `should deny upgrades not matched by a specific rule when a fallback deny rule is set`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r ->
                        r.add("/ws/public/*", r.allow)
                        r.fallback = r.deny
                    }
                }
            }
            cfg.routes.ws("/ws/public/chat") { }
            cfg.routes.ws("/ws/secret") { }
        }

        JavalinTest.test(app) { _, client ->
            // when / then
            val (publicConnected, _) = tryConnect(client.origin, "/ws/public/chat")
            assertThat(publicConnected).isTrue()

            // when / then
            val (secretConnected, secretCode) = tryConnect(client.origin, "/ws/secret")
            assertThat(secretConnected).isFalse()
            assertThat(secretCode).isEqualTo(401)
        }
    }

    @Test
    fun `should deny anonymous and allow authenticated upgrade when using an async authenticator`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.authenticated) }
                    ws.authentication = asyncAuthenticationStrategy(
                        { ctx ->
                            CompletableFuture.supplyAsync {
                                val user = ctx.header("X-User")
                                if (user != null) {
                                    AuthenticationResult.Success(Authentication.authenticated(TestIdentity(user)))
                                } else {
                                    AuthenticationResult.NotAuthenticated
                                }
                            }
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when / then
            val (anonConnected, anonCode) = tryConnect(client.origin, "/ws/chat")
            assertThat(anonConnected).isFalse()
            assertThat(anonCode).isEqualTo(401)

            // when / then
            val (authConnected, _) = tryConnect(client.origin, "/ws/chat", "X-User" to "alice")
            assertThat(authConnected).isTrue()
        }
    }

    @Test
    fun `should deny the upgrade when an async authenticator future completes with Failure`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncAuthenticationStrategy(
                        { _ ->
                            CompletableFuture.completedFuture(
                                AuthenticationResult.Failure("async credential failure"),
                            )
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should not leak the failure message when an async authenticator future completes with Failure`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncAuthenticationStrategy(
                        { _ ->
                            CompletableFuture.completedFuture(
                                AuthenticationResult.Failure("async credential failure"),
                            )
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val body = upgradeRejectionBody(client.origin, "/ws/chat")

            // then
            assertThat(body).doesNotContain("async credential failure")
        }
    }

    @Test
    fun `should deny the upgrade when an async authenticator future completes exceptionally`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncAuthenticationStrategy(
                        { _ -> CompletableFuture.failedFuture(RuntimeException("internal IdP crash")) },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should not leak the cause when an async authenticator future completes exceptionally`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncAuthenticationStrategy(
                        { _ -> CompletableFuture.failedFuture(RuntimeException("internal IdP crash")) },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val body = upgradeRejectionBody(client.origin, "/ws/chat")

            // then
            assertThat(body).doesNotContain("internal IdP crash")
        }
    }

    @Test
    fun `should deny the upgrade when an async authenticator throws synchronously`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncAuthenticationStrategy(
                        { _ -> throw IllegalStateException("sync crash in async ws authenticator") },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, code) = tryConnect(client.origin, "/ws/chat")

            // then
            assertThat(connected).isFalse()
            assertThat(code).isEqualTo(401)
        }
    }

    @Test
    fun `should not leak the cause when an async authenticator throws synchronously`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncAuthenticationStrategy(
                        { _ -> throw IllegalStateException("sync crash in async ws authenticator") },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val body = upgradeRejectionBody(client.origin, "/ws/chat")

            // then
            assertThat(body).doesNotContain("sync crash in async ws authenticator")
        }
    }

    @Test
    fun `should expose the authentication set during upgrade from WsContext in onConnect`() {
        // given
        val identityName = AtomicReference<String?>(null)
        val connectLatch = CountDownLatch(1)
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.authenticated) }
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { ws ->
                ws.onConnect { ctx ->
                    identityName.set((ctx.authentication().identity as? TestIdentity)?.name)
                    connectLatch.countDown()
                }
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            tryConnect(client.origin, "/ws/chat", "X-User" to "alice")

            // then
            assertThat(connectLatch.await(3, TimeUnit.SECONDS)).isTrue()
            assertThat(identityName.get()).isEqualTo("alice")
        }
    }

    @Test
    fun `should permit an anonymous upgrade when the WS endpoint declares the Anyone role`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws -> ws.rules { r -> r.fallback = r.deny } }
            }
            cfg.routes.ws("/ws/public", { }, Anyone)
        }

        JavalinTest.test(app) { _, client ->
            // when
            val (connected, _) = tryConnect(client.origin, "/ws/public")

            // then
            assertThat(connected).isTrue()
        }
    }

    @Test
    fun `should grant the upgrade when the WS endpoint declares roles and the caller holds a matching role`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.authentication = authenticationStrategy(headerAuthenticator)
                    ws.rules { r -> r.fallback = r.deny } // rule table must NOT be consulted
                }
            }
            cfg.routes.ws("/ws/admin", { }, Role.ADMIN)
        }

        JavalinTest.test(app) { _, client ->
            // when / then
            val (_, anonCode) = tryConnect(client.origin, "/ws/admin")
            assertThat(anonCode).isEqualTo(401)

            // when / then
            val (_, forbiddenCode) = tryConnect(client.origin, "/ws/admin", "X-User" to "bob")
            assertThat(forbiddenCode).isEqualTo(403)

            // when / then
            val (granted, _) = tryConnect(client.origin, "/ws/admin", "X-User" to "alice", "X-Roles" to "ADMIN")
            assertThat(granted).isTrue()
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

    private fun upgradeRejectionBody(
        origin: String,
        path: String,
        vararg headers: Pair<String, String>,
    ): String {
        val latch = CountDownLatch(1)
        val body = AtomicReference("")

        val wsUri = URI.create(origin.replace("http://", "ws://") + path)
        val builder = JdkHttpClient.newHttpClient().newWebSocketBuilder()
        headers.forEach { (k, v) -> builder.header(k, v) }

        builder.buildAsync(wsUri, object : WebSocket.Listener {
            override fun onOpen(ws: WebSocket) {
                ws.sendClose(WebSocket.NORMAL_CLOSURE, "").thenRun { latch.countDown() }
            }
        }).exceptionally { t ->
            val cause = if (t is java.util.concurrent.CompletionException) t.cause ?: t else t
            if (cause is WebSocketHandshakeException) {
                body.set(cause.response.body()?.toString() ?: "")
            }
            latch.countDown()
            null
        }

        latch.await(3, TimeUnit.SECONDS)
        return body.get()
    }
}
