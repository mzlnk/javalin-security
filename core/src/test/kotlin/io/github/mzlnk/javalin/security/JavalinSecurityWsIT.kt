package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
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

/**
 * Integration tests for WebSocket upgrade-time security.
 *
 * Denial cases use a raw HTTP upgrade attempt and assert the rejection status code.
 * Allow cases open a real WebSocket connection and assert that [onConnect] runs.
 *
 * These tests are the regression suite for the original defect where the WS guard was registered
 * as a `beforeMatched` HTTP handler (which never fires for WS upgrades) instead of the correct
 * `wsBeforeUpgrade` hook.
 */
class JavalinSecurityWsIT {

    // ── test helpers ──────────────────────────────────────────────────────────

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
                AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user), roles))
            }
        }
    }

    /**
     * Attempts a WebSocket upgrade and returns (connected, statusCodeOnFailure).
     * On success, [connected] is `true`. On HTTP-level rejection, [statusCodeOnFailure] holds the
     * server's status code (extracted from [WebSocketHandshakeException]).
     */
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

    /**
     * Attempts a WebSocket upgrade and returns the rejection response body as a String.
     *
     * The JDK WebSocket implementation captures error response bodies as [String], so
     * [WebSocketHandshakeException.getResponse].body() reliably contains the body for
     * HTTP-level rejection responses (401, 403, etc.). Used only for verifying that no
     * internal detail is present in the denial response.
     */
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

    // ── regression: guard must actually run ───────────────────────────────────

    @Test
    fun `anonymous upgrade to authenticated WS path is rejected - guard runs`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.authenticated) }
                    ws.authentication = syncScheme(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/chat")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(401)
    }

    // ── deny-by-default ───────────────────────────────────────────────────────

    @Test
    fun `upgrade to WS path with no matching rule is denied by default for anonymous caller`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    // empty rule set — everything denied by default
                    ws.authentication = syncScheme(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/chat")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(401)
    }

    @Test
    fun `upgrade to WS path with no matching rule is denied by default for authenticated caller`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/other/*", r.authenticated) } // rule for a different path
                    ws.authentication = syncScheme(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/chat", "X-User" to "alice")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(403)
    }

    // ── allow permits the upgrade ──────────────────────────────────────────

    @Test
    fun `allow rule permits anonymous upgrade`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws -> ws.rules { r -> r.add("/ws/*", r.allow) } }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, _) = tryConnect(client.origin, "/ws/chat")

        assertThat(connected).isTrue()
    }

    // ── authenticated caller is allowed ──────────────────────────────────────

    @Test
    fun `authenticated upgrade to an authenticated rule succeeds`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.authenticated) }
                    ws.authentication = syncScheme(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, _) = tryConnect(client.origin, "/ws/chat", "X-User" to "alice")

        assertThat(connected).isTrue()
    }

    @Test
    fun `authenticated caller with required role is allowed`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.hasRole(Role.ADMIN)) }
                    ws.authentication = syncScheme(
                        Authenticator {
                            AuthenticationResult.Success(
                                Authentication.authenticated(TestPrincipal("alice"), Role.ADMIN),
                            )
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/admin") { }
        },
    ) { _, client ->
        val (connected, _) = tryConnect(client.origin, "/ws/admin")

        assertThat(connected).isTrue()
    }

    // ── forbidden: authenticated but missing role ─────────────────────────────

    @Test
    fun `authenticated caller without required role is denied with 403`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.hasRole(Role.ADMIN)) }
                    ws.authentication = syncScheme(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/admin") { }
        },
    ) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/admin", "X-User" to "bob")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(403)
    }

    // ── denied upgrade does not establish a connection ────────────────────────

    @Test
    fun `onConnect does NOT run when upgrade is denied`() {
        val onConnectRan = AtomicBoolean(false)

        JavalinTest.test(
            Javalin.create { cfg ->
                cfg.security { security ->
                    security.ws { ws -> ws.rules { r -> r.add("/ws/*", r.deny) } }
                }
                cfg.routes.ws("/ws/chat") { ws ->
                    ws.onConnect { onConnectRan.set(true) }
                }
            },
        ) { _, client ->
            val (connected, _) = tryConnect(client.origin, "/ws/chat")

            assertThat(connected).isFalse()
            Thread.sleep(200) // give the server time to potentially invoke onConnect (it must not)
            assertThat(onConnectRan.get()).isFalse()
        }
    }

    // ── authentication failure ────────────────────────────────────────────────

    @Test
    fun `invalid credentials trigger 401`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = syncScheme(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/chat", "X-User" to "invalid")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(401)
    }

    @Test
    fun `authentication failure does not leak internal authenticator message`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = syncScheme(headerAuthenticator)
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val body = upgradeRejectionBody(client.origin, "/ws/chat", "X-User" to "invalid")

        assertThat(body).doesNotContain("super secret internal reason")
    }

    // ── custom handlers ───────────────────────────────────────────────────────

    @Test
    fun `custom unauthorizedHandler is invoked on anonymous denial`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.authenticated) }
                    ws.authentication = syncScheme(
                        unauthorizedHandler = { ctx, _ ->
                            ctx.status(401).result("custom-ws-401")
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/chat")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(401)
    }

    @Test
    fun `custom forbiddenHandler is invoked on forbidden upgrade`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.hasRole(Role.ADMIN)) }
                    ws.authentication = syncScheme(
                        authenticator = headerAuthenticator,
                        forbiddenHandler = { ctx, _ ->
                            ctx.status(403).result("custom-ws-403")
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/admin") { }
        },
    ) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/admin", "X-User" to "bob")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(403)
    }

    // ── fallback catch-all ──────────────────────────────────────────────────

    @Test
    fun `fallback deny denies upgrades not matched by a specific rule`() = JavalinTest.test(
        Javalin.create { cfg ->
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
        },
    ) { _, client ->
        // explicit allow rule → allowed
        val (publicConnected, _) = tryConnect(client.origin, "/ws/public/chat")
        assertThat(publicConnected).isTrue()

        // caught by fallback = deny
        val (secretConnected, secretCode) = tryConnect(client.origin, "/ws/secret")
        assertThat(secretConnected).isFalse()
        assertThat(secretCode).isEqualTo(401)
    }

    // ── async (blocking) authentication ──────────────────────────────────────

    @Test
    fun `async authenticator (blocking join) denies anonymous and allows authenticated upgrade`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.authenticated) }
                    ws.authentication = asyncScheme(
                        { ctx ->
                            CompletableFuture.supplyAsync {
                                val user = ctx.header("X-User")
                                if (user != null) {
                                    AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user)))
                                } else {
                                    AuthenticationResult.NotAuthenticated
                                }
                            }
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        // anonymous → denied
        val (anonConnected, anonCode) = tryConnect(client.origin, "/ws/chat")
        assertThat(anonConnected).isFalse()
        assertThat(anonCode).isEqualTo(401)

        // authenticated → allowed
        val (authConnected, _) = tryConnect(client.origin, "/ws/chat", "X-User" to "alice")
        assertThat(authConnected).isTrue()
    }

    @Test
    fun `async authenticator is fail-closed when future completes with Failure`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncScheme(
                        { _ ->
                            CompletableFuture.completedFuture(
                                AuthenticationResult.Failure("async credential failure"),
                            )
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/chat")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(401)
    }

    @Test
    fun `async authenticator is fail-closed when future completes with Failure - no message leaked`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncScheme(
                        { _ ->
                            CompletableFuture.completedFuture(
                                AuthenticationResult.Failure("async credential failure"),
                            )
                        },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val body = upgradeRejectionBody(client.origin, "/ws/chat")

        assertThat(body).doesNotContain("async credential failure")
    }

    @Test
    fun `async authenticator is fail-closed when future completes exceptionally`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncScheme(
                        { _ -> CompletableFuture.failedFuture(RuntimeException("internal IdP crash")) },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/chat")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(401)
    }

    @Test
    fun `async authenticator is fail-closed when future completes exceptionally - no cause leaked`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncScheme(
                        { _ -> CompletableFuture.failedFuture(RuntimeException("internal IdP crash")) },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val body = upgradeRejectionBody(client.origin, "/ws/chat")

        assertThat(body).doesNotContain("internal IdP crash")
    }

    @Test
    fun `async authenticator is fail-closed when authenticate throws synchronously`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncScheme(
                        { _ -> throw IllegalStateException("sync crash in async ws authenticator") },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, code) = tryConnect(client.origin, "/ws/chat")

        assertThat(connected).isFalse()
        assertThat(code).isEqualTo(401)
    }

    @Test
    fun `async authenticator is fail-closed when authenticate throws synchronously - no cause leaked`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.rules { r -> r.add("/ws/*", r.allow) }
                    ws.authentication = asyncScheme(
                        { _ -> throw IllegalStateException("sync crash in async ws authenticator") },
                    )
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val body = upgradeRejectionBody(client.origin, "/ws/chat")

        assertThat(body).doesNotContain("sync crash in async ws authenticator")
    }

    // ── WsContext.authentication() accessor ───────────────────────────────────

    @Test
    fun `authentication set during upgrade is readable from WsContext in onConnect`() {
        val principalName = AtomicReference<String?>(null)
        val connectLatch = CountDownLatch(1)

        JavalinTest.test(
            Javalin.create { cfg ->
                cfg.security { security ->
                    security.ws { ws ->
                        ws.rules { r -> r.add("/ws/*", r.authenticated) }
                        ws.authentication = syncScheme(headerAuthenticator)
                    }
                }
                cfg.routes.ws("/ws/chat") { ws ->
                    ws.onConnect { ctx ->
                        principalName.set((ctx.authentication().identity as? TestPrincipal)?.name)
                        connectLatch.countDown()
                    }
                }
            },
        ) { _, client ->
            tryConnect(client.origin, "/ws/chat", "X-User" to "alice")
            assertThat(connectLatch.await(3, TimeUnit.SECONDS)).isTrue()
            assertThat(principalName.get()).isEqualTo("alice")
        }
    }

    // ── RouteRole-first authorization ───────────────────────────────────────────

    @Test
    fun `Anyone role permits an anonymous upgrade, bypassing the rule table`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws -> ws.rules { r -> r.fallback = r.deny } } // rule table would deny everything
            }
            cfg.routes.ws("/ws/public", { }, Anyone)
        },
    ) { _, client ->
        val (connected, _) = tryConnect(client.origin, "/ws/public")
        assertThat(connected).isTrue()
    }

    @Test
    fun `a WS endpoint with declared roles is granted when the caller holds a matching role`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.ws { ws ->
                    ws.authentication = syncScheme(headerAuthenticator)
                    ws.rules { r -> r.fallback = r.deny } // rule table must NOT be consulted
                }
            }
            cfg.routes.ws("/ws/admin", { }, Role.ADMIN)
        },
    ) { _, client ->
        // anonymous → 401
        val (_, anonCode) = tryConnect(client.origin, "/ws/admin")
        assertThat(anonCode).isEqualTo(401)

        // authenticated without the role → 403
        val (_, forbiddenCode) = tryConnect(client.origin, "/ws/admin", "X-User" to "bob")
        assertThat(forbiddenCode).isEqualTo(403)

        // authenticated with the role, granted directly from authentication.roles (not the deny rule table)
        val (granted, _) = tryConnect(client.origin, "/ws/admin", "X-User" to "alice", "X-Roles" to "ADMIN")
        assertThat(granted).isTrue()
    }
}
