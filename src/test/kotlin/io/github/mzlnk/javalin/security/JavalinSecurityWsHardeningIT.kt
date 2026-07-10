package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.Javalin
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
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

/**
 * Hardening tests for WebSocket upgrade-time security.
 *
 * Covers:
 * - Path normalization (trailing slash, duplicate slashes, context path) cannot be used to
 *   bypass authorization rules.
 * - `allowedOrigins` allowlist: correct Origin allowed, incorrect/missing Origin rejected before
 *   authentication, allowlist unset is backward-compatible.
 * - Pattern matching: `{param}`-style patterns are literal in [AntPathMatcher] and do NOT match
 *   concrete paths (documents the known limitation and registers it as a regression guard).
 * - `allowedOrigins` configuration validation (empty set, blank entries, double-set).
 */
class JavalinSecurityWsHardeningIT {

    // ── helpers ───────────────────────────────────────────────────────────────

    private val headerAuthManager = AuthenticationManager { ctx ->
        when (val user = ctx.header("X-User")) {
            null -> AuthenticationResult.NotAuthenticated
            else -> AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user)))
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

    /**
     * Sends a raw HTTP WebSocket upgrade request via a plain TCP socket, giving full control
     * over which headers are included (or omitted). Used for tests that require customising headers
     * that the JDK WebSocket client manages automatically, such as `Origin`.
     *
     * Returns the HTTP response status code from the server's status line (e.g. 101, 401, 403).
     */
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

    // ── path normalization: trailing slash ────────────────────────────────────

    @Test
    fun `denyAll rule on exact path also governs request with trailing slash`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                ws {
                    authorizeRequests { authorize("/ws/admin", denyAll) }
                }
            }
            cfg.routes.ws("/ws/admin") { }
        },
    ) { _, client ->
        // denyAll + anonymous → 401; the path /ws/admin/ is normalized to /ws/admin by PathNormalizer
        val (_, code) = tryConnect(client.origin, "/ws/admin/")
        assertThat(code).isEqualTo(401)
    }

    // ── path normalization: duplicate slashes ─────────────────────────────────

    @Test
    fun `denyAll rule governs request with duplicate slashes when normalization is enabled`() {
        JavalinTest.test(
            Javalin.create { cfg ->
                cfg.router.treatMultipleSlashesAsSingleSlash = true
                cfg.security {
                    ws {
                        authorizeRequests { authorize("/ws/admin", denyAll) }
                    }
                }
                cfg.routes.ws("/ws/admin") { }
            },
        ) { server, _ ->
            // raw socket so the path "/ws//admin" is sent literally without URI normalization
            val code = rawUpgradeStatusCode("localhost", server.port(), "/ws//admin")
            // PathNormalizer collapses the duplicate slash; denyAll + anonymous → 401
            assertThat(code).isEqualTo(401)
        }
    }

    // ── path normalization: context path ──────────────────────────────────────

    @Test
    fun `authorization rule matches after context path is stripped from the request path`() {
        JavalinTest.test(
            Javalin.create { cfg ->
                cfg.router.contextPath = "/ctx"
                cfg.security {
                    ws {
                        authorizeRequests { authorize("/ws/**", authenticated) }
                        authenticationManager = headerAuthManager
                    }
                }
                cfg.routes.ws("/ws/chat") { }
            },
        ) { _, client ->
            // anonymous → 401: rule matched after context path stripped (/ctx/ws/chat → /ws/chat)
            val (_, anonCode) = tryConnect(client.origin, "/ctx/ws/chat")
            assertThat(anonCode).isEqualTo(401)

            // authenticated → connected: same normalization, rule matched and grants access
            val (connected, _) = tryConnect(client.origin, "/ctx/ws/chat", "X-User" to "alice")
            assertThat(connected).isTrue()
        }
    }

    // ── allowedOrigins: disallowed Origin ─────────────────────────────────────

    @Test
    fun `allowedOrigins - upgrade with disallowed Origin is rejected with 403`() {
        JavalinTest.test(
            Javalin.create { cfg ->
                cfg.security {
                    ws {
                        authorizeRequests { anyRequest = permitAll }
                        allowedOrigins = listOf("https://allowed.example.com")
                    }
                }
                cfg.routes.ws("/ws/chat") { }
            },
        ) { server, _ ->
            val code = rawUpgradeStatusCode(
                "localhost", server.port(), "/ws/chat",
                mapOf("Origin" to "https://evil.example.com"),
            )
            assertThat(code).isEqualTo(403)
        }
    }

    // ── allowedOrigins: missing Origin ────────────────────────────────────────

    @Test
    fun `allowedOrigins - upgrade without Origin header is rejected with 403`() {
        JavalinTest.test(
            Javalin.create { cfg ->
                cfg.security {
                    ws {
                        authorizeRequests { anyRequest = permitAll }
                        allowedOrigins = listOf("https://allowed.example.com")
                    }
                }
                cfg.routes.ws("/ws/chat") { }
            },
        ) { server, _ ->
            // raw upgrade with no Origin header at all
            val code = rawUpgradeStatusCode("localhost", server.port(), "/ws/chat")
            assertThat(code).isEqualTo(403)
        }
    }

    // ── allowedOrigins: allowed Origin ────────────────────────────────────────

    @Test
    fun `allowedOrigins - upgrade with allowed Origin is accepted`() {
        JavalinTest.test(
            Javalin.create { cfg ->
                cfg.security {
                    ws {
                        authorizeRequests { anyRequest = permitAll }
                        allowedOrigins = listOf("https://allowed.example.com")
                    }
                }
                cfg.routes.ws("/ws/chat") { }
            },
        ) { server, _ ->
            // 101 Switching Protocols means the security guard allowed the upgrade through
            val code = rawUpgradeStatusCode(
                "localhost", server.port(), "/ws/chat",
                mapOf("Origin" to "https://allowed.example.com"),
            )
            assertThat(code).isEqualTo(101)
        }
    }

    // ── allowedOrigins: unset (backward compatibility) ────────────────────────

    @Test
    fun `allowedOrigins unset - any Origin is accepted (backward compatible)`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                ws {
                    authorizeRequests { anyRequest = permitAll }
                    // allowedOrigins NOT configured — no Origin check performed
                }
            }
            cfg.routes.ws("/ws/chat") { }
        },
    ) { _, client ->
        val (connected, _) = tryConnect(client.origin, "/ws/chat")
        assertThat(connected).isTrue()
    }

    // ── allowedOrigins: fires before authentication ───────────────────────────

    @Test
    fun `allowedOrigins - Origin check fires before authentication even with valid credentials`() {
        JavalinTest.test(
            Javalin.create { cfg ->
                cfg.security {
                    ws {
                        authorizeRequests { anyRequest = authenticated }
                        allowedOrigins = listOf("https://allowed.example.com")
                        authenticationManager = headerAuthManager
                    }
                }
                cfg.routes.ws("/ws/chat") { }
            },
        ) { server, _ ->
            // Valid credentials in X-User header, but the disallowed Origin is checked first
            val code = rawUpgradeStatusCode(
                "localhost", server.port(), "/ws/chat",
                mapOf("Origin" to "https://evil.example.com", "X-User" to "alice"),
            )
            assertThat(code).isEqualTo(403)
        }
    }

    // ── allowedOrigins: configuration validation ──────────────────────────────

    @Test
    fun `allowedOrigins - empty collection is rejected at configuration time`() {
        assertThatThrownBy {
            javalinSecurity {
                ws {
                    allowedOrigins = emptyList()
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("empty")
    }

    @Test
    fun `allowedOrigins - collection containing blank entries is rejected at configuration time`() {
        assertThatThrownBy {
            javalinSecurity {
                ws {
                    allowedOrigins = listOf("https://ok.example.com", "  ")
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("blank")
    }

    @Test
    fun `allowedOrigins - setting it twice is rejected at configuration time`() {
        assertThatThrownBy {
            javalinSecurity {
                ws {
                    allowedOrigins = listOf("https://first.example.com")
                    allowedOrigins = listOf("https://second.example.com")
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("allowedOrigins")
    }

    // ── allowedOrigins: custom accessDeniedHandler ────────────────────────────

    @Test
    fun `allowedOrigins - custom accessDeniedHandler is invoked when Origin is disallowed`() {
        JavalinTest.test(
            Javalin.create { cfg ->
                cfg.security {
                    ws {
                        authorizeRequests { anyRequest = permitAll }
                        allowedOrigins = listOf("https://allowed.example.com")
                        accessDeniedHandler = { ctx, _ ->
                            ctx.status(403).result("custom-origin-denied")
                        }
                    }
                }
                cfg.routes.ws("/ws/chat") { }
            },
        ) { server, _ ->
            val code = rawUpgradeStatusCode(
                "localhost", server.port(), "/ws/chat",
                mapOf("Origin" to "https://evil.example.com"),
            )
            assertThat(code).isEqualTo(403)
        }
    }

    // ── {param} placeholder does not match concrete paths ────────────────────

    @Test
    fun `authorize pattern with param placeholder does not match a concrete request path`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                ws {
                    // Intentionally mis-written with {id}: AntPathMatcher treats { and } as
                    // literal characters, so this rule will NOT match /ws/room/5.
                    // Use wildcards instead: /ws/room/* or /ws/**
                    authorizeRequests {
                        authorize("/ws/room/{id}", permitAll)
                        // no anyRequest — deny-by-default catches everything else
                    }
                }
            }
            cfg.routes.ws("/ws/room/{id}") { }
        },
    ) { _, client ->
        // {id} is a literal in AntPathMatcher; /ws/room/5 matches no rule → deny-by-default
        val (connected, code) = tryConnect(client.origin, "/ws/room/5")
        assertThat(connected).isFalse()
        // anonymous caller → 401 (deny-by-default)
        assertThat(code).isEqualTo(401)
    }

    @Test
    fun `authorize pattern with wildcard correctly matches concrete request path`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                ws {
                    // Correctly written with a wildcard
                    authorizeRequests { authorize("/ws/room/*", permitAll) }
                }
            }
            cfg.routes.ws("/ws/room/{id}") { }
        },
    ) { _, client ->
        val (connected, _) = tryConnect(client.origin, "/ws/room/5")
        assertThat(connected).isTrue()
    }

}
