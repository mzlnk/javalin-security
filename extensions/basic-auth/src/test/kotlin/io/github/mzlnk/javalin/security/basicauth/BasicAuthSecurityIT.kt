package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.principal
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.http.HandlerType.GET
import io.javalin.http.HandlerType.POST
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Integration tests for the `basicAuth { }` scheme factory assigned via `http.authentication = basicAuth { }`.
 */
class BasicAuthSecurityIT {

    private enum class Role : RouteRole { USER, ADMIN }

    private val testUserLookup = UserLookup { username ->
        when (username) {
            "alice" -> BasicUser(username = "alice", password = "alice-pw", roles = setOf(Role.USER))
            "admin" -> BasicUser(username = "admin", password = "admin-pw", roles = setOf(Role.ADMIN))
            else -> null
        }
    }

    private fun basicHeader(username: String, password: String): String =
        "Basic " + Base64.getEncoder().encodeToString("$username:$password".toByteArray())

    private fun app(basicChallenge: Boolean = false): Javalin = Javalin.create { cfg ->
        cfg.security { security ->
            security.http { http ->
                http.authenticationStrategy = basicAuth { basic ->
                    basic.userLookup = testUserLookup
                    basic.basicChallenge = basicChallenge
                    basic.realm = "TestAPI"
                }
                http.rules { r ->
                    r.add("/public/*", GET, r.allow)
                    r.add("/protected/*", POST, r.authenticated)
                    r.add("/admin/*", GET, r.hasRole(Role.ADMIN))
                    r.fallback = r.deny
                }
            }
        }
        cfg.routes.get("/public/info") { it.result("public") }
        cfg.routes.post("/protected/data") { it.result("created") }
        cfg.routes.get("/admin/dashboard") { it.result("dashboard") }
    }

    // ── Anonymous access ──────────────────────────────────────────────────────

    @Test
    fun `should allow anonymous access to allow route`() = JavalinTest.test(app()) { _, client ->
        assertThat(client.get("/public/info").code).isEqualTo(200)
    }

    @Test
    fun `should return 401 when authenticated route is hit without credentials`() = JavalinTest.test(app()) { _, client ->
        assertThat(client.post("/protected/data", "").code).isEqualTo(401)
    }

    @Test
    fun `should return 401 on deny route even without credentials`() = JavalinTest.test(app()) { _, client ->
        assertThat(client.get("/admin/dashboard").code).isEqualTo(401)
    }

    // ── Authenticated access ──────────────────────────────────────────────────

    @Test
    fun `should allow access with valid credentials on authenticated route`() = JavalinTest.test(app()) { _, client ->
        val response = client.post("/protected/data", "") { it.header("Authorization", basicHeader("alice", "alice-pw")) }
        assertThat(response.code).isEqualTo(200)
    }

    // ── Failure: bad credentials ──────────────────────────────────────────────

    @Test
    fun `should return 401 when username is unknown`() = JavalinTest.test(app()) { _, client ->
        val response = client.post("/protected/data", "") { it.header("Authorization", basicHeader("nobody", "whatever")) }
        assertThat(response.code).isEqualTo(401)
    }

    @Test
    fun `should return 401 when password is wrong`() = JavalinTest.test(app()) { _, client ->
        val response = client.post("/protected/data", "") { it.header("Authorization", basicHeader("alice", "wrong-pw")) }
        assertThat(response.code).isEqualTo(401)
    }

    @Test
    fun `should return 401 when credentials are malformed`() = JavalinTest.test(app()) { _, client ->
        val response = client.post("/protected/data", "") { it.header("Authorization", "Basic not-valid-base64!!!") }
        assertThat(response.code).isEqualTo(401)
    }

    // ── Role-based access ──────────────────────────────────────────────────────

    @Test
    fun `should return 403 when authenticated caller lacks required role`() = JavalinTest.test(app()) { _, client ->
        // "alice" has USER, not ADMIN
        val response = client.get("/admin/dashboard") { it.header("Authorization", basicHeader("alice", "alice-pw")) }
        assertThat(response.code).isEqualTo(403)
    }

    @Test
    fun `should allow access when caller holds required role`() = JavalinTest.test(app()) { _, client ->
        val response = client.get("/admin/dashboard") { it.header("Authorization", basicHeader("admin", "admin-pw")) }
        assertThat(response.code).isEqualTo(200)
    }

    // ── Principal access from route handler ───────────────────────────────────

    @Test
    fun `should expose BasicAuthPrincipal on context with correct username`() {
        val accessibleApp = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.authenticationStrategy = basicAuth { basic -> basic.userLookup = testUserLookup }
                    http.rules { r -> r.fallback = r.authenticated }
                }
            }
            cfg.routes.get("/me") { ctx ->
                val principal = ctx.principal<BasicAuthPrincipal>()!!
                ctx.result(principal.name)
            }
        }
        JavalinTest.test(accessibleApp) { _, client ->
            val response = client.get("/me") { it.header("Authorization", basicHeader("alice", "alice-pw")) }
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice")
        }
    }

    // ── Basic challenge ───────────────────────────────────────────────────────

    @Test
    fun `should include WWW-Authenticate header when basicChallenge is enabled and credentials are absent`() =
        JavalinTest.test(app(basicChallenge = true)) { _, client ->
            val response = client.post("/protected/data", "")
            assertThat(response.code).isEqualTo(401)
            val wwwAuthenticate = response.headers().get("WWW-Authenticate")?.firstOrNull()
            assertThat(wwwAuthenticate).startsWith("""Basic realm="TestAPI"""")
        }

    @Test
    fun `should include WWW-Authenticate header when basicChallenge is enabled and credentials are invalid`() =
        JavalinTest.test(app(basicChallenge = true)) { _, client ->
            val response = client.post("/protected/data", "") {
                it.header("Authorization", basicHeader("alice", "wrong-pw"))
            }
            assertThat(response.code).isEqualTo(401)
            val wwwAuthenticate = response.headers().get("WWW-Authenticate")?.firstOrNull()
            assertThat(wwwAuthenticate).startsWith("""Basic realm="TestAPI"""")
        }

    @Test
    fun `should NOT include WWW-Authenticate header when basicChallenge is disabled`() =
        JavalinTest.test(app(basicChallenge = false)) { _, client ->
            val response = client.post("/protected/data", "")
            assertThat(response.code).isEqualTo(401)
            assertThat(response.headers().get("WWW-Authenticate")).isNull()
        }

    // ── Custom credentialsResolver ────────────────────────────────────────────

    @Test
    fun `should authenticate from a custom header when credentialsResolver is set to a custom header`() {
        val customApp = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.authenticationStrategy = basicAuth { basic ->
                        basic.userLookup = testUserLookup
                        basic.credentialsResolver = BasicCredentialsResolver.basicHeader("X-Custom-Auth")
                    }
                    http.rules { r -> r.fallback = r.authenticated }
                }
            }
            cfg.routes.get("/me") { ctx ->
                val principal = ctx.principal<BasicAuthPrincipal>()!!
                ctx.result(principal.name)
            }
        }
        JavalinTest.test(customApp) { _, client ->
            val response = client.get("/me") { it.header("X-Custom-Auth", basicHeader("alice", "alice-pw")) }
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice")
        }
    }

    // ── Config validation ─────────────────────────────────────────────────────

    @Test
    fun `should throw SecurityConfigurationException when userLookup is not configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security { security ->
                    security.http { http ->
                        http.authenticationStrategy = basicAuth { basic ->
                            // userLookup not set — should fail
                        }
                        http.rules { r -> r.fallback = r.allow }
                    }
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("userLookup")
    }

}
