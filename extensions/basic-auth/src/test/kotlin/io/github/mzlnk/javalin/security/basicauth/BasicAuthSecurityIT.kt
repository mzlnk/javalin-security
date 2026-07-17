package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.principal
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.http.HandlerType.GET
import io.javalin.http.HandlerType.POST
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Integration tests for the `basicAuth {}` DSL wired through `config.security { http { basicAuth { } } }`.
 */
class BasicAuthSecurityIT {

    private val testUserLookup = UserLookup { username ->
        when (username) {
            "alice" -> BasicUser(username = "alice", password = "alice-pw", authorities = setOf("USER"))
            "admin" -> BasicUser(username = "admin", password = "admin-pw", authorities = setOf("ADMIN"))
            else -> null
        }
    }

    private fun basicHeader(username: String, password: String): String =
        "Basic " + Base64.getEncoder().encodeToString("$username:$password".toByteArray())

    private fun app(basicChallenge: Boolean = false): Javalin = Javalin.create { cfg ->
        cfg.security {
            http {
                basicAuth {
                    userLookup = testUserLookup
                    this.basicChallenge = basicChallenge
                    realm = "TestAPI"
                }
                authorizeRequests {
                    authorize("/public/**", GET, permitAll)
                    authorize("/protected/**", POST, authenticated)
                    authorize("/admin/**", GET, hasAuthority("ADMIN"))
                    anyRequest = denyAll
                }
            }
        }
        cfg.routes.get("/public/info") { it.result("public") }
        cfg.routes.post("/protected/data") { it.result("created") }
        cfg.routes.get("/admin/dashboard") { it.result("dashboard") }
    }

    // ── Anonymous access ──────────────────────────────────────────────────────

    @Test
    fun `should allow anonymous access to permitAll route`() = JavalinTest.test(app()) { _, client ->
        assertThat(client.get("/public/info").code).isEqualTo(200)
    }

    @Test
    fun `should return 401 when authenticated route is hit without credentials`() = JavalinTest.test(app()) { _, client ->
        assertThat(client.post("/protected/data", "").code).isEqualTo(401)
    }

    @Test
    fun `should return 401 on denyAll route even without credentials`() = JavalinTest.test(app()) { _, client ->
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

    // ── Authority-based access ────────────────────────────────────────────────

    @Test
    fun `should return 403 when authenticated caller lacks required authority`() = JavalinTest.test(app()) { _, client ->
        // "alice" has USER, not ADMIN
        val response = client.get("/admin/dashboard") { it.header("Authorization", basicHeader("alice", "alice-pw")) }
        assertThat(response.code).isEqualTo(403)
    }

    @Test
    fun `should allow access when caller holds required authority`() = JavalinTest.test(app()) { _, client ->
        val response = client.get("/admin/dashboard") { it.header("Authorization", basicHeader("admin", "admin-pw")) }
        assertThat(response.code).isEqualTo(200)
    }

    // ── Principal access from route handler ───────────────────────────────────

    @Test
    fun `should expose BasicAuthPrincipal on context with correct username`() {
        val accessibleApp = Javalin.create { cfg ->
            cfg.security {
                http {
                    basicAuth { userLookup = testUserLookup }
                    authorizeRequests { anyRequest = authenticated }
                }
            }
            cfg.routes.get("/me") { ctx ->
                val principal = ctx.principal<BasicAuthPrincipal>()
                ctx.result(principal.name)
            }
        }
        JavalinTest.test(accessibleApp) { _, client ->
            val response = client.get("/me") { it.header("Authorization", basicHeader("alice", "alice-pw")) }
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body!!.string()).isEqualTo("alice")
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
            cfg.security {
                http {
                    basicAuth {
                        userLookup = testUserLookup
                        credentialsResolver = BasicCredentialsResolver.basicHeader("X-Custom-Auth")
                    }
                    authorizeRequests { anyRequest = authenticated }
                }
            }
            cfg.routes.get("/me") { ctx ->
                val principal = ctx.principal<BasicAuthPrincipal>()
                ctx.result(principal.name)
            }
        }
        JavalinTest.test(customApp) { _, client ->
            val response = client.get("/me") { it.header("X-Custom-Auth", basicHeader("alice", "alice-pw")) }
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body!!.string()).isEqualTo("alice")
        }
    }

    // ── DSL validation ────────────────────────────────────────────────────────

    @Test
    fun `should throw SecurityConfigurationException when userLookup is not configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security {
                    http {
                        basicAuth {
                            // userLookup not set — should fail
                        }
                        authorizeRequests { anyRequest = permitAll }
                    }
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("userLookup")
    }

}
