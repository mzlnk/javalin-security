package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authentication.PasswordCredentials
import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.identity
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Base64

class BasicAuthSecurityTest {
    private enum class Role : RouteRole { USER, ADMIN }

    private data class TestUser(
        override val name: String,
        override val roles: Set<RouteRole> = emptySet(),
    ) : Identity

    private val testUserLookup = UserLookup { username ->
        when (username) {
            "alice" -> PasswordCredentials(TestUser(name = "alice", roles = setOf(Role.USER)), encodedPassword = "alice-pw")
            "admin" -> PasswordCredentials(TestUser(name = "admin", roles = setOf(Role.ADMIN)), encodedPassword = "admin-pw")
            else -> null
        }
    }

    @Test
    fun `should allow anonymous access when route is allow`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when / then
            assertThat(client.get("/public/info").code).isEqualTo(200)
        }
    }

    @Test
    fun `should return 401 when authenticated route is hit without credentials`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when / then
            assertThat(client.post("/protected/data", "").code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 401 when a denied route is hit even without credentials`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when / then
            assertThat(client.get("/admin/dashboard").code).isEqualTo(401)
        }
    }

    @Test
    fun `should allow access when authenticated route is hit with valid credentials`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "") { it.header("Authorization", basicHeader("alice", "alice-pw")) }

            // then
            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should return 401 when username is unknown`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "") { it.header("Authorization", basicHeader("nobody", "whatever")) }

            // then
            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 401 when password is wrong`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "") { it.header("Authorization", basicHeader("alice", "wrong-pw")) }

            // then
            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 401 when credentials are malformed`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "") { it.header("Authorization", "Basic not-valid-base64!!!") }

            // then
            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 403 when authenticated caller lacks required role`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/admin/dashboard") { it.header("Authorization", basicHeader("alice", "alice-pw")) }

            // then
            assertThat(response.code).isEqualTo(403)
        }
    }

    @Test
    fun `should allow access when caller holds required role`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/admin/dashboard") { it.header("Authorization", basicHeader("admin", "admin-pw")) }

            // then
            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should expose the user-defined identity on the context when the caller is authenticated`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = basicAuth { basic -> basic.userLookup = testUserLookup }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx ->
                val identity = ctx.identity<TestUser>()
                ctx.result(identity.name)
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/me") { it.header("Authorization", basicHeader("alice", "alice-pw")) }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice")
        }
    }

    @Test
    fun `should include WWW-Authenticate header when basicChallenge is enabled and credentials are absent`() {
        // given
        val app = app(basicChallenge = true)

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "")

            // then
            assertThat(response.code).isEqualTo(401)
            val wwwAuthenticate = response.headers().get("WWW-Authenticate")?.firstOrNull()
            assertThat(wwwAuthenticate).startsWith("""Basic realm="TestAPI"""")
        }
    }

    @Test
    fun `should include WWW-Authenticate header when basicChallenge is enabled and credentials are invalid`() {
        // given
        val app = app(basicChallenge = true)

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "") {
                it.header("Authorization", basicHeader("alice", "wrong-pw"))
            }

            // then
            assertThat(response.code).isEqualTo(401)
            val wwwAuthenticate = response.headers().get("WWW-Authenticate")?.firstOrNull()
            assertThat(wwwAuthenticate).startsWith("""Basic realm="TestAPI"""")
        }
    }

    @Test
    fun `should NOT include WWW-Authenticate header when basicChallenge is disabled`() {
        // given
        val app = app(basicChallenge = false)

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "")

            // then
            assertThat(response.code).isEqualTo(401)
            assertThat(response.headers().get("WWW-Authenticate")).isNull()
        }
    }

    @Test
    fun `should authenticate from a custom header when credentialsResolver is set to a custom header`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = basicAuth { basic ->
                    basic.userLookup = testUserLookup
                    basic.credentialsResolver = BasicCredentialsResolver.basicHeader("X-Custom-Auth")
                }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx ->
                val identity = ctx.identity<TestUser>()
                ctx.result(identity.name)
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/me") { it.header("X-Custom-Auth", basicHeader("alice", "alice-pw")) }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice")
        }
    }

    private fun basicHeader(username: String, password: String): String =
        "Basic " + Base64.getEncoder().encodeToString("$username:$password".toByteArray())

    private fun app(basicChallenge: Boolean = false): Javalin = Javalin.create { cfg ->
        cfg.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.post("/protected/*", Rules.authenticated())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = basicAuth { basic ->
                basic.userLookup = testUserLookup
                basic.basicChallenge = basicChallenge
                basic.realm = "TestAPI"
            }
            security.http.fallback = Rules.deny()
        }
        cfg.routes.get("/public/info") { it.result("public") }
        cfg.routes.post("/protected/data") { it.result("created") }
        cfg.routes.get("/admin/dashboard") { it.result("dashboard") }
    }
}
