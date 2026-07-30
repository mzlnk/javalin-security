package io.github.mzlnk.javalin.security.opaquetoken

import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.github.mzlnk.javalin.security.identity
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Instant

class OpaqueTokenSecurityTest {
    private enum class Role : RouteRole { USER, ADMIN }

    private data class Principal(
        override val name: String,
        override val roles: Set<RouteRole> = emptySet(),
    ) : Identity

    private val testTokenLookup = OpaqueTokenLookup { rawToken ->
        when (rawToken) {
            "t-alice" -> TokenRecord(Principal(name = "alice", roles = setOf(Role.USER)))
            "t-admin" -> TokenRecord(Principal(name = "admin", roles = setOf(Role.ADMIN)))
            "t-expired" -> TokenRecord(
                Principal(name = "expired-user", roles = setOf(Role.USER)),
                expiresAt = Instant.now().minusSeconds(60),
            )
            else -> null
        }
    }

    @Test
    fun `should allow anonymous access when route is allow`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            assertThat(client.get("/public/info").code).isEqualTo(200)
        }
    }

    @Test
    fun `should return 401 when authenticated route is hit without token`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            assertThat(client.post("/protected/data", "").code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 401 when a denied route is hit even without token`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            assertThat(client.get("/admin/dashboard").code).isEqualTo(401)
        }
    }

    @Test
    fun `should allow access when authenticated route is hit with valid token`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            val response = client.post("/protected/data", "") {
                it.header("Authorization", "Bearer t-alice")
            }

            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should return 401 when token is unknown`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            val response = client.post("/protected/data", "") {
                it.header("Authorization", "Bearer t-nobody")
            }

            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 401 when token is expired`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            val response = client.post("/protected/data", "") {
                it.header("Authorization", "Bearer t-expired")
            }

            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 403 when authenticated caller lacks required role`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            val response = client.get("/admin/dashboard") {
                it.header("Authorization", "Bearer t-alice")
            }

            assertThat(response.code).isEqualTo(403)
        }
    }

    @Test
    fun `should allow access when caller holds required role`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            val response = client.get("/admin/dashboard") {
                it.header("Authorization", "Bearer t-admin")
            }

            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should expose the user-defined identity on the context when the caller is authenticated`() {
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = opaqueToken { ot -> ot.lookup = testTokenLookup }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx ->
                val identity = ctx.identity<Principal>()
                ctx.result(identity.name)
            }
        }

        JavalinTest.test(app) { _, client ->
            val response = client.get("/me") { it.header("Authorization", "Bearer t-alice") }

            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice")
        }
    }

    @Test
    fun `should authenticate from a cookie when resolver is set to cookie`() {
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = opaqueToken { ot ->
                    ot.lookup = testTokenLookup
                    ot.resolver = TokenResolver.cookie("session")
                }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx ->
                val identity = ctx.identity<Principal>()
                ctx.result(identity.name)
            }
        }

        JavalinTest.test(app) { _, client ->
            val response = client.get("/me") { it.header("Cookie", "session=t-alice") }

            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice")
        }
    }

    @Test
    fun `should include WWW-Authenticate header when bearerChallenge is enabled and token is absent`() {
        val app = app(bearerChallenge = true)

        JavalinTest.test(app) { _, client ->
            val response = client.post("/protected/data", "")

            assertThat(response.code).isEqualTo(401)
            val wwwAuthenticate = response.headers().get("WWW-Authenticate")?.firstOrNull()
            assertThat(wwwAuthenticate).isEqualTo("Bearer realm=\"API\"")
        }
    }

    @Test
    fun `should include an error attribute in WWW-Authenticate when the token is invalid`() {
        val app = app(bearerChallenge = true)

        JavalinTest.test(app) { _, client ->
            val response = client.post("/protected/data", "") {
                it.header("Authorization", "Bearer t-nobody")
            }

            assertThat(response.code).isEqualTo(401)
            val wwwAuthenticate = response.headers().get("WWW-Authenticate")?.firstOrNull()
            assertThat(wwwAuthenticate).contains("error=\"invalid_token\"")
        }
    }

    @Test
    fun `should use custom unauthorizedHandler when configured`() {
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = opaqueToken { ot ->
                    ot.lookup = testTokenLookup
                    ot.unauthorizedHandler = UnauthorizedHandler { ctx, _ ->
                        ctx.status(401).result("""{"error":"invalid_token"}""")
                    }
                }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx -> ctx.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            val response = client.get("/me") { it.header("Authorization", "Bearer t-nobody") }

            assertThat(response.code).isEqualTo(401)
            assertThat(response.body.string()).contains("invalid_token")
        }
    }

    private fun app(bearerChallenge: Boolean = false): Javalin = Javalin.create { cfg ->
        cfg.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.post("/protected/*", Rules.authenticated())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = opaqueToken { ot ->
                ot.lookup = testTokenLookup
                ot.bearerChallenge = bearerChallenge
            }
            security.http.fallback = Rules.deny()
        }
        cfg.routes.get("/public/info") { it.result("public") }
        cfg.routes.post("/protected/data") { it.result("created") }
        cfg.routes.get("/admin/dashboard") { it.result("dashboard") }
    }
}
