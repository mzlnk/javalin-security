package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.github.mzlnk.javalin.security.identity
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JwtSecurityTest {
    private enum class Role : RouteRole { ADMIN, USER }

    private val roleOf: (String) -> RouteRole? = { name -> Role.entries.find { it.name == name } }

    private val testDecoder = JwtDecoder { token, _ ->
        if (token == "INVALID") throw IllegalArgumentException("bad token")
        SimpleDecodedJwt(
            subject = token,
            claims = mapOf("sub" to token, "roles" to listOf("USER")),
        )
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
    fun `should return 401 when authenticated route is hit without a token`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when / then
            assertThat(client.post("/protected/data", "").code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 401 when a denied route is hit even without a token`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when / then
            assertThat(client.get("/admin/dashboard").code).isEqualTo(401)
        }
    }

    @Test
    fun `should allow access when authenticated route is hit with a valid bearer token`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "") { it.header("Authorization", "Bearer alice") }

            // then
            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should return 401 when the decoder throws for an invalid token`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "") { it.header("Authorization", "Bearer INVALID") }

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
            val response = client.get("/admin/dashboard") { it.header("Authorization", "Bearer bob") }

            // then
            assertThat(response.code).isEqualTo(403)
        }
    }

    @Test
    fun `should allow access when caller holds required role`() {
        // given
        val adminDecoder = JwtDecoder { token, _ ->
            SimpleDecodedJwt(subject = token, claims = mapOf("roles" to listOf("ADMIN")))
        }
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
                security.http.authentication = jwt { jwt ->
                    jwt.decoder = adminDecoder
                    jwt.keySource = JwtKeySource.secret("test-secret")
                    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", roleOf)
                }
            }
            cfg.routes.get("/admin/dashboard") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/admin/dashboard") { it.header("Authorization", "Bearer admin-user") }

            // then
            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should expose JwtIdentity on the context when the caller is authenticated`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = jwt { jwt ->
                    jwt.decoder = testDecoder
                    jwt.keySource = JwtKeySource.secret("test-secret")
                }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx ->
                val identity = ctx.identity<JwtIdentity>()
                ctx.result(identity.name)
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/me") { it.header("Authorization", "Bearer alice") }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice")
        }
    }

    @Test
    fun `should include WWW-Authenticate header when bearerChallenge is enabled and token is absent`() {
        // given
        val app = app(bearerChallenge = true)

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "")

            // then
            assertThat(response.code).isEqualTo(401)
            val wwwAuthenticate = response.headers().get("WWW-Authenticate")?.firstOrNull()
            assertThat(wwwAuthenticate).startsWith("Bearer realm=\"TestAPI\"")
        }
    }

    @Test
    fun `should include an error attribute in WWW-Authenticate when the token is invalid`() {
        // given
        val app = app(bearerChallenge = true)

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "") {
                it.header("Authorization", "Bearer INVALID")
            }

            // then
            assertThat(response.code).isEqualTo(401)
            val wwwAuthenticate = response.headers().get("WWW-Authenticate")?.firstOrNull()
            assertThat(wwwAuthenticate).contains("error=\"invalid_token\"")
        }
    }

    @Test
    fun `should NOT include WWW-Authenticate header when bearerChallenge is disabled`() {
        // given
        val app = app(bearerChallenge = false)

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "")

            // then
            assertThat(response.code).isEqualTo(401)
            assertThat(response.headers().get("WWW-Authenticate")).isNull()
        }
    }

    @Test
    fun `should authenticate from a cookie when tokenResolver is set to cookie-based resolution`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = jwt { jwt ->
                    jwt.decoder = testDecoder
                    jwt.keySource = JwtKeySource.secret("test-secret")
                    jwt.tokenResolver = TokenResolver.cookie("access_token")
                }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx ->
                val identity = ctx.identity<JwtIdentity>()
                ctx.result(identity.name)
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/me") { it.header("Cookie", "access_token=alice") }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice")
        }
    }

    @Test
    fun `should return 401 when tokenResolver is cookie-based and the cookie is absent`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = jwt { jwt ->
                    jwt.decoder = testDecoder
                    jwt.keySource = JwtKeySource.secret("test-secret")
                    jwt.tokenResolver = TokenResolver.cookie("access_token")
                }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/me") { it.header("Authorization", "Bearer alice") }

            // then
            assertThat(response.code).isEqualTo(401)
        }
    }

    private fun app(bearerChallenge: Boolean = false): Javalin = Javalin.create { cfg ->
        cfg.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.post("/protected/*", Rules.authenticated())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = jwt { jwt ->
                jwt.decoder = testDecoder
                jwt.keySource = JwtKeySource.secret("test-secret-not-actually-used-by-test-double")
                jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", roleOf)
                jwt.bearerChallenge = bearerChallenge
                jwt.realm = "TestAPI"
            }
            security.http.fallback = Rules.deny()
        }
        cfg.routes.get("/public/info") { it.result("public") }
        cfg.routes.post("/protected/data") { it.result("created") }
        cfg.routes.get("/admin/dashboard") { it.result("dashboard") }
    }
}
