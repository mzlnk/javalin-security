package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.javalin.Javalin
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JavalinSecurityHttpKtTest {
    private enum class Role : RouteRole { ADMIN, USER }

    private val headerAuthenticator = Authenticator { context ->
        when (val user = context.header("X-User")) {
            null -> AuthenticationResult.NotAuthenticated
            "invalid" -> AuthenticationResult.Failure(message = "bad credentials")
            else -> {
                val roles = context.header("X-Roles")
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
    fun `should allow anonymous access when rule is allow`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/resource")

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("ok")
        }
    }

    @Test
    fun `should return 401 when authenticated rule is hit without credentials`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/api/v1/resource")

            // then
            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should allow access when authenticated rule is hit with credentials`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/api/v1/resource", null) { it.header("X-User", "bob") }

            // then
            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should return 401 when role protected rule is hit anonymously`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.delete("/api/v1/resource")

            // then
            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 403 when role protected rule is hit without the role`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.delete("/api/v1/resource", null) {
                it.header("X-User", "bob")
                it.header("X-Roles", "USER")
            }

            // then
            assertThat(response.code).isEqualTo(403)
        }
    }

    @Test
    fun `should allow access when role protected rule is hit with the role`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.delete("/api/v1/resource", null) {
                it.header("X-User", "admin")
                it.header("X-Roles", "ADMIN")
            }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("deleted")
        }
    }

    @Test
    fun `should return 401 when the authenticator reports a failure`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/api/v1/resource", null) { it.header("X-User", "invalid") }

            // then
            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should expose the authenticated identity on the context when the caller is authenticated`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/me") { it.header("X-User", "bob") }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("bob")
        }
    }

    @Test
    fun `should deny by default when no rule matches the route`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.rules.get("/api/v1/*", Rules.allow())
                security.http.authentication = authenticationStrategy(headerAuthenticator)
            }
            cfg.routes.get("/internal") { it.result("secret") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/internal")

            // then
            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should treat every request as anonymous when no authenticator is configured`() {
        // given
        val app = app(authenticator = null)

        JavalinTest.test(app) { _, client ->
            // when / then
            assertThat(client.get("/api/v1/resource").code).isEqualTo(200)
            assertThat(client.post("/api/v1/resource").code).isEqualTo(401)
        }
    }

    @Test
    fun `should deny HTTP routes by default when only ws is configured`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.ws.fallback = Rules.deny()
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/resource")

            // then
            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should deny HTTP routes by default when security has no further configuration`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/resource")

            // then
            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should grant access to anonymous callers when route declares the Anyone role`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.fallback = Rules.deny()
            }
            cfg.routes.get("/public", { it.result("ok") }, Anyone)
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/public")

            // then
            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should grant access when route declares roles and the caller holds a matching role`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = authenticationStrategy(headerAuthenticator)
                security.http.fallback = Rules.deny() // rule table must NOT be consulted
            }
            cfg.routes.get("/admin", { it.result("admin-ok") }, Role.ADMIN)
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/admin") {
                it.header("X-User", "alice")
                it.header("X-Roles", "ADMIN")
            }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("admin-ok")
        }
    }

    @Test
    fun `should deny access when route declares roles and the caller holds no matching role`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = authenticationStrategy(headerAuthenticator)
                security.http.fallback = Rules.allow() // even a permissive fallback must not apply
            }
            cfg.routes.get("/admin", { it.result("admin-ok") }, Role.ADMIN)
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/admin") {
                it.header("X-User", "alice")
                it.header("X-Roles", "USER")
            }

            // then
            assertThat(response.code).isEqualTo(403)
        }
    }

    @Test
    fun `should fall through to the pattern rule table when route declares no roles`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.rules.get("/plain", Rules.deny())
                security.http.authentication = authenticationStrategy(
                    Authenticator {
                        AuthenticationResult.Success(Authentication.authenticated(TestIdentity("alice"), setOf(Role.ADMIN)))
                    },
                )
            }
            cfg.routes.get("/plain") { it.result("ok") } // no roles declared
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/plain")

            // then
            assertThat(response.code).isEqualTo(403)
        }
    }

    private fun app(authenticator: Authenticator? = headerAuthenticator): Javalin =
        Javalin.create { cfg ->
            cfg.security { security ->
                security.rules.get("/api/v1/*", Rules.allow())
                security.rules.post("/api/v1/*", Rules.authenticated())
                security.rules.delete("/api/v1/*", Rules.hasRole(Role.ADMIN))
                authenticator?.let { security.http.authentication = authenticationStrategy(it) }
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
            cfg.routes.post("/api/v1/resource") { it.result("created") }
            cfg.routes.delete("/api/v1/resource") { it.result("deleted") }
            cfg.routes.get("/api/v1/me") { it.result(it.identity<TestIdentity>().name) }
        }

    @Test
    fun `should throw when identity is read for an anonymous caller`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.rules.get("/api/v1/*", Rules.allow())
                security.http.authentication = authenticationStrategy(headerAuthenticator)
            }
            cfg.routes.get("/api/v1/me") { ctx ->
                ctx.result(ctx.identity<TestIdentity>().name)
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/me")

            // then
            assertThat(response.code).isEqualTo(500)
        }
    }

    @Test
    fun `should return null from identityOrNull when the caller is anonymous`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.rules.get("/api/v1/*", Rules.allow())
                security.http.authentication = authenticationStrategy(headerAuthenticator)
            }
            cfg.routes.get("/api/v1/me") { ctx ->
                val identity = ctx.identityOrNull<TestIdentity>()
                ctx.result(identity?.name ?: "anonymous")
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/me")

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("anonymous")
        }
    }

    @Test
    fun `should return the identity from identityOrNull when the caller is authenticated`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.rules.get("/api/v1/*", Rules.allow())
                security.http.authentication = authenticationStrategy(headerAuthenticator)
            }
            cfg.routes.get("/api/v1/me") { ctx ->
                val identity = ctx.identityOrNull<TestIdentity>()
                ctx.result(identity?.name ?: "anonymous")
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/me") { it.header("X-User", "bob") }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("bob")
        }
    }
}
