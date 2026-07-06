package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.Javalin
import io.javalin.http.HandlerType.DELETE
import io.javalin.http.HandlerType.GET
import io.javalin.http.HandlerType.POST
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JavalinSecurityIT {

    /**
     * Test manager: authenticates when an `X-User` header is present, granting the authorities
     * listed (comma separated) in `X-Authorities`. A user named "invalid" simulates a bad credential.
     */
    private val headerManager = AuthenticationManager { context ->
        when (val user = context.header("X-User")) {
            null -> AuthenticationResult.NotAuthenticated
            "invalid" -> AuthenticationResult.Failure(message = "bad credentials")
            else -> {
                val authorities = context.header("X-Authorities")
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.filter { it.isNotEmpty() }
                    ?.toSet()
                    ?: emptySet()
                AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user), authorities))
            }
        }
    }

    private fun app(manager: AuthenticationManager? = headerManager): Javalin =
        Javalin.create { cfg ->
            cfg.security {
                http {
                    authorizeRequests {
                        authorize("/api/v1/**", GET, permitAll)
                        authorize("/api/v1/**", POST, authenticated)
                        authorize("/api/v1/**", DELETE, hasRole("ADMIN"))
                    }
                    manager?.let { authenticationManager = it }
                }
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
            cfg.routes.post("/api/v1/resource") { it.result("created") }
            cfg.routes.delete("/api/v1/resource") { it.result("deleted") }
            cfg.routes.get("/api/v1/me") { it.result((it.principal() as TestPrincipal).name) }
        }

    @Test
    fun `should allow anonymous access when rule is permitAll`() = JavalinTest.test(app()) { _, client ->
        // when
        val response = client.get("/api/v1/resource")

        // then
        assertThat(response.code).isEqualTo(200)
        assertThat(response.body.string()).isEqualTo("ok")
    }

    @Test
    fun `should return 401 when authenticated rule is hit without credentials`() = JavalinTest.test(app()) { _, client ->
        // when
        val response = client.post("/api/v1/resource")

        // then
        assertThat(response.code).isEqualTo(401)
    }

    @Test
    fun `should allow access when authenticated rule is hit with credentials`() = JavalinTest.test(app()) { _, client ->
        // when
        val response = client.post("/api/v1/resource", null) { it.header("X-User", "bob") }

        // then
        assertThat(response.code).isEqualTo(200)
    }

    @Test
    fun `should return 401 when role protected rule is hit anonymously`() = JavalinTest.test(app()) { _, client ->
        // when
        val response = client.delete("/api/v1/resource")

        // then
        assertThat(response.code).isEqualTo(401)
    }

    @Test
    fun `should return 403 when role protected rule is hit without the role`() = JavalinTest.test(app()) { _, client ->
        // when
        val response = client.delete("/api/v1/resource", null) {
            it.header("X-User", "bob")
            it.header("X-Authorities", "ROLE_USER")
        }

        // then
        assertThat(response.code).isEqualTo(403)
    }

    @Test
    fun `should allow access when role protected rule is hit with the role`() = JavalinTest.test(app()) { _, client ->
        // when
        val response = client.delete("/api/v1/resource", null) {
            it.header("X-User", "admin")
            it.header("X-Authorities", "ROLE_ADMIN")
        }

        // then
        assertThat(response.code).isEqualTo(200)
        assertThat(response.body.string()).isEqualTo("deleted")
    }

    @Test
    fun `should return 401 when provider reports a failure`() = JavalinTest.test(app()) { _, client ->
        // when
        val response = client.post("/api/v1/resource", null) { it.header("X-User", "invalid") }

        // then
        assertThat(response.code).isEqualTo(401)
    }

    @Test
    fun `should expose the authenticated principal on the context`() = JavalinTest.test(app()) { _, client ->
        // when
        val response = client.get("/api/v1/me") { it.header("X-User", "bob") }

        // then
        assertThat(response.code).isEqualTo(200)
        assertThat(response.body.string()).isEqualTo("bob")
    }

    @Test
    fun `should deny by default when no rule matches the route`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                http {
                    authorizeRequests {
                        authorize("/api/v1/**", GET, permitAll)
                    }
                    authenticationManager = headerManager
                }
            }
            cfg.routes.get("/internal") { it.result("secret") }
        },
    ) { _, client ->
        // when
        val response = client.get("/internal")

        // then
        assertThat(response.code).isEqualTo(401)
    }

    @Test
    fun `should treat every request as anonymous when no manager is configured`() = JavalinTest.test(
        app(manager = null),
    ) { _, client ->
        // when / then: permitAll succeeds, authenticated is rejected with 401
        assertThat(client.get("/api/v1/resource").code).isEqualTo(200)
        assertThat(client.post("/api/v1/resource").code).isEqualTo(401)
    }
}
