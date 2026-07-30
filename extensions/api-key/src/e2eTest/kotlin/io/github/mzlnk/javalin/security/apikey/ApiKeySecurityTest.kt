package io.github.mzlnk.javalin.security.apikey

import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.identity
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ApiKeySecurityTest {
    private enum class Role : RouteRole { USER, ADMIN }

    private data class Client(
        override val name: String,
        override val roles: Set<RouteRole> = emptySet(),
    ) : Identity

    private val testApiKeyLookup = ApiKeyLookup { rawKey ->
        when (rawKey) {
            "k-alice" -> Client(name = "alice-svc", roles = setOf(Role.USER))
            "k-admin" -> Client(name = "admin-svc", roles = setOf(Role.ADMIN))
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
    fun `should return 401 when authenticated route is hit without api key`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when / then
            assertThat(client.post("/protected/data", "").code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 401 when a denied route is hit even without api key`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when / then
            assertThat(client.get("/admin/dashboard").code).isEqualTo(401)
        }
    }

    @Test
    fun `should allow access when authenticated route is hit with valid api key`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "") { it.header("X-Api-Key", "k-alice") }

            // then
            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should return 401 when api key is unknown`() {
        // given
        val app = app()

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.post("/protected/data", "") { it.header("X-Api-Key", "k-nobody") }

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
            val response = client.get("/admin/dashboard") { it.header("X-Api-Key", "k-alice") }

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
            val response = client.get("/admin/dashboard") { it.header("X-Api-Key", "k-admin") }

            // then
            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should expose the user-defined identity on the context when the caller is authenticated`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = apiKey { api -> api.lookup = testApiKeyLookup }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx ->
                val identity = ctx.identity<Client>()
                ctx.result(identity.name)
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/me") { it.header("X-Api-Key", "k-alice") }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice-svc")
        }
    }

    @Test
    fun `should authenticate from a custom header when resolver is set to a custom header`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = apiKey { api ->
                    api.lookup = testApiKeyLookup
                    api.resolver = ApiKeyResolver.header("X-App-Key")
                }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx ->
                val identity = ctx.identity<Client>()
                ctx.result(identity.name)
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/me") { it.header("X-App-Key", "k-alice") }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice-svc")
        }
    }

    @Test
    fun `should authenticate from a query parameter when resolver is set to query`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = apiKey { api ->
                    api.lookup = testApiKeyLookup
                    api.resolver = ApiKeyResolver.query("api_key")
                }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx ->
                val identity = ctx.identity<Client>()
                ctx.result(identity.name)
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/me?api_key=k-alice")

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice-svc")
        }
    }

    @Test
    fun `should use custom unauthorizedHandler when configured`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = apiKey { api ->
                    api.lookup = testApiKeyLookup
                    api.unauthorizedHandler = UnauthorizedHandler { ctx, _ ->
                        ctx.status(401).result("""{"error":"invalid_api_key"}""")
                    }
                }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx -> ctx.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/me") { it.header("X-Api-Key", "k-nobody") }

            // then
            assertThat(response.code).isEqualTo(401)
            assertThat(response.body.string()).contains("invalid_api_key")
        }
    }

    private fun app(): Javalin = Javalin.create { cfg ->
        cfg.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.post("/protected/*", Rules.authenticated())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = apiKey { api ->
                api.lookup = testApiKeyLookup
            }
            security.http.fallback = Rules.deny()
        }
        cfg.routes.get("/public/info") { it.result("public") }
        cfg.routes.post("/protected/data") { it.result("created") }
        cfg.routes.get("/admin/dashboard") { it.result("dashboard") }
    }
}
