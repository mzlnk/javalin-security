package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.javalin.Javalin
import io.javalin.http.HandlerType.GET
import io.javalin.http.UnauthorizedResponse
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JavalinSecurityCustomHandlersKtTest {

    private enum class Role : RouteRole { ADMIN }

    private val headerAuthenticator = Authenticator { context ->
        when (val user = context.header("X-User")) {
            null -> AuthenticationResult.NotAuthenticated
            "invalid" -> AuthenticationResult.Failure(message = "super secret internal reason")
            else -> AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user)))
        }
    }

    @Test
    fun `should authenticate with a custom authenticator when one is provided`() {
        // given
        val alwaysBob = Authenticator {
            AuthenticationResult.Success(Authentication.authenticated(TestPrincipal("bob")))
        }
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/v1/*", GET, r.authenticated) }
                    http.authenticationStrategy = authenticationStrategy(alwaysBob)
                }
            }
            cfg.routes.get("/api/v1/me") { it.result(it.principal<TestPrincipal>()!!.name) }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/me")

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("bob")
        }
    }

    @Test
    fun `should emit a custom challenge when a custom unauthorizedHandler is configured`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/v1/*", GET, r.authenticated) }
                    http.authenticationStrategy = authenticationStrategy(
                        unauthorizedHandler = { ctx, _ ->
                            ctx.header("WWW-Authenticate", "Bearer")
                            throw UnauthorizedResponse()
                        },
                    )
                }
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/resource")

            // then
            assertThat(response.code).isEqualTo(401)
            assertThat(response.headers().get("WWW-Authenticate")).contains("Bearer")
        }
    }

    @Test
    fun `should render a custom response when a custom forbiddenHandler is configured`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/v1/*", GET, r.hasRole(Role.ADMIN)) }
                    http.authenticationStrategy = authenticationStrategy(
                        authenticator = headerAuthenticator,
                        forbiddenHandler = { _, _ ->
                            throw io.javalin.http.ForbiddenResponse("custom denied")
                        },
                    )
                }
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/resource") { it.header("X-User", "bob") }

            // then
            assertThat(response.code).isEqualTo(403)
            assertThat(response.body.string()).contains("custom denied")
        }
    }

    @Test
    fun `should not leak the authenticator failure message when authentication fails`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/v1/*", GET, r.allow) }
                    http.authenticationStrategy = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/resource") { it.header("X-User", "invalid") }

            // then
            assertThat(response.code).isEqualTo(401)
            assertThat(response.body.string()).doesNotContain("super secret internal reason")
        }
    }

    @Test
    fun `should not run the route handler when a custom unauthorizedHandler renders without throwing`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/v1/*", GET, r.authenticated) }
                    http.authenticationStrategy = authenticationStrategy(
                        unauthorizedHandler = { ctx, _ -> ctx.status(401).result("denied-without-throwing") },
                    )
                }
            }
            cfg.routes.get("/api/v1/resource") { it.result("protected-content") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/resource")

            // then
            assertThat(response.code).isEqualTo(401)
            val body = response.body.string()
            assertThat(body).isEqualTo("denied-without-throwing")
            assertThat(body).doesNotContain("protected-content")
        }
    }

    @Test
    fun `should not run the route handler when a custom forbiddenHandler renders without throwing`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/v1/*", GET, r.hasRole(Role.ADMIN)) }
                    http.authenticationStrategy = authenticationStrategy(
                        authenticator = headerAuthenticator,
                        forbiddenHandler = { ctx, _ -> ctx.status(403).result("forbidden-without-throwing") },
                    )
                }
            }
            cfg.routes.get("/api/v1/resource") { it.result("protected-content") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/resource") { it.header("X-User", "bob") }

            // then
            assertThat(response.code).isEqualTo(403)
            val body = response.body.string()
            assertThat(body).isEqualTo("forbidden-without-throwing")
            assertThat(body).doesNotContain("protected-content")
        }
    }

    @Test
    fun `should run the route handler after the guard grants access to an authenticated caller`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/v1/*", GET, r.authenticated) }
                    http.authenticationStrategy = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.get("/api/v1/resource") { ctx ->
                // Route handler: only reachable when the security guard grants access
                ctx.result((ctx.authentication().identity as TestPrincipal).name)
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/resource") { it.header("X-User", "alice") }

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice")
        }
    }
}
