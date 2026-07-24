package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.Javalin
import io.javalin.http.HandlerType.GET
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture

class JavalinSecurityAsyncAuthKtTest {

    @Test
    fun `should authenticate and allow access when an async authenticator succeeds`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/*", GET, r.authenticated) }
                    http.authentication = asyncAuthenticationStrategy(
                        { ctx ->
                            // Simulate I/O without blocking the request thread
                            CompletableFuture.supplyAsync {
                                val user = ctx.header("X-User")
                                if (user != null) {
                                    AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user)))
                                } else {
                                    AuthenticationResult.NotAuthenticated
                                }
                            }
                        },
                    )
                }
            }
            cfg.routes.get("/api/resource") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when / then
            assertThat(client.get("/api/resource").code).isEqualTo(401)
            assertThat(client.get("/api/resource") { it.header("X-User", "alice") }.code).isEqualTo(200)
        }
    }

    @Test
    fun `should deny access when an async authenticator reports a failure`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/*", GET, r.allow) }
                    http.authentication = asyncAuthenticationStrategy(
                        { _ ->
                            CompletableFuture.completedFuture(
                                AuthenticationResult.Failure("async credential failure"),
                            )
                        },
                    )
                }
            }
            cfg.routes.get("/api/resource") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/resource")

            // then
            assertThat(response.code).isEqualTo(401)
            assertThat(response.body.string()).doesNotContain("async credential failure")
        }
    }

    @Test
    fun `should not run the route handler when an async authenticator denies the request`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/*", GET, r.authenticated) }
                    http.authentication = asyncAuthenticationStrategy(
                        { _ -> CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) },
                    )
                }
            }
            cfg.routes.get("/api/resource") { it.result("protected-content") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/resource")

            // then
            assertThat(response.code).isEqualTo(401)
            assertThat(response.body.string()).doesNotContain("protected-content")
        }
    }

    @Test
    fun `should deny with 401 when an async authenticator future completes exceptionally`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/*", GET, r.allow) }
                    http.authentication = asyncAuthenticationStrategy(
                        { _ -> CompletableFuture.failedFuture(RuntimeException("internal IdP error")) },
                    )
                }
            }
            cfg.routes.get("/api/resource") { it.result("protected-content") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/resource")

            // then
            assertThat(response.code).isEqualTo(401)
            assertThat(response.body.string()).doesNotContain("protected-content")
            assertThat(response.body.string()).doesNotContain("internal IdP error")
        }
    }

    @Test
    fun `should deny with 401 when an async authenticator throws synchronously`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/*", GET, r.allow) }
                    http.authentication = asyncAuthenticationStrategy(
                        { _ -> throw IllegalStateException("sync crash in authenticator") },
                    )
                }
            }
            cfg.routes.get("/api/resource") { it.result("protected-content") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/resource")

            // then
            assertThat(response.code).isEqualTo(401)
            assertThat(response.body.string()).doesNotContain("protected-content")
            assertThat(response.body.string()).doesNotContain("sync crash in authenticator")
        }
    }
}
