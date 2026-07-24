package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.javalin.Javalin
import io.javalin.http.HandlerType.GET
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JavalinSecurityPathNormalizationKtTest {

    private val headerAuthenticator = Authenticator { context ->
        when (val user = context.header("X-User")) {
            null -> AuthenticationResult.NotAuthenticated
            "invalid" -> AuthenticationResult.Failure(message = "super secret internal reason")
            else -> AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user)))
        }
    }

    @Test
    fun `should keep denying a path when a trailing slash is added`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r ->
                        r.add("/api/v1/admin", GET, r.deny)
                        r.add("/api/v1/*", GET, r.allow)
                    }
                }
            }
            cfg.routes.get("/api/v1/admin") { it.result("admin") }
            cfg.routes.get("/api/v1/public") { it.result("public") }
        }

        JavalinTest.test(app) { _, client ->
            // when / then
            assertThat(client.get("/api/v1/admin").code).isEqualTo(401)
            assertThat(client.get("/api/v1/admin/").code).isEqualTo(401)
            // and a genuinely permitted sibling still works
            assertThat(client.get("/api/v1/public").code).isEqualTo(200)
        }
    }

    @Test
    fun `should authorize a parameterized route against the concrete request path`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/v1/users/{id}", GET, r.deny) }
                    http.authentication = authenticationStrategy(headerAuthenticator)
                }
            }
            cfg.routes.get("/api/v1/users/{id}") { it.result("user-${it.pathParam("id")}") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/api/v1/users/42") { it.header("X-User", "bob") }

            // then
            assertThat(response.code).isEqualTo(403)
            assertThat(response.body.string()).doesNotContain("user-42")
        }
    }
}
