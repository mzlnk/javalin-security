package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationProvider
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.Javalin
import io.javalin.http.HandlerType.GET
import io.javalin.http.HandlerType.POST
import io.javalin.http.UnauthorizedResponse
import io.javalin.http.staticfiles.Location
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.http.HttpResponse
import java.net.http.HttpClient as JdkHttpClient
import java.net.http.HttpRequest as JdkHttpRequest

class JavalinSecurityHardeningIT {

    private val headerProvider = AuthenticationProvider { context ->
        when (val user = context.header("X-User")) {
            null -> AuthenticationResult.NotAuthenticated
            "invalid" -> AuthenticationResult.Failure(message = "super secret internal reason")
            else -> AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user)))
        }
    }

    @Test
    fun `should treat HEAD like GET for a permitAll GET rule`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.configureSecurity(
                config {
                    authorizeRequests { authorize("/api/v1/**", GET, permitAll) }
                },
            )
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        },
    ) { _, client ->
        // when: a HEAD request to a GET-permitted route
        val request = JdkHttpRequest.newBuilder(URI.create(client.origin + "/api/v1/resource"))
            .method("HEAD", JdkHttpRequest.BodyPublishers.noBody())
            .build()
        val response = JdkHttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())

        // then: it is allowed just like the GET
        assertThat(response.statusCode()).isEqualTo(200)
    }

    @Test
    fun `should guard static files with deny-by-default`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.staticFiles.add("/public", Location.CLASSPATH)
            cfg.configureSecurity(
                config {
                    authorizeRequests { authorize("/api/v1/**", GET, permitAll) }
                },
            )
        },
    ) { _, client ->
        // when: a static file that matches no authorization rule
        val response = client.get("/secret.txt")

        // then: it is denied by default rather than served unguarded
        assertThat(response.code).isEqualTo(401)
        assertThat(response.body.string()).doesNotContain("top secret static content")
    }

    @Test
    fun `should serve a static file that is explicitly permitted`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.staticFiles.add("/public", Location.CLASSPATH)
            cfg.configureSecurity(
                config {
                    authorizeRequests { authorize("/**", GET, permitAll) }
                },
            )
        },
    ) { _, client ->
        // when
        val response = client.get("/secret.txt")

        // then
        assertThat(response.code).isEqualTo(200)
        assertThat(response.body.string()).contains("top secret static content")
    }

    @Test
    fun `should not be bypassed by a trailing slash`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.configureSecurity(
                config {
                    authorizeRequests {
                        authorize("/api/v1/admin", GET, denyAll)
                        authorize("/api/v1/**", GET, permitAll)
                    }
                },
            )
            cfg.routes.get("/api/v1/admin") { it.result("admin") }
            cfg.routes.get("/api/v1/public") { it.result("public") }
        },
    ) { _, client ->
        // when / then: the denied path is denied with or without the trailing slash
        assertThat(client.get("/api/v1/admin").code).isEqualTo(401)
        assertThat(client.get("/api/v1/admin/").code).isEqualTo(401)
        // and a genuinely permitted sibling still works
        assertThat(client.get("/api/v1/public").code).isEqualTo(200)
    }

    @Test
    fun `should try multiple providers in registration order`() = JavalinTest.test(
        Javalin.create { cfg ->
            val abstains = AuthenticationProvider { AuthenticationResult.NotAuthenticated }
            cfg.configureSecurity(
                config {
                    authorizeRequests { authorize("/api/v1/**", POST, authenticated) }
                    authenticationProvider(abstains)
                    authenticationProvider(headerProvider)
                },
            )
            cfg.routes.post("/api/v1/resource") { it.result("created") }
        },
    ) { _, client ->
        // when: the first provider abstains, the second authenticates
        val response = client.post("/api/v1/resource", null) { it.header("X-User", "bob") }

        // then
        assertThat(response.code).isEqualTo(200)
    }

    @Test
    fun `should use a custom authentication manager when provided`() = JavalinTest.test(
        Javalin.create { cfg ->
            val alwaysBob = AuthenticationManager {
                AuthenticationResult.Success(Authentication.authenticated(TestPrincipal("bob")))
            }
            cfg.configureSecurity(
                config {
                    authorizeRequests { authorize("/api/v1/**", GET, authenticated) }
                    authenticationManager(alwaysBob)
                },
            )
            cfg.routes.get("/api/v1/me") { it.result((it.principal() as TestPrincipal).name) }
        },
    ) { _, client ->
        // when
        val response = client.get("/api/v1/me")

        // then
        assertThat(response.code).isEqualTo(200)
        assertThat(response.body.string()).isEqualTo("bob")
    }

    @Test
    fun `should emit a challenge from a custom authentication entry point`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.configureSecurity(
                config {
                    authorizeRequests { authorize("/api/v1/**", GET, authenticated) }
                    authenticationEntryPoint { ctx, _ ->
                        ctx.header("WWW-Authenticate", "Bearer")
                        throw UnauthorizedResponse()
                    }
                },
            )
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        },
    ) { _, client ->
        // when: an anonymous caller hits an authenticated rule
        val response = client.get("/api/v1/resource")

        // then: the custom challenge header is present
        assertThat(response.code).isEqualTo(401)
        assertThat(response.headers().get("WWW-Authenticate")).contains("Bearer")
    }

    @Test
    fun `should render a custom access denied response`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.configureSecurity(
                config {
                    authorizeRequests { authorize("/api/v1/**", GET, hasRole("ADMIN")) }
                    accessDeniedHandler { ctx, _ ->
                        throw io.javalin.http.ForbiddenResponse("custom denied")
                    }
                    authenticationProvider(headerProvider)
                },
            )
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        },
    ) { _, client ->
        // when: an authenticated caller lacking the role
        val response = client.get("/api/v1/resource") { it.header("X-User", "bob") }

        // then
        assertThat(response.code).isEqualTo(403)
        assertThat(response.body.string()).contains("custom denied")
    }

    @Test
    fun `should not leak the provider failure message`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.configureSecurity(
                config {
                    authorizeRequests { authorize("/api/v1/**", GET, permitAll) }
                    authenticationProvider(headerProvider)
                },
            )
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        },
    ) { _, client ->
        // when: credentials are present but invalid
        val response = client.get("/api/v1/resource") { it.header("X-User", "invalid") }

        // then: the internal reason is never exposed to the client
        assertThat(response.code).isEqualTo(401)
        assertThat(response.body.string()).doesNotContain("super secret internal reason")
    }

    private fun config(init: io.github.mzlnk.javalin.security.http.HttpConfig.Dsl.() -> Unit): JavalinSecurityConfig =
        object : JavalinSecurityConfig {
            override val security = javalinSecurity { http(init) }
        }
}
