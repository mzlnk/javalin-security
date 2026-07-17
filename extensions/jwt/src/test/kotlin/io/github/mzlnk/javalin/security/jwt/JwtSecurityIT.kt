package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.github.mzlnk.javalin.security.principal
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.http.HandlerType.GET
import io.javalin.http.HandlerType.POST
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

/**
 * Integration tests for the `jwt {}` DSL wired through `config.security { http { jwt { } } }`.
 * The decoder is a test double that reads the raw token string directly as the subject.
 */
class JwtSecurityIT {

    private val testDecoder = JwtDecoder { token, _ ->
        if (token == "INVALID") throw IllegalArgumentException("bad token")
        SimpleDecodedJwt(
            subject = token,
            claims = mapOf("sub" to token, "roles" to listOf("USER")),
        )
    }

    private fun app(bearerChallenge: Boolean = false): Javalin = Javalin.create { cfg ->
        cfg.security {
            http {
                jwt {
                    decoder = testDecoder
                    keySource = JwtKeySource.secret("test-secret-not-actually-used-by-test-double")
                    authoritiesMapper = JwtAuthoritiesMapper.fromClaim("roles")
                    this.bearerChallenge = bearerChallenge
                    realm = "TestAPI"
                }
                authorizeRequests {
                    authorize("/public/**", GET, permitAll)
                    authorize("/protected/**", POST, authenticated)
                    authorize("/admin/**", GET, hasAuthority("ADMIN"))
                    anyRequest = denyAll
                }
            }
        }
        cfg.routes.get("/public/info") { it.result("public") }
        cfg.routes.post("/protected/data") { it.result("created") }
        cfg.routes.get("/admin/dashboard") { it.result("dashboard") }
    }

    // ── Anonymous access ──────────────────────────────────────────────────────

    @Test
    fun `should allow anonymous access to permitAll route`() = JavalinTest.test(app()) { _, client ->
        assertThat(client.get("/public/info").code).isEqualTo(200)
    }

    @Test
    fun `should return 401 when authenticated route is hit without a token`() = JavalinTest.test(app()) { _, client ->
        assertThat(client.post("/protected/data", "").code).isEqualTo(401)
    }

    @Test
    fun `should return 401 on denyAll route even without a token`() = JavalinTest.test(app()) { _, client ->
        assertThat(client.get("/admin/dashboard").code).isEqualTo(401)
    }

    // ── Authenticated access ──────────────────────────────────────────────────

    @Test
    fun `should allow access with valid bearer token on authenticated route`() = JavalinTest.test(app()) { _, client ->
        val response = client.post("/protected/data", "") { it.header("Authorization", "Bearer alice") }
        assertThat(response.code).isEqualTo(200)
    }

    // ── Failure: bad token ────────────────────────────────────────────────────

    @Test
    fun `should return 401 when decoder throws for an invalid token`() = JavalinTest.test(app()) { _, client ->
        val response = client.post("/protected/data", "") { it.header("Authorization", "Bearer INVALID") }
        assertThat(response.code).isEqualTo(401)
    }

    // ── Authority-based access ────────────────────────────────────────────────

    @Test
    fun `should return 403 when authenticated caller lacks required authority`() = JavalinTest.test(app()) { _, client ->
        // token "bob" decodes to roles=["USER"], not "ADMIN"
        val response = client.get("/admin/dashboard") { it.header("Authorization", "Bearer bob") }
        assertThat(response.code).isEqualTo(403)
    }

    @Test
    fun `should allow access when caller holds required authority`() {
        val adminDecoder = JwtDecoder { token, _ ->
            SimpleDecodedJwt(subject = token, claims = mapOf("roles" to listOf("ADMIN")))
        }
        val adminApp = Javalin.create { cfg ->
            cfg.security {
                http {
                    jwt {
                        decoder = adminDecoder
                        keySource = JwtKeySource.secret("test-secret")
                        authoritiesMapper = JwtAuthoritiesMapper.fromClaim("roles")
                    }
                    authorizeRequests { authorize("/admin/**", GET, hasAuthority("ADMIN")) }
                }
            }
            cfg.routes.get("/admin/dashboard") { it.result("ok") }
        }
        JavalinTest.test(adminApp) { _, client ->
            val response = client.get("/admin/dashboard") { it.header("Authorization", "Bearer admin-user") }
            assertThat(response.code).isEqualTo(200)
        }
    }

    // ── Principal access from route handler ───────────────────────────────────

    @Test
    fun `should expose JwtPrincipal on context with correct subject`() {
        val accessibleApp = Javalin.create { cfg ->
            cfg.security {
                http {
                    jwt {
                        decoder = testDecoder
                        keySource = JwtKeySource.secret("test-secret")
                    }
                    authorizeRequests { anyRequest = authenticated }
                }
            }
            cfg.routes.get("/me") { ctx ->
                val principal = ctx.principal<JwtPrincipal>()
                ctx.result(principal.name)
            }
        }
        JavalinTest.test(accessibleApp) { _, client ->
            val response = client.get("/me") { it.header("Authorization", "Bearer alice") }
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body!!.string()).isEqualTo("alice")
        }
    }

    // ── Bearer challenge ──────────────────────────────────────────────────────

    @Test
    fun `should include WWW-Authenticate header when bearerChallenge is enabled and token is absent`() =
        JavalinTest.test(app(bearerChallenge = true)) { _, client ->
            val response = client.post("/protected/data", "")
            assertThat(response.code).isEqualTo(401)
            val wwwAuthenticate = response.headers().get("WWW-Authenticate")?.firstOrNull()
            assertThat(wwwAuthenticate).startsWith("Bearer realm=\"TestAPI\"")
        }

    @Test
    fun `should include error attribute in WWW-Authenticate when token is invalid`() =
        JavalinTest.test(app(bearerChallenge = true)) { _, client ->
            val response = client.post("/protected/data", "") {
                it.header("Authorization", "Bearer INVALID")
            }
            assertThat(response.code).isEqualTo(401)
            val wwwAuthenticate = response.headers().get("WWW-Authenticate")?.firstOrNull()
            assertThat(wwwAuthenticate).contains("error=\"invalid_token\"")
        }

    @Test
    fun `should NOT include WWW-Authenticate header when bearerChallenge is disabled`() =
        JavalinTest.test(app(bearerChallenge = false)) { _, client ->
            val response = client.post("/protected/data", "")
            assertThat(response.code).isEqualTo(401)
            assertThat(response.headers().get("WWW-Authenticate")).isNull()
        }

    // ── Custom tokenResolver ────────────────────────────────────────────────────

    @Test
    fun `should authenticate from a cookie when tokenResolver is set to cookie-based resolution`() {
        val cookieApp = Javalin.create { cfg ->
            cfg.security {
                http {
                    jwt {
                        decoder = testDecoder
                        keySource = JwtKeySource.secret("test-secret")
                        tokenResolver = TokenResolver.cookie("access_token")
                    }
                    authorizeRequests { anyRequest = authenticated }
                }
            }
            cfg.routes.get("/me") { ctx ->
                val principal = ctx.principal<JwtPrincipal>()
                ctx.result(principal.name)
            }
        }
        JavalinTest.test(cookieApp) { _, client ->
            val response = client.get("/me") { it.header("Cookie", "access_token=alice") }
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body!!.string()).isEqualTo("alice")
        }
    }

    @Test
    fun `should return 401 when tokenResolver is cookie-based and the cookie is absent`() {
        val cookieApp = Javalin.create { cfg ->
            cfg.security {
                http {
                    jwt {
                        decoder = testDecoder
                        keySource = JwtKeySource.secret("test-secret")
                        tokenResolver = TokenResolver.cookie("access_token")
                    }
                    authorizeRequests { anyRequest = authenticated }
                }
            }
            cfg.routes.get("/me") { it.result("ok") }
        }
        JavalinTest.test(cookieApp) { _, client ->
            // Bearer header is present, but the resolver only looks at the cookie.
            val response = client.get("/me") { it.header("Authorization", "Bearer alice") }
            assertThat(response.code).isEqualTo(401)
        }
    }

    // ── DSL validation ────────────────────────────────────────────────────────

    @Test
    fun `should throw SecurityConfigurationException when decoder is not configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security {
                    http {
                        jwt {
                            keySource = JwtKeySource.secret("test-secret")
                            // decoder not set — should fail
                        }
                        authorizeRequests { anyRequest = permitAll }
                    }
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("decoder")
    }

    @Test
    fun `should throw SecurityConfigurationException when keySource is not configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security {
                    http {
                        jwt {
                            decoder = testDecoder
                            // keySource not set — should fail
                        }
                        authorizeRequests { anyRequest = permitAll }
                    }
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("keySource")
    }

}
