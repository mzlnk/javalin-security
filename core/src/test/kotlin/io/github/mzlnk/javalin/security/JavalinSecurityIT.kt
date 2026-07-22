package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.Javalin
import io.javalin.http.HandlerType.DELETE
import io.javalin.http.HandlerType.GET
import io.javalin.http.HandlerType.POST
import io.javalin.security.RouteRole
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JavalinSecurityIT {

    private enum class Role : RouteRole { ADMIN, USER }

    /**
     * Test authenticator: authenticates when an `X-User` header is present, granting the roles
     * listed (comma separated) in `X-Roles`. A user named "invalid" simulates a bad credential.
     */
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
                AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user), roles))
            }
        }
    }

    private fun app(authenticator: Authenticator? = headerAuthenticator): Javalin =
        Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r ->
                        r.add("/api/v1/*", GET, r.allow)
                        r.add("/api/v1/*", POST, r.authenticated)
                        r.add("/api/v1/*", DELETE, r.hasRole(Role.ADMIN))
                    }
                    authenticator?.let { http.authentication = syncScheme(it) }
                }
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
            cfg.routes.post("/api/v1/resource") { it.result("created") }
            cfg.routes.delete("/api/v1/resource") { it.result("deleted") }
            cfg.routes.get("/api/v1/me") { it.result(it.principal<TestPrincipal>()!!.name) }
        }

    @Test
    fun `should allow anonymous access when rule is allow`() = JavalinTest.test(app()) { _, client ->
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
            it.header("X-Roles", "USER")
        }

        // then
        assertThat(response.code).isEqualTo(403)
    }

    @Test
    fun `should allow access when role protected rule is hit with the role`() = JavalinTest.test(app()) { _, client ->
        // when
        val response = client.delete("/api/v1/resource", null) {
            it.header("X-User", "admin")
            it.header("X-Roles", "ADMIN")
        }

        // then
        assertThat(response.code).isEqualTo(200)
        assertThat(response.body.string()).isEqualTo("deleted")
    }

    @Test
    fun `should return 401 when the authenticator reports a failure`() = JavalinTest.test(app()) { _, client ->
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
            cfg.security { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/v1/*", GET, r.allow) }
                    http.authentication = syncScheme(headerAuthenticator)
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
    fun `should treat every request as anonymous when no authenticator is configured`() = JavalinTest.test(
        app(authenticator = null),
    ) { _, client ->
        // when / then: allow succeeds, authenticated is rejected with 401
        assertThat(client.get("/api/v1/resource").code).isEqualTo(200)
        assertThat(client.post("/api/v1/resource").code).isEqualTo(401)
    }

    @Test
    fun `should leave HTTP routes unguarded when only ws block is configured`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                // no http { } block — HTTP guard is opt-in and must NOT be installed
                security.ws { ws -> ws.rules { r -> r.fallback = r.deny } }
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        },
    ) { _, client ->
        // HTTP guard is absent, so the route is reachable without any credentials
        assertThat(client.get("/api/v1/resource").code).isEqualTo(200)
    }

    @Test
    fun `should leave HTTP routes unguarded when security block has no sub-blocks`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                // neither http { } nor ws { } — no guards installed at all
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        },
    ) { _, client ->
        assertThat(client.get("/api/v1/resource").code).isEqualTo(200)
    }

    // ── RouteRole-first authorization ───────────────────────────────────────────

    @Test
    fun `Anyone role grants access even to anonymous callers, bypassing the rule table`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http -> http.rules { r -> r.fallback = r.deny } } // rule table would deny everything
            }
            cfg.routes.get("/public", { it.result("ok") }, Anyone)
        },
    ) { _, client ->
        assertThat(client.get("/public").code).isEqualTo(200)
    }

    @Test
    fun `a route with declared roles is granted when the caller holds a matching role`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.authentication = syncScheme(headerAuthenticator)
                    http.rules { r -> r.fallback = r.deny } // rule table must NOT be consulted
                }
            }
            cfg.routes.get("/admin", { it.result("admin-ok") }, Role.ADMIN)
        },
    ) { _, client ->
        // anonymous → 401, no roles to match
        assertThat(client.get("/admin").code).isEqualTo(401)

        // authenticated without the role → 403
        val forbidden = client.get("/admin") {
            it.header("X-User", "bob")
            it.header("X-Roles", "USER")
        }
        assertThat(forbidden.code).isEqualTo(403)

        // authenticated with the role → 200, granted directly from authentication.roles, not the (deny) rule table
        val granted = client.get("/admin") {
            it.header("X-User", "alice")
            it.header("X-Roles", "ADMIN")
        }
        assertThat(granted.code).isEqualTo(200)
        assertThat(granted.body.string()).isEqualTo("admin-ok")
    }

    @Test
    fun `a route with declared roles is denied when the caller holds no matching role`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.authentication = syncScheme(headerAuthenticator)
                    http.rules { r -> r.fallback = r.allow } // even a permissive fallback must not apply
                }
            }
            cfg.routes.get("/admin", { it.result("admin-ok") }, Role.ADMIN)
        },
    ) { _, client ->
        val response = client.get("/admin") {
            it.header("X-User", "alice")
            it.header("X-Roles", "USER") // authenticated, but not ADMIN
        }
        assertThat(response.code).isEqualTo(403)
    }

    @Test
    fun `a route with no declared roles falls through to the pattern rule table`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.authentication = syncScheme(
                        Authenticator {
                            AuthenticationResult.Success(Authentication.authenticated(TestPrincipal("alice"), Role.ADMIN))
                        },
                    )
                    http.rules { r -> r.add("/plain", GET, r.deny) }
                }
            }
            cfg.routes.get("/plain") { it.result("ok") } // no roles declared
        },
    ) { _, client ->
        // the caller's ADMIN role is irrelevant here since the route declares no roles — the rule table decides
        assertThat(client.get("/plain").code).isEqualTo(403)
    }
}
