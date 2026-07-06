package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationProvider
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.Javalin
import io.javalin.http.HandlerType.GET
import io.javalin.http.HandlerType.POST
import io.javalin.http.UnauthorizedResponse
import io.javalin.http.staticfiles.Location
import io.javalin.plugin.bundled.CorsPlugin
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.http.HttpResponse
import java.util.concurrent.CompletableFuture
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
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/**", GET, permitAll) }
                }
            }
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
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/**", GET, permitAll) }
                }
            }
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
            cfg.security {
                http {
                    authorizeRequests { authorize("/**", GET, permitAll) }
                }
            }
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
            cfg.security {
                http {
                    authorizeRequests {
                        authorize("/api/v1/admin", GET, denyAll)
                        authorize("/api/v1/**", GET, permitAll)
                    }
                }
            }
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
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/**", POST, authenticated) }
                    authenticationProvider(abstains)
                    authenticationProvider(headerProvider)
                }
            }
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
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/**", GET, authenticated) }
                    authenticationManager(alwaysBob)
                }
            }
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
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/**", GET, authenticated) }
                    authenticationEntryPoint { ctx, _ ->
                        ctx.header("WWW-Authenticate", "Bearer")
                        throw UnauthorizedResponse()
                    }
                }
            }
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
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/**", GET, hasRole("ADMIN")) }
                    accessDeniedHandler { ctx, _ ->
                        throw io.javalin.http.ForbiddenResponse("custom denied")
                    }
                    authenticationProvider(headerProvider)
                }
            }
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
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/**", GET, permitAll) }
                    authenticationProvider(headerProvider)
                }
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        },
    ) { _, client ->
        // when: credentials are present but invalid
        val response = client.get("/api/v1/resource") { it.header("X-User", "invalid") }

        // then: the internal reason is never exposed to the client
        assertThat(response.code).isEqualTo(401)
        assertThat(response.body.string()).doesNotContain("super secret internal reason")
    }

    @Test
    fun `should not run the matched handler when a custom entry point does not throw`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/**", GET, authenticated) }
                    // A natural but unsafe implementation: render a 401 and return without throwing.
                    authenticationEntryPoint { ctx, _ -> ctx.status(401).result("denied-without-throwing") }
                }
            }
            cfg.routes.get("/api/v1/resource") { it.result("protected-content") }
        },
    ) { _, client ->
        // when: an anonymous caller hits an authenticated rule
        val response = client.get("/api/v1/resource")

        // then: the guard halts the request, so the protected handler never runs
        assertThat(response.code).isEqualTo(401)
        val body = response.body.string()
        assertThat(body).isEqualTo("denied-without-throwing")
        assertThat(body).doesNotContain("protected-content")
    }

    @Test
    fun `should not run the matched handler when a custom access denied handler does not throw`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/**", GET, hasRole("ADMIN")) }
                    // Render a 403 and return without throwing.
                    accessDeniedHandler { ctx, _ -> ctx.status(403).result("forbidden-without-throwing") }
                    authenticationProvider(headerProvider)
                }
            }
            cfg.routes.get("/api/v1/resource") { it.result("protected-content") }
        },
    ) { _, client ->
        // when: an authenticated caller lacking the role
        val response = client.get("/api/v1/resource") { it.header("X-User", "bob") }

        // then: the guard halts the request, so the protected handler never runs
        assertThat(response.code).isEqualTo(403)
        val body = response.body.string()
        assertThat(body).isEqualTo("forbidden-without-throwing")
        assertThat(body).doesNotContain("protected-content")
    }

    /**
     * Guard ordering constraint (documented, not asserted via a fragile ordering test):
     *
     * [io.github.mzlnk.javalin.security.JavalinSecurityPlugin] runs at [PluginPriority.EARLY].
     * The security guard is guaranteed to execute before the matched route handler — this is
     * enforced by Javalin's own `beforeMatched` lifecycle, which runs all `beforeMatched` handlers
     * before any route handler is invoked. This guarantee is implicit in all other IT tests.
     *
     * There is no strong guarantee on the relative order among *multiple* `beforeMatched` handlers.
     * In particular, Javalin does not expose a first-class API to insert a `beforeMatched` handler
     * at the head of the chain. EARLY plugin priority affects plugin initialization order but not
     * the position of `beforeMatched` registrations relative to other plugins or direct
     * `cfg.routes.beforeMatched()` calls.
     *
     * For handlers that must observe the resolved [authentication.Authentication], the recommended pattern is to
     * add them inside the matched route handler itself, which always runs after the guard.
     */
    @Test
    fun `security guard intercepts authenticated request before the route handler runs`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/**", GET, authenticated) }
                    authenticationProvider(headerProvider)
                }
            }
            cfg.routes.get("/api/v1/resource") { ctx ->
                // Route handler: only reachable when security guard grants access
                ctx.result((ctx.authentication().principal as TestPrincipal).name)
            }
        },
    ) { _, client ->
        // when: authenticated caller — guard grants access, route handler runs and sees the principal
        val response = client.get("/api/v1/resource") { it.header("X-User", "alice") }
        assertThat(response.code).isEqualTo(200)
        assertThat(response.body.string()).isEqualTo("alice")
    }

    @Test
    fun `permitCorsPreflight should allow a CORS preflight OPTIONS request`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.registerPlugin(CorsPlugin { cors ->
                cors.addRule { it.anyHost() }
            })
            cfg.security {
                http {
                    authorizeRequests {
                        permitCorsPreflight()
                        authorize("/api/**", GET, permitAll)
                        anyRequest(denyAll)
                    }
                }
            }
            cfg.routes.get("/api/resource") { it.result("ok") }
        },
    ) { _, client ->
        // when: a CORS preflight OPTIONS with Access-Control-Request-Method
        val preflightRequest = JdkHttpRequest.newBuilder(URI.create(client.origin + "/api/resource"))
            .method("OPTIONS", JdkHttpRequest.BodyPublishers.noBody())
            .header("Origin", "https://example.com")
            .header("Access-Control-Request-Method", "GET")
            .build()
        val preflightResponse = JdkHttpClient.newHttpClient().send(preflightRequest, HttpResponse.BodyHandlers.discarding())

        // then: preflight passes (not 401)
        assertThat(preflightResponse.statusCode()).isNotEqualTo(401)
        assertThat(preflightResponse.statusCode()).isNotEqualTo(403)

        // and: the real GET request is still evaluated against its rule
        val realResponse = client.get("/api/resource")
        assertThat(realResponse.code).isEqualTo(200)
    }

    @Test
    fun `permitCorsPreflight should deny OPTIONS without Access-Control-Request-Method header`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                http {
                    authorizeRequests {
                        permitCorsPreflight()
                        authorize("/api/**", GET, permitAll)
                        anyRequest(denyAll)
                    }
                }
            }
            cfg.routes.options("/api/resource") { it.result("options-ok") }
        },
    ) { _, client ->
        // when: a plain OPTIONS request without the preflight marker header
        val request = JdkHttpRequest.newBuilder(URI.create(client.origin + "/api/resource"))
            .method("OPTIONS", JdkHttpRequest.BodyPublishers.noBody())
            .build()
        val response = JdkHttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())

        // then: it is denied (no blanket OPTIONS exemption)
        assertThat(response.statusCode()).isIn(401, 403)
    }

    @Test
    fun `should authorize a parameterized route against the matched route template`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/v1/users/**", GET, denyAll) }
                    authenticationProvider(headerProvider)
                }
            }
            cfg.routes.get("/api/v1/users/{id}") { it.result("user-${it.pathParam("id")}") }
        },
    ) { _, client ->
        // when: a concrete request to the parameterized route
        val response = client.get("/api/v1/users/42") { it.header("X-User", "bob") }

        // then: authorization is evaluated against the matched template /api/v1/users/{id}
        assertThat(response.code).isEqualTo(403)
        assertThat(response.body.string()).doesNotContain("user-42")
    }

    // ── async authentication ──────────────────────────────────────────────────

    @Test
    fun `async provider should authenticate and allow access`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/**", GET, authenticated) }
                    asyncAuthenticationProvider { ctx ->
                        // Simulate I/O without blocking the request thread
                        CompletableFuture.supplyAsync {
                            val user = ctx.header("X-User")
                            if (user != null) {
                                AuthenticationResult.Success(Authentication.authenticated(TestPrincipal(user)))
                            } else {
                                AuthenticationResult.NotAuthenticated
                            }
                        }
                    }
                }
            }
            cfg.routes.get("/api/resource") { it.result("ok") }
        },
    ) { _, client ->
        // anonymous → 401
        assertThat(client.get("/api/resource").code).isEqualTo(401)

        // authenticated → 200
        assertThat(client.get("/api/resource") { it.header("X-User", "alice") }.code).isEqualTo(200)
    }

    @Test
    fun `async provider should be fail-closed on authentication failure`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/**", GET, permitAll) }
                    asyncAuthenticationProvider { _ ->
                        CompletableFuture.completedFuture(
                            AuthenticationResult.Failure("async credential failure"),
                        )
                    }
                }
            }
            cfg.routes.get("/api/resource") { it.result("ok") }
        },
    ) { _, client ->
        // when: async provider reports a failure
        val response = client.get("/api/resource")

        // then: request is rejected (fail-closed) — content not served, failure message not leaked
        assertThat(response.code).isEqualTo(401)
        assertThat(response.body.string()).doesNotContain("async credential failure")
    }

    @Test
    fun `async provider should not run the handler after denial`() = JavalinTest.test(
        Javalin.create { cfg ->
            cfg.security {
                http {
                    authorizeRequests { authorize("/api/**", GET, authenticated) }
                    asyncAuthenticationProvider { _ ->
                        CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated)
                    }
                }
            }
            cfg.routes.get("/api/resource") { it.result("protected-content") }
        },
    ) { _, client ->
        // when: anonymous async result hits authenticated rule
        val response = client.get("/api/resource")

        // then: the handler never runs
        assertThat(response.code).isEqualTo(401)
        assertThat(response.body.string()).doesNotContain("protected-content")
    }
}
