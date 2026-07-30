package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.identity
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.javalin.http.Context
import io.javalin.security.RouteRole
import io.javalin.testtools.HttpClient
import io.javalin.testtools.JavalinTest
import io.javalin.testtools.Response
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.Serializable

class SessionSecurityTest {
    private enum class Role : RouteRole { USER, ADMIN }

    private data class Principal(
        override val name: String,
        override val roles: Set<RouteRole> = emptySet(),
    ) : Identity, Serializable

    @Test
    fun `should allow anonymous access when route is allow`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            assertThat(client.get("/public/info").code).isEqualTo(200)
        }
    }

    @Test
    fun `should return 401 when authenticated route is hit without login`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            assertThat(client.post("/protected/data", "").code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 401 when a denied route is hit even without login`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            assertThat(client.get("/admin/dashboard").code).isEqualTo(401)
        }
    }

    @Test
    fun `should allow access when authenticated route is hit after login`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            val cookie = login(client, "alice", Role.USER)

            val response = client.post("/protected/data", "") {
                it.header("Cookie", cookie)
            }

            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should return 401 after logout`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            val cookie = login(client, "alice", Role.USER)

            val logout = client.post("/logout", "") {
                it.header("Cookie", cookie)
            }
            assertThat(logout.code).isEqualTo(200)

            val response = client.post("/protected/data", "") {
                it.header("Cookie", cookie)
            }
            assertThat(response.code).isEqualTo(401)
        }
    }

    @Test
    fun `should return 403 when authenticated caller lacks required role`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            val cookie = login(client, "alice", Role.USER)

            val response = client.get("/admin/dashboard") {
                it.header("Cookie", cookie)
            }

            assertThat(response.code).isEqualTo(403)
        }
    }

    @Test
    fun `should allow access when caller holds required role`() {
        val app = app()

        JavalinTest.test(app) { _, client ->
            val cookie = login(client, "admin", Role.ADMIN)

            val response = client.get("/admin/dashboard") {
                it.header("Cookie", cookie)
            }

            assertThat(response.code).isEqualTo(200)
        }
    }

    @Test
    fun `should expose the user-defined identity on the context when the caller is authenticated`() {
        val sessions = HttpSessionManager.of()
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = session { it.sessionManager = sessions }
                security.rules.post("/login", Rules.allow())
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.post("/login") { ctx ->
                sessions.create(ctx, Principal(name = "alice", roles = setOf(Role.USER)))
                ctx.result("ok")
            }
            cfg.routes.get("/me") { ctx ->
                val identity = ctx.identity<Principal>()
                ctx.result(identity.name)
            }
        }

        JavalinTest.test(app) { _, client ->
            val cookie = loginCookie(client)

            val response = client.get("/me") { it.header("Cookie", cookie) }

            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("alice")
        }
    }

    @Test
    fun `should authenticate with an HttpSessionManager using a custom attributeKey`() {
        val sessions = HttpSessionManager.of("custom.principal")
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = session { it.sessionManager = sessions }
                security.rules.post("/login", Rules.allow())
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.post("/login") { ctx ->
                sessions.create(ctx, Principal(name = "carol", roles = setOf(Role.USER)))
                ctx.result("ok")
            }
            cfg.routes.get("/me") { ctx ->
                ctx.result(ctx.identity<Principal>().name)
            }
        }

        JavalinTest.test(app) { _, client ->
            val cookie = loginCookie(client)
            val response = client.get("/me") { it.header("Cookie", cookie) }
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).isEqualTo("carol")
        }
    }

    @Test
    fun `should rotate session id on create when HttpSessionManager rotateSessionIdOnCreate is enabled`() {
        val sessions = HttpSessionManager.builder()
            .rotateSessionIdOnCreate(true)
            .build()
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = session { it.sessionManager = sessions }
                security.rules.get("/touch", Rules.allow())
                security.rules.post("/login", Rules.allow())
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/touch") { ctx ->
                val session = ctx.req().getSession(true)
                ctx.result(session.id)
            }
            cfg.routes.post("/login") { ctx ->
                sessions.create(ctx, Principal(name = "alice", roles = setOf(Role.USER)))
                ctx.result(ctx.req().session.id)
            }
        }

        JavalinTest.test(app) { _, client ->
            val touch = client.get("/touch")
            assertThat(touch.code).isEqualTo(200)
            val beforeId = touch.body.string()
            val beforeCookie = sessionCookie(touch)
            assertThat(beforeCookie).isNotNull()

            val login = client.post("/login", "") {
                it.header("Cookie", beforeCookie!!)
            }
            assertThat(login.code).isEqualTo(200)
            val afterId = login.body.string()

            assertThat(afterId).isNotEqualTo(beforeId)
        }
    }

    @Test
    fun `should authenticate via a custom SessionManager plugged in through composition`() {
        val store = mutableMapOf<String, Principal>()
        val customManager = object : SessionManager {
            override fun create(context: Context, identity: Identity) {
                val token = "sid-${store.size + 1}"
                store[token] = identity as Principal
                context.cookie("APPSESSION", token)
            }

            override fun validate(context: Context): Identity? {
                val token = context.cookie("APPSESSION") ?: return null
                return store[token]
            }

            override fun invalidate(context: Context) {
                val token = context.cookie("APPSESSION") ?: return
                store.remove(token)
                context.removeCookie("APPSESSION")
            }
        }

        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = session { it.sessionManager = customManager }
                security.rules.post("/login", Rules.allow())
                security.rules.post("/logout", Rules.allow())
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.post("/login") { ctx ->
                customManager.create(ctx, Principal(name = "alice", roles = setOf(Role.USER)))
                ctx.result("ok")
            }
            cfg.routes.post("/logout") { ctx ->
                customManager.invalidate(ctx)
                ctx.result("ok")
            }
            cfg.routes.get("/me") { ctx ->
                ctx.result(ctx.identity<Principal>().name)
            }
        }

        JavalinTest.test(app) { _, client ->
            assertThat(client.get("/me").code).isEqualTo(401)

            val login = client.post("/login", "")
            assertThat(login.code).isEqualTo(200)
            val cookie = login.headers().get("Set-Cookie")
                ?.firstOrNull { it.startsWith("APPSESSION=") }
                ?.substringBefore(';')
            assertThat(cookie).isNotNull()

            val me = client.get("/me") { it.header("Cookie", cookie!!) }
            assertThat(me.code).isEqualTo(200)
            assertThat(me.body.string()).isEqualTo("alice")

            val logout = client.post("/logout", "") { it.header("Cookie", cookie!!) }
            assertThat(logout.code).isEqualTo(200)

            val afterLogout = client.get("/me") { it.header("Cookie", cookie!!) }
            assertThat(afterLogout.code).isEqualTo(401)
        }
    }

    @Test
    fun `should use custom unauthorizedHandler when configured`() {
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = session { s ->
                    s.unauthorizedHandler = UnauthorizedHandler { ctx, _ ->
                        ctx.status(401).result("""{"error":"login_required"}""")
                    }
                }
                security.http.fallback = Rules.authenticated()
            }
            cfg.routes.get("/me") { ctx -> ctx.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            val response = client.get("/me")

            assertThat(response.code).isEqualTo(401)
            assertThat(response.body.string()).contains("login_required")
        }
    }

    private fun app(): Javalin {
        val sessions = HttpSessionManager.of()
        return Javalin.create { cfg ->
            cfg.security { security ->
                security.rules.get("/public/*", Rules.allow())
                security.rules.post("/login", Rules.allow())
                security.rules.post("/logout", Rules.allow())
                security.rules.post("/protected/*", Rules.authenticated())
                security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
                security.http.authentication = session { it.sessionManager = sessions }
                security.http.fallback = Rules.deny()
            }
            cfg.routes.get("/public/info") { it.result("public") }
            cfg.routes.post("/login") { ctx ->
                val username = ctx.queryParam("user") ?: "alice"
                val role = when (ctx.queryParam("role")) {
                    "ADMIN" -> Role.ADMIN
                    else -> Role.USER
                }
                sessions.create(ctx, Principal(name = username, roles = setOf(role)))
                ctx.result("ok")
            }
            cfg.routes.post("/logout") { ctx ->
                sessions.invalidate(ctx)
                ctx.result("ok")
            }
            cfg.routes.post("/protected/data") { it.result("created") }
            cfg.routes.get("/admin/dashboard") { it.result("dashboard") }
        }
    }

    private fun login(client: HttpClient, username: String, role: Role): String {
        val response = client.post("/login?user=$username&role=${role.name}", "")
        assertThat(response.code).isEqualTo(200)
        val cookie = sessionCookie(response)
        assertThat(cookie).isNotNull()
        return cookie!!
    }

    private fun loginCookie(client: HttpClient): String {
        val response = client.post("/login", "")
        assertThat(response.code).isEqualTo(200)
        val cookie = sessionCookie(response)
        assertThat(cookie).isNotNull()
        return cookie!!
    }

    private fun sessionCookie(response: Response): String? {
        val setCookies = response.headers().get("Set-Cookie") ?: return null
        if (setCookies.isEmpty()) return null
        // Prefer JSESSIONID; fall back to the first Set-Cookie name=value pair.
        val session = setCookies.firstOrNull { it.startsWith("JSESSIONID=", ignoreCase = true) }
            ?: setCookies.first()
        return session.substringBefore(';')
    }
}
