package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.TestIdentity
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.http.authorization.AuthorizationManager
import io.github.mzlnk.javalin.security.mockContext
import io.javalin.config.RouterConfig
import io.javalin.http.HandlerType
import io.javalin.security.RouteRole
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AuthorizationManagerTest {
    private enum class Role : RouteRole { ADMIN, USER }

    private val anonymous = Authentication.unauthenticated()

    private val defaultRouter = RouterConfig()

    @Test
    fun `should apply the first matching rule when several patterns match`() {
        // given
        // Javalin's own "*" wildcard already crosses path segments, so no "**" is needed.
        val manager = AuthorizationManager(
            entries = listOf(
                entry("/api/*", HandlerType.GET, Rules.allow()),
                entry("/api/*", HandlerType.GET, Rules.deny()),
            ),
            fallback = Rules.deny(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.GET, "/api/x", anonymous, mockContext())

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny by default when no rule matches the request`() {
        // given
        val manager = AuthorizationManager(
            entries = listOf(entry("/public/*", HandlerType.GET, Rules.allow())),
            fallback = Rules.deny(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.GET, "/private", authenticated(), mockContext())

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should only match the configured http method`() {
        // given
        val manager = AuthorizationManager(
            entries = listOf(entry("/api/*", HandlerType.POST, Rules.allow())),
            fallback = Rules.deny(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.GET, "/api/x", anonymous, mockContext())

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should match any method when no method is configured`() {
        // given
        val manager = AuthorizationManager(
            entries = listOf(entry("/api/*", null, Rules.allow())),
            fallback = Rules.deny(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.DELETE, "/api/x", anonymous, mockContext())

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should treat HEAD as GET when matching a GET rule`() {
        // given
        val manager = AuthorizationManager(
            entries = listOf(entry("/api/*", HandlerType.GET, Rules.allow())),
            fallback = Rules.deny(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.HEAD, "/api/x", anonymous, mockContext())

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny when the matching rule is not satisfied`() {
        // given
        val manager = AuthorizationManager(
            entries = listOf(entry("/api/*", HandlerType.GET, Rules.hasRole(Role.ADMIN))),
            fallback = Rules.deny(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.GET, "/api/x", authenticated(Role.USER), mockContext())

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should grant access when the matching rule is satisfied`() {
        // given
        val manager = AuthorizationManager(
            entries = listOf(entry("/api/*", HandlerType.DELETE, Rules.hasRole(Role.ADMIN))),
            fallback = Rules.deny(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.DELETE, "/api/x", authenticated(Role.ADMIN), mockContext())

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should match a path parameter segment against the concrete request path`() {
        // given
        // literal string, so it matches concrete path segments directly.
        val manager = AuthorizationManager(
            entries = listOf(entry("/api/users/{id}", HandlerType.GET, Rules.allow())),
            fallback = Rules.deny(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.GET, "/api/users/42", anonymous, mockContext())

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should match case-insensitively when configured on the router`() {
        // given
        val caseInsensitiveRouter = RouterConfig().apply { caseInsensitiveRoutes = true }
        val manager = AuthorizationManager(
            entries = listOf(entry("/api/admin/*", HandlerType.GET, Rules.allow(), caseInsensitiveRouter)),
            fallback = Rules.deny(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.GET, "/API/ADMIN/x", anonymous, mockContext())

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should not match case-insensitively by default`() {
        // given
        val manager = AuthorizationManager(
            entries = listOf(entry("/api/admin/*", HandlerType.GET, Rules.allow())),
            fallback = Rules.deny(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.GET, "/API/ADMIN/x", anonymous, mockContext())

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should apply the fallback rule when no entry matches`() {
        // given
        val manager = AuthorizationManager(
            entries = listOf(entry("/public/*", HandlerType.GET, Rules.deny())),
            fallback = Rules.allow(),
            allowCorsPreflight = false,
        )

        // when
        val granted = manager.isGranted(HandlerType.GET, "/other", anonymous, mockContext())

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny when no entry matches and no fallback is configured`() {
        // given
        val manager = AuthorizationManager(entries = emptyList(), fallback = Rules.deny(), allowCorsPreflight = false)

        // when
        val granted = manager.isGranted(HandlerType.GET, "/anything", authenticated(), mockContext())

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should grant a CORS preflight OPTIONS request when allowCorsPreflight is enabled`() {
        // given
        val manager = AuthorizationManager(entries = emptyList(), fallback = Rules.deny(), allowCorsPreflight = true)
        val context = mockContext(method = HandlerType.OPTIONS, headers = mapOf("Access-Control-Request-Method" to "GET"))

        // when
        val granted = manager.isGranted(HandlerType.OPTIONS, "/api/x", anonymous, context)

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should not grant a plain OPTIONS request even when allowCorsPreflight is enabled`() {
        // given
        val manager = AuthorizationManager(entries = emptyList(), fallback = Rules.deny(), allowCorsPreflight = true)
        val context = mockContext(method = HandlerType.OPTIONS)

        // when
        val granted = manager.isGranted(HandlerType.OPTIONS, "/api/x", anonymous, context)

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should not exempt OPTIONS requests when allowCorsPreflight is disabled`() {
        // given
        val manager = AuthorizationManager(entries = emptyList(), fallback = Rules.deny(), allowCorsPreflight = false)
        val context = mockContext(method = HandlerType.OPTIONS, headers = mapOf("Access-Control-Request-Method" to "GET"))

        // when
        val granted = manager.isGranted(HandlerType.OPTIONS, "/api/x", anonymous, context)

        // then
        assertThat(granted).isFalse()
    }

    private fun authenticated(vararg roles: RouteRole): Authentication =
        Authentication.authenticated(TestIdentity("bob"), roles.toSet())

    private fun entry(pattern: String, method: HandlerType?, rule: Rule, router: RouterConfig = defaultRouter) =
        AuthorizationManager.Entry(pattern, method, rule, router)
}
