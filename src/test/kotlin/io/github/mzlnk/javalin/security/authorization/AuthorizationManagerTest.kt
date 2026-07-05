package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.Authentication
import io.github.mzlnk.javalin.security.TestPrincipal
import io.github.mzlnk.javalin.security.mockContext
import io.javalin.http.HandlerType
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AuthorizationManagerTest {

    private val anonymous = Authentication.unauthenticated()

    private fun authenticated(vararg authorities: String): Authentication =
        Authentication.authenticated(TestPrincipal("bob"), *authorities)

    @Test
    fun `should apply the first matching rule when several patterns match`() {
        // given: a permissive rule declared before a restrictive one for the same path
        val manager = AuthorizationManager(
            listOf(
                AuthorizationManager.Entry("/api/**", HandlerType.GET, AuthorizationRules.permitAll),
                AuthorizationManager.Entry("/api/**", HandlerType.GET, AuthorizationRules.denyAll),
            ),
        )

        // when
        val granted = manager.isGranted(mockContext(HandlerType.GET, "/api/x"), anonymous)

        // then: first-match-wins grants access
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny by default when no rule matches the request`() {
        // given
        val manager = AuthorizationManager(
            listOf(AuthorizationManager.Entry("/public/**", HandlerType.GET, AuthorizationRules.permitAll)),
        )

        // when
        val granted = manager.isGranted(mockContext(HandlerType.GET, "/private"), authenticated())

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should only match the configured http method`() {
        // given
        val manager = AuthorizationManager(
            listOf(AuthorizationManager.Entry("/api/**", HandlerType.POST, AuthorizationRules.permitAll)),
        )

        // when: a GET does not match the POST rule
        val granted = manager.isGranted(mockContext(HandlerType.GET, "/api/x"), anonymous)

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should match any method when no method is configured`() {
        // given
        val manager = AuthorizationManager(
            listOf(AuthorizationManager.Entry("/api/**", null, AuthorizationRules.permitAll)),
        )

        // when
        val granted = manager.isGranted(mockContext(HandlerType.DELETE, "/api/x"), anonymous)

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny when the matching rule is not satisfied`() {
        // given
        val manager = AuthorizationManager(
            listOf(AuthorizationManager.Entry("/api/**", HandlerType.GET, AuthorizationRules.hasRole("ADMIN"))),
        )

        // when
        val granted = manager.isGranted(mockContext(HandlerType.GET, "/api/x"), authenticated("ROLE_USER"))

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should grant access when the matching rule is satisfied`() {
        // given
        val manager = AuthorizationManager(
            listOf(AuthorizationManager.Entry("/api/**", HandlerType.DELETE, AuthorizationRules.hasRole("ADMIN"))),
        )

        // when
        val granted = manager.isGranted(mockContext(HandlerType.DELETE, "/api/x"), authenticated("ROLE_ADMIN"))

        // then
        assertThat(granted).isTrue()
    }
}
