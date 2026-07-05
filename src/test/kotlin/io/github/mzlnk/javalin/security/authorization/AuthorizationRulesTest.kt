package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.Authentication
import io.github.mzlnk.javalin.security.TestPrincipal
import io.github.mzlnk.javalin.security.mockContext
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AuthorizationRulesTest {

    private val context = mockContext()
    private val anonymous = Authentication.unauthenticated()

    private fun authenticated(vararg authorities: String): Authentication =
        Authentication.authenticated(TestPrincipal("bob"), *authorities)

    @Test
    fun `should grant when rule is permitAll even for anonymous caller`() {
        // when
        val granted = AuthorizationRules.permitAll.isGranted(anonymous, context)

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny when rule is denyAll even for authenticated caller`() {
        // when
        val granted = AuthorizationRules.denyAll.isGranted(authenticated(), context)

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should grant when rule is authenticated and caller is authenticated`() {
        // when
        val granted = AuthorizationRules.authenticated.isGranted(authenticated(), context)

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny when rule is authenticated and caller is anonymous`() {
        // when
        val granted = AuthorizationRules.authenticated.isGranted(anonymous, context)

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should grant when caller has the required role`() {
        // when
        val granted = AuthorizationRules.hasRole("ADMIN").isGranted(authenticated("ROLE_ADMIN"), context)

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny when caller lacks the required role`() {
        // when
        val granted = AuthorizationRules.hasRole("ADMIN").isGranted(authenticated("ROLE_USER"), context)

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should deny hasRole when caller is anonymous`() {
        // when
        val granted = AuthorizationRules.hasRole("ADMIN").isGranted(anonymous, context)

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should grant when caller has any of the required roles`() {
        // when
        val granted = AuthorizationRules.hasAnyRole("ADMIN", "USER").isGranted(authenticated("ROLE_USER"), context)

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should grant when caller has the required authority`() {
        // when
        val granted = AuthorizationRules.hasAuthority("SCOPE_read").isGranted(authenticated("SCOPE_read"), context)

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny when caller lacks the required authority`() {
        // when
        val granted = AuthorizationRules.hasAuthority("SCOPE_read").isGranted(authenticated("SCOPE_write"), context)

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should grant when caller has any of the required authorities`() {
        // when
        val granted = AuthorizationRules.hasAnyAuthority("SCOPE_read", "SCOPE_write")
            .isGranted(authenticated("SCOPE_write"), context)

        // then
        assertThat(granted).isTrue()
    }
}
