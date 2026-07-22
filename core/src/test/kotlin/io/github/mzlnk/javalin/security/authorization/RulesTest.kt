package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.TestPrincipal
import io.github.mzlnk.javalin.security.authentication.Authentication
import io.github.mzlnk.javalin.security.mockContext
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class RulesTest {

    private val context = mockContext()
    private val anonymous = Authentication.unauthenticated()

    private fun authenticated(vararg authorities: String): Authentication =
        Authentication.authenticated(TestPrincipal("bob"), *authorities)

    @Test
    fun `should grant when rule is allow even for anonymous caller`() {
        // when
        val granted = Rules.allow().isGranted(anonymous, context)

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny when rule is deny even for authenticated caller`() {
        // when
        val granted = Rules.deny().isGranted(authenticated(), context)

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should grant when rule is authenticated and caller is authenticated`() {
        // when
        val granted = Rules.authenticated().isGranted(authenticated(), context)

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny when rule is authenticated and caller is anonymous`() {
        // when
        val granted = Rules.authenticated().isGranted(anonymous, context)

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should grant when caller has the required authority`() {
        // when
        val granted = Rules.hasAuthority("SCOPE_read").isGranted(authenticated("SCOPE_read"), context)

        // then
        assertThat(granted).isTrue()
    }

    @Test
    fun `should deny when caller lacks the required authority`() {
        // when
        val granted = Rules.hasAuthority("SCOPE_read").isGranted(authenticated("SCOPE_write"), context)

        // then
        assertThat(granted).isFalse()
    }

    @Test
    fun `should grant when caller has any of the required authorities`() {
        // when
        val granted = Rules.hasAnyAuthority("SCOPE_read", "SCOPE_write")
            .isGranted(authenticated("SCOPE_write"), context)

        // then
        assertThat(granted).isTrue()
    }

    // ── DSL delegation (RuleFactory / DefaultRules) ────────────────────────────

    @Test
    fun `DefaultRules should expose the same rule logic as Rules for delegation`() {
        assertThat(DefaultRules.allow.isGranted(anonymous, context)).isTrue()
        assertThat(DefaultRules.deny.isGranted(authenticated(), context)).isFalse()
        assertThat(DefaultRules.authenticated.isGranted(authenticated(), context)).isTrue()
        assertThat(DefaultRules.hasAuthority("ADMIN").isGranted(authenticated("ADMIN"), context)).isTrue()
        assertThat(DefaultRules.hasAnyAuthority("ADMIN", "USER").isGranted(authenticated("USER"), context)).isTrue()
    }
}
